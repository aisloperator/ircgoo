//! User configuration, stored as a GLib key file in `$XDG_CONFIG_HOME/ircgoo/ircgoo.conf`.

use gtk::glib;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum SaslMech {
    #[default]
    None,
    Plain,
    External,
}

impl SaslMech {
    pub fn as_str(self) -> &'static str {
        match self {
            SaslMech::None => "none",
            SaslMech::Plain => "plain",
            SaslMech::External => "external",
        }
    }
    pub fn parse(s: &str) -> SaslMech {
        match s.to_ascii_lowercase().as_str() {
            "plain" => SaslMech::Plain,
            "external" => SaslMech::External,
            _ => SaslMech::None,
        }
    }
    pub fn index(self) -> u32 {
        match self {
            SaslMech::None => 0,
            SaslMech::Plain => 1,
            SaslMech::External => 2,
        }
    }
    pub fn from_index(i: u32) -> SaslMech {
        match i {
            1 => SaslMech::Plain,
            2 => SaslMech::External,
            _ => SaslMech::None,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Sasl {
    pub mech: SaslMech,
    pub account: String,
    pub password: String,
    /// PEM file with client certificate (chain) and private key, for EXTERNAL.
    pub cert_file: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Server {
    pub host: String,
    pub port: u16,
    pub tls: bool,
    /// Overrides the network's SASL settings when set.
    pub sasl: Option<Sasl>,
}

impl Default for Server {
    fn default() -> Self {
        Server {
            host: String::new(),
            port: 6697,
            tls: true,
            sasl: None,
        }
    }
}

impl Server {
    pub fn describe(&self) -> String {
        describe_addr(&self.host, self.port, self.tls)
    }
}

pub fn describe_addr(host: &str, port: u16, tls: bool) -> String {
    let h = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    format!("{h}:{port}{}", if tls { " (TLS)" } else { "" })
}

#[derive(Clone, Debug, PartialEq)]
pub struct Bouncer {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub username: String,
    /// Bouncer-side network name (ZNC: user/network:password).
    pub network: String,
    pub password: String,
}

impl Default for Bouncer {
    fn default() -> Self {
        Bouncer {
            enabled: false,
            host: String::new(),
            port: 6697,
            tls: true,
            username: String::new(),
            network: String::new(),
            password: String::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Network {
    pub name: String,
    pub autoconnect: bool,
    /// Empty means "use the global default".
    pub nick: String,
    pub username: String,
    pub realname: String,
    pub servers: Vec<Server>,
    pub sasl: Sasl,
    pub use_system_cas: bool,
    /// PEM files with additional trusted CA or server certificates.
    pub trusted_certs: Vec<String>,
    pub bouncer: Bouncer,
    pub use_proxy: bool,
    pub autojoin: Vec<String>,
}

impl Default for Network {
    fn default() -> Self {
        Network {
            name: String::new(),
            autoconnect: false,
            nick: String::new(),
            username: String::new(),
            realname: String::new(),
            servers: Vec::new(),
            sasl: Sasl::default(),
            use_system_cas: true,
            trusted_certs: Vec::new(),
            bouncer: Bouncer::default(),
            use_proxy: true,
            autojoin: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Proxy {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
}

impl Default for Proxy {
    fn default() -> Self {
        Proxy {
            enabled: false,
            host: "127.0.0.1".into(),
            port: 9050,
            username: String::new(),
            password: String::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Config {
    pub nick: String,
    pub username: String,
    pub realname: String,
    pub proxy: Proxy,
    pub networks: Vec<Network>,
}

fn sanitize_nick(s: &str) -> String {
    let n: String = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || "-_[]{}\\|^`".contains(*c))
        .take(16)
        .collect();
    if n.is_empty() || n.starts_with(|c: char| c.is_ascii_digit() || c == '-') {
        format!("goo{n}")
    } else {
        n
    }
}

impl Config {
    pub fn dir() -> PathBuf {
        glib::user_config_dir().join("ircgoo")
    }

    pub fn path() -> PathBuf {
        Self::dir().join("ircgoo.conf")
    }

    /// A fresh configuration for first run.
    pub fn new_default() -> Config {
        let login = glib::user_name().to_string_lossy().into_owned();
        let nick = sanitize_nick(&login);
        let realname = glib::real_name().to_string_lossy().into_owned();
        let realname = if realname.is_empty() || realname == "Unknown" {
            nick.clone()
        } else {
            realname
        };
        Config {
            username: nick.to_ascii_lowercase(),
            nick,
            realname,
            proxy: Proxy::default(),
            networks: vec![Network {
                name: "Libera.Chat".into(),
                servers: vec![Server {
                    host: "irc.libera.chat".into(),
                    port: 6697,
                    tls: true,
                    sasl: None,
                }],
                ..Network::default()
            }],
        }
    }

    pub fn load() -> Result<Config, String> {
        let path = Self::path();
        if !path.exists() {
            return Ok(Self::new_default());
        }
        let kf = glib::KeyFile::new();
        kf.load_from_file(&path, glib::KeyFileFlags::NONE)
            .map_err(|e| format!("Cannot read {}: {e}", path.display()))?;
        let d = Self::new_default();
        let g = "General";
        let mut cfg = Config {
            nick: or_default(gs(&kf, g, "nick"), &d.nick),
            username: or_default(gs(&kf, g, "username"), &d.username),
            realname: or_default(gs(&kf, g, "realname"), &d.realname),
            proxy: Proxy {
                enabled: gb(&kf, "Proxy", "enabled", false),
                host: or_default(gs(&kf, "Proxy", "host"), "127.0.0.1"),
                port: gport(&kf, "Proxy", "port", 9050),
                username: gs(&kf, "Proxy", "username"),
                password: gs(&kf, "Proxy", "password"),
            },
            networks: Vec::new(),
        };
        let mut i = 0;
        loop {
            let ng = format!("Network {i}");
            if !kf.has_group(&ng) {
                break;
            }
            let mut net = Network {
                name: gs(&kf, &ng, "name"),
                autoconnect: gb(&kf, &ng, "autoconnect", false),
                nick: gs(&kf, &ng, "nick"),
                username: gs(&kf, &ng, "username"),
                realname: gs(&kf, &ng, "realname"),
                servers: Vec::new(),
                sasl: read_sasl(&kf, &ng),
                use_system_cas: gb(&kf, &ng, "use_system_cas", true),
                trusted_certs: glist(&kf, &ng, "trusted_certs"),
                bouncer: Bouncer {
                    enabled: gb(&kf, &ng, "bouncer_enabled", false),
                    host: gs(&kf, &ng, "bouncer_host"),
                    port: gport(&kf, &ng, "bouncer_port", 6697),
                    tls: gb(&kf, &ng, "bouncer_tls", true),
                    username: gs(&kf, &ng, "bouncer_username"),
                    network: gs(&kf, &ng, "bouncer_network"),
                    password: gs(&kf, &ng, "bouncer_password"),
                },
                use_proxy: gb(&kf, &ng, "use_proxy", true),
                autojoin: glist(&kf, &ng, "autojoin"),
            };
            let mut j = 0;
            loop {
                let sg = format!("Network {i} Server {j}");
                if !kf.has_group(&sg) {
                    break;
                }
                net.servers.push(Server {
                    host: gs(&kf, &sg, "host"),
                    port: gport(&kf, &sg, "port", 6697),
                    tls: gb(&kf, &sg, "tls", true),
                    sasl: if gb(&kf, &sg, "sasl_override", false) {
                        Some(read_sasl(&kf, &sg))
                    } else {
                        None
                    },
                });
                j += 1;
            }
            if net.name.is_empty() {
                net.name = format!("Network {}", i + 1);
            }
            cfg.networks.push(net);
            i += 1;
        }
        Ok(cfg)
    }

    pub fn save(&self) -> Result<(), String> {
        let kf = glib::KeyFile::new();
        let g = "General";
        kf.set_string(g, "nick", &self.nick);
        kf.set_string(g, "username", &self.username);
        kf.set_string(g, "realname", &self.realname);
        let p = "Proxy";
        kf.set_boolean(p, "enabled", self.proxy.enabled);
        kf.set_string(p, "host", &self.proxy.host);
        kf.set_integer(p, "port", self.proxy.port.into());
        kf.set_string(p, "username", &self.proxy.username);
        kf.set_string(p, "password", &self.proxy.password);
        for (i, n) in self.networks.iter().enumerate() {
            let ng = format!("Network {i}");
            kf.set_string(&ng, "name", &n.name);
            kf.set_boolean(&ng, "autoconnect", n.autoconnect);
            kf.set_string(&ng, "nick", &n.nick);
            kf.set_string(&ng, "username", &n.username);
            kf.set_string(&ng, "realname", &n.realname);
            write_sasl(&kf, &ng, &n.sasl);
            kf.set_boolean(&ng, "use_system_cas", n.use_system_cas);
            kf.set_string(&ng, "trusted_certs", &n.trusted_certs.join("\n"));
            kf.set_boolean(&ng, "use_proxy", n.use_proxy);
            kf.set_string(&ng, "autojoin", &n.autojoin.join("\n"));
            let b = &n.bouncer;
            kf.set_boolean(&ng, "bouncer_enabled", b.enabled);
            kf.set_string(&ng, "bouncer_host", &b.host);
            kf.set_integer(&ng, "bouncer_port", b.port.into());
            kf.set_boolean(&ng, "bouncer_tls", b.tls);
            kf.set_string(&ng, "bouncer_username", &b.username);
            kf.set_string(&ng, "bouncer_network", &b.network);
            kf.set_string(&ng, "bouncer_password", &b.password);
            for (j, s) in n.servers.iter().enumerate() {
                let sg = format!("Network {i} Server {j}");
                kf.set_string(&sg, "host", &s.host);
                kf.set_integer(&sg, "port", s.port.into());
                kf.set_boolean(&sg, "tls", s.tls);
                kf.set_boolean(&sg, "sasl_override", s.sasl.is_some());
                if let Some(sasl) = &s.sasl {
                    write_sasl(&kf, &sg, sasl);
                }
            }
        }
        let data = kf.to_data();
        let dir = Self::dir();
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .map_err(|e| format!("Cannot create {}: {e}", dir.display()))?;
        // The file may contain passwords: write privately, then atomically replace.
        let path = Self::path();
        let tmp = dir.join("ircgoo.conf.tmp");
        let write = || -> std::io::Result<()> {
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            f.set_permissions(fs::Permissions::from_mode(0o600))?;
            f.write_all(data.as_bytes())?;
            f.sync_all()?;
            fs::rename(&tmp, &path)
        };
        write().map_err(|e| format!("Cannot write {}: {e}", path.display()))
    }

    pub fn network(&self, name: &str) -> Option<&Network> {
        self.networks.iter().find(|n| n.name.eq_ignore_ascii_case(name))
    }

    pub fn nick_for(&self, n: &Network) -> String {
        or_default(n.nick.clone(), &self.nick)
    }
    pub fn username_for(&self, n: &Network) -> String {
        or_default(n.username.clone(), &self.username)
    }
    pub fn realname_for(&self, n: &Network) -> String {
        or_default(n.realname.clone(), &self.realname)
    }
}

fn or_default(v: String, d: &str) -> String {
    if v.trim().is_empty() { d.to_string() } else { v }
}

fn gs(kf: &glib::KeyFile, g: &str, k: &str) -> String {
    kf.string(g, k).map(|s| s.to_string()).unwrap_or_default()
}

fn gb(kf: &glib::KeyFile, g: &str, k: &str, default: bool) -> bool {
    kf.boolean(g, k).unwrap_or(default)
}

fn gport(kf: &glib::KeyFile, g: &str, k: &str, default: u16) -> u16 {
    kf.integer(g, k)
        .ok()
        .and_then(|v| u16::try_from(v).ok())
        .filter(|v| *v > 0)
        .unwrap_or(default)
}

fn glist(kf: &glib::KeyFile, g: &str, k: &str) -> Vec<String> {
    gs(kf, g, k)
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

fn read_sasl(kf: &glib::KeyFile, g: &str) -> Sasl {
    Sasl {
        mech: SaslMech::parse(&gs(kf, g, "sasl_mechanism")),
        account: gs(kf, g, "sasl_account"),
        password: gs(kf, g, "sasl_password"),
        cert_file: gs(kf, g, "sasl_cert"),
    }
}

fn write_sasl(kf: &glib::KeyFile, g: &str, s: &Sasl) {
    kf.set_string(g, "sasl_mechanism", s.mech.as_str());
    kf.set_string(g, "sasl_account", &s.account);
    kf.set_string(g, "sasl_password", &s.password);
    kf.set_string(g, "sasl_cert", &s.cert_file);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_load_round_trip() {
        let dir = std::env::temp_dir().join(format!("ircgoo-test-{}", std::process::id()));
        // SAFETY: this is the only test that touches the environment, and it runs before
        // GLib caches the config directory.
        unsafe { std::env::set_var("XDG_CONFIG_HOME", &dir) };
        let mut cfg = Config::new_default();
        cfg.proxy.enabled = true;
        cfg.networks.push(Network {
            name: "Test Net".into(),
            autoconnect: true,
            nick: "alt".into(),
            servers: vec![
                Server {
                    host: "irc.example.org".into(),
                    port: 6697,
                    tls: true,
                    sasl: None,
                },
                Server {
                    host: "irc.example.org".into(),
                    port: 6667,
                    tls: false,
                    sasl: Some(Sasl {
                        mech: SaslMech::External,
                        cert_file: "/x/y.pem".into(),
                        ..Sasl::default()
                    }),
                },
            ],
            sasl: Sasl {
                mech: SaslMech::Plain,
                account: "me".into(),
                password: "p;w=\n#x".into(),
                ..Sasl::default()
            },
            trusted_certs: vec!["/a/b.pem".into(), "/c;d.pem".into()],
            bouncer: Bouncer {
                enabled: true,
                host: "znc.local".into(),
                username: "u".into(),
                ..Bouncer::default()
            },
            autojoin: vec!["#a".into(), "#b key".into()],
            ..Network::default()
        });
        cfg.save().unwrap();
        assert!(Config::path().starts_with(&dir));
        let mode = fs::metadata(Config::path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let loaded = Config::load().unwrap();
        let _ = fs::remove_dir_all(&dir);
        assert_eq!(loaded, cfg);
    }
}
