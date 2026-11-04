//! Application state: the main window, tabs, and per-network IRC sessions.

use crate::config::{Config, Network, Sasl, SaslMech};
use crate::irc::{self, Message, irc_eq, irc_lower};
use crate::net::{self, ConnectParams, Connection, EventSink, NetEvent};
use crate::tab::{Activity, Completion, Part, Tab, TabKind};
use crate::tls::TlsSettings;
use gtk::prelude::*;
use gtk::{gdk, gio, glib};
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const APP_ID: &str = "com.aisloperator.IrcGoo";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const WEBSITE: &str = "https://www.aisloperator.com/";
const DEFAULT_QUIT: &str = "IrcGoo";
const PING_INTERVAL: Duration = Duration::from_secs(30);
const PING_TIMEOUT: Duration = Duration::from_secs(180);
const LAG_SHOW: Duration = Duration::from_secs(2);
const WHOIS_CACHE: Duration = Duration::from_secs(120);

type ActionFn = fn(&Rc<App>);

const CSS: &str = "
notebook > header > tabs > tab { padding: 2px 8px; min-height: 0; }
.ircgoo-tab-label.activity { font-weight: bold; }
.ircgoo-tab-label.highlight { font-weight: bold; color: #e01b24; }
.ircgoo-menu-button > button { padding: 2px 6px; min-height: 0; min-width: 0; }
.ircgoo-bottom { padding: 2px 3px; }
.ircgoo-nick { font-weight: bold; }
.ircgoo-lag { color: #e66100; font-weight: bold; }
.ircgoo-nicklist row { padding: 0 6px; min-height: 0; }
";

const HELP: &[(&str, &str)] = &[
    ("/join /j <#chan>[,<#chan>] [keys]", "Join channels"),
    ("/part /p [#chan] [reason]", "Leave a channel (the tab stays open)"),
    ("/close", "Close the tab (parts a channel, disconnects a network tab)"),
    ("/msg <nick|#chan> <text>", "Send a message"),
    ("/query <nick> [text]", "Open a private chat"),
    ("/me <action>", "Send an action"),
    ("/notice <target> <text>", "Send a notice"),
    ("/nick <newnick>", "Change your nick"),
    ("/topic [text]", "Show or set the channel topic"),
    ("/op /deop /voice /devoice <nicks>", "Change channel user modes"),
    ("/kick <nick> [reason]", "Kick a user from the channel"),
    ("/mode [target] <modes> [args]", "Set or show modes"),
    ("/whois <nick>", "Show information about a user"),
    ("/names [#chan]", "List users in a channel"),
    ("/invite <nick> [#chan]", "Invite a user to a channel"),
    ("/away [message]", "Set or clear away status"),
    ("/ctcp <target> <command> [args]", "Send a CTCP request"),
    ("/network [list]", "List configured networks"),
    ("/network connect <name>", "Connect to a network"),
    ("/network disconnect [name]", "Disconnect from a network"),
    (
        "/server [list|next|<number>|<host>[:port]]",
        "Show or change the server for this network",
    ),
    ("/quit [reason]", "Disconnect from this tab's network"),
    ("/exit", "Quit IrcGoo"),
    ("/quote /raw <line>", "Send a raw protocol line"),
    ("/clear /c", "Clear this tab's messages"),
];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ConnState {
    Disconnected,
    Connecting,
    Registering,
    Connected,
}

#[derive(Clone, Default, Debug)]
struct WhoisInfo {
    nick: String,
    userhost: String,
    realname: String,
    server: String,
    idle: Option<u64>,
    signon: Option<i64>,
    account: String,
    channels: String,
    away: String,
    error: String,
    fetched: Option<Instant>,
}

impl WhoisInfo {
    fn tooltip(&self) -> String {
        let mut lines = vec![if self.userhost.is_empty() {
            self.nick.clone()
        } else {
            format!("{} ({})", self.nick, self.userhost)
        }];
        if !self.error.is_empty() {
            lines.push(self.error.clone());
        }
        if !self.realname.is_empty() {
            lines.push(format!("Real name: {}", irc::strip_formatting(&self.realname)));
        }
        if let Some(idle) = self.idle {
            let since = self.fetched.map(|f| f.elapsed().as_secs()).unwrap_or(0);
            lines.push(format!("Idle: {}", irc::fmt_duration(idle + since)));
        }
        if !self.account.is_empty() {
            lines.push(format!("Account: {}", self.account));
        }
        if !self.away.is_empty() {
            lines.push(format!("Away: {}", irc::strip_formatting(&self.away)));
        }
        if !self.channels.is_empty() {
            lines.push(format!("Channels: {}", self.channels));
        }
        if !self.server.is_empty() {
            lines.push(format!("Server: {}", self.server));
        }
        if let Some(t) = self.signon.and_then(fmt_unix_time) {
            lines.push(format!("Signed on: {t}"));
        }
        lines.join("\n")
    }
}

struct Member {
    nick: String,
    /// Prefix symbols held (e.g. "@+"), ordered by rank.
    prefixes: String,
}

struct Channel {
    name: String,
    members: HashMap<String, Member>,
    topic: String,
}

struct Session {
    name: String,
    cfg: Network,
    conn: Option<Connection>,
    conn_id: u64,
    state: ConnState,
    server_idx: usize,
    want_connected: bool,
    nick: String,
    prefix: Vec<(char, char)>,
    chanmodes: [String; 4],
    chantypes: String,
    max_modes: usize,
    channels: HashMap<String, Channel>,
    cap_ls: Vec<String>,
    sasl_current: Option<Sasl>,
    sasl_active: bool,
    ping_sent: Option<(String, Instant)>,
    last_ping: Instant,
    reconnect_source: Option<glib::SourceId>,
    failures: u32,
    whois_hover: HashSet<String>,
    whois_partial: HashMap<String, WhoisInfo>,
    whois_cache: HashMap<String, WhoisInfo>,
    user_joins: HashSet<String>,
    /// Last reply time per CTCP command, for flood protection.
    last_ctcp_reply: HashMap<&'static str, Instant>,
    /// Host, port and TLS of the server (or bouncer) last connected to.
    endpoint: Option<(String, u16, bool)>,
}

impl Session {
    fn new(cfg: Network) -> Session {
        Session {
            name: cfg.name.clone(),
            cfg,
            conn: None,
            conn_id: 0,
            state: ConnState::Disconnected,
            server_idx: 0,
            want_connected: false,
            nick: String::new(),
            prefix: vec![('o', '@'), ('v', '+')],
            chanmodes: ["beI".into(), "k".into(), "l".into(), "imnpst".into()],
            chantypes: "#&".into(),
            max_modes: 3,
            channels: HashMap::new(),
            cap_ls: Vec::new(),
            sasl_current: None,
            sasl_active: false,
            ping_sent: None,
            last_ping: Instant::now(),
            reconnect_source: None,
            failures: 0,
            whois_hover: HashSet::new(),
            whois_partial: HashMap::new(),
            whois_cache: HashMap::new(),
            user_joins: HashSet::new(),
            last_ctcp_reply: HashMap::new(),
            endpoint: None,
        }
    }

    fn send(&self, line: &str) {
        if let Some(c) = &self.conn {
            let line = line.split(['\r', '\n']).next().unwrap_or("");
            c.send(line.to_string());
        }
    }

    fn connected(&self) -> bool {
        self.state == ConnState::Connected
    }

    fn is_channel(&self, t: &str) -> bool {
        t.starts_with(|c| self.chantypes.contains(c))
    }

    fn prefix_symbols(&self) -> String {
        self.prefix.iter().map(|(_, s)| *s).collect()
    }

    fn rank(&self, sym: char) -> usize {
        self.prefix.iter().position(|(_, s)| *s == sym).unwrap_or(usize::MAX)
    }

    fn sort_prefixes(&self, p: &str) -> String {
        let mut v: Vec<char> = p.chars().collect();
        v.sort_by_key(|c| self.rank(*c));
        v.dedup();
        v.into_iter().collect()
    }

    fn member_prefix(&self, chan: &str, nick: &str) -> String {
        self.channels
            .get(&irc_lower(chan))
            .and_then(|c| c.members.get(&irc_lower(nick)))
            .and_then(|m| m.prefixes.chars().next())
            .map(String::from)
            .unwrap_or_default()
    }

    fn add_member(&mut self, chan: &str, nick_with_prefix: &str) {
        let syms = self.prefix_symbols();
        let nick = nick_with_prefix.trim_start_matches(|c| syms.contains(c));
        let prefixes = self.sort_prefixes(&nick_with_prefix[..nick_with_prefix.len() - nick.len()]);
        // Strip any user@host (userhost-in-names).
        let nick = nick.split('!').next().unwrap_or(nick).to_string();
        if let Some(ch) = self.channels.get_mut(&irc_lower(chan)) {
            ch.members.insert(irc_lower(&nick), Member { nick, prefixes });
        }
    }

    fn sorted_members(&self, chan: &str) -> Vec<(String, String)> {
        let Some(ch) = self.channels.get(&irc_lower(chan)) else {
            return Vec::new();
        };
        let mut v: Vec<&Member> = ch.members.values().collect();
        v.sort_by(|a, b| {
            let ra = a.prefixes.chars().next().map(|c| self.rank(c)).unwrap_or(usize::MAX);
            let rb = b.prefixes.chars().next().map(|c| self.rank(c)).unwrap_or(usize::MAX);
            ra.cmp(&rb).then_with(|| irc_lower(&a.nick).cmp(&irc_lower(&b.nick)))
        });
        v.into_iter()
            .map(|m| {
                (
                    format!(
                        "{}{}",
                        m.prefixes.chars().next().map(String::from).unwrap_or_default(),
                        m.nick
                    ),
                    m.nick.clone(),
                )
            })
            .collect()
    }
}

pub struct App {
    pub gtk_app: gtk::Application,
    pub window: gtk::ApplicationWindow,
    notebook: gtk::Notebook,
    menu_button: gtk::MenuButton,
    connect_menu: gio::Menu,
    pub config: RefCell<Config>,
    tabs: RefCell<Vec<Rc<Tab>>>,
    sessions: RefCell<Vec<Session>>,
    next_id: Cell<u64>,
    sink: EventSink,
    rx: mpsc::Receiver<(u64, NetEvent)>,
    nicklist_visible: Cell<bool>,
    nicklist_dirty: RefCell<HashSet<(String, String)>>,
    pub prefs_window: RefCell<Option<gtk::Window>>,
    pub networks_window: RefCell<Option<Rc<crate::prefs::NetworksWindow>>>,
    quitting: Cell<bool>,
    /// Holds the message font size rule; empty when following the desktop default.
    font_css: gtk::CssProvider,
    /// GNOME's interface settings, when installed (source of the monospace font size).
    desktop_settings: Option<gio::Settings>,
}

thread_local! {
    static APP: RefCell<Option<Rc<App>>> = const { RefCell::new(None) };
}

pub fn current() -> Option<Rc<App>> {
    APP.with(|a| a.borrow().clone())
}

fn drain_net_events() {
    if let Some(a) = current() {
        a.drain_events();
    }
}

fn split1(s: &str) -> (&str, &str) {
    let s = s.trim_start();
    match s.find(char::is_whitespace) {
        Some(i) => (&s[..i], s[i..].trim_start()),
        None => (s, ""),
    }
}

fn unix_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn fmt_unix_time(t: i64) -> Option<String> {
    glib::DateTime::from_unix_local(t)
        .ok()?
        .format("%Y-%m-%d %H:%M:%S")
        .ok()
        .map(|s| s.to_string())
}

/// Split a message into chunks that fit in one protocol line.
fn split_message(text: &str, max: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while rest.len() > max {
        let mut cut = max;
        while !rest.is_char_boundary(cut) {
            cut -= 1;
        }
        if let Some(sp) = rest[..cut].rfind(' ').filter(|&i| i > max / 2) {
            cut = sp;
        }
        out.push(rest[..cut].to_string());
        rest = rest[cut..].trim_start_matches(' ');
    }
    out.push(rest.to_string());
    out
}

const GNOME_INTERFACE: &str = "org.gnome.desktop.interface";
const GNOME_MONO_KEY: &str = "monospace-font-name";

/// True when `XDG_CURRENT_DESKTOP` lists GNOME (for example "GNOME", "ubuntu:GNOME" or
/// "Phosh:GNOME").
fn is_gnome_session() -> bool {
    std::env::var("XDG_CURRENT_DESKTOP").is_ok_and(|v| v.split(':').any(|d| d.eq_ignore_ascii_case("GNOME")))
}

fn gnome_interface_settings() -> Option<gio::Settings> {
    let schema = gio::SettingsSchemaSource::default()?.lookup(GNOME_INTERFACE, true)?;
    schema
        .has_key(GNOME_MONO_KEY)
        .then(|| gio::Settings::new(GNOME_INTERFACE))
}

/// Size in points of a Pango font description string such as "Monospace 11".
fn font_size_pt(desc: &str) -> Option<f64> {
    let fd = gtk::pango::FontDescription::from_string(desc);
    let size = f64::from(fd.size()) / f64::from(gtk::pango::SCALE);
    let pt = if fd.is_size_absolute() { size * 0.75 } else { size };
    (pt > 0.0).then_some(pt)
}

fn nick_menu(nick: &str) -> gio::Menu {
    let menu = gio::Menu::new();
    let sections: [&[(&str, &str)]; 3] = [
        &[("Private Chat", "nick.query"), ("Whois", "nick.whois")],
        &[
            ("Op", "nick.op"),
            ("Deop", "nick.deop"),
            ("Voice", "nick.voice"),
            ("Devoice", "nick.devoice"),
        ],
        &[("Kick", "nick.kick")],
    ];
    for items in sections {
        let sec = gio::Menu::new();
        for (label, action) in items {
            let item = gio::MenuItem::new(Some(label), None);
            item.set_action_and_target_value(Some(action), Some(&nick.to_variant()));
            sec.append_item(&item);
        }
        menu.append_section(None, &sec);
    }
    menu
}

pub fn activate(gtk_app: &gtk::Application) {
    if let Some(a) = current() {
        a.window.present();
        return;
    }
    let provider = gtk::CssProvider::new();
    provider.load_from_data(CSS);
    if let Some(display) = gdk::Display::default() {
        gtk::style_context_add_provider_for_display(&display, &provider, gtk::STYLE_PROVIDER_PRIORITY_APPLICATION);
    }

    let first_run = !Config::path().exists();
    let (config, load_err) = match Config::load() {
        Ok(c) => (c, None),
        Err(e) => (Config::new_default(), Some(e)),
    };

    let connect_menu = gio::Menu::new();
    let menu = gio::Menu::new();
    let s1 = gio::Menu::new();
    s1.append_submenu(Some("Connect To"), &connect_menu);
    s1.append(Some("Networks…"), Some("app.networks"));
    s1.append(Some("Preferences…"), Some("app.preferences"));
    menu.append_section(None, &s1);
    let s2 = gio::Menu::new();
    s2.append(Some("Show Nick List"), Some("win.nicklist"));
    s2.append(Some("Close Tab"), Some("win.close-tab"));
    menu.append_section(None, &s2);
    let s3 = gio::Menu::new();
    s3.append(Some("About IrcGoo"), Some("app.about"));
    s3.append(Some("Quit"), Some("app.quit"));
    menu.append_section(None, &s3);

    let menu_button = gtk::MenuButton::builder()
        .icon_name("open-menu-symbolic")
        .menu_model(&menu)
        .has_frame(false)
        .focus_on_click(false)
        .tooltip_text("Main Menu (F10)")
        .build();
    menu_button.add_css_class("ircgoo-menu-button");

    let notebook = gtk::Notebook::builder().scrollable(true).show_border(false).build();
    notebook.set_action_widget(&menu_button, gtk::PackType::End);
    notebook.popup_enable();

    let window = gtk::ApplicationWindow::builder()
        .application(gtk_app)
        .title("IrcGoo")
        .default_width(720)
        .default_height(460)
        .child(&notebook)
        .build();

    let (sink, rx) = EventSink::new(drain_net_events);
    let app = Rc::new(App {
        gtk_app: gtk_app.clone(),
        window,
        notebook,
        menu_button,
        connect_menu,
        config: RefCell::new(config),
        tabs: RefCell::new(Vec::new()),
        sessions: RefCell::new(Vec::new()),
        next_id: Cell::new(1),
        sink,
        rx,
        nicklist_visible: Cell::new(true),
        nicklist_dirty: RefCell::new(HashSet::new()),
        prefs_window: RefCell::new(None),
        networks_window: RefCell::new(None),
        quitting: Cell::new(false),
        font_css: gtk::CssProvider::new(),
        desktop_settings: gnome_interface_settings(),
    });
    APP.with(|a| *a.borrow_mut() = Some(app.clone()));

    app.setup_actions();
    app.rebuild_connect_menu();
    app.setup_font_size();
    crate::theme::follow_desktop(crate::tab::set_dark_palette);
    app.notebook.connect_switch_page(|_, page, _| {
        let page = page.clone();
        glib::idle_add_local_once(move || {
            if let Some(a) = current() {
                a.on_tab_switched(&page);
            }
        });
    });
    app.window.connect_close_request(|_| {
        if let Some(a) = current() {
            a.request_quit();
        }
        glib::Propagation::Stop
    });

    let home = app.add_tab(TabKind::Home);
    app.window.present();
    home.entry.grab_focus();

    if let Some(e) = load_err {
        app.error(&home, &e);
    } else if first_run && let Err(e) = app.config.borrow().save() {
        app.error(&home, &e);
    }

    glib::timeout_add_seconds_local(1, || {
        if let Some(a) = current() {
            a.tick();
        }
        glib::ControlFlow::Continue
    });

    let auto: Vec<String> = app
        .config
        .borrow()
        .networks
        .iter()
        .filter(|n| n.autoconnect)
        .map(|n| n.name.clone())
        .collect();
    for name in auto {
        app.connect_network(&name, false);
    }
}

impl App {
    fn new_id(&self) -> u64 {
        let id = self.next_id.get();
        self.next_id.set(id + 1);
        id
    }

    // ----- actions and menus -------------------------------------------------------------

    fn setup_actions(&self) {
        let app_actions: [(&str, ActionFn); 4] = [
            ("preferences", |a| crate::prefs::show_preferences(a)),
            ("networks", |a| crate::prefs::show_networks(a)),
            ("about", |a| a.show_about()),
            ("quit", |a| a.request_quit()),
        ];
        for (name, f) in app_actions {
            let action = gio::SimpleAction::new(name, None);
            // Deferred so a menu popover has finished closing before a window opens.
            action.connect_activate(move |_, _| {
                glib::idle_add_local_once(move || {
                    if let Some(a) = current() {
                        f(&a);
                    }
                });
            });
            self.gtk_app.add_action(&action);
        }
        let win_actions: [(&str, ActionFn); 5] = [
            ("close-tab", |a| {
                if let Some(t) = a.current_tab() {
                    a.close_tab(&t);
                }
            }),
            ("clear", |a| {
                if let Some(t) = a.current_tab() {
                    t.clear();
                }
            }),
            ("next-tab", |a| a.cycle_tab(true)),
            ("prev-tab", |a| a.cycle_tab(false)),
            ("menu", |a| a.menu_button.popup()),
        ];
        for (name, f) in win_actions {
            let action = gio::SimpleAction::new(name, None);
            action.connect_activate(move |_, _| {
                if let Some(a) = current() {
                    f(&a);
                }
            });
            self.window.add_action(&action);
        }
        let nicklist = gio::SimpleAction::new_stateful("nicklist", None, &true.to_variant());
        nicklist.connect_activate(|action, _| {
            let visible = !action.state().and_then(|s| s.get::<bool>()).unwrap_or(true);
            action.set_state(&visible.to_variant());
            if let Some(a) = current() {
                a.set_nicklist_visible(visible);
            }
        });
        self.window.add_action(&nicklist);
        let goto = gio::SimpleAction::new("goto-tab", Some(glib::VariantTy::INT32));
        goto.connect_activate(|_, p| {
            if let (Some(a), Some(n)) = (current(), p.and_then(|p| p.get::<i32>()))
                && n >= 1
                && (n as u32) <= a.notebook.n_pages()
            {
                a.notebook.set_current_page(Some(n as u32 - 1));
            }
        });
        self.window.add_action(&goto);
        let connect = gio::SimpleAction::new("connect-network", Some(glib::VariantTy::STRING));
        connect.connect_activate(|_, p| {
            if let (Some(a), Some(name)) = (current(), p.and_then(|p| p.get::<String>())) {
                a.connect_network(&name, true);
            }
        });
        self.window.add_action(&connect);
        let open_link = gio::SimpleAction::new("open-link", Some(glib::VariantTy::STRING));
        open_link.connect_activate(|_, p| {
            if let (Some(a), Some(url)) = (current(), p.and_then(|p| p.get::<String>())) {
                a.open_link(&url);
            }
        });
        self.window.add_action(&open_link);

        let accels: &[(&str, &[&str])] = &[
            ("app.quit", &["<Ctrl>q"]),
            ("app.preferences", &["<Ctrl>comma"]),
            ("win.close-tab", &["<Ctrl>w"]),
            ("win.clear", &["<Ctrl>l"]),
            // Like Firefox. With Shift held, X11 and Wayland report Tab as ISO_Left_Tab.
            ("win.next-tab", &["<Ctrl>Page_Down", "<Ctrl>Tab"]),
            (
                "win.prev-tab",
                &["<Ctrl>Page_Up", "<Ctrl><Shift>Tab", "<Ctrl><Shift>ISO_Left_Tab"],
            ),
            ("win.menu", &["F10"]),
            ("win.nicklist", &["<Ctrl><Shift>l"]),
        ];
        for (action, keys) in accels {
            self.gtk_app.set_accels_for_action(action, keys);
        }
        for i in 1..=10 {
            let key = format!("<Alt>{}", i % 10);
            self.gtk_app
                .set_accels_for_action(&format!("win.goto-tab({i})"), &[key.as_str()]);
        }
    }

    pub fn rebuild_connect_menu(&self) {
        self.connect_menu.remove_all();
        for n in &self.config.borrow().networks {
            let item = gio::MenuItem::new(Some(&n.name), None);
            item.set_action_and_target_value(Some("win.connect-network"), Some(&n.name.to_variant()));
            self.connect_menu.append_item(&item);
        }
    }

    fn show_about(&self) {
        let d = gtk::AboutDialog::builder()
            .transient_for(&self.window)
            .modal(true)
            .program_name("IrcGoo")
            .version(VERSION)
            .comments("A spartan, keyboard-driven IRC client for Linux desktops.")
            .website(WEBSITE)
            .website_label("AI Sloperator")
            .authors(vec!["AI Sloperator with Claude Code"])
            .license("No license is given.")
            .license_type(gtk::License::Custom)
            .logo_icon_name("internet-chat")
            .build();
        d.present();
    }

    fn request_quit(&self) {
        if self.quitting.replace(true) {
            return;
        }
        let mut any = false;
        for s in self.sessions.borrow_mut().iter_mut() {
            if let Some(src) = s.reconnect_source.take() {
                src.remove();
            }
            if let Some(c) = s.conn.take() {
                if matches!(s.state, ConnState::Registering | ConnState::Connected) {
                    c.send(irc::build("QUIT", &[DEFAULT_QUIT]));
                }
                c.close();
                any = true;
            }
        }
        let gtk_app = self.gtk_app.clone();
        glib::timeout_add_local_once(Duration::from_millis(if any { 400 } else { 0 }), move || gtk_app.quit());
    }

    /// Apply edited configuration: save it and refresh dependent state.
    pub fn update_config(&self, f: impl FnOnce(&mut Config)) -> Result<(), String> {
        let mut new = self.config.borrow().clone();
        f(&mut new);
        let res = new.save();
        for s in self.sessions.borrow_mut().iter_mut() {
            if let Some(n) = new.network(&s.name) {
                s.cfg = n.clone();
            }
        }
        *self.config.borrow_mut() = new;
        self.rebuild_connect_menu();
        self.apply_font_size();
        res
    }

    // ----- message font size -----------------------------------------------------------------

    /// The desktop's monospace font size in points. GNOME's monospace font setting is used
    /// when it reflects a real choice: in a GNOME session, or when it was set explicitly.
    /// Its schema is installed on most systems even without GNOME, and its built-in default
    /// ("Monospace 11") would otherwise override other desktops. In every other case this is
    /// GTK's default font size.
    pub fn desktop_mono_font_size(&self) -> Option<f64> {
        let gnome = self
            .desktop_settings
            .as_ref()
            .filter(|s| is_gnome_session() || s.user_value(GNOME_MONO_KEY).is_some())
            .and_then(|s| font_size_pt(&s.string(GNOME_MONO_KEY)));
        gnome.or_else(|| {
            gtk::Settings::default()
                .and_then(|s| s.gtk_font_name())
                .and_then(|n| font_size_pt(&n))
        })
    }

    fn setup_font_size(&self) {
        if let Some(display) = gdk::Display::default() {
            // Above the base stylesheet so it wins over it.
            gtk::style_context_add_provider_for_display(
                &display,
                &self.font_css,
                gtk::STYLE_PROVIDER_PRIORITY_APPLICATION + 1,
            );
        }
        if let Some(settings) = &self.desktop_settings {
            settings.connect_changed(Some(GNOME_MONO_KEY), |_, _| {
                if let Some(a) = current() {
                    a.apply_font_size();
                }
            });
        }
        if let Some(settings) = gtk::Settings::default() {
            settings.connect_gtk_font_name_notify(|_| {
                if let Some(a) = current() {
                    a.apply_font_size();
                }
            });
        }
        self.apply_font_size();
    }

    /// Set the message view font size from the preference, or from the desktop default.
    fn apply_font_size(&self) {
        let size = self
            .config
            .borrow()
            .message_font_size
            .map(f64::from)
            .or_else(|| self.desktop_mono_font_size());
        let css = match size {
            Some(pt) => format!(".ircgoo-messages {{ font-size: {pt}pt; }}"),
            None => String::new(),
        };
        self.font_css.load_from_data(&css);
    }

    // ----- tabs ------------------------------------------------------------------------------

    /// Open a URL in the default web browser.
    fn open_link(&self, url: &str) {
        let shown = url.to_string();
        gtk::show_uri_full(
            Some(&self.window),
            url,
            gdk::CURRENT_TIME,
            None::<&gio::Cancellable>,
            move |result| {
                if let (Err(e), Some(a)) = (result, current())
                    && let Some(t) = a.current_tab()
                {
                    a.error(&t, &format!("Could not open {shown}: {e}"));
                }
            },
        );
    }

    fn tab_for_widget(&self, w: &gtk::Widget) -> Option<Rc<Tab>> {
        self.tabs
            .borrow()
            .iter()
            .find(|t| t.root.upcast_ref::<gtk::Widget>() == w)
            .cloned()
    }

    pub fn current_tab(&self) -> Option<Rc<Tab>> {
        let n = self.notebook.current_page()?;
        self.tab_for_widget(&self.notebook.nth_page(Some(n))?)
    }

    fn find_tab(&self, f: impl Fn(&TabKind) -> bool) -> Option<Rc<Tab>> {
        self.tabs.borrow().iter().find(|t| f(&t.kind.borrow())).cloned()
    }

    fn net_tabs(&self, net: &str) -> Vec<Rc<Tab>> {
        self.tabs
            .borrow()
            .iter()
            .filter(|t| t.kind.borrow().network().is_some_and(|n| n.eq_ignore_ascii_case(net)))
            .cloned()
            .collect()
    }

    /// The tabs that show the server messages of `net`: its network, channel and private
    /// chat tabs. The network tab is created if the network has no tabs.
    fn server_tabs(&self, net: &str) -> Vec<Rc<Tab>> {
        let tabs = self.net_tabs(net);
        if tabs.is_empty() {
            vec![self.status_tab(net)]
        } else {
            tabs
        }
    }

    /// The tabs for a server reply about `chan`: that channel's tab if it has one.
    fn channel_tabs(&self, net: &str, chan: &str) -> Vec<Rc<Tab>> {
        match self.channel_tab(net, chan) {
            Some(t) => vec![t],
            None => self.server_tabs(net),
        }
    }

    fn channel_tab(&self, net: &str, chan: &str) -> Option<Rc<Tab>> {
        self.find_tab(|k| matches!(k, TabKind::Channel(n, c) if n.eq_ignore_ascii_case(net) && irc_eq(c, chan)))
    }

    fn query_tab(&self, net: &str, nick: &str) -> Option<Rc<Tab>> {
        self.find_tab(|k| matches!(k, TabKind::Query(n, q) if n.eq_ignore_ascii_case(net) && irc_eq(q, nick)))
    }

    /// The network's tab, created if needed. Use `server_tabs` or `net_tab` to reach a
    /// network without opening this tab next to its channels.
    fn status_tab(&self, net: &str) -> Rc<Tab> {
        if let Some(t) = self.find_tab(|k| matches!(k, TabKind::Status(n) if n.eq_ignore_ascii_case(net))) {
            return t;
        }
        let tab = self.add_tab(TabKind::Status(net.to_string()));
        let cfg = self.config.borrow();
        if let Some(n) = cfg.network(net) {
            tab.nick_label.set_text(&cfg.nick_for(n));
        }
        tab
    }

    fn ensure_channel_tab(&self, net: &str, chan: &str) -> Rc<Tab> {
        if let Some(t) = self.channel_tab(net, chan) {
            if t.target().as_deref() != Some(chan) {
                t.set_kind(TabKind::Channel(net.to_string(), chan.to_string()));
            }
            return t;
        }
        self.add_tab(TabKind::Channel(net.to_string(), chan.to_string()))
    }

    fn ensure_query_tab(&self, net: &str, nick: &str, own_nick: &str) -> Rc<Tab> {
        if let Some(t) = self.query_tab(net, nick) {
            return t;
        }
        let t = self.add_tab(TabKind::Query(net.to_string(), nick.to_string()));
        t.nick_label.set_text(own_nick);
        t
    }

    /// The current tab if it belongs to `net`, otherwise one of the network's tabs.
    fn net_tab(&self, net: &str) -> Rc<Tab> {
        match self.current_tab() {
            Some(t) if t.network().is_some_and(|n| n.eq_ignore_ascii_case(net)) => t,
            _ => self.server_tabs(net).remove(0),
        }
    }

    fn add_tab(&self, kind: TabKind) -> Rc<Tab> {
        let tab = Rc::new(Tab::new(kind.clone(), self.nicklist_visible.get()));
        self.wire_tab(&tab);
        let mut pos = None;
        if let (Some(net), false) = (kind.network(), matches!(kind, TabKind::Status(_))) {
            for i in 0..self.notebook.n_pages() {
                let same = self
                    .notebook
                    .nth_page(Some(i))
                    .and_then(|w| self.tab_for_widget(&w))
                    .is_some_and(|t| t.network().is_some_and(|n| n.eq_ignore_ascii_case(net)));
                if same {
                    pos = Some(i + 1);
                }
            }
        }
        self.tabs.borrow_mut().push(tab.clone());
        self.notebook.insert_page(&tab.root, Some(&tab.label), pos);
        self.notebook.set_tab_reorderable(&tab.root, true);
        if kind == TabKind::Home {
            tab.nick_label.set_visible(false);
            self.home_welcome(&tab);
        } else if let Some(home) = self.find_tab(|k| *k == TabKind::Home) {
            self.remove_tab(&home);
        }
        if let TabKind::Channel(net, _) | TabKind::Query(net, _) = kind {
            // Deferred because the command or message being handled may still use that tab.
            glib::idle_add_local_once(move || {
                if let Some(a) = current() {
                    a.close_status_tab(&net);
                }
            });
        }
        tab
    }

    /// Close the network's tab now that a channel or private chat tab has taken over.
    /// If it was showing, its unsent text, input history and focus move to the first
    /// remaining tab, which after connecting is the first channel joined.
    fn close_status_tab(&self, net: &str) {
        let is_status = |t: &Rc<Tab>| matches!(*t.kind.borrow(), TabKind::Status(_));
        let tabs = self.net_tabs(net);
        let (Some(status), Some(other)) = (tabs.iter().find(|t| is_status(t)), tabs.iter().find(|t| !is_status(t)))
        else {
            return;
        };
        if self.current_tab().is_some_and(|c| Rc::ptr_eq(&c, status)) {
            *other.history.borrow_mut() = status.history.take();
            let draft = status.entry.text();
            self.switch_to(other);
            if !draft.is_empty() && other.entry.text().is_empty() {
                other.entry.set_text(&draft);
                // After switching, which selects the text; typing would replace it.
                other.entry.set_position(-1);
            }
        }
        self.remove_tab(status);
    }

    /// Close a channel or private chat tab. The network's last such tab is replaced by the
    /// network tab, in the same place, so there is still a place for commands and messages.
    fn close_net_tab(&self, tab: &Rc<Tab>, net: &str) {
        if self.net_tabs(net).len() == 1 {
            let status = self.status_tab(net);
            status.nick_label.set_text(&self.own_nick(net));
            if tab.lag_label.is_visible() {
                status.set_lag(Some(tab.lag_label.text().as_str()));
            }
            self.info(
                &status,
                "No channels or private chats are open here. Use /join to join a channel, or close this tab to leave this network.",
            );
            if let Some(n) = self.notebook.page_num(&tab.root) {
                self.notebook.reorder_child(&status.root, Some(n));
            }
            if self.current_tab().is_some_and(|c| Rc::ptr_eq(&c, tab)) {
                self.switch_to(&status);
            }
        }
        self.remove_tab(tab);
    }

    fn remove_tab(&self, tab: &Rc<Tab>) {
        if let Some(n) = self.notebook.page_num(&tab.root) {
            self.notebook.remove_page(Some(n));
        }
        if let Some(nl) = &tab.nicklist {
            nl.popover.unparent();
        }
        self.tabs.borrow_mut().retain(|t| !Rc::ptr_eq(t, tab));
        if self.tabs.borrow().is_empty() {
            let home = self.add_tab(TabKind::Home);
            home.entry.grab_focus();
        }
    }

    fn switch_to(&self, tab: &Rc<Tab>) {
        if let Some(n) = self.notebook.page_num(&tab.root) {
            self.notebook.set_current_page(Some(n));
        }
    }

    fn cycle_tab(&self, forward: bool) {
        let n = self.notebook.n_pages();
        if n == 0 {
            return;
        }
        let cur = self.notebook.current_page().unwrap_or(0);
        let next = if forward { (cur + 1) % n } else { (cur + n - 1) % n };
        self.notebook.set_current_page(Some(next));
    }

    fn on_tab_switched(&self, page: &gtk::Widget) {
        let Some(tab) = self.tab_for_widget(page) else { return };
        if self.current_tab().is_some_and(|c| Rc::ptr_eq(&c, &tab)) {
            tab.set_activity(Activity::None);
            tab.entry.grab_focus_without_selecting();
            let title = match tab.kind() {
                TabKind::Home => "IrcGoo".to_string(),
                TabKind::Status(n) => format!("{n} — IrcGoo"),
                TabKind::Channel(n, t) | TabKind::Query(n, t) => format!("{t} ({n}) — IrcGoo"),
            };
            self.window.set_title(Some(&title));
        }
    }

    fn note_activity(&self, tab: &Rc<Tab>, a: Activity) {
        let is_current = self.current_tab().is_some_and(|c| Rc::ptr_eq(&c, tab));
        if !is_current && a > tab.activity.get() {
            tab.set_activity(a);
        }
    }

    fn set_nicklist_visible(&self, visible: bool) {
        self.nicklist_visible.set(visible);
        for t in self.tabs.borrow().iter() {
            if let Some(nl) = &t.nicklist {
                nl.container.set_visible(visible);
            }
        }
    }

    fn home_welcome(&self, tab: &Tab) {
        self.info(tab, &format!("Welcome to IrcGoo {VERSION}."));
        let nets: Vec<String> = self.config.borrow().networks.iter().map(|n| n.name.clone()).collect();
        if nets.is_empty() {
            self.info(
                tab,
                "No networks are configured yet. Press F10 and choose Networks… to add one.",
            );
        } else {
            self.info(tab, &format!("Configured networks: {}", nets.join(", ")));
            self.info(
                tab,
                "Type /network connect <name> to connect, or press F10 for the menu.",
            );
        }
        self.info(tab, "Type /help for a list of commands.");
    }

    fn wire_tab(&self, tab: &Rc<Tab>) {
        tab.label.set_has_tooltip(true);
        let w = Rc::downgrade(tab);
        tab.label.connect_query_tooltip(move |_, _, _, _, tooltip| {
            let (Some(a), Some(t)) = (current(), w.upgrade()) else {
                return false;
            };
            let Some(text) = a.tab_tooltip(&t) else {
                return false;
            };
            tooltip.set_text(Some(&text));
            true
        });

        let w = Rc::downgrade(tab);
        tab.entry.connect_activate(move |_| {
            if let (Some(a), Some(t)) = (current(), w.upgrade()) {
                a.on_entry_activate(&t);
            }
        });

        let w = Rc::downgrade(tab);
        tab.entry.connect_changed(move |_| {
            if let Some(t) = w.upgrade()
                && !t.completing.get()
            {
                t.completion.borrow_mut().take();
            }
        });

        let keys = gtk::EventControllerKey::new();
        keys.set_propagation_phase(gtk::PropagationPhase::Capture);
        let w = Rc::downgrade(tab);
        keys.connect_key_pressed(move |_, key, _, state| {
            let Some(t) = w.upgrade() else {
                return glib::Propagation::Proceed;
            };
            let mods = state & (gdk::ModifierType::CONTROL_MASK | gdk::ModifierType::ALT_MASK);
            if !mods.is_empty() {
                return glib::Propagation::Proceed;
            }
            match key {
                gdk::Key::Up => history_move(&t, true),
                gdk::Key::Down => history_move(&t, false),
                gdk::Key::Page_Up => t.scroll_page(false),
                gdk::Key::Page_Down => t.scroll_page(true),
                gdk::Key::Tab => {
                    if let Some(a) = current() {
                        a.complete(&t);
                    }
                }
                _ => return glib::Propagation::Proceed,
            }
            glib::Propagation::Stop
        });
        tab.entry.add_controller(keys);

        // Typing while the message view has focus goes to the entry.
        let view_keys = gtk::EventControllerKey::new();
        let entry = tab.entry.clone();
        view_keys.connect_key_pressed(move |_, key, _, state| {
            let mods = gdk::ModifierType::CONTROL_MASK | gdk::ModifierType::ALT_MASK | gdk::ModifierType::SUPER_MASK;
            if state.intersects(mods) {
                return glib::Propagation::Proceed;
            }
            match key.to_unicode() {
                Some(c) if !c.is_control() => {
                    entry.grab_focus_without_selecting();
                    let mut pos = entry.text().chars().count() as i32;
                    entry.insert_text(&c.to_string(), &mut pos);
                    entry.set_position(pos);
                    glib::Propagation::Stop
                }
                _ => glib::Propagation::Proceed,
            }
        });
        tab.view.add_controller(view_keys);

        // Runs before the text view opens its context menu, for a right click or a long press.
        let press = gtk::GestureClick::new();
        press.set_button(0);
        press.set_propagation_phase(gtk::PropagationPhase::Capture);
        let w = Rc::downgrade(tab);
        press.connect_pressed(move |_, _, x, y| {
            if let Some(t) = w.upgrade() {
                t.update_link_menu(x, y);
            }
        });
        tab.view.add_controller(press);

        if let Some(nl) = &tab.nicklist {
            let group = gio::SimpleActionGroup::new();
            for name in ["query", "whois", "op", "deop", "voice", "devoice", "kick"] {
                let action = gio::SimpleAction::new(name, Some(glib::VariantTy::STRING));
                let w = Rc::downgrade(tab);
                action.connect_activate(move |action, p| {
                    if let (Some(a), Some(t), Some(nick)) = (current(), w.upgrade(), p.and_then(|p| p.get::<String>()))
                    {
                        a.nick_action(&t, &action.name(), &nick);
                    }
                });
                group.add_action(&action);
            }
            nl.container.insert_action_group("nick", Some(&group));

            let click = gtk::GestureClick::new();
            click.set_button(gdk::BUTTON_SECONDARY);
            let w = Rc::downgrade(tab);
            click.connect_pressed(move |_, _, x, y| {
                let Some(t) = w.upgrade() else { return };
                let Some(nl) = &t.nicklist else { return };
                let Some(row) = nl.list.row_at_y(y as i32) else { return };
                let Some(nick) = nl.nicks.borrow().get(row.index() as usize).cloned() else {
                    return;
                };
                nl.popover.set_menu_model(Some(&nick_menu(&nick)));
                let (px, py) = nl.list.translate_coordinates(&nl.container, x, y).unwrap_or((x, y));
                nl.popover
                    .set_pointing_to(Some(&gdk::Rectangle::new(px as i32, py as i32, 1, 1)));
                nl.popover.popup();
            });
            nl.list.add_controller(click);

            let w = Rc::downgrade(tab);
            nl.list.connect_row_activated(move |_, row| {
                let Some(t) = w.upgrade() else { return };
                let nick = t
                    .nicklist
                    .as_ref()
                    .and_then(|nl| nl.nicks.borrow().get(row.index() as usize).cloned());
                if let (Some(a), Some(nick)) = (current(), nick) {
                    a.nick_action(&t, "query", &nick);
                }
            });
        }
    }

    // ----- input -----------------------------------------------------------------------------

    fn on_entry_activate(&self, tab: &Rc<Tab>) {
        let text = tab.entry.text().to_string();
        if text.trim().is_empty() {
            return;
        }
        tab.entry.set_text("");
        {
            let mut h = tab.history.borrow_mut();
            if h.last() != Some(&text) {
                h.push(text.clone());
                if h.len() > 200 {
                    h.remove(0);
                }
            }
        }
        tab.history_pos.set(None);
        for line in text.lines().filter(|l| !l.is_empty()) {
            match line.strip_prefix('/') {
                Some(rest) if rest.starts_with('/') => self.say(tab, rest),
                Some(rest) => self.run_command(tab, rest),
                None => self.say(tab, line),
            }
        }
    }

    fn complete(&self, tab: &Rc<Tab>) {
        let text = tab.entry.text().to_string();
        let mut comp = tab.completion.borrow_mut();
        let (before, after, cand, suffix) = if let Some(c) = comp.as_mut() {
            c.index = (c.index + 1) % c.candidates.len();
            (
                text[..c.start].to_string(),
                String::new(),
                c.candidates[c.index].clone(),
                c.suffix.clone(),
            )
        } else {
            let cursor_chars = tab.entry.position().max(0) as usize;
            let cursor = text
                .char_indices()
                .nth(cursor_chars)
                .map(|(b, _)| b)
                .unwrap_or(text.len());
            let start = text[..cursor].rfind(' ').map(|i| i + 1).unwrap_or(0);
            let prefix = irc_lower(&text[start..cursor]);
            if prefix.is_empty() {
                return;
            }
            let Some(net) = tab.network() else { return };
            let mut candidates: Vec<String> = Vec::new();
            if let Ok(sessions) = self.sessions.try_borrow()
                && let Some(s) = sessions.iter().find(|s| s.name.eq_ignore_ascii_case(&net))
            {
                if s.is_channel(&prefix) {
                    candidates.extend(s.channels.values().map(|c| c.name.clone()));
                } else if let TabKind::Channel(_, chan) = tab.kind()
                    && let Some(ch) = s.channels.get(&irc_lower(&chan))
                {
                    candidates.extend(ch.members.values().map(|m| m.nick.clone()));
                }
            }
            if let TabKind::Query(_, q) = tab.kind() {
                candidates.push(q);
            }
            candidates.retain(|c| irc_lower(c).starts_with(&prefix));
            candidates.sort_by_key(|c| irc_lower(c));
            candidates.dedup();
            if candidates.is_empty() {
                return;
            }
            let suffix = if start == 0 && !candidates[0].starts_with(|c| "#&".contains(c)) {
                ": "
            } else {
                " "
            };
            let after = text[cursor..].to_string();
            *comp = Some(Completion {
                start,
                candidates: candidates.clone(),
                index: 0,
                suffix: suffix.to_string(),
            });
            (
                text[..start].to_string(),
                after,
                candidates[0].clone(),
                suffix.to_string(),
            )
        };
        drop(comp);
        let new_text = format!("{before}{cand}{suffix}");
        let pos = new_text.chars().count() as i32;
        tab.completing.set(true);
        tab.entry.set_text(&format!("{new_text}{after}"));
        tab.entry.set_position(pos);
        tab.completing.set(false);
    }

    fn say(&self, tab: &Rc<Tab>, text: &str) {
        match tab.kind() {
            TabKind::Channel(net, target) | TabKind::Query(net, target) => {
                self.send_message(tab, &net, &target, text, false);
            }
            _ => self.error(
                tab,
                "This tab is not a channel or private chat. Use /join #channel or /msg <nick> <text>.",
            ),
        }
    }

    /// Send a PRIVMSG (or NOTICE) and echo it locally.
    fn send_message(&self, tab: &Rc<Tab>, net: &str, target: &str, text: &str, notice: bool) {
        let sessions = self.sessions.borrow();
        let Some(s) = sessions
            .iter()
            .find(|s| s.name.eq_ignore_ascii_case(net))
            .filter(|s| s.connected())
        else {
            self.error(tab, &format!("Not connected to {net}."));
            return;
        };
        let cmd = if notice { "NOTICE" } else { "PRIVMSG" };
        let max = 400usize.saturating_sub(target.len()).max(100);
        let echo_tab = if notice {
            None
        } else if s.is_channel(target) {
            self.channel_tab(net, target)
        } else {
            self.query_tab(net, target)
        };
        for chunk in split_message(text, max) {
            s.send(&irc::build(cmd, &[target, &chunk]));
            match &echo_tab {
                Some(t) => t.line(
                    &[
                        Part::Text("<", ""),
                        Part::Text(&s.nick, "own"),
                        Part::Text("> ", ""),
                        Part::Irc(&chunk),
                    ],
                    None,
                ),
                None => {
                    let (l, r) = if notice { ("-> -", "- ") } else { ("-> *", "* ") };
                    tab.line(
                        &[
                            Part::Text(l, "dim"),
                            Part::Nick(target),
                            Part::Text(r, "dim"),
                            Part::Irc(&chunk),
                        ],
                        None,
                    );
                }
            }
        }
    }

    fn with_session<R>(&self, tab: &Rc<Tab>, need_connected: bool, f: impl FnOnce(&mut Session) -> R) -> Option<R> {
        let Some(net) = tab.network() else {
            self.error(
                tab,
                "This command needs a network. Switch to a network, channel or private chat tab.",
            );
            return None;
        };
        let mut sessions = self.sessions.borrow_mut();
        match sessions.iter_mut().find(|s| s.name.eq_ignore_ascii_case(&net)) {
            Some(s) if !need_connected || s.connected() => Some(f(s)),
            _ => {
                drop(sessions);
                self.error(tab, &format!("Not connected to {net}."));
                None
            }
        }
    }

    fn send_cmd(&self, tab: &Rc<Tab>, line: &str) {
        self.with_session(tab, true, |s| s.send(line));
    }

    fn run_command(&self, tab: &Rc<Tab>, input: &str) {
        let (cmd, rest) = split1(input);
        let cmd = cmd.to_ascii_lowercase();
        let args: Vec<&str> = rest.split_whitespace().collect();
        let chan = match tab.kind() {
            TabKind::Channel(_, c) => Some(c),
            _ => None,
        };
        let is_chan = |s: &str| s.starts_with(['#', '&', '!', '+']);
        let usage = |u: &str| self.error(tab, &format!("Usage: {u}"));
        match cmd.as_str() {
            "help" => {
                for (c, d) in HELP {
                    tab.line(&[Part::Text(&format!("{c:<44}"), "marker"), Part::Text(d, "")], None);
                }
            }
            "join" | "j" => {
                let Some(first) = args.first() else {
                    return usage("/join <#chan>[,<#chan>] [keys]");
                };
                let chans: Vec<String> = first
                    .split(',')
                    .filter(|c| !c.is_empty())
                    .map(|c| if is_chan(c) { c.to_string() } else { format!("#{c}") })
                    .collect();
                let joined = chans.join(",");
                let keys = args.get(1).copied().unwrap_or("");
                self.with_session(tab, true, |s| {
                    for c in &chans {
                        s.user_joins.insert(irc_lower(c));
                    }
                    if keys.is_empty() {
                        s.send(&irc::build("JOIN", &[&joined]))
                    } else {
                        s.send(&irc::build("JOIN", &[&joined, keys]))
                    }
                });
            }
            "part" | "p" | "leave" => {
                let (target, reason) = match args.first() {
                    Some(a) if is_chan(a) => (Some(a.to_string()), split1(rest).1.to_string()),
                    _ => (chan.clone(), rest.to_string()),
                };
                let Some(target) = target else {
                    return usage("/part [#chan] [reason]");
                };
                let reason = if reason.is_empty() {
                    DEFAULT_QUIT.to_string()
                } else {
                    reason
                };
                self.send_cmd(tab, &irc::build("PART", &[&target, &reason]));
            }
            "close" => self.close_tab(tab),
            "quit" | "disconnect" => {
                let Some(net) = tab.network() else {
                    return self.error(tab, "Not in a network tab.");
                };
                let reason = if rest.is_empty() { DEFAULT_QUIT } else { rest };
                self.disconnect_network(&net, reason);
            }
            "exit" => self.request_quit(),
            "nick" => {
                let Some(n) = args.first() else {
                    return usage("/nick <newnick>");
                };
                self.send_cmd(tab, &irc::build("NICK", &[n]));
            }
            "op" | "deop" | "voice" | "devoice" => {
                let Some(chan) = chan else {
                    return self.error(tab, "Use this command in a channel tab.");
                };
                if args.is_empty() {
                    return usage(&format!("/{cmd} <nick> [nick…]"));
                }
                let (sign, letter) = match cmd.as_str() {
                    "op" => ('+', 'o'),
                    "deop" => ('-', 'o'),
                    "voice" => ('+', 'v'),
                    _ => ('-', 'v'),
                };
                self.with_session(tab, true, |s| {
                    for group in args.chunks(s.max_modes.max(1)) {
                        let modes = format!("{sign}{}", letter.to_string().repeat(group.len()));
                        let mut p: Vec<&str> = vec![&chan, &modes];
                        p.extend(group.iter().copied());
                        s.send(&format!("MODE {}", p.join(" ")));
                    }
                });
            }
            "kick" => {
                let Some(chan) = chan else {
                    return self.error(tab, "Use this command in a channel tab.");
                };
                let (nick, reason) = split1(rest);
                if nick.is_empty() {
                    return usage("/kick <nick> [reason]");
                }
                self.send_cmd(tab, &irc::build("KICK", &[&chan, nick, reason]));
            }
            "mode" => {
                let line = match args.first() {
                    None => match &chan {
                        Some(c) => format!("MODE {c}"),
                        None => self
                            .with_session(tab, true, |s| format!("MODE {}", s.nick))
                            .unwrap_or_default(),
                    },
                    Some(a) if a.starts_with(['+', '-']) => match &chan {
                        Some(c) => format!("MODE {c} {rest}"),
                        None => self
                            .with_session(tab, true, |s| format!("MODE {} {rest}", s.nick))
                            .unwrap_or_default(),
                    },
                    Some(_) => format!("MODE {rest}"),
                };
                if !line.is_empty() {
                    self.send_cmd(tab, &line);
                }
            }
            "ctcp" => {
                let (target, rest2) = split1(rest);
                let (ctcp, cargs) = split1(rest2);
                if ctcp.is_empty() {
                    return usage("/ctcp <target> <command> [args]");
                }
                let ctcp = ctcp.to_ascii_uppercase();
                let cargs = if ctcp == "PING" && cargs.is_empty() {
                    unix_millis().to_string()
                } else {
                    cargs.to_string()
                };
                let body = if cargs.is_empty() {
                    ctcp.clone()
                } else {
                    format!("{ctcp} {cargs}")
                };
                if self
                    .with_session(tab, true, |s| {
                        s.send(&irc::build("PRIVMSG", &[target, &format!("\x01{body}\x01")]))
                    })
                    .is_some()
                {
                    tab.line(
                        &[
                            Part::Text("-> [", "dim"),
                            Part::Nick(target),
                            Part::Text("] ", "dim"),
                            Part::Text(&body, ""),
                        ],
                        None,
                    );
                }
            }
            "me" => match tab.kind() {
                TabKind::Channel(net, t) | TabKind::Query(net, t) => {
                    let nick = self.with_session(tab, true, |s| {
                        s.send(&irc::build("PRIVMSG", &[&t, &format!("\x01ACTION {rest}\x01")]));
                        s.nick.clone()
                    });
                    if let Some(nick) = nick {
                        let _ = net;
                        tab.line(
                            &[
                                Part::Text("* ", ""),
                                Part::Text(&nick, "own"),
                                Part::Text(" ", ""),
                                Part::Irc(rest),
                            ],
                            None,
                        );
                    }
                }
                _ => self.error(tab, "Use /me in a channel or private chat tab."),
            },
            "msg" | "notice" => {
                let (target, text) = split1(rest);
                if text.is_empty() {
                    return usage(&format!("/{cmd} <target> <text>"));
                }
                let Some(net) = tab.network() else {
                    return self.error(tab, "Not in a network tab.");
                };
                self.send_message(tab, &net, target, text, cmd == "notice");
            }
            "query" | "q" => {
                let (nick, text) = split1(rest);
                if nick.is_empty() {
                    return usage("/query <nick> [text]");
                }
                let Some(net) = tab.network() else {
                    return self.error(tab, "Not in a network tab.");
                };
                let own = self.own_nick(&net);
                let q = self.ensure_query_tab(&net, nick, &own);
                self.switch_to(&q);
                if !text.is_empty() {
                    self.send_message(&q, &net, nick, text, false);
                }
            }
            "topic" => {
                let (target, text) = match args.first() {
                    Some(a) if is_chan(a) => (Some(a.to_string()), split1(rest).1),
                    _ => (chan.clone(), rest),
                };
                let Some(target) = target else {
                    return usage("/topic [#chan] [text]");
                };
                if text.is_empty() {
                    self.send_cmd(tab, &irc::build("TOPIC", &[&target]));
                } else {
                    self.send_cmd(tab, &irc::build("TOPIC", &[&target, text]));
                }
            }
            "whois" | "wi" => {
                let Some(n) = args.first() else {
                    return usage("/whois <nick>");
                };
                self.send_cmd(tab, &irc::build("WHOIS", &[n]));
            }
            "names" => {
                let target = args.first().map(|s| s.to_string()).or(chan);
                let Some(target) = target else {
                    return usage("/names <#chan>");
                };
                self.send_cmd(tab, &irc::build("NAMES", &[&target]));
            }
            "invite" => {
                let Some(nick) = args.first() else {
                    return usage("/invite <nick> [#chan]");
                };
                let Some(target) = args.get(1).map(|s| s.to_string()).or(chan) else {
                    return usage("/invite <nick> <#chan>");
                };
                self.send_cmd(tab, &irc::build("INVITE", &[nick, &target]));
            }
            "away" => {
                if rest.is_empty() {
                    self.send_cmd(tab, "AWAY");
                } else {
                    self.send_cmd(tab, &irc::build("AWAY", &[rest]));
                }
            }
            "quote" | "raw" => {
                if rest.is_empty() {
                    return usage("/quote <raw line>");
                }
                self.send_cmd(tab, rest);
            }
            "network" | "net" => self.network_command(tab, &args, rest),
            "server" => self.server_command(tab, &args),
            "clear" | "c" => tab.clear(),
            _ => {
                // Unknown commands are passed to the server, as most clients do.
                let connected = self.with_session_quiet(tab, |s| s.connected()).unwrap_or(false);
                if connected {
                    let line = if rest.is_empty() {
                        cmd.to_ascii_uppercase()
                    } else {
                        format!("{} {rest}", cmd.to_ascii_uppercase())
                    };
                    self.send_cmd(tab, &line);
                } else {
                    self.error(tab, &format!("Unknown command /{cmd}. Type /help for a list."));
                }
            }
        }
    }

    /// Network name, then the server's host:port and "TLS" or "non-TLS", one per line.
    fn tab_tooltip(&self, tab: &Rc<Tab>) -> Option<String> {
        let net = tab.network()?;
        let sessions = self.sessions.try_borrow().ok()?;
        let Some(s) = sessions.iter().find(|s| s.name.eq_ignore_ascii_case(&net)) else {
            return Some(format!("{net}\nNot connected"));
        };
        let mut text = s.name.clone();
        match (&s.state, &s.endpoint) {
            (ConnState::Disconnected, _) | (_, None) => text.push_str("\nNot connected"),
            (state, Some((host, port, tls))) => {
                text.push('\n');
                text.push_str(&crate::config::describe_addr(host, *port, false));
                text.push_str(if *tls { "\nTLS" } else { "\nnon-TLS" });
                if matches!(state, ConnState::Connecting | ConnState::Registering) {
                    text.push_str("\nConnecting…");
                }
            }
        }
        Some(text)
    }

    fn with_session_quiet<R>(&self, tab: &Rc<Tab>, f: impl FnOnce(&Session) -> R) -> Option<R> {
        let net = tab.network()?;
        let sessions = self.sessions.borrow();
        sessions.iter().find(|s| s.name.eq_ignore_ascii_case(&net)).map(f)
    }

    fn own_nick(&self, net: &str) -> String {
        if let Some(s) = self.sessions.borrow().iter().find(|s| s.name.eq_ignore_ascii_case(net))
            && !s.nick.is_empty()
        {
            return s.nick.clone();
        }
        let cfg = self.config.borrow();
        cfg.network(net)
            .map(|n| cfg.nick_for(n))
            .unwrap_or_else(|| cfg.nick.clone())
    }

    fn network_command(&self, tab: &Rc<Tab>, args: &[&str], rest: &str) {
        let sub = args.first().map(|s| s.to_ascii_lowercase()).unwrap_or_default();
        let name_arg = split1(rest).1;
        match sub.as_str() {
            "" | "list" => {
                let cfg = self.config.borrow();
                if cfg.networks.is_empty() {
                    return self.info(
                        tab,
                        "No networks configured. Press F10 and choose Networks… to add one.",
                    );
                }
                self.info(tab, "Networks:");
                let sessions = self.sessions.borrow();
                for n in &cfg.networks {
                    let state = match sessions
                        .iter()
                        .find(|s| s.name.eq_ignore_ascii_case(&n.name))
                        .map(|s| s.state)
                    {
                        Some(ConnState::Connected) => "connected",
                        Some(ConnState::Connecting | ConnState::Registering) => "connecting",
                        _ => "not connected",
                    };
                    let auto = if n.autoconnect { ", connects automatically" } else { "" };
                    self.info(tab, &format!("  {} ({state}{auto})", n.name));
                }
            }
            "connect" | "c" => {
                if name_arg.is_empty() {
                    return self.error(tab, "Usage: /network connect <name>");
                }
                self.connect_network(name_arg, true);
            }
            "disconnect" | "d" => {
                let name = if name_arg.is_empty() {
                    tab.network()
                } else {
                    Some(name_arg.to_string())
                };
                match name {
                    Some(n) => self.disconnect_network(&n, DEFAULT_QUIT),
                    None => self.error(tab, "Usage: /network disconnect <name>"),
                }
            }
            _ => self.connect_network(rest, true),
        }
    }

    fn server_command(&self, tab: &Rc<Tab>, args: &[&str]) {
        let Some(net) = tab.network() else {
            return self.error(tab, "Use /server in a network tab, or /network connect <name> first.");
        };
        let Some(cfg) = self.config.borrow().network(&net).cloned() else {
            return self.error(tab, &format!("Network {net} is no longer configured."));
        };
        let mut sessions = self.sessions.borrow_mut();
        if !sessions.iter().any(|s| s.name.eq_ignore_ascii_case(&net)) {
            sessions.push(Session::new(cfg));
        }
        let s = sessions.iter_mut().find(|s| s.name.eq_ignore_ascii_case(&net)).unwrap();
        let n = s.cfg.servers.len();
        if args.is_empty() || args[0] == "list" {
            if s.cfg.bouncer.enabled {
                let b = &s.cfg.bouncer;
                self.info(
                    tab,
                    &format!(
                        "{net} connects through a bouncer at {}",
                        crate::config::describe_addr(&b.host, b.port, b.tls)
                    ),
                );
            }
            self.info(tab, &format!("Servers for {net}:"));
            for (i, sv) in s.cfg.servers.iter().enumerate() {
                let mark = if i == s.server_idx && s.conn.is_some() {
                    "  (current)"
                } else {
                    ""
                };
                self.info(tab, &format!("  {}. {}{mark}", i + 1, sv.describe()));
            }
            return;
        }
        if s.cfg.bouncer.enabled {
            return self.error(
                tab,
                "This network connects through a bouncer. Change that in Networks… first.",
            );
        }
        if n == 0 {
            return self.error(tab, &format!("No servers are configured for {net}."));
        }
        let idx = if args[0] == "next" {
            Some((s.server_idx + 1) % n)
        } else if let Ok(i) = args[0].parse::<usize>() {
            (1..=n).contains(&i).then(|| i - 1)
        } else {
            let a = args[0];
            let (host, port) = match a.rsplit_once(':') {
                Some((h, p)) if !h.contains(':') || h.starts_with('[') => {
                    (h.trim_matches(['[', ']']), p.parse::<u16>().ok())
                }
                _ => (a.trim_matches(['[', ']']), None),
            };
            s.cfg
                .servers
                .iter()
                .position(|sv| sv.host.eq_ignore_ascii_case(host) && port.is_none_or(|p| sv.port == p))
        };
        let Some(idx) = idx else {
            return self.error(
                tab,
                &format!("No such server for {net}. Type /server to list them; add servers in Networks…"),
            );
        };
        if let Some(c) = s.conn.take() {
            c.send(irc::build("QUIT", &["Changing servers"]));
            c.close();
        }
        self.reset_session(s);
        s.server_idx = idx;
        s.want_connected = true;
        s.failures = 0;
        self.info(tab, &format!("Switching to {}", s.cfg.servers[idx].describe()));
        self.start_connect(s);
    }

    fn nick_action(&self, tab: &Rc<Tab>, action: &str, nick: &str) {
        let Some(net) = tab.network() else { return };
        let chan = tab.target().unwrap_or_default();
        match action {
            "query" => {
                let own = self.own_nick(&net);
                let q = self.ensure_query_tab(&net, nick, &own);
                self.switch_to(&q);
            }
            "whois" => self.send_cmd(tab, &irc::build("WHOIS", &[nick])),
            "op" => self.send_cmd(tab, &irc::build("MODE", &[&chan, "+o", nick])),
            "deop" => self.send_cmd(tab, &irc::build("MODE", &[&chan, "-o", nick])),
            "voice" => self.send_cmd(tab, &irc::build("MODE", &[&chan, "+v", nick])),
            "devoice" => self.send_cmd(tab, &irc::build("MODE", &[&chan, "-v", nick])),
            "kick" => self.send_cmd(tab, &irc::build("KICK", &[&chan, nick])),
            _ => {}
        }
    }

    fn close_tab(&self, tab: &Rc<Tab>) {
        match tab.kind() {
            TabKind::Home => {}
            TabKind::Status(net) => {
                self.disconnect_network(&net, DEFAULT_QUIT);
                for t in self.net_tabs(&net) {
                    self.remove_tab(&t);
                }
                self.sessions
                    .borrow_mut()
                    .retain(|s| !s.name.eq_ignore_ascii_case(&net));
            }
            TabKind::Channel(net, chan) => {
                if let Some(s) = self
                    .sessions
                    .borrow()
                    .iter()
                    .find(|s| s.name.eq_ignore_ascii_case(&net))
                    && s.connected()
                    && s.channels.contains_key(&irc_lower(&chan))
                {
                    s.send(&irc::build("PART", &[&chan, DEFAULT_QUIT]));
                }
                self.close_net_tab(tab, &net);
            }
            TabKind::Query(net, _) => self.close_net_tab(tab, &net),
        }
    }

    // ----- printing helpers ------------------------------------------------------------------

    fn info(&self, tab: &Tab, text: &str) {
        tab.line(&[Part::Text("-!- ", "marker"), Part::Irc(text)], None);
    }

    fn info_tag(&self, tab: &Tab, text: &str, tag: &'static str) {
        tab.line(&[Part::Text("-!- ", "marker"), Part::Text(text, tag)], None);
    }

    fn error(&self, tab: &Tab, text: &str) {
        tab.line(&[Part::Text("-!- ", "error"), Part::Text(text, "error")], None);
    }

    fn server_line(&self, net: &str, parts: &[Part]) {
        for t in self.server_tabs(net) {
            t.line(parts, None);
        }
    }

    fn server_info(&self, net: &str, text: &str) {
        for t in self.server_tabs(net) {
            self.info(&t, text);
        }
    }

    fn server_info_tag(&self, net: &str, text: &str, tag: &'static str) {
        for t in self.server_tabs(net) {
            self.info_tag(&t, text, tag);
        }
    }

    fn server_error(&self, net: &str, text: &str) {
        for t in self.server_tabs(net) {
            self.error(&t, text);
        }
    }

    fn set_lag(&self, net: &str, lag: Option<Duration>) {
        let text = lag.map(|d| format!("Lag:{}s", d.as_secs_f64().round() as u64));
        for t in self.net_tabs(net) {
            t.set_lag(text.as_deref());
        }
    }

    fn update_nick_labels(&self, s: &Session) {
        for t in self.net_tabs(&s.name) {
            let text = match t.kind() {
                TabKind::Channel(_, c) => format!("{}{}", s.member_prefix(&c, &s.nick), s.nick),
                _ => s.nick.clone(),
            };
            t.nick_label.set_text(&text);
        }
    }

    fn queue_nicklist(&self, net: &str, chan: &str) {
        let was_empty = self.nicklist_dirty.borrow().is_empty();
        self.nicklist_dirty
            .borrow_mut()
            .insert((net.to_ascii_lowercase(), irc_lower(chan)));
        if was_empty {
            glib::idle_add_local_once(|| {
                if let Some(a) = current() {
                    a.flush_nicklists();
                }
            });
        }
    }

    fn flush_nicklists(&self) {
        let dirty: Vec<(String, String)> = self.nicklist_dirty.borrow_mut().drain().collect();
        for (net, chan) in dirty {
            let Some(tab) = self.channel_tab(&net, &chan) else {
                continue;
            };
            let entries = {
                let sessions = self.sessions.borrow();
                sessions
                    .iter()
                    .find(|s| s.name.eq_ignore_ascii_case(&net))
                    .map(|s| s.sorted_members(&chan))
                    .unwrap_or_default()
            };
            let Some(nl) = &tab.nicklist else { continue };
            while let Some(child) = nl.list.first_child() {
                nl.list.remove(&child);
            }
            let mut labels = Vec::with_capacity(entries.len());
            for (display, nick) in &entries {
                let label = gtk::Label::builder()
                    .label(display)
                    .xalign(0.0)
                    .has_tooltip(true)
                    .build();
                let (net2, nick2) = (net.clone(), nick.clone());
                label.connect_query_tooltip(move |_, _, _, _, tip| {
                    match current().and_then(|a| a.nick_tooltip(&net2, &nick2)) {
                        Some(t) => {
                            tip.set_text(Some(&t));
                            true
                        }
                        None => false,
                    }
                });
                nl.list.append(&label);
                labels.push(label);
            }
            nl.container.set_tooltip_text(Some(&format!("{} users", entries.len())));
            *nl.nicks.borrow_mut() = entries.into_iter().map(|(_, n)| n).collect();
            *nl.labels.borrow_mut() = labels;
        }
    }

    fn nick_tooltip(&self, net: &str, nick: &str) -> Option<String> {
        let mut sessions = self.sessions.try_borrow_mut().ok()?;
        let s = sessions.iter_mut().find(|s| s.name.eq_ignore_ascii_case(net))?;
        let key = irc_lower(nick);
        let cached = s.whois_cache.get(&key);
        if let Some(info) = cached.filter(|i| i.fetched.is_some_and(|f| f.elapsed() < WHOIS_CACHE)) {
            return Some(info.tooltip());
        }
        let stale = cached.map(|i| i.tooltip());
        if s.connected() && s.whois_hover.is_empty() {
            s.whois_hover.insert(key);
            s.send(&irc::build("WHOIS", &[nick]));
        }
        Some(stale.unwrap_or_else(|| format!("{nick}\nLooking up…")))
    }

    fn refresh_nick_tooltip(&self, net: &str, nick: &str) {
        for t in self.net_tabs(net) {
            if let Some(nl) = &t.nicklist {
                let idx = nl.nicks.borrow().iter().position(|n| irc_eq(n, nick));
                if let Some(label) = idx.and_then(|i| nl.labels.borrow().get(i).cloned()) {
                    glib::idle_add_local_once(move || label.trigger_tooltip_query());
                }
            }
        }
    }

    // ----- connections -----------------------------------------------------------------------

    pub fn connect_network(&self, name: &str, user_initiated: bool) {
        let cfg = self.config.borrow().network(name).cloned();
        let Some(cfg) = cfg else {
            if let Some(t) = self.current_tab() {
                self.error(&t, &format!("No network named \"{name}\". Type /network to list them."));
            }
            return;
        };
        let tab = self.net_tab(&cfg.name);
        if user_initiated {
            self.switch_to(&tab);
        }
        let mut sessions = self.sessions.borrow_mut();
        if !sessions.iter().any(|s| s.name.eq_ignore_ascii_case(&cfg.name)) {
            sessions.push(Session::new(cfg.clone()));
        }
        let s = sessions
            .iter_mut()
            .find(|s| s.name.eq_ignore_ascii_case(&cfg.name))
            .unwrap();
        if s.conn.is_some() {
            self.info(
                &tab,
                &format!(
                    "Already connected to {}. Use /network disconnect to disconnect.",
                    s.name
                ),
            );
            return;
        }
        s.cfg = cfg;
        s.want_connected = true;
        s.failures = 0;
        self.start_connect(s);
    }

    pub fn disconnect_network(&self, name: &str, reason: &str) {
        let mut sessions = self.sessions.borrow_mut();
        let Some(s) = sessions.iter_mut().find(|s| s.name.eq_ignore_ascii_case(name)) else {
            if let Some(t) = self.current_tab() {
                self.error(&t, &format!("Not connected to {name}."));
            }
            return;
        };
        s.want_connected = false;
        if let Some(src) = s.reconnect_source.take() {
            src.remove();
        }
        if let Some(c) = s.conn.take() {
            if matches!(s.state, ConnState::Registering | ConnState::Connected) {
                c.send(irc::build("QUIT", &[reason]));
            }
            c.close();
            s.conn_id = self.new_id();
            self.on_disconnected(s, "Disconnected");
        }
    }

    fn start_connect(&self, s: &mut Session) {
        if let Some(src) = s.reconnect_source.take() {
            src.remove();
        }
        if let Some(c) = s.conn.take() {
            c.close();
        }
        let cfg = self.config.borrow();
        let b = &s.cfg.bouncer;
        let (host, port, tls, server_sasl) = if b.enabled {
            (b.host.clone(), b.port, b.tls, None)
        } else {
            if s.cfg.servers.is_empty() {
                s.want_connected = false;
                self.server_error(
                    &s.name,
                    &format!(
                        "No servers are configured for {}. Add one in the Networks window (F10, Networks…).",
                        s.name
                    ),
                );
                return;
            }
            s.server_idx %= s.cfg.servers.len();
            let sv = &s.cfg.servers[s.server_idx];
            (sv.host.clone(), sv.port, sv.tls, sv.sasl.clone())
        };
        if host.trim().is_empty() {
            s.want_connected = false;
            self.server_error(
                &s.name,
                "The server host name is empty. Fix it in the Networks window (F10, Networks…).",
            );
            return;
        }
        let sasl = if b.enabled {
            None
        } else {
            Some(server_sasl.unwrap_or_else(|| s.cfg.sasl.clone()))
        }
        .filter(|x| x.mech != SaslMech::None);
        let client_cert = sasl
            .as_ref()
            .filter(|x| x.mech == SaslMech::External && !x.cert_file.is_empty())
            .map(|x| PathBuf::from(&x.cert_file));
        let proxy = (cfg.proxy.enabled && s.cfg.use_proxy).then(|| cfg.proxy.clone());
        let params = ConnectParams {
            host,
            port,
            tls,
            proxy,
            tls_settings: TlsSettings {
                use_system_cas: s.cfg.use_system_cas,
                trusted_certs: s.cfg.trusted_certs.iter().map(PathBuf::from).collect(),
                client_cert,
            },
        };
        s.endpoint = Some((params.host.clone(), params.port, params.tls));
        let id = self.new_id();
        s.conn_id = id;
        s.sasl_current = sasl;
        s.state = ConnState::Connecting;
        s.nick = cfg.nick_for(&s.cfg);
        s.conn = Some(net::spawn(id, params, self.sink.clone()));
    }

    fn reset_session(&self, s: &mut Session) {
        s.state = ConnState::Disconnected;
        s.ping_sent = None;
        s.sasl_active = false;
        s.whois_hover.clear();
        s.whois_partial.clear();
        let chans: Vec<String> = s.channels.values().map(|c| c.name.clone()).collect();
        s.channels.clear();
        for c in chans {
            self.queue_nicklist(&s.name, &c);
        }
        self.set_lag(&s.name, None);
    }

    fn on_disconnected(&self, s: &mut Session, reason: &str) {
        let was_registered = s.state == ConnState::Connected;
        s.conn = None;
        self.reset_session(s);
        for t in self.net_tabs(&s.name) {
            self.error(&t, reason);
        }
        if s.want_connected && !self.quitting.get() {
            let n = s.cfg.servers.len().max(1);
            if !was_registered && !s.cfg.bouncer.enabled {
                s.server_idx = (s.server_idx + 1) % n;
            }
            s.failures += 1;
            let delay = if s.failures as usize > n { 30 } else { 5 };
            self.server_info(
                &s.name,
                &format!("Reconnecting in {delay} seconds… (/network disconnect to stop)"),
            );
            let name = s.name.clone();
            s.reconnect_source = Some(glib::timeout_add_seconds_local_once(delay, move || {
                let Some(a) = current() else { return };
                let mut sessions = a.sessions.borrow_mut();
                if let Some(s) = sessions.iter_mut().find(|s| s.name == name) {
                    s.reconnect_source = None;
                    if s.want_connected && s.conn.is_none() {
                        a.start_connect(s);
                    }
                }
            }));
        }
    }

    fn drain_events(&self) {
        self.sink.clear_pending();
        while let Ok((id, ev)) = self.rx.try_recv() {
            self.handle_net_event(id, ev);
        }
    }

    fn handle_net_event(&self, id: u64, ev: NetEvent) {
        let mut sessions = self.sessions.borrow_mut();
        let Some(s) = sessions.iter_mut().find(|s| s.conn_id == id) else {
            return;
        };
        match ev {
            NetEvent::Status(text) => {
                self.server_info(&s.name, &text);
            }
            NetEvent::Connected => self.on_connected(s),
            NetEvent::Line(line) => {
                if let Some(m) = Message::parse(&line) {
                    self.handle_message(s, &m);
                }
            }
            NetEvent::Disconnected(reason) => self.on_disconnected(s, &reason),
        }
    }

    fn on_connected(&self, s: &mut Session) {
        s.state = ConnState::Registering;
        s.cap_ls.clear();
        s.sasl_active = false;
        let cfg = self.config.borrow();
        let nick = cfg.nick_for(&s.cfg);
        let user = cfg.username_for(&s.cfg);
        let real = cfg.realname_for(&s.cfg);
        s.nick = nick.clone();
        let b = &s.cfg.bouncer;
        if b.enabled && (!b.username.is_empty() || !b.password.is_empty()) {
            let pass = if b.network.is_empty() {
                format!("{}:{}", b.username, b.password)
            } else {
                format!("{}/{}:{}", b.username, b.network, b.password)
            };
            s.send(&irc::build("PASS", &[&pass]));
        }
        s.send("CAP LS 302");
        s.send(&irc::build("NICK", &[&nick]));
        s.send(&irc::build("USER", &[&user, "0", "*", &real]));
        self.update_nick_labels(s);
    }

    // ----- protocol --------------------------------------------------------------------------

    fn handle_cap(&self, s: &mut Session, m: &Message) {
        let sub = m.param(1).to_ascii_uppercase();
        match sub.as_str() {
            "LS" => {
                let (more, caps) = if m.param(2) == "*" {
                    (true, m.param(3))
                } else {
                    (false, m.param(2))
                };
                s.cap_ls.extend(
                    caps.split_whitespace()
                        .map(|c| c.split('=').next().unwrap_or(c).to_string()),
                );
                if more || s.state != ConnState::Registering {
                    return;
                }
                let mut req = Vec::new();
                if s.sasl_current.is_some() {
                    if s.cap_ls.iter().any(|c| c == "sasl") {
                        req.push("sasl");
                    } else {
                        self.server_error(
                            &s.name,
                            "This server does not offer SASL; continuing without authentication.",
                        );
                    }
                }
                if s.cap_ls.iter().any(|c| c == "multi-prefix") {
                    req.push("multi-prefix");
                }
                if req.is_empty() {
                    s.send("CAP END");
                } else {
                    s.send(&irc::build("CAP", &["REQ", &req.join(" ")]));
                }
            }
            "ACK" => {
                let acked: Vec<&str> = m.param(2).split_whitespace().collect();
                if acked.contains(&"sasl")
                    && let Some(sasl) = &s.sasl_current
                {
                    let mech = if sasl.mech == SaslMech::External {
                        "EXTERNAL"
                    } else {
                        "PLAIN"
                    };
                    self.server_info(&s.name, &format!("Authenticating with SASL {mech}…"));
                    s.sasl_active = true;
                    s.send(&irc::build("AUTHENTICATE", &[mech]));
                    return;
                }
                if s.state == ConnState::Registering && !s.sasl_active {
                    s.send("CAP END");
                }
            }
            "NAK" if s.state == ConnState::Registering => {
                s.send("CAP END");
            }
            _ => {}
        }
    }

    fn sasl_respond(&self, s: &mut Session) {
        let Some(sasl) = s.sasl_current.clone() else {
            s.send("AUTHENTICATE *");
            return;
        };
        match sasl.mech {
            SaslMech::Plain => {
                let payload = format!("{0}\0{0}\0{1}", sasl.account, sasl.password);
                let enc = irc::base64(payload.as_bytes());
                for chunk in enc.as_bytes().chunks(400) {
                    s.send(&format!("AUTHENTICATE {}", String::from_utf8_lossy(chunk)));
                }
                if enc.len().is_multiple_of(400) {
                    s.send("AUTHENTICATE +");
                }
            }
            SaslMech::External => s.send("AUTHENTICATE +"),
            SaslMech::None => s.send("AUTHENTICATE *"),
        }
    }

    fn sasl_finished(&self, s: &mut Session) {
        if s.sasl_active {
            s.sasl_active = false;
            if s.state == ConnState::Registering {
                s.send("CAP END");
            }
        }
    }

    fn handle_message(&self, s: &mut Session, m: &Message) {
        let from = m.nick().to_string();
        let is_me = irc_eq(&from, &s.nick);
        let cmd = m.command.as_str();
        match cmd {
            "PING" => s.send(&irc::build("PONG", &[m.param(0)])),
            "PONG" => {
                let token = m.params.last().map(String::as_str).unwrap_or("");
                if let Some((tok, sent)) = &s.ping_sent
                    && tok == token
                {
                    let rtt = sent.elapsed();
                    s.ping_sent = None;
                    s.last_ping = Instant::now();
                    self.set_lag(&s.name, (rtt >= LAG_SHOW).then_some(rtt));
                }
            }
            "CAP" => self.handle_cap(s, m),
            "AUTHENTICATE" => {
                if m.param(0) == "+" {
                    self.sasl_respond(s);
                }
            }
            "900" => {
                self.server_info(&s.name, m.params.last().map(String::as_str).unwrap_or(""));
            }
            "903" => {
                self.server_info_tag(&s.name, "SASL authentication successful", "join");
                self.sasl_finished(s);
            }
            "902" | "904" | "905" | "906" | "907" => {
                self.server_error(
                    &s.name,
                    &format!(
                        "SASL authentication failed: {}",
                        m.params.last().map(String::as_str).unwrap_or("")
                    ),
                );
                self.sasl_finished(s);
            }
            "001" => {
                s.state = ConnState::Connected;
                s.nick = m.param(0).to_string();
                s.failures = 0;
                s.last_ping = Instant::now();
                s.ping_sent = None;
                self.server_info(&s.name, m.param(1));
                self.update_nick_labels(s);
                let mut chans: Vec<String> = s.cfg.autojoin.clone();
                for t in self.net_tabs(&s.name) {
                    if let TabKind::Channel(_, c) = t.kind()
                        && !chans
                            .iter()
                            .any(|x| irc_eq(x.split_whitespace().next().unwrap_or(""), &c))
                    {
                        chans.push(c);
                    }
                }
                for c in chans {
                    let mut it = c.split_whitespace();
                    let (name, key) = (it.next().unwrap_or(""), it.next());
                    if name.is_empty() {
                        continue;
                    }
                    match key {
                        Some(k) => s.send(&irc::build("JOIN", &[name, k])),
                        None => s.send(&irc::build("JOIN", &[name])),
                    }
                }
            }
            "005" => {
                let end = m.params.len().saturating_sub(1);
                for tok in m.params.get(1..end).unwrap_or(&[]) {
                    let (k, v) = tok.split_once('=').unwrap_or((tok, ""));
                    match k {
                        "PREFIX" => {
                            if let Some((modes, syms)) = v.strip_prefix('(').and_then(|r| r.split_once(')')) {
                                s.prefix = modes.chars().zip(syms.chars()).collect();
                            }
                        }
                        "CHANTYPES" => s.chantypes = v.to_string(),
                        "CHANMODES" => {
                            for (i, part) in v.split(',').take(4).enumerate() {
                                s.chanmodes[i] = part.to_string();
                            }
                        }
                        "MODES" => s.max_modes = v.parse().unwrap_or(3),
                        _ => {}
                    }
                }
                self.server_line(
                    &s.name,
                    &[Part::Text("-!- ", "marker"), Part::Text(&m.params_from(1), "dim")],
                );
            }
            "433" | "432" | "436" | "437" if s.state == ConnState::Registering => {
                let bad = m.param(1).to_string();
                let base = if cmd == "432" { "Goo".to_string() } else { bad.clone() };
                let mut next = format!("{base}_");
                if next.len() > 16 {
                    next = format!("{}{}", &base[..base.len().min(12)], unix_millis() % 1000);
                }
                self.server_error(
                    &s.name,
                    &format!(
                        "Nick {bad} is unavailable ({}); trying {next}",
                        m.params.last().map(String::as_str).unwrap_or("")
                    ),
                );
                s.nick = next.clone();
                s.send(&irc::build("NICK", &[&next]));
            }
            "NICK" => {
                let new = m.param(0).to_string();
                let lfrom = irc_lower(&from);
                let mut seen_in = Vec::new();
                for ch in s.channels.values_mut() {
                    if let Some(mut mem) = ch.members.remove(&lfrom) {
                        mem.nick = new.clone();
                        ch.members.insert(irc_lower(&new), mem);
                        seen_in.push(ch.name.clone());
                    }
                }
                if is_me {
                    s.nick = new.clone();
                    for t in self.net_tabs(&s.name) {
                        self.info(&t, &format!("You are now known as {new}"));
                    }
                    self.update_nick_labels(s);
                } else {
                    for c in &seen_in {
                        if let Some(t) = self.channel_tab(&s.name, c) {
                            t.line(
                                &[
                                    Part::Text("-!- ", "marker"),
                                    Part::Nick(&from),
                                    Part::Text(" is now known as ", ""),
                                    Part::Nick(&new),
                                ],
                                None,
                            );
                        }
                    }
                    if let Some(q) = self.query_tab(&s.name, &from) {
                        q.set_kind(TabKind::Query(s.name.clone(), new.clone()));
                        q.line(
                            &[
                                Part::Text("-!- ", "marker"),
                                Part::Nick(&from),
                                Part::Text(" is now known as ", ""),
                                Part::Nick(&new),
                            ],
                            None,
                        );
                    }
                }
                for c in seen_in {
                    self.queue_nicklist(&s.name, &c);
                }
            }
            "JOIN" => {
                let chan = m.param(0).to_string();
                if is_me {
                    s.channels.insert(
                        irc_lower(&chan),
                        Channel {
                            name: chan.clone(),
                            members: HashMap::new(),
                            topic: String::new(),
                        },
                    );
                    let tab = self.ensure_channel_tab(&s.name, &chan);
                    if s.user_joins.remove(&irc_lower(&chan)) {
                        self.switch_to(&tab);
                    }
                    self.info_tag(&tab, &format!("You have joined {chan}"), "join");
                    self.update_nick_labels(s);
                } else if let Some(tab) = self.channel_tab(&s.name, &chan) {
                    tab.line(
                        &[
                            Part::Text("-!- ", "marker"),
                            Part::Nick(&from),
                            Part::Text(&format!(" ({}) has joined {chan}", m.userhost()), "join"),
                        ],
                        None,
                    );
                }
                s.add_member(&chan, &from);
                self.queue_nicklist(&s.name, &chan);
            }
            "PART" => {
                let chan = m.param(0).to_string();
                let reason = m.param(1);
                let tab = self.channel_tab(&s.name, &chan);
                if is_me {
                    s.channels.remove(&irc_lower(&chan));
                    if let Some(t) = &tab {
                        self.info_tag(t, &format!("You have left {chan}"), "part");
                    }
                } else {
                    if let Some(ch) = s.channels.get_mut(&irc_lower(&chan)) {
                        ch.members.remove(&irc_lower(&from));
                    }
                    if let Some(t) = &tab {
                        let r = if reason.is_empty() {
                            String::new()
                        } else {
                            format!(" [{reason}]")
                        };
                        t.line(
                            &[
                                Part::Text("-!- ", "marker"),
                                Part::Nick(&from),
                                Part::Text(&format!(" ({}) has left {chan}{r}", m.userhost()), "part"),
                            ],
                            None,
                        );
                    }
                }
                self.queue_nicklist(&s.name, &chan);
            }
            "KICK" => {
                let chan = m.param(0).to_string();
                let victim = m.param(1).to_string();
                let reason = m.param(2);
                let tab = self.channel_tab(&s.name, &chan);
                if irc_eq(&victim, &s.nick) {
                    s.channels.remove(&irc_lower(&chan));
                    if let Some(t) = &tab {
                        self.error(t, &format!("You were kicked from {chan} by {from} [{reason}]"));
                        self.note_activity(t, Activity::Highlight);
                    }
                } else {
                    if let Some(ch) = s.channels.get_mut(&irc_lower(&chan)) {
                        ch.members.remove(&irc_lower(&victim));
                    }
                    if let Some(t) = &tab {
                        t.line(
                            &[
                                Part::Text("-!- ", "marker"),
                                Part::Nick(&victim),
                                Part::Text(&format!(" was kicked from {chan} by {from} [{reason}]"), "part"),
                            ],
                            None,
                        );
                    }
                }
                self.queue_nicklist(&s.name, &chan);
            }
            "QUIT" => {
                let reason = m.param(0);
                let lfrom = irc_lower(&from);
                let mut chans = Vec::new();
                for ch in s.channels.values_mut() {
                    if ch.members.remove(&lfrom).is_some() {
                        chans.push(ch.name.clone());
                    }
                }
                let text = format!(" ({}) has quit [{reason}]", m.userhost());
                let mut tabs: Vec<Rc<Tab>> = chans.iter().filter_map(|c| self.channel_tab(&s.name, c)).collect();
                tabs.extend(self.query_tab(&s.name, &from));
                for t in tabs {
                    t.line(
                        &[
                            Part::Text("-!- ", "marker"),
                            Part::Nick(&from),
                            Part::Text(&text, "part"),
                        ],
                        None,
                    );
                }
                for c in chans {
                    self.queue_nicklist(&s.name, &c);
                }
            }
            "MODE" => {
                let target = m.param(0).to_string();
                let modes = m.params_from(1);
                if s.is_channel(&target) {
                    self.apply_channel_modes(s, &target, m.param(1), m.params.get(2..).unwrap_or(&[]));
                    let tab = self.ensure_channel_tab(&s.name, &target);
                    tab.line(
                        &[
                            Part::Text("-!- ", "marker"),
                            Part::Text(&format!("mode/{target} [{modes}] by "), ""),
                            Part::Nick(&from),
                        ],
                        None,
                    );
                    self.update_nick_labels(s);
                    self.queue_nicklist(&s.name, &target);
                } else {
                    self.server_info(&s.name, &format!("Mode change [{modes}] for {target}"));
                }
            }
            "TOPIC" => {
                let chan = m.param(0).to_string();
                let topic = m.param(1).to_string();
                if let Some(ch) = s.channels.get_mut(&irc_lower(&chan)) {
                    ch.topic = topic.clone();
                }
                if let Some(t) = self.channel_tab(&s.name, &chan) {
                    t.line(
                        &[
                            Part::Text("-!- ", "marker"),
                            Part::Nick(&from),
                            Part::Text(" changed the topic to: ", ""),
                            Part::Irc(&topic),
                        ],
                        None,
                    );
                }
            }
            "332" => {
                let chan = m.param(1).to_string();
                let topic = m.param(2).to_string();
                if let Some(ch) = s.channels.get_mut(&irc_lower(&chan)) {
                    ch.topic = topic.clone();
                }
                for tab in self.channel_tabs(&s.name, &chan) {
                    tab.line(
                        &[
                            Part::Text("-!- ", "marker"),
                            Part::Text(&format!("Topic for {chan}: "), ""),
                            Part::Irc(&topic),
                        ],
                        None,
                    );
                }
            }
            "333" => {
                let chan = m.param(1);
                let setter = m.param(2).split('!').next().unwrap_or("");
                let when = m
                    .param(3)
                    .parse::<i64>()
                    .ok()
                    .and_then(fmt_unix_time)
                    .unwrap_or_default();
                for tab in self.channel_tabs(&s.name, chan) {
                    tab.line(
                        &[
                            Part::Text("-!- ", "marker"),
                            Part::Text(&format!("Topic set by {setter} [{when}]"), "dim"),
                        ],
                        None,
                    );
                }
            }
            "353" => {
                let chan = m.param(2).to_string();
                if s.channels.contains_key(&irc_lower(&chan)) {
                    for n in m.param(3).split_whitespace() {
                        s.add_member(&chan, n);
                    }
                } else {
                    self.server_info(&s.name, &format!("Users on {chan}: {}", m.param(3)));
                }
            }
            "366" => {
                let chan = m.param(1).to_string();
                if let Some(ch) = s.channels.get(&irc_lower(&chan)) {
                    let n = ch.members.len();
                    if let Some(t) = self.channel_tab(&s.name, &chan) {
                        t.line(
                            &[
                                Part::Text("-!- ", "marker"),
                                Part::Text(&format!("{chan}: {n} users"), "dim"),
                            ],
                            None,
                        );
                    }
                }
                self.update_nick_labels(s);
                self.queue_nicklist(&s.name, &chan);
            }
            "324" => {
                let chan = m.param(1);
                for tab in self.channel_tabs(&s.name, chan) {
                    self.info(&tab, &format!("Modes for {chan}: {}", m.params_from(2)));
                }
            }
            "329" => {
                let chan = m.param(1);
                if let Some(when) = m.param(2).parse::<i64>().ok().and_then(fmt_unix_time) {
                    for tab in self.channel_tabs(&s.name, chan) {
                        tab.line(
                            &[
                                Part::Text("-!- ", "marker"),
                                Part::Text(&format!("Channel {chan} created {when}"), "dim"),
                            ],
                            None,
                        );
                    }
                }
            }
            "PRIVMSG" | "NOTICE" => self.handle_privmsg(s, m, cmd == "NOTICE"),
            "INVITE" => {
                let tab = self.net_tab(&s.name);
                tab.line(
                    &[
                        Part::Text("-!- ", "marker"),
                        Part::Nick(&from),
                        Part::Text(&format!(" invites you to {}", m.param(1)), ""),
                    ],
                    None,
                );
                self.note_activity(&tab, Activity::Highlight);
            }
            "ERROR" => {
                self.server_error(&s.name, &format!("Server error: {}", m.param(0)));
            }
            "311" | "312" | "313" | "317" | "318" | "319" | "330" | "301" | "671" | "378" | "338" | "320" | "401" => {
                self.handle_whois(s, m);
            }
            _ => {
                let numeric = cmd.len() == 3 && cmd.bytes().all(|b| b.is_ascii_digit());
                if numeric {
                    let text = m.params.get(1..).map(|p| p.join(" ")).unwrap_or_default();
                    if cmd.starts_with('4') || cmd.starts_with('5') {
                        self.server_error(&s.name, &text);
                    } else {
                        self.server_info(&s.name, &text);
                    }
                } else {
                    self.server_line(
                        &s.name,
                        &[Part::Text(
                            &format!("{} {} {}", m.nick(), m.command, m.params.join(" ")),
                            "dim",
                        )],
                    );
                }
            }
        }
    }

    fn apply_channel_modes(&self, s: &mut Session, chan: &str, modes: &str, args: &[String]) {
        let prefix = s.prefix.clone();
        let chanmodes = s.chanmodes.clone();
        let mut adding = true;
        let mut ai = 0;
        let mut changes: Vec<(String, char, bool)> = Vec::new();
        for c in modes.chars() {
            match c {
                '+' => adding = true,
                '-' => adding = false,
                _ => {
                    if let Some(&(_, sym)) = prefix.iter().find(|(mc, _)| *mc == c) {
                        if let Some(nick) = args.get(ai) {
                            changes.push((nick.clone(), sym, adding));
                        }
                        ai += 1;
                    } else if chanmodes[0].contains(c)
                        || chanmodes[1].contains(c)
                        || (chanmodes[2].contains(c) && adding)
                    {
                        ai += 1;
                    }
                }
            }
        }
        for (nick, sym, add) in changes {
            let sorted = {
                let Some(mem) = s
                    .channels
                    .get(&irc_lower(chan))
                    .and_then(|ch| ch.members.get(&irc_lower(&nick)))
                else {
                    continue;
                };
                let mut p = mem.prefixes.clone();
                if add {
                    if !p.contains(sym) {
                        p.push(sym);
                    }
                } else {
                    p.retain(|x| x != sym);
                }
                s.sort_prefixes(&p)
            };
            if let Some(mem) = s
                .channels
                .get_mut(&irc_lower(chan))
                .and_then(|ch| ch.members.get_mut(&irc_lower(&nick)))
            {
                mem.prefixes = sorted;
            }
        }
    }

    fn handle_privmsg(&self, s: &mut Session, m: &Message, notice: bool) {
        let target = m.param(0);
        let text = m.param(1);
        let from = m.nick().to_string();
        if notice && (!m.is_from_user() || target == "*" || s.state != ConnState::Connected) {
            let src = if from.is_empty() { "*" } else { &from };
            self.server_line(&s.name, &[Part::Text(&format!("-{src}- "), "notice"), Part::Irc(text)]);
            return;
        }
        let syms = s.prefix_symbols();
        let t = target.trim_start_matches(|c| syms.contains(c));
        let to_channel = s.is_channel(t);
        let own = irc_eq(&from, &s.nick);

        if let Some(inner) = text.strip_prefix('\x01') {
            let inner = inner.strip_suffix('\x01').unwrap_or(inner);
            let (ctcp, args) = split1(inner);
            let ctcp = ctcp.to_ascii_uppercase();
            if ctcp == "ACTION" && !notice {
                let tab = if to_channel {
                    self.ensure_channel_tab(&s.name, t)
                } else {
                    let other = if own { target } else { from.as_str() };
                    self.ensure_query_tab(&s.name, other, &s.nick.clone())
                };
                let hl = !own && irc::contains_word(args, &s.nick);
                let nick_part = if own {
                    Part::Text(&from, "own")
                } else {
                    Part::Nick(&from)
                };
                tab.line(
                    &[Part::Text("* ", ""), nick_part, Part::Text(" ", ""), Part::Irc(args)],
                    hl.then_some("highlight"),
                );
                self.note_activity(
                    &tab,
                    if hl || !to_channel {
                        Activity::Highlight
                    } else {
                        Activity::Message
                    },
                );
                return;
            }
            let tab = self.net_tab(&s.name);
            if notice {
                let mut shown = args.to_string();
                if ctcp == "PING"
                    && let Ok(sent) = args.trim().parse::<u128>()
                {
                    shown = format!("{:.3}s", unix_millis().saturating_sub(sent) as f64 / 1000.0);
                }
                tab.line(
                    &[
                        Part::Text("-!- ", "marker"),
                        Part::Text(&format!("CTCP {ctcp} reply from "), ""),
                        Part::Nick(&from),
                        Part::Text(&format!(": {shown}"), ""),
                    ],
                    None,
                );
            } else {
                let to = if to_channel {
                    format!(" (to {t})")
                } else {
                    String::new()
                };
                tab.line(
                    &[
                        Part::Text("-!- ", "marker"),
                        Part::Text(&format!("CTCP {ctcp} request from "), ""),
                        Part::Nick(&from),
                        Part::Text(&to, ""),
                    ],
                    None,
                );
                self.ctcp_reply(s, &from, &ctcp, args);
            }
            return;
        }

        let tab = if to_channel {
            self.ensure_channel_tab(&s.name, t)
        } else if notice {
            self.query_tab(&s.name, &from).unwrap_or_else(|| self.net_tab(&s.name))
        } else {
            let other = if own { target } else { from.as_str() };
            self.ensure_query_tab(&s.name, other, &s.nick.clone())
        };
        let hl = !own && irc::contains_word(text, &s.nick);
        let nick_part = if own {
            Part::Text(&from, "own")
        } else {
            Part::Nick(&from)
        };
        if notice {
            tab.line(
                &[
                    Part::Text("-", "notice"),
                    nick_part,
                    Part::Text("- ", "notice"),
                    Part::Irc(text),
                ],
                hl.then_some("highlight"),
            );
        } else {
            tab.line(
                &[Part::Text("<", ""), nick_part, Part::Text("> ", ""), Part::Irc(text)],
                hl.then_some("highlight"),
            );
        }
        if !own {
            self.note_activity(
                &tab,
                if hl || !to_channel {
                    Activity::Highlight
                } else {
                    Activity::Message
                },
            );
        }
    }

    /// Answers CTCP VERSION with the bare client name (no version number) and CTCP PING by
    /// echoing its argument back. Other CTCP requests are not answered. Each command gets at
    /// most one reply every 2 seconds.
    fn ctcp_reply(&self, s: &mut Session, to: &str, ctcp: &str, args: &str) {
        let (cmd, body) = match ctcp {
            "VERSION" => ("VERSION", "VERSION IrcGoo".to_string()),
            "PING" if args.is_empty() => ("PING", "PING".to_string()),
            "PING" => ("PING", format!("PING {args}")),
            _ => return,
        };
        if s.last_ctcp_reply
            .get(cmd)
            .is_some_and(|t| t.elapsed() < Duration::from_secs(2))
        {
            return;
        }
        s.last_ctcp_reply.insert(cmd, Instant::now());
        s.send(&irc::build("NOTICE", &[to, &format!("\x01{body}\x01")]));
    }

    fn handle_whois(&self, s: &mut Session, m: &Message) {
        let who = m.param(1).to_string();
        let key = irc_lower(&who);
        let cmd = m.command.as_str();
        if s.whois_hover.contains(&key) {
            let e = s.whois_partial.entry(key.clone()).or_default();
            e.nick = who.clone();
            match cmd {
                "311" => {
                    e.userhost = format!("{}@{}", m.param(2), m.param(3));
                    e.realname = m.params.last().cloned().unwrap_or_default();
                }
                "312" => e.server = m.param(2).to_string(),
                "317" => {
                    e.idle = m.param(2).parse().ok();
                    e.signon = m.param(3).parse().ok();
                }
                "330" => e.account = m.param(2).to_string(),
                "319" => e.channels = m.param(2).to_string(),
                "301" => e.away = m.param(2).to_string(),
                "401" => e.error = "No such nick".into(),
                _ => {}
            }
            if cmd == "318" || cmd == "401" {
                let mut info = s.whois_partial.remove(&key).unwrap_or_default();
                info.fetched = Some(Instant::now());
                s.whois_cache.insert(key.clone(), info);
                s.whois_hover.remove(&key);
                self.refresh_nick_tooltip(&s.name, &who);
            }
            return;
        }
        let text = match cmd {
            "311" => format!(
                "{who} is {}@{} ({})",
                m.param(2),
                m.param(3),
                m.params.last().map(String::as_str).unwrap_or("")
            ),
            "312" => format!("{who} is using {} ({})", m.param(2), m.param(3)),
            "317" => {
                let idle = m.param(2).parse::<u64>().map(irc::fmt_duration).unwrap_or_default();
                let on = m
                    .param(3)
                    .parse::<i64>()
                    .ok()
                    .and_then(fmt_unix_time)
                    .map(|t| format!(", signed on {t}"))
                    .unwrap_or_default();
                format!("{who} has been idle {idle}{on}")
            }
            "318" => format!("End of WHOIS for {who}"),
            "319" => format!("{who} is on {}", m.param(2)),
            "330" => format!("{who} is logged in as {}", m.param(2)),
            "301" => format!("{who} is away: {}", m.param(2)),
            "401" => {
                return self.server_error(
                    &s.name,
                    &format!(
                        "{who}: {}",
                        m.params.last().map(String::as_str).unwrap_or("No such nick")
                    ),
                );
            }
            _ => format!("{who} {}", m.params_from(2)),
        };
        self.server_info(&s.name, &text);
    }

    fn tick(&self) {
        let mut sessions = self.sessions.borrow_mut();
        for s in sessions.iter_mut() {
            if s.state != ConnState::Connected {
                continue;
            }
            if let Some((_, sent)) = &s.ping_sent {
                let elapsed = sent.elapsed();
                if elapsed >= PING_TIMEOUT {
                    if let Some(c) = s.conn.take() {
                        c.close();
                    }
                    s.conn_id = self.new_id();
                    self.on_disconnected(s, "Ping timeout");
                } else if elapsed >= LAG_SHOW {
                    self.set_lag(&s.name, Some(elapsed));
                }
            } else if s.last_ping.elapsed() >= PING_INTERVAL {
                let tok = format!("ircgoo-{}", unix_millis());
                s.send(&irc::build("PING", &[&tok]));
                s.ping_sent = Some((tok, Instant::now()));
            }
        }
    }
}

fn history_move(tab: &Tab, up: bool) {
    let hist = tab.history.borrow();
    if hist.is_empty() {
        return;
    }
    let new = match (tab.history_pos.get(), up) {
        (None, true) => {
            *tab.history_draft.borrow_mut() = tab.entry.text().to_string();
            Some(hist.len() - 1)
        }
        (None, false) => return,
        (Some(i), true) => Some(i.saturating_sub(1)),
        (Some(i), false) => (i + 1 < hist.len()).then_some(i + 1),
    };
    tab.history_pos.set(new);
    let text = match new {
        Some(i) => hist[i].clone(),
        None => tab.history_draft.borrow().clone(),
    };
    tab.entry.set_text(&text);
    tab.entry.set_position(-1);
}
