//! Legacy TLS through GIO (GnuTLS, from glib-networking), for servers that accept nothing
//! rustls supports, such as TLS 1.2 with RSA key exchange only. Used only for servers the
//! user has allowed; nothing here runs before that.
//!
//! Certificates are checked by the same verifier as rustls connections (see `tls`), not by
//! GnuTLS: the connection has no certificate database, so GIO asks about every certificate.

use crate::tls::{self, CertRejection, TlsSettings};
use gtk::gio;
use gtk::gio::prelude::*;
use gtk::glib;
use std::cell::RefCell;
use std::io;
use std::net::TcpStream;
use std::rc::Rc;
use std::time::Duration;

pub struct LegacyStream {
    conn: gio::TlsClientConnection,
    socket: gio::Socket,
    input: gio::PollableInputStream,
    output: gio::OutputStream,
    poll: Duration,
}

fn io_err(e: glib::Error) -> io::Error {
    if e.matches(gio::IOErrorEnum::WouldBlock) {
        io::Error::from(io::ErrorKind::WouldBlock)
    } else if e.matches(gio::IOErrorEnum::TimedOut) {
        io::Error::from(io::ErrorKind::TimedOut)
    } else {
        io::Error::other(e.message().to_string())
    }
}

fn cert_der(c: &gio::TlsCertificate) -> Vec<u8> {
    c.property::<Option<glib::ByteArray>>("certificate")
        .map(|b| b.to_vec())
        .unwrap_or_default()
}

/// Result of a failed legacy handshake: the message, and a certificate refusal the user
/// may override.
pub struct Failure {
    pub message: String,
    pub rejection: Option<CertRejection>,
}

/// Our check of the server's certificate: the message and refusal on failure.
type Verdict = Result<(), (String, Option<CertRejection>)>;

/// TLS handshake over an already connected socket (direct or through the proxy).
pub fn connect(
    sock: TcpStream,
    host: &str,
    port: u16,
    settings: &TlsSettings,
    timeout: Duration,
    poll: Duration,
) -> Result<LegacyStream, Failure> {
    let fail = |message: String| Failure {
        message,
        rejection: None,
    };
    let socket = gio::Socket::from_fd(sock.into()).map_err(|e| fail(format!("Socket error: {e}")))?;
    socket.set_timeout(timeout.as_secs().max(1) as u32);
    let base = socket.connection_factory_create_connection();
    let identity = gio::NetworkAddress::new(host.trim_matches(['[', ']']), port);
    let conn = gio::TlsClientConnection::new(&base, Some(&identity))
        .map_err(|e| fail(format!("Legacy TLS is not available: {e}")))?;
    conn.set_database(None::<&gio::TlsDatabase>);
    if let Some(path) = &settings.client_cert {
        let cert = gio::TlsCertificate::from_file(path)
            .map_err(|e| fail(format!("Cannot read client certificate {}: {e}", path.display())))?;
        conn.set_certificate(&cert);
    }

    let verdict: Rc<RefCell<Option<Verdict>>> = Rc::default();
    let v = verdict.clone();
    let settings = settings.clone();
    let name = host.to_string();
    conn.connect_accept_certificate(move |_, cert, _| {
        let mut chain = Vec::new();
        let mut next = Some(cert.clone());
        while let Some(c) = next {
            chain.push(cert_der(&c));
            next = c.issuer();
        }
        let res = tls::verify_chain(&settings, &name, &chain);
        let ok = res.is_ok();
        *v.borrow_mut() = Some(res);
        ok
    });

    if let Err(e) = conn.handshake(None::<&gio::Cancellable>) {
        let (message, rejection) = match verdict.borrow_mut().take() {
            Some(Err((m, r))) => (format!("Legacy TLS handshake failed: {m}"), r),
            _ => (format!("Legacy TLS handshake failed: {e}"), None),
        };
        return Err(Failure { message, rejection });
    }
    if !matches!(*verdict.borrow(), Some(Ok(()))) {
        // GIO always asks when there is no database; never accept without our check.
        return Err(fail(
            "Legacy TLS handshake failed: the certificate was not checked".into(),
        ));
    }
    let input = conn
        .input_stream()
        .dynamic_cast::<gio::PollableInputStream>()
        .map_err(|_| fail("Legacy TLS stream is not pollable".into()))?;
    let output = conn.output_stream();
    Ok(LegacyStream {
        conn,
        socket,
        input,
        output,
        poll,
    })
}

impl LegacyStream {
    /// Protocol version and cipher suite, for the status line.
    pub fn describe(&self) -> String {
        // Read as properties: the typed getters need newer GLib bindings than IrcGoo enables.
        let has = |name| self.conn.find_property(name).is_some();
        let version = if has("protocol-version") {
            match self
                .conn
                .property_value("protocol-version")
                .transform::<i32>()
                .ok()
                .and_then(|v| v.get::<i32>().ok())
            {
                // GTlsProtocolVersion: SSL 3.0, TLS 1.0, 1.1, 1.2, 1.3, then DTLS.
                Some(1) => "SSL 3.0",
                Some(2) => "TLS 1.0",
                Some(3) => "TLS 1.1",
                Some(4) => "TLS 1.2",
                Some(5) => "TLS 1.3",
                _ => "",
            }
        } else {
            ""
        };
        let suite = if has("ciphersuite-name") {
            self.conn
                .property::<Option<String>>("ciphersuite-name")
                .unwrap_or_default()
        } else {
            String::new()
        };
        [version, suite.as_str()]
            .iter()
            .filter(|s| !s.is_empty())
            .copied()
            .collect::<Vec<_>>()
            .join(", ")
    }

    pub fn shutdown(&mut self) {
        let _ = self.conn.close(None::<&gio::Cancellable>);
    }
}

impl io::Read for LegacyStream {
    /// Waits at most the poll interval, then fails with `WouldBlock`.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.input.read_nonblocking(buf, None::<&gio::Cancellable>) {
            Ok(n) => return Ok(n as usize),
            Err(e) if e.matches(gio::IOErrorEnum::WouldBlock) => {}
            Err(e) => return Err(io_err(e)),
        }
        let _ = self.socket.condition_timed_wait(
            glib::IOCondition::IN,
            self.poll.as_micros() as i64,
            None::<&gio::Cancellable>,
        );
        self.input
            .read_nonblocking(buf, None::<&gio::Cancellable>)
            .map(|n| n as usize)
            .map_err(io_err)
    }
}

impl io::Write for LegacyStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.output
            .write(buf, None::<&gio::Cancellable>)
            .map(|n| n as usize)
            .map_err(io_err)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.output.flush(None::<&gio::Cancellable>).map_err(io_err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::ClientConnection;
    use rustls::pki_types::ServerName;

    /// Against a real legacy-only server, named by IRCGOO_LEGACY_TEST_SERVER=host:port.
    /// Run with: IRCGOO_LEGACY_TEST_SERVER=… cargo test legacy_server -- --ignored
    #[test]
    #[ignore]
    fn legacy_server() {
        let target = std::env::var("IRCGOO_LEGACY_TEST_SERVER").expect("IRCGOO_LEGACY_TEST_SERVER");
        let (host, port) = target.rsplit_once(':').expect("host:port");
        let port: u16 = port.parse().unwrap();
        let t = Duration::from_secs(20);
        let mut settings = TlsSettings {
            use_system_cas: true,
            ..TlsSettings::default()
        };

        // rustls fails in a way that offers legacy TLS.
        let (config, _) = tls::client_config(&settings).unwrap();
        let name = ServerName::try_from(host.to_string()).unwrap();
        let mut conn = ClientConnection::new(config, name).unwrap();
        let mut sock = crate::socks::tcp_connect(host, port, t).unwrap();
        let err = loop {
            if let Err(e) = conn.complete_io(&mut sock) {
                break e;
            }
            assert!(conn.is_handshaking(), "rustls handshake succeeded");
        };
        assert!(tls::legacy_might_help(&err), "{err}");

        // GnuTLS gets as far as the certificate, which is refused but may be trusted.
        let sock = crate::socks::tcp_connect(host, port, t).unwrap();
        let f = connect(sock, host, port, &settings, t, Duration::from_millis(50))
            .err()
            .expect("untrusted certificate accepted");
        let r = f.rejection.expect(&f.message);
        eprintln!("refused: {} ({})", f.message, r.reason);

        // Trusted, it connects.
        settings.accepted_certs = vec![r.chain[0].clone()];
        let sock = crate::socks::tcp_connect(host, port, t).unwrap();
        let s = connect(sock, host, port, &settings, t, Duration::from_millis(50))
            .map_err(|f| f.message)
            .unwrap();
        eprintln!("connected: {}", s.describe());
    }
}
