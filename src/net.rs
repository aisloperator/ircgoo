//! Network connections. Each connection runs on its own thread with blocking I/O and
//! reports events to the GTK main loop through a channel.

use crate::config::{Proxy, describe_addr};
use crate::socks;
use crate::tls::{self, TlsSettings};
use gtk::glib;
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, StreamOwned};
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::Duration;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const POLL_INTERVAL: Duration = Duration::from_millis(50);

pub enum NetEvent {
    Status(String),
    Connected,
    Line(String),
    Disconnected(String),
}

/// Delivers events to the main loop, coalescing wake-ups.
#[derive(Clone)]
pub struct EventSink {
    tx: mpsc::Sender<(u64, NetEvent)>,
    pending: Arc<AtomicBool>,
    wake: fn(),
}

impl EventSink {
    pub fn new(wake: fn()) -> (EventSink, mpsc::Receiver<(u64, NetEvent)>) {
        let (tx, rx) = mpsc::channel();
        (
            EventSink {
                tx,
                pending: Arc::new(AtomicBool::new(false)),
                wake,
            },
            rx,
        )
    }

    fn send(&self, id: u64, ev: NetEvent) {
        if self.tx.send((id, ev)).is_ok() && !self.pending.swap(true, Ordering::SeqCst) {
            let wake = self.wake;
            glib::MainContext::default().invoke(wake);
        }
    }

    /// Called on the main thread before draining the receiver.
    pub fn clear_pending(&self) {
        self.pending.store(false, Ordering::SeqCst);
    }
}

pub struct ConnectParams {
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub proxy: Option<Proxy>,
    pub tls_settings: TlsSettings,
}

enum Cmd {
    Send(String),
    Close,
}

pub struct Connection {
    tx: mpsc::Sender<Cmd>,
}

impl Connection {
    pub fn send(&self, line: String) {
        let _ = self.tx.send(Cmd::Send(line));
    }
    pub fn close(&self) {
        let _ = self.tx.send(Cmd::Close);
    }
}

pub fn spawn(id: u64, params: ConnectParams, sink: EventSink) -> Connection {
    let (tx, rx) = mpsc::channel();
    let s2 = sink.clone();
    let res = std::thread::Builder::new()
        .name(format!("ircgoo-conn-{id}"))
        .spawn(move || {
            let reason = run(id, &params, &sink, &rx);
            sink.send(id, NetEvent::Disconnected(reason));
        });
    if let Err(e) = res {
        s2.send(
            id,
            NetEvent::Disconnected(format!("Cannot start connection thread: {e}")),
        );
    }
    Connection { tx }
}

enum Stream {
    Plain(TcpStream),
    Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Stream::Plain(s) => s.read(buf),
            Stream::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Stream::Plain(s) => s.write(buf),
            Stream::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Stream::Plain(s) => s.flush(),
            Stream::Tls(s) => s.flush(),
        }
    }
}

impl Stream {
    fn shutdown(&mut self) {
        match self {
            Stream::Plain(s) => {
                let _ = s.shutdown(Shutdown::Both);
            }
            Stream::Tls(s) => {
                s.conn.send_close_notify();
                let _ = s.flush();
                let _ = s.sock.shutdown(Shutdown::Both);
            }
        }
    }
}

fn decode_line(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_string(),
        // Fall back to Latin-1, which is what most non-UTF-8 IRC text is.
        Err(_) => bytes.iter().map(|&b| b as char).collect(),
    }
}

fn run(id: u64, p: &ConnectParams, sink: &EventSink, rx: &mpsc::Receiver<Cmd>) -> String {
    let addr = describe_addr(&p.host, p.port, p.tls);
    let via = match &p.proxy {
        Some(px) => format!(" via SOCKS5 proxy {}:{}", px.host, px.port),
        None => String::new(),
    };
    sink.send(id, NetEvent::Status(format!("Connecting to {addr}{via}…")));

    let sock = match &p.proxy {
        Some(px) => socks::connect(px, &p.host, p.port, CONNECT_TIMEOUT),
        None => socks::tcp_connect(&p.host, p.port, CONNECT_TIMEOUT),
    };
    let sock = match sock {
        Ok(s) => s,
        Err(e) => return format!("Connection failed: {e}"),
    };
    let _ = sock.set_nodelay(true);

    let mut stream = if p.tls {
        let config = match tls::client_config(&p.tls_settings) {
            Ok(c) => c,
            Err(e) => return e,
        };
        let name = match ServerName::try_from(p.host.trim_matches(['[', ']']).to_string()) {
            Ok(n) => n,
            Err(e) => return format!("Invalid server name {}: {e}", p.host),
        };
        let mut conn = match ClientConnection::new(config, name) {
            Ok(c) => c,
            Err(e) => return format!("TLS error: {e}"),
        };
        let mut sock = sock;
        let _ = sock.set_read_timeout(Some(CONNECT_TIMEOUT));
        while conn.is_handshaking() {
            if let Err(e) = conn.complete_io(&mut sock) {
                return format!("TLS handshake failed: {e}");
            }
        }
        let version = conn.protocol_version().map(|v| format!("{v:?}")).unwrap_or_default();
        let suite = conn
            .negotiated_cipher_suite()
            .map(|s| format!("{:?}", s.suite()))
            .unwrap_or_default();
        sink.send(id, NetEvent::Status(format!("TLS established ({version}, {suite})")));
        Stream::Tls(Box::new(StreamOwned::new(conn, sock)))
    } else {
        Stream::Plain(sock)
    };
    let set_timeout = match &stream {
        Stream::Plain(s) => s.set_read_timeout(Some(POLL_INTERVAL)),
        Stream::Tls(s) => s.sock.set_read_timeout(Some(POLL_INTERVAL)),
    };
    if let Err(e) = set_timeout {
        return format!("Socket error: {e}");
    }
    sink.send(id, NetEvent::Connected);

    let mut inbuf: Vec<u8> = Vec::with_capacity(8192);
    let mut buf = [0u8; 8192];
    loop {
        loop {
            match rx.try_recv() {
                Ok(Cmd::Send(line)) => {
                    let mut data = line.into_bytes();
                    data.extend_from_slice(b"\r\n");
                    if let Err(e) = stream.write_all(&data).and_then(|_| stream.flush()) {
                        return format!("Write error: {e}");
                    }
                }
                Ok(Cmd::Close) | Err(mpsc::TryRecvError::Disconnected) => {
                    stream.shutdown();
                    return "Disconnected".into();
                }
                Err(mpsc::TryRecvError::Empty) => break,
            }
        }
        match stream.read(&mut buf) {
            Ok(0) => return "Connection closed by server".into(),
            Ok(n) => {
                inbuf.extend_from_slice(&buf[..n]);
                while let Some(pos) = inbuf.iter().position(|&b| b == b'\n') {
                    let mut line: Vec<u8> = inbuf.drain(..=pos).collect();
                    line.pop();
                    if line.last() == Some(&b'\r') {
                        line.pop();
                    }
                    if !line.is_empty() {
                        sink.send(id, NetEvent::Line(decode_line(&line)));
                    }
                }
                if inbuf.len() > 65536 {
                    inbuf.clear();
                }
            }
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return format!("Read error: {e}"),
        }
    }
}
