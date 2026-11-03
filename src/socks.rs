//! Minimal SOCKS5 client (RFC 1928) with optional username/password auth (RFC 1929).
//! Hostnames are resolved by the proxy, so DNS does not leak around it.

use crate::config::Proxy;
use std::io::{self, Read, Write};
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

fn err(msg: impl Into<String>) -> io::Error {
    io::Error::other(msg.into())
}

pub fn tcp_connect(host: &str, port: u16, timeout: Duration) -> io::Result<TcpStream> {
    let mut last = err(format!("{host}: no addresses found"));
    for addr in (host, port).to_socket_addrs()? {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(s) => return Ok(s),
            Err(e) => last = e,
        }
    }
    Err(last)
}

pub fn connect(proxy: &Proxy, host: &str, port: u16, timeout: Duration) -> io::Result<TcpStream> {
    let mut s = tcp_connect(&proxy.host, proxy.port, timeout)
        .map_err(|e| err(format!("SOCKS5 proxy {}:{}: {e}", proxy.host, proxy.port)))?;
    s.set_read_timeout(Some(timeout))?;
    s.set_write_timeout(Some(timeout))?;

    let use_auth = !proxy.username.is_empty();
    if use_auth {
        s.write_all(&[5, 2, 0, 2])?;
    } else {
        s.write_all(&[5, 1, 0])?;
    }
    let mut b = [0u8; 2];
    s.read_exact(&mut b)?;
    if b[0] != 5 {
        return Err(err("SOCKS5: the proxy did not answer as a SOCKS5 server"));
    }
    match b[1] {
        0 => {}
        2 if use_auth => {
            let (u, p) = (proxy.username.as_bytes(), proxy.password.as_bytes());
            if u.len() > 255 || p.len() > 255 {
                return Err(err("SOCKS5: username or password too long"));
            }
            let mut req = vec![1, u.len() as u8];
            req.extend_from_slice(u);
            req.push(p.len() as u8);
            req.extend_from_slice(p);
            s.write_all(&req)?;
            s.read_exact(&mut b)?;
            if b[1] != 0 {
                return Err(err("SOCKS5: proxy authentication failed"));
            }
        }
        0xFF => return Err(err("SOCKS5: proxy rejected all offered authentication methods")),
        m => return Err(err(format!("SOCKS5: proxy chose unsupported method {m}"))),
    }

    let mut req = vec![5, 1, 0];
    match host.trim_matches(['[', ']']).parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            req.push(1);
            req.extend_from_slice(&ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            req.push(4);
            req.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            if host.len() > 255 {
                return Err(err("SOCKS5: hostname too long"));
            }
            req.push(3);
            req.push(host.len() as u8);
            req.extend_from_slice(host.as_bytes());
        }
    }
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req)?;

    let mut h = [0u8; 4];
    s.read_exact(&mut h)?;
    if h[1] != 0 {
        let why = match h[1] {
            1 => "general failure",
            2 => "connection not allowed by ruleset",
            3 => "network unreachable",
            4 => "host unreachable",
            5 => "connection refused",
            6 => "TTL expired",
            7 => "command not supported",
            8 => "address type not supported",
            _ => "unknown error",
        };
        return Err(err(format!("SOCKS5: proxy could not connect to {host}:{port}: {why}")));
    }
    let n = match h[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l)?;
            l[0] as usize
        }
        _ => return Err(err("SOCKS5: malformed reply")),
    };
    let mut rest = vec![0u8; n + 2];
    s.read_exact(&mut rest)?;
    s.set_write_timeout(None)?;
    Ok(s)
}
