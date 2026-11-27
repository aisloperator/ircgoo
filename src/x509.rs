//! Just enough X.509 (DER) parsing to show a server certificate to the user as text.

use gtk::glib;

/// One DER element: its tag and content.
fn read<'a>(input: &mut &'a [u8]) -> Option<(u8, &'a [u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, mut rest) = rest.split_first()?;
    let len = if first < 0x80 {
        first as usize
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let len = rest[..n].iter().fold(0usize, |a, &b| (a << 8) | b as usize);
        rest = &rest[n..];
        len
    };
    if rest.len() < len {
        return None;
    }
    let (content, after) = rest.split_at(len);
    *input = after;
    Some((tag, content))
}

fn expect<'a>(input: &mut &'a [u8], tag: u8) -> Option<&'a [u8]> {
    match read(input)? {
        (t, c) if t == tag => Some(c),
        _ => None,
    }
}

const SEQUENCE: u8 = 0x30;
const SET: u8 = 0x31;
const OID: u8 = 0x06;

fn oid_string(b: &[u8]) -> String {
    let mut parts = Vec::new();
    let mut v: u64 = 0;
    for (i, &byte) in b.iter().enumerate() {
        v = (v << 7) | (byte & 0x7f) as u64;
        if byte & 0x80 == 0 {
            if parts.is_empty() {
                let first = if i == 0 { (v / 40).min(2) } else { 2 };
                parts.push(first);
                parts.push(v - first * 40);
            } else {
                parts.push(v);
            }
            v = 0;
        }
    }
    parts.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(".")
}

fn attr_name(oid: &str) -> &str {
    match oid {
        "2.5.4.3" => "CN",
        "2.5.4.5" => "serialNumber",
        "2.5.4.6" => "C",
        "2.5.4.7" => "L",
        "2.5.4.8" => "ST",
        "2.5.4.9" => "street",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        "1.2.840.113549.1.9.1" => "emailAddress",
        "0.9.2342.19200300.100.1.25" => "DC",
        "0.9.2342.19200300.100.1.1" => "UID",
        other => other,
    }
}

fn der_string(tag: u8, b: &[u8]) -> String {
    match tag {
        // BMPString: UTF-16BE.
        0x1e => {
            let units: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
            String::from_utf16_lossy(&units)
        }
        // UniversalString: UTF-32BE.
        0x1c => b
            .chunks_exact(4)
            .map(|c| char::from_u32(u32::from_be_bytes([c[0], c[1], c[2], c[3]])).unwrap_or('\u{fffd}'))
            .collect(),
        // T61String: treat as Latin-1.
        0x14 => b.iter().map(|&c| c as char).collect(),
        _ => String::from_utf8_lossy(b).into_owned(),
    }
}

/// A distinguished name such as "C=US, O=Example, CN=irc.example.org".
fn name_string(mut name: &[u8]) -> Option<String> {
    let mut out = Vec::new();
    while !name.is_empty() {
        let mut set = expect(&mut name, SET)?;
        while !set.is_empty() {
            let mut atv = expect(&mut set, SEQUENCE)?;
            let oid = oid_string(expect(&mut atv, OID)?);
            let (tag, value) = read(&mut atv)?;
            out.push(format!("{}={}", attr_name(&oid), der_string(tag, value)));
        }
    }
    Some(out.join(", "))
}

fn time_string(tag: u8, b: &[u8]) -> String {
    let s = String::from_utf8_lossy(b);
    let digits = |r: std::ops::Range<usize>| s.get(r).filter(|d| d.bytes().all(|c| c.is_ascii_digit()));
    let (year, rest) = match tag {
        0x17 => match digits(0..2).and_then(|y| y.parse::<u32>().ok()) {
            Some(y) => (if y >= 50 { 1900 + y } else { 2000 + y }, 2),
            None => return s.into_owned(),
        },
        _ => match digits(0..4).and_then(|y| y.parse::<u32>().ok()) {
            Some(y) => (y, 4),
            None => return s.into_owned(),
        },
    };
    match (
        digits(rest..rest + 2),
        digits(rest + 2..rest + 4),
        digits(rest + 4..rest + 6),
        digits(rest + 6..rest + 8),
        digits(rest + 8..rest + 10),
    ) {
        (Some(mo), Some(d), Some(h), Some(mi), Some(sec)) if s.ends_with('Z') => {
            format!("{year}-{mo}-{d} {h}:{mi}:{sec} UTC")
        }
        _ => s.into_owned(),
    }
}

fn hex_colons(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect::<Vec<_>>().join(":")
}

pub fn fingerprint(der: &[u8], kind: glib::ChecksumType) -> String {
    let hex = glib::compute_checksum_for_data(kind, der)
        .map(|g| g.to_string())
        .unwrap_or_default();
    let bytes: Vec<u8> = (0..hex.len() / 2)
        .filter_map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok())
        .collect();
    hex_colons(&bytes)
}

fn public_key_string(mut spki: &[u8]) -> Option<String> {
    let mut alg = expect(&mut spki, SEQUENCE)?;
    let oid = oid_string(expect(&mut alg, OID)?);
    Some(match oid.as_str() {
        "1.2.840.113549.1.1.1" => {
            let bits = expect(&mut spki, 0x03)?;
            let mut key = bits.get(1..)?;
            let mut seq = expect(&mut key, SEQUENCE)?;
            let n = expect(&mut seq, 0x02)?;
            let n = match n.iter().position(|&b| b != 0) {
                Some(i) => &n[i..],
                None => &[],
            };
            let size = n.len() * 8 - n.first().map_or(0, |b| b.leading_zeros() as usize);
            format!("RSA, {size} bits")
        }
        "1.2.840.10045.2.1" => {
            let curve = expect(&mut alg, OID).map(oid_string).unwrap_or_default();
            let curve = match curve.as_str() {
                "1.2.840.10045.3.1.7" => "P-256",
                "1.3.132.0.34" => "P-384",
                "1.3.132.0.35" => "P-521",
                other => other,
            };
            format!("ECDSA, {curve}")
        }
        "1.3.101.112" => "Ed25519".into(),
        "1.3.101.113" => "Ed448".into(),
        other => other.to_string(),
    })
}

/// Host names, addresses and email addresses from the subjectAltName extension.
fn alt_names(mut gn: &[u8]) -> Option<Vec<String>> {
    let mut seq = expect(&mut gn, SEQUENCE)?;
    let mut out = Vec::new();
    while !seq.is_empty() {
        let (tag, v) = read(&mut seq)?;
        match tag {
            0x81 | 0x82 | 0x86 => out.push(String::from_utf8_lossy(v).into_owned()),
            0x87 if v.len() == 4 => out.push(std::net::Ipv4Addr::new(v[0], v[1], v[2], v[3]).to_string()),
            0x87 if v.len() == 16 => {
                let a: [u8; 16] = v.try_into().ok()?;
                out.push(std::net::Ipv6Addr::from(a).to_string());
            }
            _ => {}
        }
    }
    Some(out)
}

#[derive(Debug, Default, PartialEq)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub self_signed: bool,
    pub not_before: String,
    pub not_after: String,
    pub alt_names: Vec<String>,
    pub serial: String,
    pub public_key: String,
}

pub fn parse(der: &[u8]) -> Option<CertInfo> {
    let mut input = der;
    let mut cert = expect(&mut input, SEQUENCE)?;
    let mut tbs = expect(&mut cert, SEQUENCE)?;
    let mut first = read(&mut tbs)?;
    if first.0 == 0xa0 {
        first = read(&mut tbs)?;
    }
    let (0x02, serial) = first else { return None };
    expect(&mut tbs, SEQUENCE)?;
    let issuer = expect(&mut tbs, SEQUENCE)?;
    let mut validity = expect(&mut tbs, SEQUENCE)?;
    let (t1, nb) = read(&mut validity)?;
    let (t2, na) = read(&mut validity)?;
    let subject = expect(&mut tbs, SEQUENCE)?;
    let spki = expect(&mut tbs, SEQUENCE)?;
    let mut info = CertInfo {
        subject: name_string(subject)?,
        issuer: name_string(issuer)?,
        self_signed: issuer == subject,
        not_before: time_string(t1, nb),
        not_after: time_string(t2, na),
        alt_names: Vec::new(),
        serial: hex_colons(serial),
        public_key: public_key_string(spki).unwrap_or_default(),
    };
    while let Some((tag, content)) = read(&mut tbs) {
        if tag != 0xa3 {
            continue;
        }
        let mut c = content;
        let mut exts = expect(&mut c, SEQUENCE)?;
        while !exts.is_empty() {
            let mut ext = expect(&mut exts, SEQUENCE)?;
            let oid = oid_string(expect(&mut ext, OID)?);
            let mut value = read(&mut ext)?;
            if value.0 == 0x01 {
                value = read(&mut ext)?;
            }
            if oid == "2.5.29.17" && value.0 == 0x04 {
                info.alt_names = alt_names(value.1).unwrap_or_default();
            }
        }
    }
    Some(info)
}

pub fn to_pem(der: &[u8]) -> String {
    let b64 = glib::base64_encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(&String::from_utf8_lossy(chunk));
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

/// The certificate's details, fingerprints and PEM text.
pub fn describe(der: &[u8]) -> String {
    let mut out = String::new();
    match parse(der) {
        Some(i) => {
            out.push_str(&format!("Subject:      {}\n", i.subject));
            let ss = if i.self_signed { "  (self-signed)" } else { "" };
            out.push_str(&format!("Issuer:       {}{ss}\n", i.issuer));
            out.push_str(&format!("Valid from:   {}\n", i.not_before));
            out.push_str(&format!("Valid until:  {}\n", i.not_after));
            if !i.alt_names.is_empty() {
                out.push_str(&format!("Names:        {}\n", i.alt_names.join(", ")));
            }
            if !i.public_key.is_empty() {
                out.push_str(&format!("Public key:   {}\n", i.public_key));
            }
            out.push_str(&format!("Serial:       {}\n", i.serial));
        }
        None => out.push_str("(The certificate could not be decoded.)\n"),
    }
    // Two lines of 16 bytes, to keep the text narrow.
    let sha256 = fingerprint(der, glib::ChecksumType::Sha256);
    let (first, second) = sha256.split_at(sha256.len().min(48));
    out.push_str(&format!("SHA-256:      {}\n", first.trim_end_matches(':')));
    if !second.is_empty() {
        out.push_str(&format!("              {second}\n"));
    }
    out.push_str(&format!(
        "SHA-1:        {}\n",
        fingerprint(der, glib::ChecksumType::Sha1)
    ));
    out.push('\n');
    out.push_str(&to_pem(der));
    out
}

/// One line identifying the certificate, for lists.
pub fn summary(der: &[u8]) -> String {
    let fp = fingerprint(der, glib::ChecksumType::Sha256);
    let short: String = fp.chars().take(23).collect();
    let who = parse(der)
        .map(|i| {
            i.subject
                .split(", ")
                .find_map(|p| p.strip_prefix("CN="))
                .map(str::to_string)
                .unwrap_or(i.subject)
        })
        .unwrap_or_else(|| "Undecodable certificate".into());
    format!("{who} — SHA-256 {short}…")
}

#[cfg(test)]
mod tests {
    use super::*;

    // A self-signed EC P-256 certificate for irc.example.org with SAN
    // DNS:irc.example.org, DNS:*.example.org, IP:192.0.2.1.
    const PEM: &str = include_str!("testdata/test-cert.pem");

    fn der() -> Vec<u8> {
        let b64: String = PEM.lines().filter(|l| !l.starts_with("-----")).collect();
        glib::base64_decode(&b64)
    }

    #[test]
    fn parses_certificate() {
        let i = parse(&der()).expect("parses");
        assert_eq!(i.subject, "C=CA, O=IrcGoo Test, CN=irc.example.org");
        assert_eq!(i.issuer, i.subject);
        assert!(i.self_signed);
        assert_eq!(i.not_before, "2026-01-01 00:00:00 UTC");
        assert_eq!(i.not_after, "2036-01-01 00:00:00 UTC");
        assert_eq!(i.alt_names, ["irc.example.org", "*.example.org", "192.0.2.1"]);
        assert_eq!(i.public_key, "ECDSA, P-256");
    }

    #[test]
    fn pem_round_trip() {
        let d = der();
        assert_eq!(to_pem(&d).trim(), PEM.trim());
        assert_eq!(
            fingerprint(&d, glib::ChecksumType::Sha256),
            "28:07:1F:6D:4D:47:57:E5:58:E2:93:0F:BA:DF:C4:A6:1E:21:6D:40:B5:A5:02:8E:8D:A5:C3:F6:77:40:39:0E"
        );
        assert!(describe(&d).contains(
            "SHA-256:      28:07:1F:6D:4D:47:57:E5:58:E2:93:0F:BA:DF:C4:A6\n              1E:21:6D:40:B5:A5:02:8E:8D:A5:C3:F6:77:40:39:0E\n"
        ));
        assert!(summary(&d).starts_with("irc.example.org — SHA-256 "));
    }

    #[test]
    fn garbage_is_not_parsed() {
        assert_eq!(parse(&[0x30, 0x05, 1, 2]), None);
        assert_eq!(parse(&[]), None);
        assert!(describe(&[1, 2, 3]).contains("could not be decoded"));
    }

    #[test]
    fn oids_and_times() {
        assert_eq!(oid_string(&[0x55, 0x04, 0x03]), "2.5.4.3");
        assert_eq!(
            oid_string(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]),
            "1.2.840.113549.1.1.1"
        );
        assert_eq!(time_string(0x17, b"991231235959Z"), "1999-12-31 23:59:59 UTC");
        assert_eq!(time_string(0x18, b"20500101000000Z"), "2050-01-01 00:00:00 UTC");
    }
}
