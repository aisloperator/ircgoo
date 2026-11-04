//! IRC protocol helpers: message parsing/building, case mapping, mIRC formatting codes.

#[derive(Debug, Clone)]
pub struct Message {
    #[allow(dead_code)]
    pub tags: Vec<(String, String)>,
    pub prefix: Option<String>,
    pub command: String,
    pub params: Vec<String>,
}

impl Message {
    pub fn parse(line: &str) -> Option<Message> {
        let mut rest = line.trim_end_matches(['\r', '\n']);
        let mut tags = Vec::new();
        if let Some(r) = rest.strip_prefix('@') {
            let (t, r2) = r.split_once(' ')?;
            for kv in t.split(';').filter(|s| !s.is_empty()) {
                let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
                tags.push((k.to_string(), unescape_tag(v)));
            }
            rest = r2.trim_start_matches(' ');
        }
        let mut prefix = None;
        if let Some(r) = rest.strip_prefix(':') {
            let (p, r2) = r.split_once(' ')?;
            prefix = Some(p.to_string());
            rest = r2.trim_start_matches(' ');
        }
        let (command, mut rest) = rest.split_once(' ').unwrap_or((rest, ""));
        if command.is_empty() {
            return None;
        }
        let mut params = Vec::new();
        loop {
            rest = rest.trim_start_matches(' ');
            if rest.is_empty() {
                break;
            }
            if let Some(trailing) = rest.strip_prefix(':') {
                params.push(trailing.to_string());
                break;
            }
            match rest.split_once(' ') {
                Some((p, r)) => {
                    params.push(p.to_string());
                    rest = r;
                }
                None => {
                    params.push(rest.to_string());
                    break;
                }
            }
        }
        Some(Message {
            tags,
            prefix,
            command: command.to_ascii_uppercase(),
            params,
        })
    }

    /// Nick part of the prefix (or the server name for server-originated messages).
    pub fn nick(&self) -> &str {
        match self.prefix.as_deref() {
            Some(p) => p.split(['!', '@']).next().unwrap_or(p),
            None => "",
        }
    }

    /// True if the prefix looks like a user (nick!user@host) rather than a server.
    pub fn is_from_user(&self) -> bool {
        self.prefix.as_deref().is_some_and(|p| p.contains('!'))
    }

    pub fn userhost(&self) -> &str {
        self.prefix
            .as_deref()
            .and_then(|p| p.split_once('!'))
            .map(|(_, uh)| uh)
            .unwrap_or("")
    }

    pub fn param(&self, i: usize) -> &str {
        self.params.get(i).map(|s| s.as_str()).unwrap_or("")
    }

    /// Parameters from index `i` onward, joined with spaces.
    pub fn params_from(&self, i: usize) -> String {
        self.params.get(i..).map(|p| p.join(" ")).unwrap_or_default()
    }
}

fn unescape_tag(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    let mut chars = v.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some(':') => out.push(';'),
                Some('s') => out.push(' '),
                Some('r') => out.push('\r'),
                Some('n') => out.push('\n'),
                Some(other) => out.push(other),
                None => {}
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Build a protocol line. The last parameter is made a trailing parameter when needed.
pub fn build(command: &str, params: &[&str]) -> String {
    let mut s = command.to_string();
    for (i, p) in params.iter().enumerate() {
        s.push(' ');
        if i + 1 == params.len() && (p.is_empty() || p.contains(' ') || p.starts_with(':')) {
            s.push(':');
        }
        s.push_str(p);
    }
    s
}

/// RFC 1459 case mapping, used for comparing nicks and channel names.
pub fn irc_lower(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' => c.to_ascii_lowercase(),
            '[' => '{',
            ']' => '}',
            '\\' => '|',
            '~' => '^',
            _ => c,
        })
        .collect()
}

pub fn irc_eq(a: &str, b: &str) -> bool {
    irc_lower(a) == irc_lower(b)
}

pub fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// Text style produced by mIRC formatting control codes.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct Style {
    pub bold: bool,
    pub italic: bool,
    pub underline: bool,
    pub strike: bool,
    pub mono: bool,
    pub reverse: bool,
    pub fg: Option<u8>,
    pub bg: Option<u8>,
}

fn read_color(chars: &mut std::iter::Peekable<std::str::Chars>) -> Option<u8> {
    let mut v: Option<u8> = None;
    for _ in 0..2 {
        match chars.peek() {
            Some(c) if c.is_ascii_digit() => {
                let d = c.to_digit(10).unwrap() as u8;
                v = Some(v.unwrap_or(0) * 10 + d);
                chars.next();
            }
            _ => break,
        }
    }
    v
}

fn color_value(c: u8) -> Option<u8> {
    // 0-15 are the classic palette; 99 means "default"; 16-98 (extended) are not rendered yet.
    if c < 16 { Some(c) } else { None }
}

/// Split text into styled spans, removing formatting control codes.
pub fn parse_formatting(s: &str) -> Vec<(Style, String)> {
    let mut out: Vec<(Style, String)> = Vec::new();
    let mut st = Style::default();
    let mut cur = String::new();
    let mut chars = s.chars().peekable();
    let flush = |out: &mut Vec<(Style, String)>, cur: &mut String, st: Style| {
        if !cur.is_empty() {
            out.push((st, std::mem::take(cur)));
        }
    };
    while let Some(c) = chars.next() {
        match c {
            '\x02' | '\x1d' | '\x1f' | '\x1e' | '\x11' | '\x16' | '\x0f' => {
                flush(&mut out, &mut cur, st);
                match c {
                    '\x02' => st.bold = !st.bold,
                    '\x1d' => st.italic = !st.italic,
                    '\x1f' => st.underline = !st.underline,
                    '\x1e' => st.strike = !st.strike,
                    '\x11' => st.mono = !st.mono,
                    '\x16' => st.reverse = !st.reverse,
                    _ => st = Style::default(),
                }
            }
            '\x03' => {
                flush(&mut out, &mut cur, st);
                match read_color(&mut chars) {
                    Some(fg) => {
                        st.fg = color_value(fg);
                        let mut look = chars.clone();
                        if look.next() == Some(',') && look.peek().is_some_and(|c| c.is_ascii_digit()) {
                            chars.next();
                            st.bg = read_color(&mut chars).and_then(color_value);
                        }
                    }
                    None => {
                        st.fg = None;
                        st.bg = None;
                    }
                }
            }
            '\x04' => {
                // Hex colour: consume and ignore.
                flush(&mut out, &mut cur, st);
                let mut n = 0;
                while n < 6 && chars.peek().is_some_and(|c| c.is_ascii_hexdigit()) {
                    chars.next();
                    n += 1;
                }
                let mut look = chars.clone();
                if n > 0 && look.next() == Some(',') && look.peek().is_some_and(|c| c.is_ascii_hexdigit()) {
                    chars.next();
                    let mut m = 0;
                    while m < 6 && chars.peek().is_some_and(|c| c.is_ascii_hexdigit()) {
                        chars.next();
                        m += 1;
                    }
                }
            }
            c if (c as u32) < 0x20 && c != '\t' => {}
            c => cur.push(c),
        }
    }
    flush(&mut out, &mut cur, st);
    out
}

/// Remove all formatting codes.
pub fn strip_formatting(s: &str) -> String {
    parse_formatting(s).into_iter().map(|(_, t)| t).collect()
}

/// The web URL in `text` that covers character index `pos`, ready to open. Only `http://`,
/// `https://` and `www.` are recognized, so text in a message can't start other URL handlers.
/// A URL without a scheme (`www.example.org`) gets `https://`. Punctuation after a URL, such
/// as a sentence's full stop or the closing bracket of `(http://example.org)`, is left out.
pub fn url_at(text: &str, pos: usize) -> Option<String> {
    const PREFIXES: [&str; 3] = ["https://", "http://", "www."];
    let chars: Vec<char> = text.chars().collect();
    let lower: Vec<char> = chars.iter().map(char::to_ascii_lowercase).collect();
    let mut i = 0;
    while i < chars.len() && i <= pos {
        let boundary = i == 0 || !chars[i - 1].is_alphanumeric();
        let prefix = PREFIXES
            .iter()
            .find(|p| lower[i..].iter().copied().take(p.len()).eq(p.chars()));
        let (true, Some(prefix)) = (boundary, prefix) else {
            i += 1;
            continue;
        };
        let stop = |c: &char| c.is_whitespace() || c.is_control() || matches!(c, '<' | '>' | '"');
        let mut end = i + chars[i..].iter().position(stop).unwrap_or(chars.len() - i);
        let url_end = end;
        while end > i + prefix.len() {
            let c = chars[end - 1];
            let open = match c {
                ')' => Some('('),
                ']' => Some('['),
                '}' => Some('{'),
                _ => None,
            };
            let unmatched = open.is_some_and(|o| {
                let url = &chars[i..end];
                url.iter().filter(|x| **x == c).count() > url.iter().filter(|x| **x == o).count()
            });
            if !unmatched && !matches!(c, '.' | ',' | ';' | ':' | '!' | '?' | '\'' | '*' | '_') {
                break;
            }
            end -= 1;
        }
        if end > i + prefix.len() && pos < end {
            let url: String = chars[i..end].iter().collect();
            return Some(if *prefix == "www." {
                format!("https://{url}")
            } else {
                url
            });
        }
        i = url_end.max(i + 1);
    }
    None
}

/// Case-insensitive whole-word search for `word` in `text` (used for highlights).
pub fn contains_word(text: &str, word: &str) -> bool {
    if word.is_empty() {
        return false;
    }
    let t = irc_lower(&strip_formatting(text));
    let w = irc_lower(word);
    let is_word_char = |c: char| c.is_alphanumeric() || "-_[]{}\\|^`".contains(c);
    let mut start = 0;
    while let Some(pos) = t[start..].find(&w) {
        let i = start + pos;
        let before = t[..i].chars().next_back();
        let after = t[i + w.len()..].chars().next();
        if !before.is_some_and(is_word_char) && !after.is_some_and(is_word_char) {
            return true;
        }
        start = i + w.len().max(1);
        while !t.is_char_boundary(start) {
            start += 1;
        }
    }
    false
}

/// "1d 2h 3m 4s" style duration.
pub fn fmt_duration(mut secs: u64) -> String {
    let d = secs / 86400;
    secs %= 86400;
    let h = secs / 3600;
    secs %= 3600;
    let m = secs / 60;
    let s = secs % 60;
    let mut out = String::new();
    for (v, u) in [(d, "d"), (h, "h"), (m, "m")] {
        if v > 0 || !out.is_empty() {
            out.push_str(&format!("{v}{u} "));
        }
    }
    out.push_str(&format!("{s}s"));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_at_finds_urls() {
        let t = "see https://example.org/a?b=1#c now";
        assert_eq!(url_at(t, 4).as_deref(), Some("https://example.org/a?b=1#c"));
        assert_eq!(url_at(t, 30).as_deref(), Some("https://example.org/a?b=1#c"));
        assert_eq!(url_at(t, 3), None);
        assert_eq!(url_at(t, 31), None);
        assert_eq!(url_at("HTTP://Example.org", 0).as_deref(), Some("HTTP://Example.org"));
        assert_eq!(
            url_at("go www.example.org", 5).as_deref(),
            Some("https://www.example.org")
        );
    }

    #[test]
    fn url_at_finds_the_url_under_the_position() {
        let t = "http://a.example http://b.example";
        assert_eq!(url_at(t, 3).as_deref(), Some("http://a.example"));
        assert_eq!(url_at(t, 20).as_deref(), Some("http://b.example"));
        assert_eq!(url_at(t, 16), None);
    }

    #[test]
    fn url_at_leaves_out_surrounding_punctuation() {
        assert_eq!(url_at("at http://a.example.", 5).as_deref(), Some("http://a.example"));
        assert_eq!(url_at("(http://a.example/b)", 5).as_deref(), Some("http://a.example/b"));
        assert_eq!(url_at("<http://a.example>", 5).as_deref(), Some("http://a.example"));
        assert_eq!(
            url_at("http://a.example/x_(y)", 5).as_deref(),
            Some("http://a.example/x_(y)")
        );
        assert_eq!(url_at("http://a.example,", 16), None);
    }

    #[test]
    fn url_at_rejects_other_text() {
        assert_eq!(url_at("file:///etc/passwd", 3), None);
        assert_eq!(url_at("javascript:alert(1)", 3), None);
        assert_eq!(url_at("xhttp://a.example", 3), None);
        assert_eq!(url_at("nothttp://a.example", 6), None);
        assert_eq!(url_at("http://", 3), None);
        assert_eq!(url_at("www.", 1), None);
        assert_eq!(url_at("", 0), None);
    }

    #[test]
    fn url_at_counts_characters_not_bytes() {
        let t = "é€ http://a.example/é";
        assert_eq!(url_at(t, 3).as_deref(), Some("http://a.example/é"));
        assert_eq!(url_at(t, 1), None);
    }

    #[test]
    fn parse_basic() {
        let m = Message::parse(":bob!b@host PRIVMSG #chan :hello there").unwrap();
        assert_eq!(m.nick(), "bob");
        assert_eq!(m.userhost(), "b@host");
        assert_eq!(m.command, "PRIVMSG");
        assert_eq!(m.params, vec!["#chan", "hello there"]);
    }

    #[test]
    fn parse_tags_and_no_prefix() {
        let m = Message::parse("@time=2020-01-01T00:00:00Z;x=a\\sb PING :tok").unwrap();
        assert_eq!(m.tags[1], ("x".into(), "a b".into()));
        assert_eq!(m.prefix, None);
        assert_eq!(m.params, vec!["tok"]);
    }

    #[test]
    fn build_line() {
        assert_eq!(build("PRIVMSG", &["#c", "hi there"]), "PRIVMSG #c :hi there");
        assert_eq!(build("JOIN", &["#c"]), "JOIN #c");
        assert_eq!(build("PART", &["#c", ""]), "PART #c :");
    }

    #[test]
    fn b64() {
        assert_eq!(base64(b"user\0user\0pass"), "dXNlcgB1c2VyAHBhc3M=");
        assert_eq!(base64(b"ab"), "YWI=");
    }

    #[test]
    fn formatting() {
        let s = parse_formatting("a\x02b\x02\x034,12c\x03d");
        assert_eq!(s.len(), 4);
        assert!(s[1].0.bold);
        assert_eq!(s[2].0.fg, Some(4));
        assert_eq!(s[2].0.bg, Some(12));
        assert_eq!(s[3].0.fg, None);
        assert_eq!(strip_formatting("\x0304,1x\x0f"), "x");
        // A comma not followed by a digit is literal text.
        assert_eq!(strip_formatting("\x034,hi"), ",hi");
    }

    #[test]
    fn words() {
        assert!(contains_word("hey Bob, sup", "bob"));
        assert!(!contains_word("bobby", "bob"));
        assert!(contains_word("x (bob)", "bob"));
        assert!(!contains_word("x [bob]", "bob"), "brackets are nick characters");
    }
}
