//! A reader for the subset of YAML that a cloudflared `config.yml` uses. It
//! gives a [`serde_json::Value`], which serde then reads into a typed value.
//!
//! The subset:
//!
//! * block mappings (`key: value`) and block sequences (`- item`), nested by
//!   indentation with spaces;
//! * a sequence item that starts a mapping (`- hostname: x`);
//! * plain, single-quoted and double-quoted scalars, on one line;
//! * `true`, `false`, `null`, `~`, integers and decimal numbers;
//! * comments (`#` at the start of a line, or after a space), a `---` line;
//! * the empty flow collections `[]` and `{}`.
//!
//! The reader refuses each other part of YAML with the line number: tabs in
//! the indentation, anchors and aliases (`&`, `*`), tags (`!`), block scalars
//! (`|`, `>`), flow collections that are not empty, and duplicate keys. It does
//! not guess.

use anyhow::{bail, Result};
use serde_json::{Map, Number, Value};

#[derive(Debug)]
struct Line<'a> {
    /// The line number, from 1.
    number: usize,
    /// The column of the first character of `text`.
    indent: usize,
    text: &'a str,
}

/// Read `text` as YAML of the subset above.
pub fn parse(text: &str) -> Result<Value> {
    let mut lines = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let number = i + 1;
        let body = strip_comment(raw, number)?;
        let content = body.trim_end();
        let trimmed = content.trim_start();
        if trimmed.is_empty() {
            continue;
        }
        let lead = &content[..content.len() - trimmed.len()];
        if lead.contains('\t') {
            bail!("line {number}: a tab in the indentation (use spaces)");
        }
        if lead.is_empty() && (trimmed == "---" || trimmed == "...") {
            continue;
        }
        lines.push(Line {
            number,
            indent: lead.len(),
            text: trimmed,
        });
    }
    if lines.is_empty() {
        return Ok(Value::Null);
    }
    let mut pos = 0;
    let indent = lines[0].indent;
    let value = node(&lines, &mut pos, indent)?;
    if let Some(line) = lines.get(pos) {
        bail!("line {}: unexpected indentation", line.number);
    }
    Ok(value)
}

/// Remove a comment: `#` at the start, or after a space, outside quotes.
fn strip_comment(line: &str, number: usize) -> Result<&str> {
    let mut quote: Option<char> = None;
    let mut prev = ' ';
    let mut chars = line.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        match quote {
            Some('"') if c == '\\' => {
                chars.next();
            }
            Some(q) if c == q => {
                if q == '\'' && chars.peek().map(|(_, n)| *n) == Some('\'') {
                    chars.next();
                } else {
                    quote = None;
                }
            }
            Some(_) => {}
            None if c == '#' && prev.is_whitespace() => return Ok(&line[..i]),
            None if (c == '"' || c == '\'') && starts_scalar(&line[..i]) => quote = Some(c),
            None => {}
        }
        prev = c;
    }
    if quote.is_some() {
        bail!("line {number}: a quoted scalar has no end on its line");
    }
    Ok(line)
}

/// A quote opens a quoted scalar only at the start of a key or a value.
fn starts_scalar(before: &str) -> bool {
    let before = before.trim_end();
    before.is_empty() || before.ends_with(':') || before.ends_with('-')
}

/// Read the node whose lines start at `indent`.
fn node(lines: &[Line], pos: &mut usize, indent: usize) -> Result<Value> {
    let line = &lines[*pos];
    if is_item(line.text) {
        sequence(lines, pos, indent)
    } else if split_key(line.text, line.number)?.is_some() {
        mapping(lines, pos, indent, None)
    } else {
        *pos += 1;
        let value = scalar(line.text, line.number)?;
        if let Some(next) = lines.get(*pos) {
            if next.indent > indent {
                bail!("line {}: a scalar has no children", next.number);
            }
        }
        Ok(value)
    }
}

fn is_item(text: &str) -> bool {
    text == "-" || text.starts_with("- ")
}

fn sequence(lines: &[Line], pos: &mut usize, indent: usize) -> Result<Value> {
    let mut items = Vec::new();
    while let Some(line) = lines.get(*pos) {
        if line.indent < indent {
            break;
        }
        if line.indent > indent {
            bail!("line {}: unexpected indentation", line.number);
        }
        if !is_item(line.text) {
            break;
        }
        let rest = line.text[1..].trim_start();
        if rest.is_empty() {
            *pos += 1;
            items.push(child(lines, pos, indent)?);
            continue;
        }
        // The column of `rest`: a mapping in the item continues there.
        let column = line.indent + (line.text.len() - rest.len());
        if is_item(rest) {
            bail!("line {}: a nested sequence on one line", line.number);
        }
        if let Some((key, value)) = split_key(rest, line.number)? {
            items.push(mapping(
                lines,
                pos,
                column,
                Some((key, value, line.number)),
            )?);
        } else {
            *pos += 1;
            items.push(scalar(rest, line.number)?);
        }
    }
    Ok(Value::Array(items))
}

/// The value of a key or an item with nothing after it: the lines that are
/// more indented, else null.
fn child(lines: &[Line], pos: &mut usize, indent: usize) -> Result<Value> {
    match lines.get(*pos) {
        Some(next) if next.indent > indent => node(lines, pos, next.indent),
        _ => Ok(Value::Null),
    }
}

/// Read a mapping at `indent`. `first` is the first entry when it is on the
/// line of a sequence item.
fn mapping(
    lines: &[Line],
    pos: &mut usize,
    indent: usize,
    first: Option<(String, &str, usize)>,
) -> Result<Value> {
    let mut map = Map::new();
    let mut pending = first;
    loop {
        let (key, value, number) = match pending.take() {
            Some(entry) => entry,
            None => {
                let Some(line) = lines.get(*pos) else { break };
                if line.indent < indent {
                    break;
                }
                if line.indent > indent {
                    bail!("line {}: unexpected indentation", line.number);
                }
                match split_key(line.text, line.number)? {
                    Some((key, value)) => (key, value, line.number),
                    None if is_item(line.text) => break,
                    None => bail!("line {}: expected `key: value`", line.number),
                }
            }
        };
        *pos += 1;
        let value = if value.is_empty() {
            match lines.get(*pos) {
                Some(next) if next.indent > indent => node(lines, pos, next.indent)?,
                // A sequence may have the indentation of its key.
                Some(next) if next.indent == indent && is_item(next.text) => {
                    sequence(lines, pos, indent)?
                }
                _ => Value::Null,
            }
        } else {
            let v = scalar(value, number)?;
            if let Some(next) = lines.get(*pos) {
                if next.indent > indent {
                    bail!("line {}: a scalar has no children", next.number);
                }
            }
            v
        };
        if map.insert(key.clone(), value).is_some() {
            bail!("line {number}: the key {key:?} is given two times");
        }
    }
    Ok(Value::Object(map))
}

/// Split `key: value` (or `key:`). The key may be quoted.
fn split_key(text: &str, number: usize) -> Result<Option<(String, &str)>> {
    if text.starts_with('"') || text.starts_with('\'') {
        let end = quoted_end(text, number)?;
        let rest = &text[end..];
        let Some(after) = rest.strip_prefix(':') else {
            return Ok(None);
        };
        if !(after.is_empty() || after.starts_with(' ')) {
            return Ok(None);
        }
        let Value::String(key) = scalar(&text[..end], number)? else {
            unreachable!("a quoted scalar is a string")
        };
        return Ok(Some((key, after.trim_start())));
    }
    let bytes = text.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        if *b == b':' && (i + 1 == bytes.len() || bytes[i + 1] == b' ') {
            let key = text[..i].trim_end();
            if key.is_empty() {
                bail!("line {number}: an empty key");
            }
            check_plain(key, number)?;
            return Ok(Some((key.to_string(), text[i + 1..].trim_start())));
        }
    }
    Ok(None)
}

/// The index after the closing quote of the quoted scalar at the start.
fn quoted_end(text: &str, number: usize) -> Result<usize> {
    let quote = text.as_bytes()[0];
    let bytes = text.as_bytes();
    let mut i = 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' if quote == b'"' => i += 2,
            b'\'' if quote == b'\'' && bytes.get(i + 1) == Some(&b'\'') => i += 2,
            b if b == quote => return Ok(i + 1),
            _ => i += 1,
        }
    }
    bail!("line {number}: a quoted scalar has no end on its line")
}

fn check_plain(text: &str, number: usize) -> Result<()> {
    match text.chars().next() {
        Some('&') | Some('*') => bail!("line {number}: anchors and aliases are not supported"),
        Some('!') => bail!("line {number}: tags are not supported"),
        Some('|') | Some('>') => bail!("line {number}: block scalars are not supported"),
        Some('{') | Some('[') if text != "{}" && text != "[]" => {
            bail!("line {number}: flow collections are not supported (only [] and {{}})")
        }
        Some('@') | Some('`') | Some('%') => {
            bail!(
                "line {number}: a plain scalar cannot start with {:?}",
                &text[..1]
            )
        }
        _ => Ok(()),
    }
}

/// Read one scalar.
fn scalar(text: &str, number: usize) -> Result<Value> {
    let text = text.trim();
    if text.starts_with('"') || text.starts_with('\'') {
        let end = quoted_end(text, number)?;
        if end != text.len() {
            bail!("line {number}: text after a quoted scalar");
        }
        let inner = &text[1..end - 1];
        return Ok(Value::String(if text.starts_with('\'') {
            inner.replace("''", "'")
        } else {
            unescape(inner, number)?
        }));
    }
    check_plain(text, number)?;
    Ok(match text {
        "{}" => Value::Object(Map::new()),
        "[]" => Value::Array(Vec::new()),
        "~" | "null" | "Null" | "NULL" => Value::Null,
        "true" | "True" | "TRUE" => Value::Bool(true),
        "false" | "False" | "FALSE" => Value::Bool(false),
        _ => number_of(text)
            .map(Value::Number)
            .unwrap_or_else(|| Value::String(text.to_string())),
    })
}

fn number_of(text: &str) -> Option<Number> {
    let digits = text.strip_prefix(['-', '+']).unwrap_or(text);
    if digits.is_empty() || !digits.chars().next()?.is_ascii_digit() {
        return None;
    }
    if digits.chars().all(|c| c.is_ascii_digit()) {
        if let Ok(n) = text.parse::<i64>() {
            return Some(n.into());
        }
        return text.parse::<u64>().ok().map(Into::into);
    }
    let valid = digits
        .chars()
        .all(|c| c.is_ascii_digit() || matches!(c, '.' | 'e' | 'E' | '-' | '+'));
    if valid && digits.matches('.').count() <= 1 {
        return text.parse::<f64>().ok().and_then(Number::from_f64);
    }
    None
}

fn unescape(inner: &str, number: usize) -> Result<String> {
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('"') => out.push('"'),
            Some('\\') => out.push('\\'),
            Some('/') => out.push('/'),
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('0') => out.push('\0'),
            Some(' ') => out.push(' '),
            Some('u') => {
                let hex: String = chars.by_ref().take(4).collect();
                let code = u32::from_str_radix(&hex, 16)
                    .ok()
                    .filter(|_| hex.len() == 4)
                    .and_then(char::from_u32);
                match code {
                    Some(c) => out.push(c),
                    None => bail!("line {number}: a bad \\u escape"),
                }
            }
            other => bail!(
                "line {number}: the escape \\{} is not supported",
                other.unwrap_or(' ')
            ),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_cloudflared_config() {
        let text = r#"
# A named tunnel.
tunnel: 6ff42ae2-765d-4adf-8112-31c55c1551ef
credentials-file: /root/.cloudflared/6ff42ae2.json   # the credentials
protocol: http2
ha-connections: 4
warp-routing:
  enabled: true
ingress:
  - hostname: app.example.com
    service: http://localhost:8000
    originRequest:
      noTLSVerify: true
      connectTimeout: 30s
  - hostname: "*.example.com"
    path: ^/api/.*$
    service: 'http://localhost:9000'
  - service: http_status:404
"#;
        let value = parse(text).unwrap();
        assert_eq!(
            value,
            json!({
                "tunnel": "6ff42ae2-765d-4adf-8112-31c55c1551ef",
                "credentials-file": "/root/.cloudflared/6ff42ae2.json",
                "protocol": "http2",
                "ha-connections": 4,
                "warp-routing": {"enabled": true},
                "ingress": [
                    {
                        "hostname": "app.example.com",
                        "service": "http://localhost:8000",
                        "originRequest": {"noTLSVerify": true, "connectTimeout": "30s"}
                    },
                    {"hostname": "*.example.com", "path": "^/api/.*$", "service": "http://localhost:9000"},
                    {"service": "http_status:404"}
                ]
            })
        );
    }

    #[test]
    fn a_sequence_at_the_indentation_of_its_key() {
        let value = parse("ingress:\n- service: a\n- service: b\nprotocol: quic\n").unwrap();
        assert_eq!(
            value,
            json!({"ingress": [{"service": "a"}, {"service": "b"}], "protocol": "quic"})
        );
    }

    #[test]
    fn scalars() {
        let value = parse(
            "a: ~\nb:\nc: -3\nd: 1.5\ne: 'it''s'\nf: \"x\\ty \\u00e9\"\ng: a#b\nh: []\ni: {}\nj: 10.0.0.1\n",
        )
        .unwrap();
        assert_eq!(
            value,
            json!({"a": null, "b": null, "c": -3, "d": 1.5, "e": "it's", "f": "x\ty \u{e9}",
                   "g": "a#b", "h": [], "i": {}, "j": "10.0.0.1"})
        );
        assert_eq!(
            parse("- a\n- 2\n-\n  - b\n").unwrap(),
            json!(["a", 2, ["b"]])
        );
        assert_eq!(parse("# only a comment\n").unwrap(), Value::Null);
        assert_eq!(parse("---\nk: v\n").unwrap(), json!({"k": "v"}));
    }

    #[test]
    fn the_unsupported_parts_are_refused_with_the_line() {
        for (text, want) in [
            ("a: 1\na: 2\n", "line 2: the key \"a\" is given two times"),
            ("a:\n\tb: 1\n", "line 2: a tab"),
            ("a: &x 1\n", "line 1: anchors"),
            ("a: *x\n", "line 1: anchors"),
            ("a: !!str 1\n", "line 1: tags"),
            ("a: |\n  text\n", "line 1: block scalars"),
            ("a: [1, 2]\n", "line 1: flow collections"),
            ("a: \"open\n", "line 1: a quoted scalar has no end"),
            ("a: 1\n  b: 2\n", "line 2: a scalar has no children"),
            ("a:\n  b: 1\n c: 2\n", "line 3: unexpected indentation"),
            ("a: 1\njust text\n", "line 2: expected `key: value`"),
        ] {
            let err = parse(text).unwrap_err().to_string();
            assert!(err.starts_with(want), "{text:?}: {err}");
        }
    }
}
