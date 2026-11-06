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
//!
//! A document that nests deeper than [`MAX_DEPTH`] levels is an error: the
//! reader is recursive, and a deep file must not overflow the stack.

use anyhow::{bail, Result};
use serde_json::{Map, Number, Value};

/// The most levels of nested mappings and sequences (issue 231). A
/// cloudflared config uses about 5.
pub const MAX_DEPTH: usize = 64;

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
    // Issue 172: a UTF-8 BOM (an editor of Windows) is not part of a key.
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
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
    let value = node(&lines, &mut pos, indent, 0)?;
    if let Some(line) = lines.get(pos) {
        bail!("line {}: unexpected indentation", line.number);
    }
    Ok(value)
}

/// The line (from 1) of each item of the top-level list `key` (T-080):
/// the errors of a config file name the line of an ingress rule. Empty
/// when there is no such list.
pub fn item_lines(text: &str, key: &str) -> Vec<usize> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let head = format!("{key}:");
    let mut inside = false;
    let mut item_indent = None;
    let mut out = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let body = strip_comment(raw, i + 1).unwrap_or(raw).trim_end();
        let trimmed = body.trim_start();
        if trimmed.is_empty() {
            continue;
        }
        let indent = body.len() - trimmed.len();
        // A list can be at the indent of its key.
        if indent == 0 && !(inside && is_item(trimmed) && item_indent.is_none_or(|n| n == 0)) {
            inside = trimmed == head || trimmed.starts_with(&format!("{head} "));
            item_indent = None;
            continue;
        }
        if inside && is_item(trimmed) && item_indent.is_none_or(|n| n == indent) {
            item_indent = Some(indent);
            out.push(i + 1);
        }
    }
    out
}

/// `what N`, and `(line L)` when `lines` has the line of item `index`.
pub fn numbered(what: &str, index: usize, lines: &[usize]) -> String {
    match lines.get(index) {
        Some(line) => format!("{what} {} (line {line})", index + 1),
        None => format!("{what} {}", index + 1),
    }
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

/// An error when a collection at `depth` is deeper than [`MAX_DEPTH`].
fn check_depth(depth: usize, number: usize) -> Result<()> {
    if depth > MAX_DEPTH {
        bail!("line {number}: the document nests deeper than {MAX_DEPTH} levels");
    }
    Ok(())
}

/// Read the node whose lines start at `indent`. `depth` is the number of
/// collections that hold it.
fn node(lines: &[Line], pos: &mut usize, indent: usize, depth: usize) -> Result<Value> {
    let line = &lines[*pos];
    if is_item(line.text) {
        sequence(lines, pos, indent, depth)
    } else if split_key(line.text, line.number)?.is_some() {
        mapping(lines, pos, indent, None, depth)
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

fn sequence(lines: &[Line], pos: &mut usize, indent: usize, depth: usize) -> Result<Value> {
    check_depth(depth, lines[*pos].number)?;
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
            items.push(child(lines, pos, indent, depth + 1)?);
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
                depth + 1,
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
fn child(lines: &[Line], pos: &mut usize, indent: usize, depth: usize) -> Result<Value> {
    match lines.get(*pos) {
        Some(next) if next.indent > indent => node(lines, pos, next.indent, depth),
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
    depth: usize,
) -> Result<Value> {
    check_depth(
        depth,
        first
            .as_ref()
            .map(|f| f.2)
            .unwrap_or_else(|| lines[*pos].number),
    )?;
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
                Some(next) if next.indent > indent => node(lines, pos, next.indent, depth + 1)?,
                // A sequence may have the indentation of its key.
                Some(next) if next.indent == indent && is_item(next.text) => {
                    sequence(lines, pos, indent, depth + 1)?
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

    /// `levels` nested mappings, one key on each line.
    fn nested(levels: usize) -> String {
        (0..levels)
            .map(|i| format!("{}a:\n", " ".repeat(i)))
            .collect()
    }

    // Issue 231: a deep document is an error with a line number, not a
    // stack overflow.
    #[test]
    fn a_deep_document_is_an_error() {
        assert!(parse(&nested(MAX_DEPTH)).is_ok());
        let err = format!("{:#}", parse(&nested(200)).unwrap_err());
        assert!(err.contains("nests deeper than 64 levels"), "{err}");
        assert!(err.contains("line 66"), "{err}");
        let items: String = (0..200)
            .map(|i| format!("{}- a:\n", "  ".repeat(i)))
            .collect();
        let err = format!("{:#}", parse(&items).unwrap_err());
        assert!(err.contains("nests deeper"), "{err}");
        // A small stack: the cap stops the recursion before an overflow.
        let text = nested(3000);
        let result = std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(move || parse(&text).map(|_| ()).map_err(|e| e.to_string()))
            .unwrap()
            .join()
            .unwrap();
        assert!(result.unwrap_err().contains("nests deeper"));
    }

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

    #[test]
    fn the_line_of_each_ingress_rule() {
        let text = "tunnel: x\n# a comment\ningress:\n  - hostname: a\n    service: http://a\n\n  - service: http_status:404\nwarp-routing: {}\n";
        assert_eq!(item_lines(text, "ingress"), [4, 7]);
        let flat = "ingress:\n- service: a\n- service: b\n";
        assert_eq!(item_lines(flat, "ingress"), [2, 3]);
        assert!(item_lines(text, "none").is_empty());
    }

    /// T-080: an error of a config file names the line of its rule.
    #[test]
    fn a_config_error_names_its_line() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("config.yml");
        let text = "tunnel: t\ningress:\n  - hostname: a.example\n    service: http://127.0.0.1:1\n  # the second rule\n  - hostnam: b.example\n    service: http://127.0.0.1:2\n  - service: http_status:404\n";
        std::fs::write(&file, text).unwrap();
        let err = format!("{:#}", crate::config::load_file(&file).unwrap_err());
        assert!(err.contains("ingress rule 2 (line 6)"), "{err}");
        assert_eq!(numbered("ingress rule", 4, &[1, 2]), "ingress rule 5");
    }
}
