//! Ingress: which local service answers which public hostname/path.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Result};
use serde::Deserialize;

use crate::share::ShareConfig;

/// A raw stream target for [`Service::Forward`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ForwardTarget {
    /// A TCP `host:port`.
    Tcp(String),
    /// A filesystem socket.
    Unix(PathBuf),
}

impl ForwardTarget {
    /// Parse `tcp://host:port`, `tcp:host:port`, `unix:/path` or `unix:///path`.
    pub fn parse(value: &str) -> Result<Self> {
        let value = value.trim();
        for prefix in ["tcp://", "tcp:"] {
            if let Some(rest) = value.strip_prefix(prefix) {
                if rest.is_empty() {
                    bail!("forward target has no address: {value:?}");
                }
                return Ok(Self::Tcp(rest.to_string()));
            }
        }
        for prefix in ["unix://", "unix:"] {
            if let Some(rest) = value.strip_prefix(prefix) {
                if rest.is_empty() {
                    bail!("forward target has no path: {value:?}");
                }
                return Ok(Self::Unix(PathBuf::from(rest)));
            }
        }
        if value.contains(':') {
            return Ok(Self::Tcp(value.to_string()));
        }
        bail!("forward target must be tcp://host:port or unix:/path, got {value:?}")
    }

    pub fn describe(&self) -> String {
        match self {
            Self::Tcp(addr) => format!("tcp://{addr}"),
            Self::Unix(path) => format!("unix:{}", path.display()),
        }
    }
}

/// A local service the tunnel can expose.
#[derive(Clone, Debug)]
pub enum Service {
    /// An `http://` or `https://` origin.
    Http(String),
    /// An HTTP origin on a filesystem socket.
    Unix(PathBuf),
    /// An HTTPS origin on a filesystem socket.
    UnixTls(PathBuf),
    /// A raw TCP origin (`tcp://host:port`), proxied byte-for-byte.
    Tcp(String),
    /// A WebSocket endpoint that bridges each connection to a raw stream.
    Forward(ForwardTarget),
    /// cloudflared's built-in hello world.
    HelloWorld,
    /// A fixed status code.
    Status(u16),
    /// A directory served from disk (a `spa` fallback serves index.html).
    Static { root: PathBuf, spa: bool },
    /// Prometheus metrics for this tunnel.
    Metrics,
    /// Upload / download / proxy session (the quickbridge feature set).
    Share(ShareConfig),
}

impl Service {
    /// Parse a cloudflared-style service string, plus podnet extensions
    /// (`static:` / `spa:` / `metrics`).
    pub fn parse(value: &str) -> Result<Self> {
        let value = value.trim();
        if value.starts_with("http://") || value.starts_with("https://") {
            // A URL with no host (http://) is refused here, before any
            // network work (issue 57), not at the first dial.
            crate::net::parse_http_url(value)
                .map_err(|e| anyhow::anyhow!("the origin {value}: {e}"))?;
            return Ok(Service::Http(value.to_string()));
        }
        if let Some(rest) = value.strip_prefix("unix+tls:") {
            return Ok(Service::UnixTls(PathBuf::from(rest)));
        }
        if let Some(rest) = value.strip_prefix("unix:") {
            return Ok(Service::Unix(PathBuf::from(rest)));
        }
        if let Some(rest) = value.strip_prefix("tcp://") {
            return Ok(Service::Tcp(rest.to_string()));
        }
        if let Some(rest) = value.strip_prefix("forward:") {
            return Ok(Service::Forward(ForwardTarget::parse(rest)?));
        }
        if let Some(rest) = value.strip_prefix("static:") {
            return Ok(Service::Static {
                root: PathBuf::from(rest),
                spa: false,
            });
        }
        if let Some(rest) = value.strip_prefix("spa:") {
            return Ok(Service::Static {
                root: PathBuf::from(rest),
                spa: true,
            });
        }
        if let Some(rest) = value.strip_prefix("http_status:") {
            let code: u16 = rest
                .parse()
                .map_err(|_| anyhow::anyhow!("bad status {rest}"))?;
            if !(100..=999).contains(&code) {
                bail!("status out of range: {code}");
            }
            return Ok(Service::Status(code));
        }
        match value {
            "hello_world" => Ok(Service::HelloWorld),
            "metrics" => Ok(Service::Metrics),
            other => bail!("unsupported service {other:?}: give http://, https://, unix:, unix+tls:, tcp://, forward:, static:, spa:, http_status:CODE, hello_world or metrics"),
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Service::Http(url) => url.clone(),
            Service::Unix(path) => format!("unix:{}", path.display()),
            Service::UnixTls(path) => format!("unix+tls:{}", path.display()),
            Service::Tcp(addr) => format!("tcp://{addr}"),
            Service::Forward(target) => format!("forward:{}", target.describe()),
            Service::HelloWorld => "hello_world".into(),
            Service::Status(code) => format!("http_status:{code}"),
            Service::Static { root, spa } => {
                format!("{}:{}", if *spa { "spa" } else { "static" }, root.display())
            }
            Service::Metrics => "metrics".into(),
            Service::Share(config) => config.describe(),
        }
    }

    /// Raw-TCP services bypass the HTTP layer entirely.
    pub fn is_tcp(&self) -> bool {
        matches!(self, Service::Tcp(_))
    }
}

/// Per-rule origin tuning, mirroring the useful subset of cloudflared's
/// `originRequest`.
#[derive(Clone, Debug, Default)]
pub struct OriginOptions {
    pub no_tls_verify: bool,
    pub http_host_header: Option<String>,
    pub connect_timeout: Option<Duration>,
    pub tls_timeout: Option<Duration>,
    pub keep_alive_timeout: Option<Duration>,
    pub disable_chunked_encoding: bool,
    /// Drop `Accept-Encoding` before the request reaches the origin. An
    /// uncompressed response cannot be buffered by the edge, which matters for
    /// streaming (SSE over POST, long-poll).
    pub strip_accept_encoding: bool,
}

/// The `path:` of a rule (issue 269). As in cloudflared, it is a regular
/// expression that can match any part of the request path: `/api` also
/// matches `/x/api`, and `^/api/` matches only paths that start with
/// `/api/`. The syntax is that of the `regex` crate, which is close to Go
/// RE2. The query (from `?`) is not part of the path; `%XX` is not decoded.
#[derive(Clone, Debug)]
pub struct PathPattern {
    text: String,
    regex: regex::Regex,
    /// True for [`PathPattern::prefix`]: `text` is literal text.
    prefix: bool,
}

impl PathPattern {
    /// Compile the regular expression `text`.
    pub fn regex(text: &str) -> Result<Self> {
        let regex = regex::Regex::new(text).map_err(|e| {
            // A syntax error has lines that point at the character; the
            // last line names the error.
            let text_of_error = e.to_string();
            let reason = text_of_error
                .lines()
                .last()
                .unwrap_or_default()
                .trim_start_matches("error: ")
                .to_string();
            anyhow::anyhow!("path: {text:?} is not a valid regular expression: {reason}")
        })?;
        Ok(Self {
            text: text.to_string(),
            regex,
            prefix: false,
        })
    }

    /// A pattern that matches each path that starts with `prefix` (no
    /// character of `prefix` is special).
    pub fn prefix(prefix: &str) -> Self {
        let regex = regex::Regex::new(&format!("^{}", regex::escape(prefix)))
            .expect("an escaped prefix is a valid regular expression");
        Self {
            text: prefix.to_string(),
            regex,
            prefix: true,
        }
    }

    /// The text of the pattern, as given.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// True when the pattern matches a part of the path of `path` (the
    /// query is not part of it).
    pub fn is_match(&self, path: &str) -> bool {
        let path = path.split_once('?').map_or(path, |(p, _)| p);
        self.regex.is_match(path)
    }

    /// The one path that the pattern names, for a URL: a prefix, or a
    /// regular expression of literal text with an optional `^` and `$`.
    /// `None` for a regular expression with a special character.
    pub fn literal_path(&self) -> Option<String> {
        if self.prefix {
            return Some(self.text.clone());
        }
        let text = self.text.strip_prefix('^').unwrap_or(&self.text);
        let text = text.strip_suffix('$').unwrap_or(text);
        let mut out = String::new();
        let mut chars = text.chars();
        while let Some(c) = chars.next() {
            match c {
                '\\' => match chars.next() {
                    Some(e) if e.is_ascii_punctuation() => out.push(e),
                    _ => return None,
                },
                '.' | '^' | '$' | '*' | '+' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '|' => {
                    return None
                }
                c => out.push(c),
            }
        }
        Some(out)
    }
}

impl std::fmt::Display for PathPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text)
    }
}

#[derive(Clone, Debug)]
pub struct IngressRule {
    pub hostname: Option<String>,
    pub path: Option<PathPattern>,
    pub service: Service,
    pub origin: OriginOptions,
}

impl IngressRule {
    pub fn catch_all(service: Service) -> Self {
        Self {
            hostname: None,
            path: None,
            service,
            origin: OriginOptions::default(),
        }
    }

    fn matches(&self, hostname: &str, path: &str) -> bool {
        if let Some(pattern) = &self.hostname {
            if !hostname_matches(pattern, hostname) {
                return false;
            }
        }
        if let Some(pattern) = &self.path {
            if !pattern.is_match(path) {
                return false;
            }
        }
        true
    }
}

fn hostname_matches(pattern: &str, hostname: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    let hostname = hostname.to_ascii_lowercase();
    if let Some(suffix) = pattern.strip_prefix("*.") {
        if hostname == suffix {
            return true;
        }
        // A wildcard matches exactly one label, so `a.b.example.com` is not
        // covered by `*.example.com`.
        return match hostname.strip_suffix(suffix) {
            Some(prefix) => match prefix.strip_suffix('.') {
                Some(label) => !label.is_empty() && !label.contains('.'),
                None => false,
            },
            None => false,
        };
    }
    pattern == hostname
}

/// An ordered rule set. The last rule is normally a catch-all.
#[derive(Clone, Debug, Default)]
pub struct Ingress {
    pub rules: Vec<IngressRule>,
    /// Issue 205: each request must give this user and password (HTTP
    /// Basic) before it reaches a rule (`--auth-user`).
    pub auth: Option<crate::proxy_auth::Credentials>,
}

impl Ingress {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a rule for `hostname`. `path` is a literal prefix of the request
    /// path ([`PathPattern::prefix`]); for a regular expression, give
    /// [`PathPattern::regex`] to [`Ingress::rule_with`].
    pub fn rule(
        mut self,
        hostname: impl Into<String>,
        path: Option<&str>,
        service: Service,
    ) -> Self {
        self.rules.push(IngressRule {
            hostname: Some(hostname.into()),
            path: path.map(PathPattern::prefix),
            service,
            origin: OriginOptions::default(),
        });
        self
    }

    pub fn rule_with(mut self, rule: IngressRule) -> Self {
        self.rules.push(rule);
        self
    }

    pub fn catch_all(mut self, service: Service) -> Self {
        self.rules.push(IngressRule::catch_all(service));
        self
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// First matching rule for a request, in declaration order.
    pub fn resolve(&self, hostname: &str, path: &str) -> Option<&IngressRule> {
        self.rules.iter().find(|rule| rule.matches(hostname, path))
    }

    /// Index of the first matching rule.
    pub fn resolve_index(&self, hostname: &str, path: &str) -> Option<usize> {
        self.rules
            .iter()
            .position(|rule| rule.matches(hostname, path))
    }
}

// ── YAML parsing (cloudflared-compatible subset) ─────────────────────────────

/// Issue 241: the keys of a rule are exactly [`crate::config::RULE_KEYS`],
/// so an unknown key is an error here too.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawIngress {
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub service: Option<String>,
    #[serde(default, rename = "originRequest")]
    pub origin_request: RawOriginOptions,
}

#[derive(Deserialize, Default)]
pub(crate) struct RawOriginOptions {
    #[serde(default, rename = "noTLSVerify")]
    pub no_tls_verify: bool,
    #[serde(default, rename = "httpHostHeader")]
    pub http_host_header: Option<String>,
    #[serde(default, rename = "connectTimeout")]
    pub connect_timeout: Option<String>,
    #[serde(default, rename = "tlsTimeout")]
    pub tls_timeout: Option<String>,
    #[serde(default, rename = "keepAliveTimeout")]
    pub keep_alive_timeout: Option<String>,
    #[serde(default, rename = "disableChunkedEncoding")]
    pub disable_chunked_encoding: bool,
    #[serde(default, rename = "stripAcceptEncoding")]
    pub strip_accept_encoding: bool,
}

fn parse_duration(value: &Option<String>) -> Option<Duration> {
    let value = value.as_ref()?;
    humantime(value).ok()
}

/// Minimal `30s` / `1m` / `500ms` parser.
fn humantime(value: &str) -> Result<Duration> {
    let value = value.trim();
    let (number, unit) = value
        .char_indices()
        .find(|(_, c)| !c.is_ascii_digit())
        .map(|(i, _)| value.split_at(i))
        .unwrap_or((value, "s"));
    let number: f64 = number
        .parse()
        .map_err(|_| anyhow::anyhow!("bad duration {value}"))?;
    let multiplier = match unit.trim() {
        "" | "s" => 1.0,
        "ms" => 0.001,
        "m" => 60.0,
        "h" => 3600.0,
        other => bail!("unknown duration unit {other:?}"),
    };
    Ok(Duration::from_secs_f64(number * multiplier))
}

impl RawOriginOptions {
    pub fn into_options(self) -> OriginOptions {
        OriginOptions {
            no_tls_verify: self.no_tls_verify,
            http_host_header: self.http_host_header,
            connect_timeout: parse_duration(&self.connect_timeout),
            tls_timeout: parse_duration(&self.tls_timeout),
            keep_alive_timeout: parse_duration(&self.keep_alive_timeout),
            disable_chunked_encoding: self.disable_chunked_encoding,
            strip_accept_encoding: self.strip_accept_encoding,
        }
    }
}

pub(crate) fn ingress_from_raw(rules: Vec<RawIngress>) -> Result<Ingress> {
    let mut ingress = Ingress::new();
    use anyhow::Context as _;
    for (i, raw) in rules.into_iter().enumerate() {
        let service = raw
            .service
            .as_deref()
            .with_context(|| format!("ingress rule {}: service: is missing", i + 1))
            .and_then(|s| Service::parse(s).with_context(|| format!("ingress rule {}", i + 1)))?;
        let path = raw
            .path
            .as_deref()
            .map(PathPattern::regex)
            .transpose()
            .with_context(|| format!("ingress rule {}", i + 1))?;
        ingress.rules.push(IngressRule {
            hostname: raw.hostname,
            path,
            service,
            origin: raw.origin_request.into_options(),
        });
    }
    Ok(ingress)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_services() {
        assert!(matches!(
            Service::parse("http://127.0.0.1:8080").unwrap(),
            Service::Http(_)
        ));
        assert!(matches!(
            Service::parse("https://x:443").unwrap(),
            Service::Http(_)
        ));
        assert!(matches!(
            Service::parse("unix:/run/x.sock").unwrap(),
            Service::Unix(_)
        ));
        assert!(matches!(
            Service::parse("tcp://db:5432").unwrap(),
            Service::Tcp(_)
        ));
        assert!(matches!(
            Service::parse("http_status:404").unwrap(),
            Service::Status(404)
        ));
        assert!(matches!(
            Service::parse("static:/srv").unwrap(),
            Service::Static { spa: false, .. }
        ));
        assert!(matches!(
            Service::parse("spa:/srv").unwrap(),
            Service::Static { spa: true, .. }
        ));
        assert!(Service::parse("nope://x").is_err());
    }

    #[test]
    fn wildcard_hosts() {
        assert!(hostname_matches("*.example.com", "a.example.com"));
        assert!(hostname_matches("*.example.com", "example.com"));
        assert!(!hostname_matches("*.example.com", "a.b.example.com"));
        assert!(!hostname_matches("*.example.com", "example.org"));
        assert!(hostname_matches("app.example.com", "APP.example.com"));
    }

    #[test]
    fn resolves_first_match() {
        let ingress = Ingress::new()
            .rule("api.example.com", Some("/v1"), Service::HelloWorld)
            .rule("api.example.com", None, Service::Status(404))
            .catch_all(Service::Status(503));
        assert!(matches!(
            ingress.resolve("api.example.com", "/v1/x").unwrap().service,
            Service::HelloWorld
        ));
        assert!(matches!(
            ingress
                .resolve("api.example.com", "/other")
                .unwrap()
                .service,
            Service::Status(404)
        ));
        assert!(matches!(
            ingress.resolve("other.example.com", "/").unwrap().service,
            Service::Status(503)
        ));
    }

    // Issue 269: a path: is a regular expression, unanchored, as in
    // cloudflared. A prefix of the builder has no special character.
    #[test]
    fn a_path_pattern_is_a_regular_expression() {
        let re = PathPattern::regex("^/api/v[0-9]+/").unwrap();
        assert!(re.is_match("/api/v12/x"));
        assert!(!re.is_match("/api/vx/"));
        assert!(!re.is_match("/x/api/v1/"));
        let dot = PathPattern::regex("/a.b").unwrap();
        assert!(dot.is_match("/aXb"));
        assert!(dot.is_match("/x/a.b/y"));
        let end = PathPattern::regex("^/ws$").unwrap();
        assert!(end.is_match("/ws?token=1"));
        assert!(!end.is_match("/ws/x"));
        let err = PathPattern::regex("[").unwrap_err().to_string();
        assert!(err.contains("not a valid regular expression"), "{err}");

        let prefix = PathPattern::prefix("/a.b");
        assert!(prefix.is_match("/a.b/c"));
        assert!(!prefix.is_match("/aXb"));
        assert!(!prefix.is_match("/x/a.b"));
        assert_eq!(prefix.as_str(), "/a.b");

        assert_eq!(prefix.literal_path().as_deref(), Some("/a.b"));
        let literal = PathPattern::regex(r"^/v1\.2/ws$").unwrap();
        assert_eq!(literal.literal_path().as_deref(), Some("/v1.2/ws"));
        assert_eq!(re.literal_path(), None);
        assert_eq!(dot.literal_path(), None);
    }

    #[test]
    fn durations() {
        assert_eq!(humantime("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(humantime("500ms").unwrap(), Duration::from_millis(500));
        assert_eq!(humantime("2m").unwrap(), Duration::from_secs(120));
        assert!(humantime("x").is_err());
    }
}
