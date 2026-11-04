//! The rules of `cfrs warp proxy` (issues 132 and 136): for each
//! destination, go through the tunnel, connect directly from the host, or
//! refuse.
//!
//! A rule is `KIND:VALUE=ACTION`. KIND is `domain` (`NAME`, or `.NAME` for
//! the name and each name under it) or `cidr` (`ADDR/PREFIX`, IPv4 or IPv6,
//! or `@FILE` with one prefix on each line). ACTION is `tunnel`, `direct`
//! or `reject`. The first rule that matches wins. A name matches the
//! domain rules first; when no domain rule matches and there is a cidr
//! rule, the name is resolved through the tunnel and its addresses match
//! the cidr rules. With no match, the built-in rules apply (a loopback, a
//! link-local or an unspecified address, and `localhost`, are refused:
//! WARP does not reach them), then the default action.
//!
//! The rules apply to TCP (SOCKS5 CONNECT, HTTP CONNECT and http:// URLs).
//! UDP goes through the tunnel.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use anyhow::{bail, Context as _, Result};
use pod_netns::socks::ProxyHost;
use pod_netns::RuleMatch;

/// What to do with a destination.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Through the WARP session (the default).
    Tunnel,
    /// From the host, with no proxy and the resolver of the host.
    Direct,
    /// Refuse: SOCKS5 reply 0x02, HTTP 403.
    Reject,
}

impl Action {
    pub fn parse(text: &str) -> Result<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "tunnel" | "warp" => Ok(Action::Tunnel),
            "direct" => Ok(Action::Direct),
            "reject" | "block" => Ok(Action::Reject),
            other => bail!("{other:?} is not an action (tunnel, direct, reject)"),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Action::Tunnel => "tunnel",
            Action::Direct => "direct",
            Action::Reject => "reject",
        }
    }
}

/// One rule.
#[derive(Clone, Debug)]
pub struct Rule {
    pub matcher: RuleMatch,
    pub action: Action,
    /// The text of the rule, for the log.
    pub spec: String,
}

impl Rule {
    /// `KIND:VALUE=ACTION`.
    pub fn parse(spec: &str) -> Result<Self> {
        let spec = spec.trim();
        let (matcher, action) = spec
            .rsplit_once('=')
            .with_context(|| format!("{spec:?}: give KIND:VALUE=ACTION"))?;
        Ok(Rule {
            matcher: RuleMatch::parse(matcher).with_context(|| format!("{spec:?}"))?,
            action: Action::parse(action).with_context(|| format!("{spec:?}"))?,
            spec: spec.to_string(),
        })
    }
}

/// The rules of the proxy, in order, and the default action.
#[derive(Clone, Debug)]
pub struct Table {
    pub rules: Vec<Rule>,
    pub default: Action,
}

impl Default for Table {
    fn default() -> Self {
        Table {
            rules: Vec::new(),
            default: Action::Tunnel,
        }
    }
}

impl Table {
    /// The rules of the flags, then the rules of `file`.
    pub fn build(specs: &[String], file: Option<&Path>, default: Action) -> Result<Self> {
        let mut rules = specs
            .iter()
            .flat_map(|s| s.split(','))
            .filter(|s| !s.trim().is_empty())
            .map(Rule::parse)
            .collect::<Result<Vec<_>>>()?;
        if let Some(file) = file {
            rules.extend(load_file(file)?);
        }
        Ok(Table { rules, default })
    }

    /// True when a rule matches addresses.
    pub fn has_cidr(&self) -> bool {
        self.rules
            .iter()
            .any(|r| matches!(r.matcher, RuleMatch::Cidr(_)))
    }

    /// The action of a name, by the domain rules; `None` when no domain
    /// rule matches and the name is not a built-in one.
    pub fn for_name(&self, name: &str) -> Option<Action> {
        let rule = self.rules.iter().find(|r| r.matcher.matches(name, None));
        if let Some(rule) = rule {
            return Some(rule.action);
        }
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        (name == "localhost" || name.ends_with(".localhost")).then_some(Action::Reject)
    }

    /// The action of an address: the rules, the built-in rules, the
    /// default.
    pub fn for_ip(&self, ip: IpAddr) -> Action {
        self.rule_for_ip(ip)
            .or_else(|| builtin(ip))
            .unwrap_or(self.default)
    }

    fn rule_for_ip(&self, ip: IpAddr) -> Option<Action> {
        let text = ip.to_string();
        self.rules
            .iter()
            .find(|r| r.matcher.matches(&text, Some(ip)))
            .map(|r| r.action)
    }

    /// The action of the addresses of a name: the first address that a
    /// rule or a built-in rule matches, else the default.
    pub fn for_addresses(&self, addresses: &[IpAddr]) -> Action {
        addresses
            .iter()
            .find_map(|ip| self.rule_for_ip(*ip).or_else(|| builtin(*ip)))
            .unwrap_or(self.default)
    }
}

/// The built-in rules: WARP does not reach these addresses.
fn builtin(ip: IpAddr) -> Option<Action> {
    let ip = ip.to_canonical();
    let local = ip.is_loopback()
        || ip.is_unspecified()
        || match ip {
            IpAddr::V4(v4) => v4.is_link_local(),
            IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
        };
    local.then_some(Action::Reject)
}

/// The rules of a file: one `KIND:VALUE=ACTION` on each line; a blank
/// line, and the text after `#`, are ignored. A bad line is an error with
/// its number.
pub fn load_file(path: &Path) -> Result<Vec<Rule>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading the rules file {}", path.display()))?;
    let mut rules = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        rules.push(Rule::parse(line).with_context(|| format!("{}:{}", path.display(), n + 1))?);
    }
    Ok(rules)
}

/// The error of a destination that a rule refuses.
#[derive(Debug)]
pub struct Refused(pub String);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} is not allowed by the rules of the proxy", self.0)
    }
}

impl std::error::Error for Refused {}

/// True when `err` is a refusal of a rule.
pub fn is_refused(err: &anyhow::Error) -> bool {
    err.downcast_ref::<Refused>().is_some()
}

/// The counters of the decisions of this process.
pub struct Counters {
    pub tunnel: AtomicU64,
    pub direct: AtomicU64,
    pub reject: AtomicU64,
    pub reloads: AtomicU64,
}

pub static COUNTERS: Counters = Counters {
    tunnel: AtomicU64::new(0),
    direct: AtomicU64::new(0),
    reject: AtomicU64::new(0),
    reloads: AtomicU64::new(0),
};

impl Counters {
    pub fn count(&self, action: Action) {
        match action {
            Action::Tunnel => &self.tunnel,
            Action::Direct => &self.direct,
            Action::Reject => &self.reject,
        }
        .fetch_add(1, Relaxed);
    }
}

static TABLE: RwLock<Option<Arc<Table>>> = RwLock::new(None);

/// Set the rules of the proxies of this process.
pub fn set(table: Table) {
    *TABLE.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(table));
}

/// The rules of now (no rule, default tunnel, when none were set).
pub fn current() -> Arc<Table> {
    TABLE
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .unwrap_or_default()
}

/// How often the rules file is checked for a change.
pub const RELOAD_EVERY: Duration = Duration::from_secs(2);

/// Read `file` again when it changes, and use its rules with the rules of
/// the flags. A file with an error is reported, and the rules before stay.
pub fn watch(specs: Vec<String>, file: PathBuf, default: Action) {
    let stamp = |p: &Path| -> Option<(SystemTime, u64)> {
        let meta = std::fs::metadata(p).ok()?;
        Some((meta.modified().ok()?, meta.len()))
    };
    tokio::spawn(async move {
        let mut last = stamp(&file);
        let mut tick = tokio::time::interval(RELOAD_EVERY);
        tick.tick().await;
        loop {
            tick.tick().await;
            let now = stamp(&file);
            if now == last {
                continue;
            }
            last = now;
            match Table::build(&specs, Some(&file), default) {
                Ok(table) => {
                    tracing::info!(file = %file.display(), rules = table.rules.len(), "the rules of the WARP proxy are read again");
                    COUNTERS.reloads.fetch_add(1, Relaxed);
                    set(table);
                }
                Err(err) => tracing::warn!(
                    error = %format!("{err:#}"),
                    "the rules file has an error; the rules before stay"
                ),
            }
        }
    });
}

/// The action for `host`, with the addresses that were resolved through
/// the tunnel to decide it (to use them for the tunnel).
pub async fn decide(
    stack: &super::ip::WarpStack,
    table: &Table,
    host: &ProxyHost,
) -> Result<(Action, Option<Vec<IpAddr>>)> {
    Ok(match host {
        ProxyHost::Ip(ip) => (table.for_ip(*ip), None),
        ProxyHost::Domain(name) => match table.for_name(name) {
            Some(action) => (action, None),
            None if table.has_cidr() => {
                let addresses = super::proxy::resolve_all(stack, name).await?;
                (table.for_addresses(&addresses), Some(addresses))
            }
            None => (table.default, None),
        },
    })
}

/// The action for `host` with no lookup of a name (`warp proxy --l4`: no
/// resolver in the tunnel, #140). A name that only an address rule can
/// decide gets the default.
pub fn decide_static(table: &Table, host: &ProxyHost) -> Action {
    match host {
        ProxyHost::Ip(ip) => table.for_ip(*ip),
        ProxyHost::Domain(name) => table.for_name(name).unwrap_or(table.default),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #140: the rules of --l4 need no lookup; the built-in rules apply.
    #[test]
    fn a_static_decision_uses_the_rules_and_the_builtins() {
        let t = table(
            &["domain:ads.example=reject", "cidr:10.0.0.0/8=direct"],
            Action::Tunnel,
        );
        let name = |n: &str| ProxyHost::Domain(n.into());
        let ip = |i: &str| ProxyHost::Ip(i.parse().unwrap());
        assert_eq!(decide_static(&t, &name("ads.example")), Action::Reject);
        assert_eq!(decide_static(&t, &name("localhost")), Action::Reject);
        assert_eq!(decide_static(&t, &ip("10.1.2.3")), Action::Direct);
        assert_eq!(decide_static(&t, &ip("127.0.0.1")), Action::Reject);
        assert_eq!(decide_static(&t, &name("example.org")), Action::Tunnel);
        let direct = table(&[], Action::Direct);
        assert_eq!(decide_static(&direct, &name("example.org")), Action::Direct);
    }

    fn table(specs: &[&str], default: Action) -> Table {
        let specs: Vec<String> = specs.iter().map(|s| s.to_string()).collect();
        Table::build(&specs, None, default).unwrap()
    }

    #[test]
    fn the_first_rule_that_matches_wins() {
        let t = table(
            &[
                "domain:.corp.example=direct",
                "domain:ads.example=reject",
                "cidr:10.0.0.0/8=direct,cidr:2001:db8::/32=reject",
            ],
            Action::Tunnel,
        );
        assert_eq!(t.rules.len(), 4);
        assert_eq!(t.for_name("git.corp.example"), Some(Action::Direct));
        assert_eq!(t.for_name("ADS.example."), Some(Action::Reject));
        assert_eq!(t.for_name("example.com"), None);
        assert!(t.has_cidr());
        assert_eq!(t.for_ip("10.1.2.3".parse().unwrap()), Action::Direct);
        assert_eq!(t.for_ip("2001:db8::1".parse().unwrap()), Action::Reject);
        assert_eq!(t.for_ip("1.1.1.1".parse().unwrap()), Action::Tunnel);
        assert_eq!(
            t.for_addresses(&["1.1.1.1".parse().unwrap(), "10.0.0.9".parse().unwrap()]),
            Action::Direct
        );
        assert_eq!(
            table(&[], Action::Reject).for_ip("1.1.1.1".parse().unwrap()),
            Action::Reject
        );
    }

    #[test]
    fn the_built_in_rules_refuse_the_host() {
        let t = table(&[], Action::Tunnel);
        for ip in [
            "127.0.0.1",
            "::1",
            "0.0.0.0",
            "169.254.169.254",
            "fe80::1",
            "::ffff:127.0.0.1",
        ] {
            assert_eq!(t.for_ip(ip.parse().unwrap()), Action::Reject, "{ip}");
        }
        assert_eq!(t.for_name("localhost"), Some(Action::Reject));
        assert_eq!(t.for_name("a.localhost"), Some(Action::Reject));
        assert_eq!(t.for_ip("192.168.1.1".parse().unwrap()), Action::Tunnel);
        // A rule of the operator comes first.
        let t = table(
            &["cidr:127.0.0.0/8=direct", "domain:localhost=direct"],
            Action::Tunnel,
        );
        assert_eq!(t.for_ip("127.0.0.1".parse().unwrap()), Action::Direct);
        assert_eq!(t.for_name("localhost"), Some(Action::Direct));
    }

    #[test]
    fn bad_rules_and_the_rules_file() {
        for bad in [
            "domain:a",
            "domain:a=maybe",
            "country:NL=direct",
            "cidr:10.0.0.0/40=direct",
            "=direct",
        ] {
            assert!(Rule::parse(bad).is_err(), "{bad}");
        }
        let dir = std::env::temp_dir().join(format!("cfrs-rules-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("rules");
        std::fs::write(
            &file,
            "# rules\ndomain:.lan=direct\n\ncidr:192.0.2.0/24=reject # test\n",
        )
        .unwrap();
        let t = Table::build(
            &["domain:x.example=reject".into()],
            Some(&file),
            Action::Tunnel,
        )
        .unwrap();
        assert_eq!(t.rules.len(), 3);
        assert_eq!(t.rules[0].spec, "domain:x.example=reject");
        assert_eq!(t.for_name("nas.lan"), Some(Action::Direct));
        std::fs::write(&file, "domain:.lan=direct\ndomain:.lan=sideways\n").unwrap();
        let err = format!(
            "{:#}",
            Table::build(&[], Some(&file), Action::Tunnel).unwrap_err()
        );
        assert!(err.contains("rules:2"), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
        let err = anyhow::Error::new(Refused("a:1".into())).context("dial");
        assert!(is_refused(&err));
        assert!(!is_refused(&anyhow::anyhow!("refused")));
    }
}
