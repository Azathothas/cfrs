//! Proxy configuration beyond the variables (issue 83): HTTP Digest
//! authentication (RFC 7616) for a `CONNECT`, and the proxy of the tool
//! configs of the host when no proxy variable is set.

use std::path::{Path, PathBuf};

/// MD5 (RFC 1321), for the `MD5` algorithm of Digest. Digest needs it; it
/// is not a check of integrity here.
pub fn md5(input: &[u8]) -> [u8; 16] {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    let k: Vec<u32> = (0..64)
        .map(|i| ((i as f64 + 1.0).sin().abs() * 4_294_967_296.0) as u32)
        .collect();
    let (mut a0, mut b0, mut c0, mut d0) =
        (0x67452301u32, 0xefcdab89u32, 0x98badcfeu32, 0x10325476u32);
    let mut msg = input.to_vec();
    let bits = (input.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bits.to_le_bytes());
    for chunk in msg.chunks(64) {
        let m: Vec<u32> = chunk
            .chunks(4)
            .map(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]))
            .collect();
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let f = f.wrapping_add(a).wrapping_add(k[i]).wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f.rotate_left(S[i]));
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }
    let mut out = [0u8; 16];
    for (i, v) in [a0, b0, c0, d0].iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A Digest challenge of a `Proxy-Authenticate` header.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Challenge {
    pub realm: String,
    pub nonce: String,
    pub opaque: Option<String>,
    /// `MD5`, `MD5-sess`, `SHA-256` or `SHA-256-sess`.
    pub algorithm: String,
    /// `auth` when the server offers it.
    pub qop: Option<String>,
}

/// Parse the parameters of `Digest a="b", c=d, ...`. `None` when the text
/// is not a Digest challenge, or names an algorithm that cfrs does not
/// have.
pub fn parse_challenge(value: &str) -> Option<Challenge> {
    let rest = value.trim().strip_prefix("Digest")?.trim_start();
    let mut c = Challenge {
        algorithm: "MD5".into(),
        ..Challenge::default()
    };
    let mut chars = rest.chars().peekable();
    loop {
        while matches!(chars.peek(), Some(' ' | ',' | '\t')) {
            chars.next();
        }
        let key: String = chars.by_ref().take_while(|ch| *ch != '=').collect();
        if key.is_empty() {
            break;
        }
        let value: String = if chars.peek() == Some(&'"') {
            chars.next();
            let mut v = String::new();
            while let Some(ch) = chars.next() {
                match ch {
                    '\\' => {
                        if let Some(n) = chars.next() {
                            v.push(n);
                        }
                    }
                    '"' => break,
                    other => v.push(other),
                }
            }
            v
        } else {
            chars
                .by_ref()
                .take_while(|ch| *ch != ',')
                .collect::<String>()
                .trim()
                .to_string()
        };
        match key.trim().to_ascii_lowercase().as_str() {
            "realm" => c.realm = value,
            "nonce" => c.nonce = value,
            "opaque" => c.opaque = Some(value),
            "algorithm" => c.algorithm = value,
            "qop" if value.split(',').any(|q| q.trim() == "auth") => {
                c.qop = Some("auth".into());
            }
            _ => {}
        }
    }
    let known = ["MD5", "MD5-sess", "SHA-256", "SHA-256-sess"];
    (!c.nonce.is_empty() && known.iter().any(|a| a.eq_ignore_ascii_case(&c.algorithm))).then_some(c)
}

fn digest_hex(algorithm: &str, text: &str) -> String {
    if algorithm.to_ascii_uppercase().starts_with("SHA-256") {
        hex(ring::digest::digest(&ring::digest::SHA256, text.as_bytes()).as_ref())
    } else {
        hex(&md5(text.as_bytes()))
    }
}

/// The value of `Proxy-Authorization` for `challenge`, `method` and
/// `uri`, with the client nonce `cnonce` and the count `nc` (1 for the
/// first request).
pub fn authorization(
    challenge: &Challenge,
    user: &str,
    password: &str,
    method: &str,
    uri: &str,
    cnonce: &str,
    nc: u32,
) -> String {
    let alg = &challenge.algorithm;
    let mut ha1 = digest_hex(alg, &format!("{user}:{}:{password}", challenge.realm));
    if alg.to_ascii_lowercase().ends_with("-sess") {
        ha1 = digest_hex(alg, &format!("{ha1}:{}:{cnonce}", challenge.nonce));
    }
    let ha2 = digest_hex(alg, &format!("{method}:{uri}"));
    let nc = format!("{nc:08x}");
    let response = match &challenge.qop {
        Some(qop) => digest_hex(
            alg,
            &format!("{ha1}:{}:{nc}:{cnonce}:{qop}:{ha2}", challenge.nonce),
        ),
        None => digest_hex(alg, &format!("{ha1}:{}:{ha2}", challenge.nonce)),
    };
    let quote = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
    let mut out = format!(
        "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", algorithm={}, response=\"{response}\"",
        quote(user),
        quote(&challenge.realm),
        quote(&challenge.nonce),
        quote(uri),
        challenge.algorithm,
    );
    if let Some(qop) = &challenge.qop {
        out.push_str(&format!(
            ", qop={qop}, nc={nc}, cnonce=\"{}\"",
            quote(cnonce)
        ));
    }
    if let Some(opaque) = &challenge.opaque {
        out.push_str(&format!(", opaque=\"{}\"", quote(opaque)));
    }
    out
}

/// A client nonce: 16 random bytes in hex.
pub fn cnonce() -> String {
    let mut bytes = [0u8; 16];
    let _ = ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut bytes);
    hex(&bytes)
}

// ── the proxy of the tool configs ──────────────────────────────────────────

/// `http.proxy` (or `https.proxy`) of a git config file.
pub fn proxy_in_gitconfig(text: &str) -> Option<String> {
    let mut section = String::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with(';') || line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            section = line
                .trim_matches(|c| c == '[' || c == ']')
                .trim()
                .to_ascii_lowercase();
            continue;
        }
        if section == "http" || section == "https" {
            if let Some((k, v)) = line.split_once('=') {
                if k.trim().eq_ignore_ascii_case("proxy") {
                    let v = v.trim().trim_matches('"').to_string();
                    if !v.is_empty() {
                        return Some(v);
                    }
                }
            }
        }
    }
    None
}

/// `https-proxy` (else `proxy`) of an npmrc file.
pub fn proxy_in_npmrc(text: &str) -> Option<String> {
    let mut plain = None;
    for line in text.lines() {
        let line = line.trim();
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let v = v.trim().trim_matches('"').to_string();
        if v.is_empty() || v == "null" {
            continue;
        }
        match k.trim().to_ascii_lowercase().as_str() {
            "https-proxy" => return Some(v),
            "proxy" => plain = Some(v),
            _ => {}
        }
    }
    plain
}

/// `proxy` of a pip config file (any section).
pub fn proxy_in_pipconf(text: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let (k, v) = line.trim().split_once(['=', ':'])?;
        (k.trim().eq_ignore_ascii_case("proxy") && !v.trim().is_empty())
            .then(|| v.trim().to_string())
    })
}

/// A proxy variable of `/etc/environment`.
pub fn proxy_in_environment_file(text: &str) -> Option<String> {
    for key in [
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
        "HTTP_PROXY",
        "http_proxy",
    ] {
        for line in text.lines() {
            let line = line.trim().trim_start_matches("export ").trim();
            if let Some(v) = line.strip_prefix(key).and_then(|r| r.strip_prefix('=')) {
                let v = v.trim().trim_matches('"').trim_matches('\'').to_string();
                if !v.is_empty() {
                    return Some(v);
                }
            }
        }
    }
    None
}

/// A parser of a tool config: the proxy that it names.
type Parser = fn(&str) -> Option<String>;

/// The files that the detection reads, in order, with their parser.
fn sources(home: Option<&Path>) -> Vec<(PathBuf, Parser)> {
    let mut out: Vec<(PathBuf, Parser)> = Vec::new();
    if let Some(home) = home {
        out.push((home.join(".gitconfig"), proxy_in_gitconfig));
        out.push((home.join(".config/git/config"), proxy_in_gitconfig));
        out.push((home.join(".npmrc"), proxy_in_npmrc));
        out.push((home.join(".config/pip/pip.conf"), proxy_in_pipconf));
        out.push((home.join(".pip/pip.conf"), proxy_in_pipconf));
    }
    out.push((PathBuf::from("/etc/gitconfig"), proxy_in_gitconfig));
    out.push((PathBuf::from("/etc/pip.conf"), proxy_in_pipconf));
    out.push((PathBuf::from("/etc/environment"), proxy_in_environment_file));
    out
}

/// The proxy of the first tool config that names one, and the file.
pub fn detect(home: Option<&Path>) -> Option<(String, PathBuf)> {
    sources(home).into_iter().find_map(|(path, parse)| {
        let text = std::fs::read_to_string(&path).ok()?;
        parse(&text).map(|proxy| (proxy, path))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_vectors_of_rfc_1321() {
        assert_eq!(hex(&md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(hex(&md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            hex(&md5(
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"
            )),
            "57edf4a22be3c955ac49da2e2107b67a"
        );
    }

    /// The example of RFC 7616 section 3.9.1.
    #[test]
    fn digest_responses_of_rfc_7616() {
        let header = "Digest realm=\"http-auth@example.org\", qop=\"auth, auth-int\", algorithm=SHA-256, nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\", opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\"";
        let challenge = parse_challenge(header).unwrap();
        assert_eq!(challenge.qop.as_deref(), Some("auth"));
        let value = authorization(
            &challenge,
            "Mufasa",
            "Circle of Life",
            "GET",
            "/dir/index.html",
            "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ",
            1,
        );
        assert!(
            value.contains(
                "response=\"753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1\""
            ),
            "{value}"
        );
        let md5_challenge = Challenge {
            algorithm: "MD5".into(),
            ..challenge
        };
        let value = authorization(
            &md5_challenge,
            "Mufasa",
            "Circle of Life",
            "GET",
            "/dir/index.html",
            "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ",
            1,
        );
        assert!(
            value.contains("response=\"8ca523f5e9506fed4657c9700eebdbec\""),
            "{value}"
        );
        assert!(value.contains("nc=00000001"));
        assert!(value.contains("opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\""));
    }

    #[test]
    fn challenges_that_cfrs_does_not_take() {
        assert!(parse_challenge("Basic realm=\"x\"").is_none());
        assert!(
            parse_challenge("Digest realm=\"x\", nonce=\"n\", algorithm=SHA-512-256").is_none()
        );
        assert!(parse_challenge("Digest realm=\"x\"").is_none(), "no nonce");
    }

    #[test]
    fn the_proxy_of_each_tool_config() {
        let git = "[core]\n\tbare = false\n[http]\n\tproxy = http://gw:3128\n";
        assert_eq!(proxy_in_gitconfig(git).as_deref(), Some("http://gw:3128"));
        assert_eq!(proxy_in_gitconfig("[user]\nproxy = x\n"), None);
        let npm = "registry=https://r\nproxy=http://a:1\nhttps-proxy=http://b:2\n";
        assert_eq!(proxy_in_npmrc(npm).as_deref(), Some("http://b:2"));
        assert_eq!(proxy_in_npmrc("proxy=null\n"), None);
        let pip = "[global]\nproxy = http://p:8080\n";
        assert_eq!(proxy_in_pipconf(pip).as_deref(), Some("http://p:8080"));
        let env = "PATH=/usr/bin\nhttps_proxy=\"http://e:3128\"\n";
        assert_eq!(
            proxy_in_environment_file(env).as_deref(),
            Some("http://e:3128")
        );
    }

    #[test]
    fn detection_takes_the_first_file() {
        let home = tempfile::tempdir().unwrap();
        std::fs::write(home.path().join(".npmrc"), "proxy=http://npm:1\n").unwrap();
        let (proxy, path) = detect(Some(home.path())).unwrap();
        assert_eq!(proxy, "http://npm:1");
        assert!(path.ends_with(".npmrc"));
        std::fs::write(
            home.path().join(".gitconfig"),
            "[http]\nproxy = http://git:2\n",
        )
        .unwrap();
        assert_eq!(detect(Some(home.path())).unwrap().0, "http://git:2");
    }
}
