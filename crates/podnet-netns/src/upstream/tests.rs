#[test]
fn a_udp_header_with_a_name() {
    let d = super::wrap_udp_name(b"x", "stun.example", 19302);
    assert_eq!(&d[..5], &[0, 0, 0, 3, 12]);
    assert_eq!(&d[5..17], b"stun.example");
    assert_eq!(&d[17..], &[0x4b, 0x66, b'x']);
}

/// Issue 102: http://unix:/path is an HTTP CONNECT proxy on a unix
/// socket; another scheme over a unix socket names the forms that work.
#[test]
fn an_http_proxy_on_a_unix_socket_parses() {
    let p = super::Proxy::parse("http://unix:/tmp/w.sock").unwrap();
    assert_eq!(p.kind, super::ProxyKind::Http);
    assert_eq!(p.unix_path.as_deref(), Some("/tmp/w.sock"));
    let p = super::Proxy::parse("socks5://unix:///tmp/w.sock").unwrap();
    assert_eq!(p.unix_path.as_deref(), Some("/tmp/w.sock"));
    for bad in ["https://unix:/x", "ftp://unix:/x"] {
        let err = super::Proxy::parse(bad).unwrap_err().to_string();
        assert!(err.contains("over a unix socket"), "{bad}: {err}");
    }
    assert!(super::Proxy::parse("http://unix:").is_err());
}

/// The HTTP CONNECT of a unix-socket proxy reaches the proxy.
#[tokio::test]
async fn an_http_connect_goes_over_the_unix_socket() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("p.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let server = tokio::spawn(async move {
        let (mut c, _) = listener.accept().await.unwrap();
        let mut head = Vec::new();
        let mut b = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            c.read_exact(&mut b).await.unwrap();
            head.push(b[0]);
        }
        c.write_all(b"HTTP/1.1 200 OK\r\n\r\nhi").await.unwrap();
        String::from_utf8(head).unwrap()
    });
    let proxy = super::Proxy::parse(&format!("http://unix:{}", path.display())).unwrap();
    let mut up = super::connect_upstream_async(&[proxy], "example.com:80")
        .await
        .unwrap();
    let mut two = [0u8; 2];
    up.read_exact(&mut two).await.unwrap();
    assert_eq!(&two, b"hi");
    assert!(server
        .await
        .unwrap()
        .starts_with("CONNECT example.com:80 HTTP/1.1"));
}

#[test]
fn domain_rules_match_a_name_or_a_suffix() {
    use super::domain_matches;
    assert!(domain_matches("example.com", "EXAMPLE.com"));
    assert!(!domain_matches("example.com", "a.example.com"));
    assert!(domain_matches(".example.com", "example.com"));
    assert!(domain_matches(".example.com", "a.b.example.com."));
    assert!(!domain_matches(".example.com", "badexample.com"));
    assert!(!domain_matches(".example.com", "example.com.evil"));
}

#[test]
fn direct_is_an_upstream() {
    let direct = super::Proxy::parse("direct").unwrap();
    assert_eq!(direct.kind, super::ProxyKind::Direct);
    assert_eq!(direct.endpoint(), "direct");
    let rules = vec![super::Rule {
        matcher: super::RuleMatch::parse("cidr:10.0.0.0/8").unwrap(),
        proxy: direct,
    }];
    let default = vec![super::Proxy::parse("socks5://127.0.0.1:1080").unwrap()];
    assert_eq!(
        super::select_chain(&rules, &default, "10.1.2.3:22")[0].endpoint(),
        "direct"
    );
    assert_eq!(
        super::select_chain(&rules, &default, "1.1.1.1:443")[0].endpoint(),
        "127.0.0.1:1080"
    );
}

use super::*;

/// Issue 304: a SOCKS5 user or password over 255 bytes is refused at
/// parse time; RFC 1929 cannot carry it. HTTP Basic has no such limit.
#[test]
fn a_socks5_credential_over_255_bytes_is_refused() {
    let long = "u".repeat(300);
    let err = Proxy::parse(&format!("socks5://{long}:p@127.0.0.1:1080")).unwrap_err();
    assert!(
        format!("{err:#}").contains("the user of the SOCKS5 proxy is longer than 255 bytes"),
        "{err:#}"
    );
    let err = Proxy::parse(&format!("socks5://u:{long}@127.0.0.1:1080")).unwrap_err();
    assert!(
        format!("{err:#}").contains("the password of the SOCKS5 proxy is longer than 255"),
        "{err:#}"
    );
    assert!(Proxy::parse(&format!("http://{long}:p@127.0.0.1:8080")).is_ok());
    let edge = "u".repeat(255);
    assert!(Proxy::parse(&format!("socks5://{edge}:{edge}@127.0.0.1:1080")).is_ok());
}

/// Issue 304: a user and a password of 255 bytes go in whole frames
/// with the right length bytes. A Proxy with a longer user, made with
/// no parse, sends no auth frame, and a target name over 255 bytes is
/// refused.
#[tokio::test]
async fn the_socks5_auth_frame_keeps_its_length() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let edge = "u".repeat(255);
    let pass = "p".repeat(255);
    let proxy = Proxy::parse(&format!("socks5://{edge}:{pass}@127.0.0.1:1080")).unwrap();
    let (client, mut server) = tokio::io::duplex(4096);
    let script = tokio::spawn(async move {
        let mut greeting = [0u8; 4];
        server.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 2, 0, 2]);
        server.write_all(&[5, 2]).await.unwrap();
        let mut head = [0u8; 2];
        server.read_exact(&mut head).await.unwrap();
        assert_eq!(head, [1, 255]);
        let mut user = vec![0u8; head[1] as usize];
        server.read_exact(&mut user).await.unwrap();
        let mut len = [0u8; 1];
        server.read_exact(&mut len).await.unwrap();
        let mut pass = vec![0u8; len[0] as usize];
        server.read_exact(&mut pass).await.unwrap();
        server.write_all(&[1, 0]).await.unwrap();
        (user, pass)
    });
    socks5_handshake(client, &proxy).await.unwrap();
    let (user, got_pass) = script.await.unwrap();
    assert_eq!(user, edge.as_bytes());
    assert_eq!(got_pass, pass.as_bytes());

    let mut long = proxy.clone();
    long.user = Some("u".repeat(300));
    let (client, mut server) = tokio::io::duplex(4096);
    // Before the fix, the handshake waits for an answer to a broken frame.
    let err = tokio::time::timeout(Duration::from_secs(5), socks5_handshake(client, &long))
        .await
        .expect("the handshake must fail at once")
        .unwrap_err();
    assert!(format!("{err:#}").contains("longer than 255"), "{err:#}");
    let mut sent = Vec::new();
    server.read_to_end(&mut sent).await.unwrap();
    assert!(sent.is_empty(), "{sent:?}");

    let plain = Proxy::parse("socks5://127.0.0.1:1080").unwrap();
    let (client, _server) = tokio::io::duplex(4096);
    let target = format!("{}.example:80", "n".repeat(300));
    let err = socks5_connect(client, &plain, &target).await.unwrap_err();
    assert!(format!("{err:#}").contains("longer than 255"), "{err:#}");
}

#[test]
fn parses_proxy_specs() {
    let p = Proxy::parse("socks5://user:pass@127.0.0.1:1080").unwrap();
    assert_eq!(p.kind, ProxyKind::Socks5);
    assert_eq!(p.host, "127.0.0.1");
    assert_eq!(p.port, 1080);
    assert_eq!(p.user.as_deref(), Some("user"));
    assert_eq!(p.pass.as_deref(), Some("pass"));

    let p = Proxy::parse("http://proxy.example:8080").unwrap();
    assert_eq!(p.kind, ProxyKind::Http);
    assert_eq!(p.endpoint(), "proxy.example:8080");

    assert!(Proxy::parse("ftp://x:1").is_err());
    assert!(Proxy::parse("socks5://nohostport").is_err());
}
#[test]
fn base64_matches_known_vectors() {
    assert_eq!(base64(b""), "");
    assert_eq!(base64(b"f"), "Zg==");
    assert_eq!(base64(b"fo"), "Zm8=");
    assert_eq!(base64(b"foo"), "Zm9v");
    assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    assert_eq!(base64(b"user:pass"), "dXNlcjpwYXNz");
}
#[test]
fn split_target_keeps_ipv4_and_names() {
    assert_eq!(
        split_target("example.com:443").unwrap(),
        ("example.com".into(), 443)
    );
    assert_eq!(split_target("1.2.3.4:80").unwrap(), ("1.2.3.4".into(), 80));
    assert!(split_target("noport").is_err());
}
#[test]
fn rules_select_chains_in_order() {
    let default = vec![Proxy::parse("socks5://127.0.0.1:1").unwrap()];
    let rules = vec![
        Rule {
            matcher: RuleMatch::Domain("example.com".into()),
            proxy: Proxy::parse("socks5://127.0.0.1:2").unwrap(),
        },
        Rule {
            matcher: RuleMatch::parse("cidr:10.0.0.0/8").unwrap(),
            proxy: Proxy::parse("socks5://127.0.0.1:3").unwrap(),
        },
        Rule {
            matcher: RuleMatch::parse("cidr:2001:db8::/32").unwrap(),
            proxy: Proxy::parse("socks5://127.0.0.1:4").unwrap(),
        },
    ];
    assert_eq!(select_chain(&rules, &default, "example.com:80")[0].port, 2);
    assert_eq!(select_chain(&rules, &default, "EXAMPLE.com:443")[0].port, 2);
    assert_eq!(select_chain(&rules, &default, "10.1.2.3:443")[0].port, 3);
    assert_eq!(select_chain(&rules, &default, "1.2.3.4:80")[0].port, 1);
    assert_eq!(
        select_chain(&rules, &default, "[2001:db8::7]:80")[0].port,
        4
    );
    assert_eq!(
        select_chain(&rules, &default, "[2001:db9::7]:80")[0].port,
        1
    );
}
#[test]
fn ipv6_prefixes_and_prefix_files() {
    let net = Net::parse("2001:db8::/32").unwrap();
    assert!(net.contains("2001:db8:ffff::1".parse().unwrap()));
    assert!(!net.contains("2001:db9::1".parse().unwrap()));
    assert!(!net.contains("10.0.0.1".parse().unwrap()));
    let v4 = Net::parse("10.0.0.0/8").unwrap();
    assert!(v4.contains("::ffff:10.1.2.3".parse().unwrap()));
    assert_eq!(Net::parse("1.2.3.4").unwrap().prefix, 32);
    assert!(Net::parse("::/0").unwrap().contains("::1".parse().unwrap()));
    assert!(Net::parse("10.0.0.0/33").is_err());
    assert!(Net::parse("2001:db8::/129").is_err());
    assert!(Net::parse("nothing/8").is_err());
    let dir = std::env::temp_dir().join(format!("podnet-netns-nets-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("nets.txt");
    std::fs::write(&file, "# a country\n10.0.0.0/8\n\n2001:db8::/32  # v6\n").unwrap();
    let rule = RuleMatch::parse(&format!("cidr:@{}", file.display())).unwrap();
    assert!(rule.matches("10.9.9.9", Some("10.9.9.9".parse().unwrap())));
    assert!(rule.matches("2001:db8::1", Some("2001:db8::1".parse().unwrap())));
    assert!(!rule.matches("1.1.1.1", Some("1.1.1.1".parse().unwrap())));
    std::fs::write(&file, "10.0.0.0/8\nbad\n").unwrap();
    let err = format!("{:#}", load_nets(&file).unwrap_err());
    assert!(err.contains(":2"), "{err}");
    std::fs::write(&file, "# none\n").unwrap();
    assert!(load_nets(&file).is_err());
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(RuleMatch::parse("domain:.Example.com")
        .unwrap()
        .matches("a.example.com", None));
    assert!(RuleMatch::parse("country:NL").is_err());
    assert!(RuleMatch::parse("domain:").is_err());
}
#[test]
fn cidr_matching_is_exact() {
    let net: Ipv4Addr = "10.0.0.0".parse().unwrap();
    assert!(in_cidr("10.0.0.1".parse().unwrap(), net, 8));
    assert!(in_cidr("10.255.255.255".parse().unwrap(), net, 8));
    assert!(!in_cidr("11.0.0.1".parse().unwrap(), net, 8));
    assert!(in_cidr("1.2.3.4".parse().unwrap(), net, 0));
}
