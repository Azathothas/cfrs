//! Origin connections: TCP, TLS, unix sockets, and TLS over unix.

use std::path::PathBuf;
use std::sync::{Arc, Once, OnceLock};

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use tokio_rustls::TlsConnector;

use crate::ingress::{OriginOptions, Service};

pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncReadWrite for T {}

pub type BoxedIo = Box<dyn AsyncReadWrite>;

/// Install the ring crypto provider once per process, before the first TLS
/// configuration is made.
/// Make `path` free for a new unix listener (issues 202 and 115, and the
/// rule of podssh): a socket that answers belongs to another process and
/// is refused (exit 69), unless `replace`; a stale socket file is removed;
/// another kind of file is never removed (exit 64).
#[cfg(unix)]
pub fn claim_socket_path(path: &std::path::Path, replace: bool) -> Result<()> {
    use crate::exit::{fault, Fault};
    use std::os::unix::fs::FileTypeExt as _;
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => {
            if !replace && std::os::unix::net::UnixStream::connect(path).is_ok() {
                return Err(fault(
                    Fault::Unavailable,
                    anyhow::anyhow!(
                        "unix:{} is served by another process (cfrs ps; cfrs stop NAME, or --replace where the command has it)",
                        path.display()
                    ),
                ));
            }
            std::fs::remove_file(path)
                .with_context(|| format!("removing the old socket unix:{}", path.display()))?;
            Ok(())
        }
        Ok(_) => Err(fault(
            Fault::Usage,
            anyhow::anyhow!("unix:{} exists and is not a socket", path.display()),
        )),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("unix:{}", path.display())),
    }
}

pub fn init_crypto() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    });
}

/// The addresses of a name of RFC 6761 for this host: `localhost` and
/// `*.localhost` (issue 119: a static build on a host with no /etc/hosts
/// did not resolve `localhost`).
pub fn local_name(host: &str) -> Option<Vec<std::net::IpAddr>> {
    let name = host.trim_end_matches('.').to_ascii_lowercase();
    (name == "localhost" || name.ends_with(".localhost")).then(|| {
        vec![
            std::net::IpAddr::from([127, 0, 0, 1]),
            std::net::IpAddr::from(std::net::Ipv6Addr::LOCALHOST),
        ]
    })
}

/// `HOST:PORT` or `[V6]:PORT`.
fn split_host_port(addr: &str) -> Option<(&str, u16)> {
    let (host, port) = addr.rsplit_once(':')?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    Some((host, port.parse().ok()?))
}

/// Connect to an origin. `localhost` needs no resolver. The error says if
/// the name or the connection failed (issue 119: both were "connecting to
/// HOST:PORT"). An origin name does not go to DNS over HTTPS.
pub async fn connect_origin(host: &str, port: u16) -> Result<TcpStream> {
    let addrs: Vec<std::net::SocketAddr> = match host.parse::<std::net::IpAddr>() {
        Ok(ip) => vec![(ip, port).into()],
        Err(_) => match local_name(host) {
            Some(ips) => ips.into_iter().map(|ip| (ip, port).into()).collect(),
            None => tokio::net::lookup_host((host, port))
                .await
                .map_err(|e| {
                    crate::hop::at(
                        crate::hop::Hop::Dns,
                        anyhow::anyhow!("resolving the origin {host}: {e}"),
                    )
                })?
                .collect(),
        },
    };
    let mut last = None;
    for addr in &addrs {
        match TcpStream::connect(addr).await {
            Ok(tcp) => return Ok(tcp),
            Err(e) => last = Some(anyhow::anyhow!("connecting to {addr}: {e}")),
        }
    }
    Err(last.unwrap_or_else(|| anyhow::anyhow!("the origin {host} has no address")))
}

/// Dial the origin for a forward service.
pub async fn dial(service: &Service, options: &OriginOptions) -> Result<BoxedIo> {
    let timeout = options.connect_timeout;
    let connect = async {
        match service {
            Service::Http(url) => {
                let (host, port, tls) = parse_http_url(url)?;
                let tcp = connect_origin(&host, port).await?;
                if tls {
                    tls_wrap(tcp, &host, options.no_tls_verify).await
                } else {
                    Ok(Box::new(tcp) as BoxedIo)
                }
            }
            Service::Unix(path) => dial_unix(path, false, options).await,
            Service::UnixTls(path) => dial_unix(path, true, options).await,
            Service::Tcp(addr) => {
                let (host, port) =
                    split_host_port(addr).with_context(|| format!("{addr} is not HOST:PORT"))?;
                let s = connect_origin(host, port).await?;
                let _ = s.set_nodelay(true);
                Ok(Box::new(s) as BoxedIo)
            }
            other => bail!("{} is not a forward service", other.describe()),
        }
    };
    match timeout {
        Some(limit) => tokio::time::timeout(limit, connect)
            .await
            .map_err(|_| anyhow::anyhow!("origin connect timed out after {limit:?}"))?,
        None => connect.await,
    }
}

/// Dial a filesystem socket, optionally wrapping it in TLS.
#[cfg(unix)]
async fn dial_unix(path: &std::path::Path, tls: bool, options: &OriginOptions) -> Result<BoxedIo> {
    let stream = UnixStream::connect(path)
        .await
        .with_context(|| format!("connecting to unix:{}", path.display()))?;
    if tls {
        tls_wrap(stream, "localhost", options.no_tls_verify).await
    } else {
        Ok(Box::new(stream) as BoxedIo)
    }
}

#[cfg(not(unix))]
async fn dial_unix(
    path: &std::path::Path,
    _tls: bool,
    _options: &OriginOptions,
) -> Result<BoxedIo> {
    bail!(
        "unix sockets are not supported on this platform: {}",
        path.display()
    )
}

/// Parse `http(s)://host[:port]` into `(host, port, tls)`.
pub fn parse_http_url(url: &str) -> Result<(String, u16, bool)> {
    let (scheme, rest) = url
        .split_once("://")
        .context("origin URL is missing a scheme")?;
    let tls = match scheme {
        "http" => false,
        "https" => true,
        other => bail!("unsupported origin scheme {other:?}"),
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() {
        bail!("origin URL has no host");
    }
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, rest) = rest
            .split_once(']')
            .context("origin URL has an unclosed IPv6 address")?;
        let port = match rest.strip_prefix(':') {
            Some(port) => port.parse().context("origin URL port is invalid")?,
            None if rest.is_empty() => {
                if tls {
                    443
                } else {
                    80
                }
            }
            None => bail!("origin URL has trailing characters after the IPv6 address"),
        };
        (host.to_string(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) if !port.contains(']') => {
                let port: u16 = port.parse().context("origin URL port is invalid")?;
                (host.to_string(), port)
            }
            _ => (authority.to_string(), if tls { 443 } else { 80 }),
        }
    };
    if host.is_empty() {
        bail!("origin URL has no host");
    }
    Ok((host, port, tls))
}

async fn tls_wrap<S>(stream: S, server_name: &str, no_verify: bool) -> Result<BoxedIo>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let connector = if no_verify {
        no_verify_connector()
    } else {
        verified_connector()
    };
    let name = ServerName::try_from(server_name.to_string())
        .map_err(|_| anyhow::anyhow!("invalid TLS server name {server_name:?}"))?;
    let tls = connector
        .connect(name, stream)
        .await
        .with_context(|| format!("TLS handshake with {server_name}"))?;
    Ok(Box::new(tls))
}

fn verified_connector() -> TlsConnector {
    static ONCE: OnceLock<TlsConnector> = OnceLock::new();
    ONCE.get_or_init(|| {
        init_crypto();
        let config = crate::trust::client_config(&[], &[]).unwrap_or_else(|err| {
            tracing::warn!("{err:#}; using the compiled-in roots only");
            let mut roots = RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth()
        });
        TlsConnector::from(Arc::new(config))
    })
    .clone()
}

fn no_verify_connector() -> TlsConnector {
    static ONCE: OnceLock<TlsConnector> = OnceLock::new();
    ONCE.get_or_init(|| {
        init_crypto();
        let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
            .with_no_client_auth();
        TlsConnector::from(Arc::new(config))
    })
    .clone()
}

#[derive(Debug)]
struct NoVerify(Arc<tokio_rustls::rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Convenience: the origin path for a service, used by logs.
pub fn origin_label(service: &Service) -> String {
    match service {
        Service::Unix(path) => format!("unix:{}", path.display()),
        Service::UnixTls(path) => format!("unix+tls:{}", path.display()),
        other => other.describe(),
    }
}

/// Keep `PathBuf` referenced so the import is used on every platform.
#[allow(dead_code)]
fn _pathbuf(_: PathBuf) {}
#[cfg(test)]
mod tests {
    use super::*;

    // Issue 119: localhost needs no resolver (a host with no /etc/hosts).
    #[test]
    fn localhost_is_a_local_name() {
        for name in ["localhost", "LOCALHOST.", "app.localhost"] {
            let ips = local_name(name).unwrap();
            assert_eq!(ips[0], std::net::IpAddr::from([127, 0, 0, 1]), "{name}");
        }
        assert!(local_name("example.com").is_none());
        assert!(local_name("localhost.example.com").is_none());
    }

    #[tokio::test]
    async fn an_origin_on_localhost_connects_and_a_refusal_names_the_address() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(connect_origin("localhost", port).await.is_ok());
        drop(listener);
        let err = connect_origin("localhost", port).await.unwrap_err();
        assert!(format!("{err}").contains("connecting to "), "{err}");
        assert!(!format!("{err}").contains("resolving"), "{err}");
        let err = connect_origin("no-such-name.invalid", 80)
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("resolving the origin"), "{err}");
        assert_eq!(split_host_port("[::1]:8080"), Some(("::1", 8080)));
    }

    #[test]
    fn parses_urls() {
        assert_eq!(
            parse_http_url("http://127.0.0.1:8080").unwrap(),
            ("127.0.0.1".into(), 8080, false)
        );
        assert_eq!(
            parse_http_url("https://example.com").unwrap(),
            ("example.com".into(), 443, true)
        );
        assert_eq!(
            parse_http_url("http://example.com/x").unwrap(),
            ("example.com".into(), 80, false)
        );
        assert_eq!(
            parse_http_url("https://[::1]:8443").unwrap(),
            ("::1".into(), 8443, true)
        );
        assert!(parse_http_url("ftp://x").is_err());
        assert!(parse_http_url("http://").is_err());
    }
}
