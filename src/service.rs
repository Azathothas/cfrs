//! Prebuilt service runtimes: built-in origins are axum routers created once
//! at startup; forward services keep their rule + options.

use std::path::Path;
use std::sync::Arc;

use anyhow::{bail, Result};
use axum::Router;
use tower_http::services::{ServeDir, ServeFile};

use crate::gate::Gate;
use crate::ingress::{ForwardTarget, Ingress, OriginOptions, Service};
use crate::metrics::Metrics;
use crate::share::{ShareApp, ShareControl, ShareMode};

/// A service prepared for dispatch.
pub enum Built {
    /// HTTP / HTTPS / unix / unix+tls origin, proxied raw.
    Forward(Service, OriginOptions),
    /// Raw TCP origin.
    Tcp(Service, OriginOptions),
    /// WebSocket endpoint bridging to a raw stream target.
    ForwardWs(ForwardTarget),
    HelloWorld,
    Status(u16),
    Static(Router),
    Metrics,
    Share(ShareApp),
    /// quickbridge proxy mode: gated forwarding to a local HTTP port.
    ShareProxy {
        target: String,
        gate: Gate,
        control: Arc<ShareControl>,
        /// Stop the session after the first request that the origin
        /// answered (`--stop-after`).
        stop_after: bool,
    },
}

pub struct ServiceRuntime {
    built: Vec<Built>,
    metrics: Metrics,
}

impl ServiceRuntime {
    /// Build every rule's runtime. Fails fast on a bad origin (missing
    /// directory, missing file) so the tunnel never starts half-configured.
    pub fn build(ingress: &Ingress, metrics: Metrics) -> Result<Self> {
        let mut built = Vec::with_capacity(ingress.rules.len());
        for rule in &ingress.rules {
            built.push(match &rule.service {
                Service::Http(_) | Service::Unix(_) | Service::UnixTls(_) => {
                    Built::Forward(rule.service.clone(), rule.origin.clone())
                }
                Service::Tcp(_) => Built::Tcp(rule.service.clone(), rule.origin.clone()),
                Service::Forward(target) => Built::ForwardWs(target.clone()),
                Service::HelloWorld => Built::HelloWorld,
                Service::Status(code) => Built::Status(*code),
                Service::Static { root, spa } => Built::Static(static_router(root, *spa)?),
                Service::Metrics => Built::Metrics,
                Service::Share(config) => match config.mode {
                    ShareMode::Proxy => Built::ShareProxy {
                        target: config
                            .target
                            .clone()
                            .unwrap_or_else(|| "127.0.0.1:80".to_string()),
                        gate: config.gate.clone(),
                        control: Arc::new(ShareControl::default()),
                        stop_after: config.stop_after,
                    },
                    _ => Built::Share(ShareApp::new(config.clone())?),
                },
            });
        }
        Ok(Self { built, metrics })
    }

    pub fn get(&self, index: usize) -> Option<&Built> {
        self.built.get(index)
    }

    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    pub fn len(&self) -> usize {
        self.built.len()
    }

    pub fn is_empty(&self) -> bool {
        self.built.is_empty()
    }

    /// Session controls for every share rule, so a host can watch for
    /// `stop_after` and idle timeouts.
    pub fn share_controls(&self) -> Vec<Arc<ShareControl>> {
        self.built
            .iter()
            .filter_map(|built| match built {
                Built::Share(app) => Some(app.control()),
                Built::ShareProxy { control, .. } => Some(control.clone()),
                _ => None,
            })
            .collect()
    }
}

fn static_router(root: &Path, spa: bool) -> Result<Router> {
    // Issue 95: a bad --dir is a usage mistake (exit 64), and the text
    // says which mistake.
    if !root.is_dir() {
        let why = if root.exists() {
            "is not a directory"
        } else {
            "does not exist"
        };
        return Err(crate::exit::fault(
            crate::exit::Fault::Usage,
            anyhow::anyhow!("the directory to serve ({}) {why}", root.display()),
        ));
    }
    let canonical = Arc::new(
        root.canonicalize()
            .map_err(|e| anyhow::anyhow!("static root {}: {e}", root.display()))?,
    );
    let dir = ServeDir::new(canonical.as_path()).append_index_html_on_directories(true);
    if spa && !canonical.join("index.html").is_file() {
        bail!(
            "--spa needs an index.html in {}: each unknown path answers it",
            root.display()
        );
    }
    let router = if spa {
        let index = ServeFile::new(canonical.join("index.html"));
        // fallback, not not_found_service: an SPA route answers 200.
        Router::new().fallback_service(dir.fallback(index))
    } else {
        // Issue 182: a missing path has the body of each other 404 of
        // the guard ("Not Found"); before, ServeDir gave an empty body.
        let missing = tower::service_fn(|_: http::Request<axum::body::Body>| async {
            Ok::<_, std::convert::Infallible>(not_found())
        });
        Router::new().fallback_service(dir.not_found_service(missing))
    };
    Ok(router.layer(axum::middleware::from_fn_with_state(
        canonical,
        static_guard,
    )))
}

/// The answer of [`static_guard`] for a path that is not served.
fn not_found() -> axum::response::Response {
    axum::response::IntoResponse::into_response((http::StatusCode::NOT_FOUND, "Not Found"))
}

/// Serve a path of the static root only when it stays in the root:
///
/// * A name that starts with a dot (`.git`, `.env`) is not served.
/// * The real path (each symlink resolved) must be in the canonical root, so
///   a link to `/etc/passwd` or `../secret` is not served.
/// * Only a regular file or a directory is served: a FIFO, a socket or a
///   device would hang or leak.
///
/// A link that is changed between this check and the open is still a race;
/// the root must not be writable by an attacker.
async fn static_guard(
    axum::extract::State(root): axum::extract::State<Arc<std::path::PathBuf>>,
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    // More than one range: answer the whole file (200), as RFC 9110 permits,
    // in place of the 416 of ServeDir for a multipart range.
    let multi = request
        .headers()
        .get(http::header::RANGE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains(','));
    if multi {
        request.headers_mut().remove(http::header::RANGE);
    }
    let decoded = match percent_decode_path(request.uri().path()) {
        Some(p) => p,
        None => return not_found(),
    };
    let mut path = root.as_path().to_path_buf();
    for segment in decoded.split('/').filter(|s| !s.is_empty()) {
        if segment.starts_with('.')
            || segment.len() > 255
            || segment.contains('\\')
            || segment.contains('\0')
        {
            return not_found();
        }
        path.push(segment);
    }
    if path.as_os_str().len() > 4096 {
        return not_found();
    }
    match std::fs::symlink_metadata(&path) {
        // A missing path: ServeDir answers 404 (or the SPA index).
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => next.run(request).await,
        Err(_) => not_found(),
        Ok(_) => match std::fs::canonicalize(&path) {
            Ok(real) if real.starts_with(root.as_path()) => match std::fs::metadata(&real) {
                Ok(meta) if meta.is_file() || meta.is_dir() => next.run(request).await,
                _ => not_found(),
            },
            _ => not_found(),
        },
    }
}

/// Decode the `%XX` escapes of a URL path. A bad escape or bytes that are
/// not UTF-8 give `None`.
fn percent_decode_path(path: &str) -> Option<String> {
    let bytes = path.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = std::str::from_utf8(bytes.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn get(router: &Router, path: &str) -> (u16, String) {
        use tower::ServiceExt;
        let request = http::Request::builder()
            .uri(path)
            .body(axum::body::Body::empty())
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        let status = response.status().as_u16();
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    /// A link out of the root, a relative link, a link to a directory out of
    /// the root, a chain of links, a dotfile and a FIFO are not served. A
    /// link in the root, a file and a directory index are served.
    #[tokio::test]
    async fn the_static_root_is_a_boundary() {
        use std::os::unix::fs::symlink;
        let base = tempfile::tempdir().unwrap();
        let root = base.path().join("www");
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("index.html"), "index").unwrap();
        std::fs::write(root.join("sub/page.html"), "page").unwrap();
        std::fs::write(root.join(".env"), "SECRET=1").unwrap();
        std::fs::write(base.path().join("outside.txt"), "outside").unwrap();
        std::fs::create_dir(base.path().join("outdir")).unwrap();
        std::fs::write(base.path().join("outdir/x.txt"), "outdir").unwrap();
        symlink(base.path().join("outside.txt"), root.join("abs-link")).unwrap();
        symlink("../outside.txt", root.join("rel-link")).unwrap();
        symlink(base.path().join("outdir"), root.join("dir-link")).unwrap();
        symlink("abs-link", root.join("chain-link")).unwrap();
        symlink("sub/page.html", root.join("in-link")).unwrap();
        let fifo = std::ffi::CString::new(root.join("fifo").to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o644) }, 0);

        let router = static_router(&root, false).unwrap();
        assert_eq!(get(&router, "/").await, (200, "index".into()));
        assert_eq!(get(&router, "/sub/page.html").await, (200, "page".into()));
        assert_eq!(get(&router, "/in-link").await, (200, "page".into()));
        for path in [
            "/abs-link",
            "/rel-link",
            "/dir-link/x.txt",
            "/chain-link",
            "/.env",
            "/%2eenv",
            "/sub/../../outside.txt",
            "/fifo",
            "/missing",
        ] {
            let (status, body) = get(&router, path).await;
            assert_eq!(status, 404, "{path}: {body}");
            // Issue 182: each 404 has one body; a missing path does not
            // look other than a refused one.
            assert_eq!(body, "Not Found", "{path}");
            assert!(
                !body.contains("outside") && !body.contains("SECRET"),
                "{path}: {body}"
            );
        }
        let long = format!("/{}", "a".repeat(300));
        assert_eq!(get(&router, &long).await.0, 404);

        // A multipart range gets the whole file.
        {
            use tower::ServiceExt;
            let request = http::Request::builder()
                .uri("/sub/page.html")
                .header("range", "bytes=0-0,2-3")
                .body(axum::body::Body::empty())
                .unwrap();
            let response = router.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), 200);
        }
        // --spa needs an index.html.
        let bare = base.path().join("bare");
        std::fs::create_dir(&bare).unwrap();
        let err = static_router(&bare, true).err().unwrap().to_string();
        assert!(err.contains("--spa needs an index.html"), "{err}");

        // An SPA route answers the index with 200; a link out of the root
        // is still refused.
        let spa = static_router(&root, true).unwrap();
        assert_eq!(get(&spa, "/some/route").await, (200, "index".into()));
        assert_eq!(get(&spa, "/abs-link").await.0, 404);
    }
}
