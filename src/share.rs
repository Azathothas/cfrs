//! Upload / download / proxy sessions — the feature set quickbridge brings,
//! reimplemented as a library service so a tunnel can expose it directly.
//!
//! - **Upload**: a multipart form saves files into a directory.
//! - **Download**: serves one file (or a clipboard snapshot) once.
//! - **Proxy**: forwards everything to an existing local HTTP port.
//!
//! A random token lives in the URL path; an optional 6-digit PIN gate adds a
//! second factor. `stop_after` tears the session down after the first
//! successful transfer.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Multipart, State};
use axum::http::{header, HeaderMap, StatusCode, Uri};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Form, Router};
use serde::Deserialize;
use tokio::sync::Notify;

use crate::gate::{Gate, UNLOCK_PATH};
use crate::util::{ensure_dir, human_bytes, sanitize_filename};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShareMode {
    Upload,
    Download,
    Proxy,
}

impl ShareMode {
    pub fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "upload" => Ok(ShareMode::Upload),
            "download" => Ok(ShareMode::Download),
            "proxy" => Ok(ShareMode::Proxy),
            other => bail!("unknown share mode {other:?}"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ShareMode::Upload => "upload",
            ShareMode::Download => "download",
            ShareMode::Proxy => "proxy",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ShareConfig {
    pub mode: ShareMode,
    pub token: String,
    pub dest: PathBuf,
    pub file: Option<PathBuf>,
    pub target: Option<String>,
    pub max_bytes: u64,
    pub max_files: u32,
    pub stop_after: bool,
    pub gate: Gate,
}

impl ShareConfig {
    pub fn upload(dest: impl Into<PathBuf>) -> Self {
        Self {
            mode: ShareMode::Upload,
            token: crate::util::random_token(),
            dest: dest.into(),
            file: None,
            target: None,
            max_bytes: 512 * 1024 * 1024,
            max_files: 32,
            stop_after: false,
            gate: Gate::off(),
        }
    }

    pub fn download(file: impl Into<PathBuf>) -> Self {
        Self {
            mode: ShareMode::Download,
            token: crate::util::random_token(),
            dest: PathBuf::new(),
            file: Some(file.into()),
            target: None,
            max_bytes: 2 * 1024 * 1024 * 1024,
            max_files: 1,
            stop_after: false,
            gate: Gate::off(),
        }
    }

    pub fn proxy(target: impl Into<String>) -> Self {
        Self {
            mode: ShareMode::Proxy,
            token: crate::util::random_token(),
            dest: PathBuf::new(),
            file: None,
            target: Some(target.into()),
            max_bytes: 32 * 1024 * 1024,
            max_files: 1,
            stop_after: false,
            gate: Gate::pin(),
        }
    }

    pub fn with_gate(mut self, gate: Gate) -> Self {
        self.gate = gate;
        self
    }

    pub fn stop_after(mut self, yes: bool) -> Self {
        self.stop_after = yes;
        self
    }

    pub fn describe(&self) -> String {
        match self.mode {
            ShareMode::Upload => format!("share:upload:{}", self.dest.display()),
            ShareMode::Download => format!(
                "share:download:{}",
                self.file
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default()
            ),
            ShareMode::Proxy => format!("share:proxy:{}", self.target.clone().unwrap_or_default()),
        }
    }

    /// Path appended to the public URL for the session.
    pub fn url_path(&self) -> String {
        match self.mode {
            ShareMode::Proxy => "/".to_string(),
            _ => format!("/s/{}/", self.token),
        }
    }
}

/// Cross-task session control: last activity + stop signal.
pub struct ShareControl {
    last: Mutex<Instant>,
    stop: Notify,
    stopped: std::sync::atomic::AtomicBool,
}

impl Default for ShareControl {
    fn default() -> Self {
        Self {
            last: Mutex::new(Instant::now()),
            stop: Notify::new(),
            stopped: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

impl ShareControl {
    pub fn touch(&self) {
        if let Ok(mut guard) = self.last.lock() {
            *guard = Instant::now();
        }
    }

    pub fn idle_for(&self) -> Duration {
        self.last
            .lock()
            .map(|guard| guard.elapsed())
            .unwrap_or_default()
    }

    pub fn request_stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        self.stop.notify_waiters();
    }

    /// True after [`request_stop`](Self::request_stop).
    pub fn stop_requested(&self) -> bool {
        self.stopped.load(Ordering::SeqCst)
    }

    /// Ready after [`request_stop`](Self::request_stop), also when the stop
    /// came before this call.
    pub async fn wait_stop(&self) {
        loop {
            let notified = self.stop.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.stop_requested() {
                return;
            }
            notified.await;
        }
    }
}

struct UploadState {
    dest: PathBuf,
    token: String,
    max_bytes: u64,
    max_files: u32,
    used_files: AtomicU32,
    used_bytes: AtomicU64,
    stop_after: bool,
    gate: Gate,
    control: Arc<ShareControl>,
}

struct DownloadState {
    token: String,
    file: PathBuf,
    name: String,
    stop_after: bool,
    gate: Gate,
    control: Arc<ShareControl>,
}

/// A built share session.
pub struct ShareApp {
    config: ShareConfig,
    control: Arc<ShareControl>,
    router: Router,
}

impl ShareApp {
    pub fn new(config: ShareConfig) -> Result<Self> {
        if config.mode == ShareMode::Proxy {
            bail!("proxy sessions are forwarded by the tunnel, not served by ShareApp");
        }
        if config.mode == ShareMode::Upload {
            ensure_dir(&config.dest)?;
        }
        if let Some(file) = &config.file {
            if !file.is_file() {
                bail!("file to share does not exist: {}", file.display());
            }
        }
        let control = Arc::new(ShareControl::default());
        let router = match config.mode {
            ShareMode::Upload => upload_router(&config, control.clone()),
            ShareMode::Download => download_router(&config, control.clone())?,
            ShareMode::Proxy => unreachable!(),
        };
        Ok(Self {
            config,
            control,
            router,
        })
    }

    pub fn config(&self) -> &ShareConfig {
        &self.config
    }

    pub fn control(&self) -> Arc<ShareControl> {
        self.control.clone()
    }

    pub fn router(&self) -> Router {
        self.router.clone()
    }
}

// ── Upload ──────────────────────────────────────────────────────────────────

fn upload_router(config: &ShareConfig, control: Arc<ShareControl>) -> Router {
    let state = Arc::new(UploadState {
        dest: config.dest.clone(),
        token: config.token.clone(),
        max_bytes: config.max_bytes,
        max_files: config.max_files,
        used_files: AtomicU32::new(0),
        used_bytes: AtomicU64::new(0),
        stop_after: config.stop_after,
        gate: config.gate.clone(),
        control,
    });
    let limit = (config.max_bytes as usize).saturating_add(1024 * 1024);
    Router::new()
        .route(
            UNLOCK_PATH,
            post(unlock_upload).layer(DefaultBodyLimit::max(crate::gate::MAX_UNLOCK_BODY as usize)),
        )
        .route("/s/{token}", get(upload_landing))
        .route("/s/{token}/", get(upload_landing))
        .route("/s/{token}/upload", post(upload_receive))
        .layer(DefaultBodyLimit::max(limit))
        .layer(axum::middleware::from_fn_with_state(
            Arc::new(config.token.clone()),
            check_session,
        ))
        .with_state(state)
}

/// A path under `/s/` must name the session id of this share: the id is the
/// secret of the URL. A wrong id (compared in constant time) answers 404.
async fn check_session(
    State(token): State<Arc<String>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    if let Some(rest) = request.uri().path().strip_prefix("/s/") {
        let id = rest.split('/').next().unwrap_or("");
        if !crate::gate::constant_time_eq(id.as_bytes(), token.as_bytes()) {
            return (StatusCode::NOT_FOUND, "Not Found").into_response();
        }
    }
    next.run(request).await
}

#[derive(Deserialize)]
struct UnlockForm {
    password: String,
    #[serde(default)]
    next: String,
}

async fn unlock_upload(
    State(state): State<Arc<UploadState>>,
    Form(form): Form<UnlockForm>,
) -> Response {
    unlock_response(&state.gate, &form.password, &form.next)
}

fn unlock_response(gate: &Gate, password: &str, next: &str) -> Response {
    match gate.unlock(password) {
        Some(cookie) => {
            let next = crate::gate::safe_next(next);
            let mut response = Redirect::to(next).into_response();
            if let Ok(value) = header::HeaderValue::from_str(&cookie) {
                response.headers_mut().insert(header::SET_COOKIE, value);
            }
            response
        }
        None => Html(gate.page_html(next, true)).into_response(),
    }
}

fn gate_blocked(gate: &Gate, headers: &HeaderMap, uri: &Uri) -> Option<Response> {
    if uri.path() == UNLOCK_PATH || gate.is_open(headers) {
        return None;
    }
    let next = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    Some(Html(gate.page_html(next, false)).into_response())
}

async fn upload_landing(
    State(state): State<Arc<UploadState>>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    if let Some(response) = gate_blocked(&state.gate, &headers, &uri) {
        return response;
    }
    state.control.touch();
    Html(upload_page(&state.token, state.max_bytes)).into_response()
}

async fn upload_receive(
    State(state): State<Arc<UploadState>>,
    headers: HeaderMap,
    uri: Uri,
    mut multipart: Multipart,
) -> Response {
    if let Some(response) = gate_blocked(&state.gate, &headers, &uri) {
        return response;
    }
    state.control.touch();

    let mut saved = Vec::new();
    let mut total = 0u64;
    loop {
        let field = match multipart.next_field().await {
            Ok(Some(field)) => field,
            Ok(None) => break,
            Err(err) => {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("bad multipart body: {err}"),
                )
                    .into_response()
            }
        };
        let Some(original) = field.file_name().map(str::to_string) else {
            continue;
        };
        let name = sanitize_filename(&original);
        // Reserve a slot of the file limit first: two uploads at the same
        // time cannot both take the last one.
        let reserved = state
            .used_files
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                (n < state.max_files).then_some(n + 1)
            });
        if reserved.is_err() {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("session file limit reached ({} files)", state.max_files),
            )
                .into_response();
        }
        let release = || state.used_files.fetch_sub(1, Ordering::SeqCst);

        let (path, mut file) = match create_unique(&state.dest, &name).await {
            Ok(created) => created,
            Err(err) => {
                release();
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("cannot create file: {err}"),
                )
                    .into_response();
            }
        };
        let mut field = field;
        let mut written = 0u64;
        loop {
            match field.chunk().await {
                Ok(Some(chunk)) => {
                    written += chunk.len() as u64;
                    if written > state.max_bytes {
                        release();
                        let _ = tokio::fs::remove_file(&path).await;
                        return (
                            StatusCode::PAYLOAD_TOO_LARGE,
                            format!("file exceeds {}", human_bytes(state.max_bytes)),
                        )
                            .into_response();
                    }
                    if let Err(err) = tokio::io::AsyncWriteExt::write_all(&mut file, &chunk).await {
                        release();
                        let _ = tokio::fs::remove_file(&path).await;
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("write failed: {err}"),
                        )
                            .into_response();
                    }
                }
                Ok(None) => break,
                Err(err) => {
                    release();
                    let _ = tokio::fs::remove_file(&path).await;
                    return (StatusCode::BAD_REQUEST, format!("upload aborted: {err}"))
                        .into_response();
                }
            }
        }
        let _ = tokio::io::AsyncWriteExt::flush(&mut file).await;
        state.used_bytes.fetch_add(written, Ordering::Relaxed);
        total += written;
        saved.push((name, written));
    }

    if saved.is_empty() {
        return (StatusCode::BAD_REQUEST, "no files in upload").into_response();
    }
    if state.stop_after {
        state.control.request_stop();
    }
    let list: String = saved
        .iter()
        .map(|(name, size)| format!("<li>{} — {}</li>", html_escape(name), human_bytes(*size)))
        .collect();
    Html(format!(
        "<!doctype html><html><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>cfrs — uploaded</title></head><body>\
         <h1>Received {} file(s), {}</h1><ul>{list}</ul></body></html>",
        saved.len(),
        human_bytes(total)
    ))
    .into_response()
}

fn upload_page(token: &str, max_bytes: u64) -> String {
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>cfrs — upload</title><style>\
         body{{font-family:system-ui,sans-serif;background:#0b1020;color:#e8ecf5;\
         display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}}\
         main{{background:#161d33;padding:2rem;border-radius:12px;width:min(90vw,420px)}}\
         button{{margin-top:1rem;width:100%;padding:.8rem;border:0;border-radius:8px;\
         background:#4f7cff;color:#fff;font-size:1rem}}input[type=file]{{width:100%}}\
         p{{color:#9aa7c7;font-size:.9rem}}</style></head><body><main>\
         <h1>Send files</h1><p>Max {} per file.</p>\
         <form method=\"post\" action=\"/s/{token}/upload\" enctype=\"multipart/form-data\">\
         <input type=\"file\" name=\"files\" multiple required>\
         <button type=\"submit\">Upload</button></form></main></body></html>",
        human_bytes(max_bytes)
    )
}

// ── Download ────────────────────────────────────────────────────────────────

fn download_router(config: &ShareConfig, control: Arc<ShareControl>) -> Result<Router> {
    let file = config
        .file
        .clone()
        .context("download session needs a file")?;
    let name = file
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "download".into());
    let state = Arc::new(DownloadState {
        token: config.token.clone(),
        file,
        name,
        stop_after: config.stop_after,
        gate: config.gate.clone(),
        control,
    });
    Ok(Router::new()
        .route(
            UNLOCK_PATH,
            post(unlock_download)
                .layer(DefaultBodyLimit::max(crate::gate::MAX_UNLOCK_BODY as usize)),
        )
        .route("/s/{token}", get(download_landing))
        .route("/s/{token}/", get(download_landing))
        .route("/s/{token}/file", get(download_file))
        .layer(axum::middleware::from_fn_with_state(
            Arc::new(config.token.clone()),
            check_session,
        ))
        .with_state(state))
}

async fn unlock_download(
    State(state): State<Arc<DownloadState>>,
    Form(form): Form<UnlockForm>,
) -> Response {
    unlock_response(&state.gate, &form.password, &form.next)
}

async fn download_landing(
    State(state): State<Arc<DownloadState>>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    if let Some(response) = gate_blocked(&state.gate, &headers, &uri) {
        return response;
    }
    state.control.touch();
    Html(format!(
        "<!doctype html><html><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>cfrs — download</title></head><body>\
         <h1>{}</h1><p><a href=\"/s/{}/file\">Download</a></p></body></html>",
        html_escape(&state.name),
        state.token
    ))
    .into_response()
}

async fn download_file(
    State(state): State<Arc<DownloadState>>,
    method: http::Method,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    if let Some(response) = gate_blocked(&state.gate, &headers, &uri) {
        return response;
    }
    state.control.touch();
    let file = match tokio::fs::File::open(&state.file).await {
        Ok(file) => file,
        Err(err) => {
            return (StatusCode::NOT_FOUND, format!("cannot open file: {err}")).into_response()
        }
    };
    let len = file.metadata().await.map(|m| m.len()).unwrap_or(0);
    let disposition = format!("attachment; filename=\"{}\"", state.name.replace('"', ""));
    let stream = tokio_util::io::ReaderStream::new(file);
    // --stop-after: the session ends when the last byte of a GET has gone
    // out. A HEAD request, and a client that closes early, do not end it.
    let body = if state.stop_after && method != http::Method::HEAD {
        use futures::StreamExt;
        let control = state.control.clone();
        let done = futures::stream::once(async move {
            control.request_stop();
            None::<std::io::Result<bytes::Bytes>>
        })
        .filter_map(|item| async move { item });
        Body::from_stream(stream.chain(done))
    } else {
        Body::from_stream(stream)
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, len)
        .header(header::CONTENT_DISPOSITION, disposition)
        .body(body)
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

// ── helpers ─────────────────────────────────────────────────────────────────

/// Make a new file for `name` in `dir`: `name`, else `stem-1.ext`,
/// `stem-2.ext` and so on. Each try uses `create_new`, so two uploads at
/// the same time never get the same file.
async fn create_unique(
    dir: &std::path::Path,
    name: &str,
) -> std::io::Result<(PathBuf, tokio::fs::File)> {
    let (stem, ext) = match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => (stem.to_string(), format!(".{ext}")),
        _ => (name.to_string(), String::new()),
    };
    for index in 0..10_000u32 {
        let candidate = if index == 0 {
            dir.join(name)
        } else {
            dir.join(format!("{stem}-{index}{ext}"))
        };
        match tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
            .await
        {
            Ok(file) => return Ok((candidate, file)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::other("no free file name"))
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// --stop-after: a HEAD does not end the session; the end of a GET body
    /// does.
    #[tokio::test]
    async fn stop_after_needs_a_full_get() {
        use tower::ServiceExt;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("ten.txt");
        std::fs::write(&file, b"0123456789").unwrap();
        let config = ShareConfig::download(&file).stop_after(true);
        let path = format!("/s/{}/file", config.token);
        let app = ShareApp::new(config).unwrap();
        let control = app.control();
        let request = |method: &str| {
            http::Request::builder()
                .method(method)
                .uri(&path)
                .body(axum::body::Body::empty())
                .unwrap()
        };
        let head = app.router().oneshot(request("HEAD")).await.unwrap();
        assert_eq!(head.status(), 200);
        let _ = axum::body::to_bytes(head.into_body(), 1 << 20).await;
        assert!(!control.stop_requested(), "HEAD ended the session");

        let get = app.router().oneshot(request("GET")).await.unwrap();
        assert!(
            !control.stop_requested(),
            "the session ended before the body"
        );
        let body = axum::body::to_bytes(get.into_body(), 1 << 20)
            .await
            .unwrap();
        assert_eq!(&body[..], b"0123456789");
        assert!(control.stop_requested());
        tokio::time::timeout(std::time::Duration::from_secs(1), control.wait_stop())
            .await
            .expect("wait_stop sees an earlier stop");
    }

    /// Twelve uploads of one name at the same time: twelve files, each with
    /// its own body.
    #[tokio::test]
    async fn concurrent_names_do_not_collide() {
        let dir = tempfile::tempdir().unwrap();
        let mut tasks = Vec::new();
        for i in 0..12 {
            let dir = dir.path().to_path_buf();
            tasks.push(tokio::spawn(async move {
                let (path, mut file) = create_unique(&dir, "race.txt").await.unwrap();
                tokio::io::AsyncWriteExt::write_all(&mut file, format!("race-{i}").as_bytes())
                    .await
                    .unwrap();
                path
            }));
        }
        let mut paths = Vec::new();
        for t in tasks {
            paths.push(t.await.unwrap());
        }
        paths.sort();
        paths.dedup();
        assert_eq!(paths.len(), 12);
        let mut bodies: Vec<String> = paths
            .iter()
            .map(|p| std::fs::read_to_string(p).unwrap())
            .collect();
        bodies.sort();
        bodies.dedup();
        assert_eq!(bodies.len(), 12);
        assert!(dir.path().join("race.txt").exists());
        assert!(dir.path().join("race-1.txt").exists());
    }

    async fn send(router: &Router, method: &str, path: &str, body: &str) -> (u16, Option<String>) {
        use tower::ServiceExt;
        let request = http::Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        let location = response
            .headers()
            .get(header::LOCATION)
            .map(|v| v.to_str().unwrap().to_string());
        (response.status().as_u16(), location)
    }

    /// Only the session id of the share opens its paths, and an unlock goes
    /// back to a path of this site only.
    #[tokio::test]
    async fn the_session_id_is_checked() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("a.bin");
        std::fs::write(&file, b"secret file").unwrap();
        let mut config = ShareConfig::download(&file);
        config.gate = Gate::pin();
        let pin = config.gate.pin_display().unwrap().to_string();
        let token = config.token.clone();
        let app = ShareApp::new(config).unwrap();
        let router = app.router();

        // The gate answers 200 with the lock page for the right id.
        assert_eq!(
            send(&router, "GET", &format!("/s/{token}/"), "").await.0,
            200
        );
        for wrong in ["/s/1/", "/s/1/file", "/s/deadbeef/", "/s/", "/"] {
            assert_eq!(send(&router, "GET", wrong, "").await.0, 404, "{wrong}");
        }
        let upper = format!("/s/{}/file", token.to_ascii_uppercase());
        assert_eq!(send(&router, "GET", &upper, "").await.0, 404);

        let (status, location) = send(
            &router,
            "POST",
            UNLOCK_PATH,
            &format!("password={pin}&next=//example.com"),
        )
        .await;
        assert_eq!((status, location.as_deref()), (303, Some("/")));

        let big = format!("password=1&next={}", "a".repeat(10_000));
        assert_eq!(send(&router, "POST", UNLOCK_PATH, &big).await.0, 413);
    }

    #[test]
    fn proxy_path_is_root() {
        let config = ShareConfig::proxy("127.0.0.1:9000");
        assert_eq!(config.url_path(), "/");
        assert!(config.gate.enabled());
    }
}
