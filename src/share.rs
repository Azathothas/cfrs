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

/// The default most bytes of one upload request: the edge of Cloudflare
/// takes at most 100 MB in one request body on the free plan.
pub const MAX_REQUEST: u64 = 100_000_000;

#[derive(Clone, Debug)]
pub struct ShareConfig {
    pub mode: ShareMode,
    pub token: String,
    pub dest: PathBuf,
    pub file: Option<PathBuf>,
    pub target: Option<String>,
    /// Upload only: the most bytes of one file.
    pub max_bytes: u64,
    /// Upload only: the most files of the session.
    pub max_files: u32,
    /// Upload only: the most bytes of the session, over all files.
    pub max_total: u64,
    /// Upload only: the most bytes of one upload request (issue 92). A
    /// larger `Content-Length` gets 413 before cfrs reads the body.
    pub max_request: u64,
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
            max_total: 4 * 1024 * 1024 * 1024,
            max_request: MAX_REQUEST,
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
            max_bytes: 0,
            max_files: 0,
            max_total: 0,
            max_request: 0,
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
            max_bytes: 0,
            max_files: 0,
            max_total: 0,
            max_request: 0,
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
    max_total: u64,
    max_request: u64,
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
            match std::fs::metadata(file) {
                Ok(meta) if meta.is_file() => {}
                // Issue 249: exit 78, not 1.
                Ok(_) => {
                    return Err(crate::exit::fault(
                        crate::exit::Fault::Config,
                        anyhow::anyhow!("--file {}: not a regular file", file.display()),
                    ))
                }
                Err(err) => {
                    return Err(crate::exit::fault(
                        crate::exit::Fault::Config,
                        anyhow::anyhow!("--file {}: {err}", file.display()),
                    ))
                }
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
        max_total: config.max_total,
        max_request: config.max_request,
        used_files: AtomicU32::new(0),
        used_bytes: AtomicU64::new(0),
        stop_after: config.stop_after,
        gate: config.gate.clone(),
        control,
    });
    // One request may hold several files: the body limit is the session
    // total, and each file and the total are checked while they arrive.
    let limit = (config.max_total.max(config.max_bytes) as usize)
        .saturating_add(1024 * 1024)
        .min(config.max_request as usize);
    Router::new()
        .route(
            UNLOCK_PATH,
            post(unlock_upload).layer(DefaultBodyLimit::max(crate::gate::MAX_UNLOCK_BODY as usize)),
        )
        .route("/s/{token}", get(upload_landing))
        .route("/s/{token}/", get(upload_landing))
        // Live run 41556133042: with the body limit of the router on this
        // route, the multipart stream ended at the limit, the rest of a
        // refused body was not read, and the edge gave 500 over HTTP/2 in
        // place of the 413. The handler counts the bytes of the request.
        // Issue 232: this layer removes each body limit of axum on the
        // route. The counter of the handler is the only limit: it counts
        // each field, with or with no file name.
        .route(
            "/s/{token}/upload",
            post(upload_receive).layer(DefaultBodyLimit::disable()),
        )
        .layer(DefaultBodyLimit::max(limit))
        .layer(axum::middleware::from_fn_with_state(
            Arc::new(config.token.clone()),
            check_session,
        ))
        .layer(axum::middleware::map_response(no_store))
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
    headers: HeaderMap,
    uri: Uri,
    Form(form): Form<UnlockForm>,
) -> Response {
    unlock_response(&state.gate, &headers, &uri, &form.password, &form.next)
}

/// The host of a request: the `Host` header, else the authority of the URI.
fn request_host<'a>(headers: &'a HeaderMap, uri: &'a Uri) -> Option<&'a str> {
    headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .or_else(|| uri.authority().map(|a| a.as_str()))
}

fn unlock_response(
    gate: &Gate,
    headers: &HeaderMap,
    uri: &Uri,
    password: &str,
    next: &str,
) -> Response {
    // Issue 229: an unlock from another site does not use a try of the PIN.
    if !crate::gate::same_site(headers, request_host(headers, uri)) {
        return (
            StatusCode::FORBIDDEN,
            "an unlock from another site is refused",
        )
            .into_response();
    }
    match gate.unlock(password) {
        Some(cookie) => {
            let next = crate::gate::safe_next(next);
            let mut response = Redirect::to(next).into_response();
            if let Ok(value) = header::HeaderValue::from_str(&cookie) {
                response.headers_mut().insert(header::SET_COOKIE, value);
            }
            response
        }
        // Issue 194: a wrong PIN is a refusal (the browser shows the page).
        None => (
            http::StatusCode::FORBIDDEN,
            Html(gate.page_html(next, true)),
        )
            .into_response(),
    }
}

fn gate_blocked(
    gate: &Gate,
    method: &http::Method,
    headers: &HeaderMap,
    uri: &Uri,
) -> Option<Response> {
    if uri.path() == UNLOCK_PATH || gate.is_open(headers) {
        return None;
    }
    let next = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let status = http::StatusCode::from_u16(crate::gate::locked_status(method.as_str()))
        .unwrap_or(http::StatusCode::FORBIDDEN);
    Some((status, Html(gate.page_html(next, false))).into_response())
}

async fn upload_landing(
    State(state): State<Arc<UploadState>>,
    method: http::Method,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    if let Some(response) = gate_blocked(&state.gate, &method, &headers, &uri) {
        return response;
    }
    state.control.touch();
    Html(upload_page(
        &state.token,
        state.max_bytes,
        state.max_request,
    ))
    .into_response()
}

/// The time limit of one chunk of an upload. A body that stops for longer
/// gets 408, and its staged files are removed.
pub const CHUNK_LIMIT: std::time::Duration = std::time::Duration::from_secs(60);

/// The files of one upload request before they are committed. Each file is
/// written to a hidden `.part` file in the destination. On drop, before the
/// commit, each part file is removed and the reserved file slots and bytes
/// go back to the session: an error, a stalled body or a dropped request
/// leaves no partial file and no used slot.
struct Staging<'a> {
    state: &'a UploadState,
    /// (part file, sanitized name, size)
    parts: Vec<(PathBuf, String, u64)>,
    slots: u32,
    bytes: u64,
}

impl Drop for Staging<'_> {
    fn drop(&mut self) {
        for (part, _, _) in &self.parts {
            let _ = std::fs::remove_file(part);
        }
        self.state
            .used_files
            .fetch_sub(self.slots, Ordering::SeqCst);
        self.state
            .used_bytes
            .fetch_sub(self.bytes, Ordering::SeqCst);
    }
}

impl Staging<'_> {
    /// Take `n` bytes of the session total, or say no.
    fn reserve_bytes(&mut self, n: u64) -> bool {
        let max = self.state.max_total;
        let used_bytes = &self.state.used_bytes;
        let ok = update_atomic!(used_bytes, |used: u64| used
            .checked_add(n)
            .filter(|t| *t <= max))
        .is_ok();
        if ok {
            self.bytes += n;
        }
        ok
    }

    /// Move each part file to a unique final name. A committed file is no
    /// longer removed on drop, and its slot and bytes stay used.
    async fn commit(mut self) -> Result<Vec<(String, u64)>, std::io::Error> {
        let mut saved = Vec::new();
        let parts = std::mem::take(&mut self.parts);
        let mut left = parts.clone();
        for (part, name, size) in parts {
            let placed = match create_unique(&self.state.dest, &name).await {
                Ok((path, placeholder)) => {
                    drop(placeholder);
                    // The placeholder (made with create_new) is ours: the
                    // rename replaces it, and never another file.
                    match tokio::fs::rename(&part, &path).await {
                        Ok(()) => Ok(path),
                        Err(err) => {
                            let _ = tokio::fs::remove_file(&path).await;
                            Err(err)
                        }
                    }
                }
                Err(err) => Err(err),
            };
            let path = match placed {
                Ok(path) => path,
                Err(err) => {
                    // The committed files keep their slots and bytes; the
                    // rest are removed and released on drop.
                    self.slots = left.len() as u32;
                    self.bytes = left.iter().map(|(_, _, size)| size).sum();
                    self.parts = left;
                    return Err(err);
                }
            };
            left.remove(0);
            let final_name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or(name);
            saved.push((final_name, size));
        }
        // Committed: keep the slots and the bytes.
        self.slots = 0;
        self.bytes = 0;
        Ok(saved)
    }
}

/// Issue 234: an error of the file system goes to the log of the operator.
/// The visitor gets a fixed text, with no error detail of the host.
fn save_failed(what: &str, err: &std::io::Error) -> Response {
    tracing::warn!(error = %err, "upload: {what}");
    refuse(
        StatusCode::INTERNAL_SERVER_ERROR,
        "the server cannot save the upload".to_string(),
    )
}

fn refuse(status: StatusCode, message: String) -> Response {
    (
        status,
        format!("{message}; no file of this upload was saved"),
    )
        .into_response()
}

/// The next chunk of a multipart field, with the time limit [`CHUNK_LIMIT`].
/// An error is the response to send.
async fn next_chunk(
    field: &mut axum::extract::multipart::Field<'_>,
) -> Result<Option<bytes::Bytes>, Box<Response>> {
    match tokio::time::timeout(CHUNK_LIMIT, field.chunk()).await {
        Ok(Ok(chunk)) => Ok(chunk),
        Ok(Err(err)) => Err(Box::new(refuse(
            StatusCode::BAD_REQUEST,
            format!("upload aborted: {err}"),
        ))),
        Err(_) => Err(Box::new(refuse(
            StatusCode::REQUEST_TIMEOUT,
            format!("no data for {} s", CHUNK_LIMIT.as_secs()),
        ))),
    }
}

/// The longest pause of a body that is read and dropped.
const DROP_IDLE: std::time::Duration = std::time::Duration::from_secs(5);
/// The longest time to read and drop a body.
const DROP_LIMIT: std::time::Duration = std::time::Duration::from_secs(120);

/// Read the rest of a multipart body and drop it: until its end, a pause of
/// [`DROP_IDLE`], or [`DROP_LIMIT`]. Gives the bytes dropped.
async fn drop_body(multipart: &mut Multipart) -> u64 {
    let mut dropped = 0u64;
    let work = async {
        while let Ok(Ok(Some(mut field))) =
            tokio::time::timeout(DROP_IDLE, multipart.next_field()).await
        {
            while let Ok(Ok(Some(chunk))) = tokio::time::timeout(DROP_IDLE, field.chunk()).await {
                dropped += chunk.len() as u64;
            }
        }
    };
    let _ = tokio::time::timeout(DROP_LIMIT, work).await;
    dropped
}

async fn upload_receive(
    State(state): State<Arc<UploadState>>,
    method: http::Method,
    headers: HeaderMap,
    uri: Uri,
    mut multipart: Multipart,
) -> Response {
    if let Some(response) = gate_blocked(&state.gate, &method, &headers, &uri) {
        return response;
    }
    state.control.touch();
    // A request over the limit (by its Content-Length, issue 92) gets 413
    // and saves nothing. The body is read and dropped first: an answer
    // before the end of the upload did not reach the visitor reliably
    // through the edge (a 502 or a 520 in place of the 413).
    let length = headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok());
    if let Some(length) = length.filter(|&n| n > state.max_request) {
        tracing::info!(
            bytes = length,
            limit = state.max_request,
            "upload refused: the request is over --max-request"
        );
        let dropped = drop_body(&mut multipart).await;
        tracing::debug!(dropped, "the body of a refused upload was read and dropped");
        return refuse(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "the upload is {}; one upload can hold at most {} (send fewer or smaller files)",
                human_bytes(length),
                human_bytes(state.max_request)
            ),
        );
    }

    let mut staging = Staging {
        state: &state,
        parts: Vec::new(),
        slots: 0,
        bytes: 0,
    };
    let mut request_bytes = 0u64;
    let mut over = false;
    'fields: loop {
        let field = match tokio::time::timeout(CHUNK_LIMIT, multipart.next_field()).await {
            Ok(Ok(Some(field))) => field,
            Ok(Ok(None)) => break,
            Ok(Err(err)) => {
                return refuse(
                    StatusCode::BAD_REQUEST,
                    format!("bad multipart body: {err}"),
                )
            }
            Err(_) => {
                return refuse(
                    StatusCode::REQUEST_TIMEOUT,
                    format!("no data for {} s", CHUNK_LIMIT.as_secs()),
                )
            }
        };
        let Some(original) = field.file_name().map(str::to_string) else {
            // Issue 232: a field with no file name counts toward
            // --max-request too. Its bytes are dropped.
            let mut field = field;
            loop {
                let chunk = match next_chunk(&mut field).await {
                    Ok(Some(chunk)) => chunk,
                    Ok(None) => break,
                    Err(response) => return *response,
                };
                state.control.touch();
                request_bytes += chunk.len() as u64;
                if request_bytes > state.max_request {
                    over = true;
                    break 'fields;
                }
            }
            continue;
        };
        let name = sanitize_filename(&original);
        // Reserve a slot of the file limit first: two uploads at the same
        // time cannot both take the last one.
        let used_files = &state.used_files;
        let reserved = update_atomic!(used_files, |n| (n < state.max_files).then_some(n + 1));
        if reserved.is_err() {
            return refuse(
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("session file limit reached ({} files)", state.max_files),
            );
        }
        staging.slots += 1;

        let part = state.dest.join(format!(
            ".cfrs-upload-{}.part",
            &crate::util::random_token()[..16]
        ));
        // Issue 233: an upload is for the operator only (mode 0600). The
        // rename keeps the mode of the part file.
        let mut file = match tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&part)
            .await
        {
            Ok(file) => file,
            Err(err) => return save_failed("cannot create a part file", &err),
        };
        staging.parts.push((part, name, 0));
        let index = staging.parts.len() - 1;
        let mut field = field;
        let mut written = 0u64;
        loop {
            let chunk = match next_chunk(&mut field).await {
                Ok(Some(chunk)) => chunk,
                Ok(None) => break,
                Err(response) => return *response,
            };
            // A long upload is activity: --idle-secs does not stop it.
            state.control.touch();
            // A request with no Content-Length over --max-request.
            request_bytes += chunk.len() as u64;
            if request_bytes > state.max_request {
                over = true;
                break 'fields;
            }
            written += chunk.len() as u64;
            if written > state.max_bytes {
                return refuse(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    format!("a file exceeds {}", human_bytes(state.max_bytes)),
                );
            }
            if !staging.reserve_bytes(chunk.len() as u64) {
                return refuse(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    format!(
                        "the session limit of {} is reached",
                        human_bytes(state.max_total)
                    ),
                );
            }
            if let Err(err) = tokio::io::AsyncWriteExt::write_all(&mut file, &chunk).await {
                return save_failed("cannot write a part file", &err);
            }
        }
        if let Err(err) = tokio::io::AsyncWriteExt::flush(&mut file).await {
            return save_failed("cannot write a part file", &err);
        }
        staging.parts[index].2 = written;
    }
    if over {
        tracing::info!(
            limit = state.max_request,
            "upload refused: the request is over --max-request"
        );
        let dropped = drop_body(&mut multipart).await;
        tracing::debug!(dropped, "the body of a refused upload was read and dropped");
        return refuse(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "the upload is over {}, the most of one upload (send fewer or smaller files)",
                human_bytes(state.max_request)
            ),
        );
    }

    if staging.parts.is_empty() {
        return (StatusCode::BAD_REQUEST, "no files in upload").into_response();
    }
    let saved = match staging.commit().await {
        Ok(saved) => saved,
        Err(err) => return save_failed("cannot move a part file to its name", &err),
    };
    let total: u64 = saved.iter().map(|(_, size)| size).sum();
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

fn upload_page(token: &str, max_bytes: u64, max_request: u64) -> String {
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
         <h1>Send files</h1><p>Max {} per file, {} per upload.</p>\
         <form id=\"f\" method=\"post\" action=\"/s/{token}/upload\" enctype=\"multipart/form-data\">\
         <input type=\"file\" name=\"files\" multiple required>\
         <button type=\"submit\">Upload</button></form>\
         <progress id=\"bar\" max=\"100\" value=\"0\" hidden style=\"width:100%;margin-top:1rem\"></progress>\
         <p id=\"state\"></p></main><script>\
         var f=document.getElementById('f'),bar=document.getElementById('bar'),st=document.getElementById('state');\
         f.addEventListener('submit',function(e){{e.preventDefault();\
         var n=0,fs=f.querySelector('input[type=file]').files;for(var i=0;i<fs.length;i++)n+=fs[i].size;\
         if(n>{max_request}){{st.textContent='The files are '+n+' bytes; one upload can hold at most {max_request} bytes.';return;}}\
         var x=new XMLHttpRequest();\
         x.open('POST',f.action);bar.hidden=false;\
         x.upload.onprogress=function(p){{if(p.lengthComputable){{bar.value=100*p.loaded/p.total;\
         st.textContent=Math.round(bar.value)+' %';}}}};\
         x.onload=function(){{document.open();document.write(x.responseText);document.close();}};\
         x.onerror=function(){{st.textContent='The upload failed.';}};\
         x.send(new FormData(f));}});</script></body></html>",
        human_bytes(max_bytes),
        human_bytes(max_request)
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
        .layer(axum::middleware::map_response(no_store))
        .with_state(state))
}

async fn unlock_download(
    State(state): State<Arc<DownloadState>>,
    headers: HeaderMap,
    uri: Uri,
    Form(form): Form<UnlockForm>,
) -> Response {
    unlock_response(&state.gate, &headers, &uri, &form.password, &form.next)
}

async fn download_landing(
    State(state): State<Arc<DownloadState>>,
    method: http::Method,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    if let Some(response) = gate_blocked(&state.gate, &method, &headers, &uri) {
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
    if let Some(response) = gate_blocked(&state.gate, &method, &headers, &uri) {
        return response;
    }
    state.control.touch();
    // podssh #105: open with O_NONBLOCK (an open of a FIFO does not
    // block), then serve only a regular file. A FIFO put at the path after
    // the start blocked the request.
    let mut file = match tokio::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&state.file)
        .await
    {
        Ok(file) => file,
        Err(err) => {
            // Issue 234: the error detail goes to the log, not to the visitor.
            tracing::warn!(error = %err, file = %state.file.display(), "download: cannot open the shared file");
            return (StatusCode::NOT_FOUND, "the shared file is not available").into_response();
        }
    };
    let meta = file.metadata().await.ok();
    if !meta.as_ref().is_some_and(|m| m.is_file()) {
        return (
            StatusCode::NOT_FOUND,
            "the shared file is not a regular file",
        )
            .into_response();
    }
    let len = meta.as_ref().map(|m| m.len()).unwrap_or(0);
    let mtime = meta
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let etag = format!("\"{len:x}-{mtime:x}\"");
    let header_text = |name: header::HeaderName| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    if header_text(header::IF_NONE_MATCH)
        .is_some_and(|v| crate::util::http::etag_matches(&v, &etag))
    {
        return Response::builder()
            .status(StatusCode::NOT_MODIFIED)
            .header(header::ETAG, &etag)
            .body(Body::empty())
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
    }
    // One range (a resume). An If-Range that is not this ETag, and more than
    // one range, give the whole file.
    let range_ok = header_text(header::IF_RANGE).is_none_or(|v| v.trim() == etag);
    let range = match header_text(header::RANGE).filter(|_| range_ok) {
        Some(value) => match parse_range(&value, len) {
            Ok(range) => range,
            Err(()) => {
                return Response::builder()
                    .status(StatusCode::RANGE_NOT_SATISFIABLE)
                    .header(header::CONTENT_RANGE, format!("bytes */{len}"))
                    .body(Body::empty())
                    .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
            }
        },
        None => None,
    };
    let (start, end) = range.unwrap_or((0, len.saturating_sub(1)));
    let count = if len == 0 { 0 } else { end - start + 1 };
    if start > 0 {
        use tokio::io::AsyncSeekExt;
        if file.seek(std::io::SeekFrom::Start(start)).await.is_err() {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }
    let disposition = content_disposition(&state.name);
    let stream = tokio_util::io::ReaderStream::new(tokio::io::AsyncReadExt::take(file, count));
    // --stop-after: the session ends when the last byte of the file has gone
    // out in a GET. A HEAD request, a range that stops before the end, and a
    // client that closes early, do not end it.
    let to_the_end = len == 0 || end + 1 == len;
    let body = if state.stop_after && method != http::Method::HEAD && to_the_end {
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
    let mut response = Response::builder()
        .status(if range.is_some() {
            StatusCode::PARTIAL_CONTENT
        } else {
            StatusCode::OK
        })
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, count)
        .header(header::CONTENT_DISPOSITION, disposition)
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::ETAG, &etag);
    if range.is_some() {
        response = response.header(header::CONTENT_RANGE, format!("bytes {start}-{end}/{len}"));
    }
    response
        .body(body)
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// Parse a Range header for a file of `len` bytes: `Ok(Some((start, end)))`
/// for one satisfiable range (end included), `Ok(None)` for a header to
/// ignore (more than one range, another unit), `Err` for an unsatisfiable
/// range.
fn parse_range(value: &str, len: u64) -> std::result::Result<Option<(u64, u64)>, ()> {
    let Some(spec) = value.trim().strip_prefix("bytes=") else {
        return Ok(None);
    };
    if spec.contains(',') {
        return Ok(None);
    }
    let (a, b) = spec.split_once('-').ok_or(())?;
    let (a, b) = (a.trim(), b.trim());
    let range = if a.is_empty() {
        let n: u64 = b.parse().map_err(|_| ())?;
        if n == 0 || len == 0 {
            return Err(());
        }
        (len.saturating_sub(n), len - 1)
    } else {
        let start: u64 = a.parse().map_err(|_| ())?;
        let end = if b.is_empty() {
            len.saturating_sub(1)
        } else {
            b.parse::<u64>().map_err(|_| ())?.min(len.saturating_sub(1))
        };
        if start >= len || start > end {
            return Err(());
        }
        (start, end)
    };
    Ok(Some(range))
}

// ── helpers ─────────────────────────────────────────────────────────────────

/// The numbered names that [`create_unique`] tries before random names.
const NUMBERED_NAMES: u32 = 100;
/// The random names that [`create_unique`] tries after the numbered names.
const RANDOM_NAMES: u32 = 16;

/// Make a new file for `name` in `dir`: `name`, else `stem-1.ext`,
/// `stem-2.ext` and so on, up to [`NUMBERED_NAMES`] names. After that,
/// `stem-<8 random hex digits>.ext` (issue 234: before, the stem was full
/// after 10 000 names, and each upload tried each name). Each try uses
/// `create_new`, so two uploads at the same time never get the same file.
async fn create_unique(
    dir: &std::path::Path,
    name: &str,
) -> std::io::Result<(PathBuf, tokio::fs::File)> {
    create_unique_with(dir, name, NUMBERED_NAMES).await
}

async fn create_unique_with(
    dir: &std::path::Path,
    name: &str,
    numbered: u32,
) -> std::io::Result<(PathBuf, tokio::fs::File)> {
    let (stem, ext) = match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => (stem.to_string(), format!(".{ext}")),
        _ => (name.to_string(), String::new()),
    };
    for index in 0..numbered + RANDOM_NAMES {
        let candidate = if index == 0 {
            dir.join(name)
        } else if index < numbered {
            dir.join(format!("{stem}-{index}{ext}"))
        } else {
            dir.join(format!("{stem}-{}{ext}", &crate::util::random_token()[..8]))
        };
        match tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
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

use crate::gate::escape_html as html_escape;

/// Issue 271: each response of a share session has `Cache-Control:
/// no-store` (the landing page, the file, the PIN page, the unlock reply).
/// A cache of the edge or of a browser keeps no copy.
async fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .entry(header::CACHE_CONTROL)
        .or_insert(header::HeaderValue::from_static("no-store"));
    response
}

/// `Content-Disposition` for a download of `name` (RFC 6266): `filename=`
/// with an ASCII form (each other byte, `"`, `\` and each control
/// character becomes `_`), and `filename*=UTF-8''` with the percent-encoded
/// name (RFC 5987) when the name is not plain ASCII. Before, a non-ASCII
/// name was put in raw, and the header was lost on the way to the edge.
pub fn content_disposition(name: &str) -> String {
    let ascii: String = name
        .chars()
        .map(|c| {
            if c.is_ascii() && !c.is_ascii_control() && c != '"' && c != '\\' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let mut value = format!("attachment; filename=\"{ascii}\"");
    if ascii != name {
        let mut encoded = String::new();
        for byte in name.bytes() {
            // attr-char of RFC 5987.
            if byte.is_ascii_alphanumeric() || b"!#$&+-.^_`|~".contains(&byte) {
                encoded.push(byte as char);
            } else {
                encoded.push_str(&format!("%{byte:02X}"));
            }
        }
        value.push_str(&format!("; filename*=UTF-8''{encoded}"));
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A multipart body with one file part for each (name, size).
    fn multipart(files: &[(&str, usize)]) -> Vec<u8> {
        let mut body = Vec::new();
        for (name, size) in files {
            body.extend_from_slice(
                format!(
                    "--XB\r\nContent-Disposition: form-data; name=\"files\"; filename=\"{name}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
                )
                .as_bytes(),
            );
            body.extend(std::iter::repeat_n(b'x', *size));
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(b"--XB--\r\n");
        body
    }

    fn upload_request(token: &str, body: axum::body::Body) -> http::Request<axum::body::Body> {
        http::Request::builder()
            .method("POST")
            .uri(format!("/s/{token}/upload"))
            .header("content-type", "multipart/form-data; boundary=XB")
            .body(body)
            .unwrap()
    }

    fn files_in(dir: &std::path::Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// Issue 58: a request over the file limit or the session total gets
    /// 413 and saves no file of it (before, the files before the limit
    /// stayed); the slots and the bytes go back, so a smaller request works.
    #[tokio::test]
    async fn an_upload_over_a_limit_saves_nothing() {
        use tower::ServiceExt;
        let dir = tempfile::tempdir().unwrap();
        let mut config = ShareConfig::upload(dir.path());
        config.max_files = 2;
        config.max_bytes = 10;
        config.max_total = 15;
        let token = config.token.clone();
        let app = ShareApp::new(config).unwrap();
        let send = |files: &[(&str, usize)]| {
            app.router().oneshot(upload_request(
                &token,
                axum::body::Body::from(multipart(files)),
            ))
        };
        let three = send(&[("a.txt", 1), ("b.txt", 1), ("c.txt", 1)])
            .await
            .unwrap();
        assert_eq!(three.status(), 413);
        assert!(
            files_in(dir.path()).is_empty(),
            "{:?}",
            files_in(dir.path())
        );
        let total = send(&[("a.txt", 10), ("b.txt", 10)]).await.unwrap();
        assert_eq!(total.status(), 413);
        let text = axum::body::to_bytes(total.into_body(), 4096).await.unwrap();
        assert!(String::from_utf8_lossy(&text).contains("session limit"));
        assert!(
            files_in(dir.path()).is_empty(),
            "{:?}",
            files_in(dir.path())
        );
        let two = send(&[("a.txt", 10), ("b.txt", 5)]).await.unwrap();
        assert_eq!(two.status(), 200);
        assert_eq!(files_in(dir.path()), ["a.txt", "b.txt"]);
        assert_eq!(
            std::fs::metadata(dir.path().join("a.txt")).unwrap().len(),
            10
        );
    }

    // Issue 233: an uploaded file has mode 0600, with each umask.
    #[tokio::test]
    async fn an_upload_has_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        use tower::ServiceExt;
        let dir = tempfile::tempdir().unwrap();
        let config = ShareConfig::upload(dir.path());
        let token = config.token.clone();
        let app = ShareApp::new(config).unwrap();
        for _ in 0..2 {
            let response = app
                .router()
                .oneshot(upload_request(
                    &token,
                    axum::body::Body::from(multipart(&[("a.txt", 5)])),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), 200);
        }
        assert_eq!(files_in(dir.path()), ["a-1.txt", "a.txt"]);
        for name in ["a.txt", "a-1.txt"] {
            let mode = std::fs::metadata(dir.path().join(name))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "{name}: {mode:o}");
        }
        let (_, file) = create_unique(dir.path(), "b.txt").await.unwrap();
        let mode = file.metadata().await.unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "{mode:o}");
    }

    /// A body in chunks of 1000 bytes that counts the bytes read.
    fn counted(body: Vec<u8>) -> (axum::body::Body, Arc<std::sync::atomic::AtomicUsize>) {
        let read = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = read.clone();
        let chunks: Vec<Result<bytes::Bytes, std::io::Error>> = body
            .chunks(1000)
            .map(|c| Ok(bytes::Bytes::copy_from_slice(c)))
            .collect();
        use futures::StreamExt as _;
        let stream = futures::stream::iter(chunks).inspect(move |c| {
            if let Ok(c) = c {
                seen.fetch_add(c.len(), Ordering::SeqCst);
            }
        });
        (axum::body::Body::from_stream(stream), read)
    }

    // Issue 232: a field with no file name counts toward --max-request. A
    // chunked body (no Content-Length) with a large text field gets 413.
    #[tokio::test]
    async fn a_field_with_no_file_name_is_counted() {
        use tower::ServiceExt;
        let dir = tempfile::tempdir().unwrap();
        let mut config = ShareConfig::upload(dir.path());
        config.max_request = 1000;
        let token = config.token.clone();
        let app = ShareApp::new(config).unwrap();
        let field = |size: usize| {
            let mut body =
                b"--XB\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\n".to_vec();
            body.extend(std::iter::repeat_n(b'n', size));
            body.extend_from_slice(b"\r\n");
            body
        };
        let mut body = field(3000);
        body.extend(multipart(&[("a.txt", 10)]));
        let (stream, _) = counted(body);
        let response = app
            .router()
            .oneshot(upload_request(&token, stream))
            .await
            .unwrap();
        assert_eq!(response.status(), 413);
        assert!(files_in(dir.path()).is_empty());
        // A small text field and a file are under the limit.
        let mut body = field(100);
        body.extend(multipart(&[("a.txt", 10)]));
        let (stream, _) = counted(body);
        let response = app
            .router()
            .oneshot(upload_request(&token, stream))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(files_in(dir.path()), ["a.txt"]);
    }

    // Live run 41556133042: a refused body is read to its end before the
    // 413, with and with no Content-Length. Before, the body limit of the
    // router stopped the read at --max-request, and over HTTP/2 the edge
    // gave 500.
    #[tokio::test]
    async fn a_refused_body_is_read_to_its_end() {
        use tower::ServiceExt;
        let dir = tempfile::tempdir().unwrap();
        let mut config = ShareConfig::upload(dir.path());
        config.max_request = 10_000;
        let token = config.token.clone();
        let app = ShareApp::new(config).unwrap();
        for with_length in [true, false] {
            let body = multipart(&[("big.bin", 60_000)]);
            let len = body.len();
            let (stream, read) = counted(body);
            let mut request = upload_request(&token, stream);
            if with_length {
                request
                    .headers_mut()
                    .insert("content-length", len.to_string().parse().unwrap());
            }
            let response = app.router().oneshot(request).await.unwrap();
            assert_eq!(response.status(), 413, "content-length {with_length}");
            assert_eq!(
                read.load(Ordering::SeqCst),
                len,
                "content-length {with_length}"
            );
            assert!(files_in(dir.path()).is_empty());
        }
        // An upload under the limit still works.
        let body = multipart(&[("small.bin", 5000)]);
        let response = app
            .router()
            .oneshot(upload_request(&token, axum::body::Body::from(body)))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
    }

    /// Issue 92: a request over max_request (by its Content-Length) is read
    /// and dropped, then gets 413, and saves nothing; the landing page and a
    /// smaller upload still work. A body that stops gets its 413 after the
    /// pause of DROP_IDLE (the clock is paused here).
    #[tokio::test(start_paused = true)]
    async fn a_content_length_over_max_request_gets_413_at_once() {
        use tower::ServiceExt;
        let dir = tempfile::tempdir().unwrap();
        let mut config = ShareConfig::upload(dir.path());
        config.max_request = 1000;
        let token = config.token.clone();
        let app = ShareApp::new(config).unwrap();
        let never = futures::stream::pending::<Result<bytes::Bytes, std::io::Error>>();
        let mut stalled = upload_request(&token, axum::body::Body::from_stream(never));
        stalled
            .headers_mut()
            .insert("content-length", "60000000".parse().unwrap());
        let response = app.router().oneshot(stalled).await.unwrap();
        assert_eq!(response.status(), 413);
        let body = multipart(&[("big.bin", 5000)]);
        let mut request = upload_request(&token, axum::body::Body::from(body.clone()));
        request
            .headers_mut()
            .insert("content-length", body.len().to_string().parse().unwrap());
        let response = app.router().oneshot(request).await.unwrap();
        assert_eq!(response.status(), 413);
        let text = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&text);
        assert!(text.contains("at most 1000 B"), "{text}");
        assert!(files_in(dir.path()).is_empty());
        let landing = app
            .router()
            .oneshot(
                http::Request::builder()
                    .uri(format!("/s/{token}/"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(landing.status(), 200);
        let page = axum::body::to_bytes(landing.into_body(), 1 << 16)
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&page).contains("per upload"));
        let small = app
            .router()
            .oneshot(upload_request(
                &token,
                axum::body::Body::from(multipart(&[("a.txt", 10)])),
            ))
            .await
            .unwrap();
        assert_eq!(small.status(), 200);
        assert_eq!(files_in(dir.path()), ["a.txt"]);
    }

    /// Issue 59: a body that stops gets 408 after CHUNK_LIMIT, and leaves no
    /// file, partial or staged.
    #[tokio::test(start_paused = true)]
    async fn a_stalled_upload_leaves_no_file() {
        use futures::StreamExt;
        use tower::ServiceExt;
        let dir = tempfile::tempdir().unwrap();
        let config = ShareConfig::upload(dir.path());
        let token = config.token.clone();
        let app = ShareApp::new(config).unwrap();
        let mut start = multipart(&[("big.bin", 1000)]);
        start.truncate(start.len() - 300);
        let stream =
            futures::stream::once(
                async move { Ok::<_, std::io::Error>(bytes::Bytes::from(start)) },
            )
            .chain(futures::stream::pending());
        let response = app
            .router()
            .oneshot(upload_request(
                &token,
                axum::body::Body::from_stream(stream),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), 408);
        assert!(
            files_in(dir.path()).is_empty(),
            "{:?}",
            files_in(dir.path())
        );
    }

    /// Issue 60: a non-ASCII name, a quote and a newline.
    #[test]
    fn content_disposition_is_ascii_with_an_rfc5987_name() {
        assert_eq!(
            content_disposition("a.txt"),
            "attachment; filename=\"a.txt\""
        );
        assert_eq!(
            content_disposition("café.txt"),
            "attachment; filename=\"caf_.txt\"; filename*=UTF-8''caf%C3%A9.txt"
        );
        let quoted = content_disposition("a\"b\nc.txt");
        assert!(
            quoted.starts_with("attachment; filename=\"a_b_c.txt\""),
            "{quoted}"
        );
        for name in ["café.txt", "a\"b\nc.txt", "日本.pdf"] {
            let value = content_disposition(name);
            assert!(value.is_ascii(), "{value}");
            assert!(http::HeaderValue::from_str(&value).is_ok(), "{value}");
        }
    }

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

    /// The upload page shows a progress bar, and its script is whole.
    #[test]
    fn the_upload_page_has_progress() {
        let page = upload_page("abc", 1 << 20, MAX_REQUEST);
        assert!(page.contains("upload.onprogress") && page.contains("<progress"));
        let script = page
            .split("<script>")
            .nth(1)
            .unwrap()
            .split("</script>")
            .next()
            .unwrap();
        assert_eq!(script.matches('{').count(), script.matches('}').count());
        assert_eq!(script.matches('(').count(), script.matches(')').count());
    }

    #[test]
    fn ranges() {
        assert_eq!(parse_range("bytes=0-4", 10), Ok(Some((0, 4))));
        assert_eq!(parse_range("bytes=5-", 10), Ok(Some((5, 9))));
        assert_eq!(parse_range("bytes=-3", 10), Ok(Some((7, 9))));
        assert_eq!(parse_range("bytes=8-99", 10), Ok(Some((8, 9))));
        assert_eq!(parse_range("bytes=0-1,4-5", 10), Ok(None));
        assert_eq!(parse_range("items=0-1", 10), Ok(None));
        assert_eq!(parse_range("bytes=10-", 10), Err(()));
        assert_eq!(parse_range("bytes=5-2", 10), Err(()));
        assert_eq!(parse_range("bytes=x-1", 10), Err(()));
    }

    /// A resume: 206 with Content-Range; 304 for the same ETag; 416 for a
    /// range past the end; --stop-after only after the end of the file.
    #[tokio::test]
    async fn downloads_resume() {
        use tower::ServiceExt;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("ten.txt");
        std::fs::write(&file, b"0123456789").unwrap();
        let config = ShareConfig::download(&file).stop_after(true);
        let path = format!("/s/{}/file", config.token);
        let app = ShareApp::new(config).unwrap();
        let control = app.control();
        let get = |extra: Vec<(&'static str, String)>| {
            let mut b = http::Request::builder().uri(&path);
            for (k, v) in extra {
                b = b.header(k, v);
            }
            app.router()
                .oneshot(b.body(axum::body::Body::empty()).unwrap())
        };
        let full = get(vec![]).await.unwrap();
        let etag = full.headers()[header::ETAG].to_str().unwrap().to_string();
        assert_eq!(full.headers()[header::ACCEPT_RANGES], "bytes");
        drop(full);

        let part = get(vec![("range", "bytes=2-4".into())]).await.unwrap();
        assert_eq!(part.status(), 206);
        assert_eq!(part.headers()[header::CONTENT_RANGE], "bytes 2-4/10");
        let body = axum::body::to_bytes(part.into_body(), 1 << 20)
            .await
            .unwrap();
        assert_eq!(&body[..], b"234");
        assert!(!control.stop_requested(), "a part ended the session");

        let not_modified = get(vec![("if-none-match", etag.clone())]).await.unwrap();
        assert_eq!(not_modified.status(), 304);
        let past = get(vec![("range", "bytes=50-".into())]).await.unwrap();
        assert_eq!(past.status(), 416);
        let stale = get(vec![
            ("range", "bytes=2-4".into()),
            ("if-range", "\"old\"".into()),
        ])
        .await
        .unwrap();
        assert_eq!(stale.status(), 200);
        drop(stale);
        assert!(!control.stop_requested());

        let rest = get(vec![("range", "bytes=5-".into())]).await.unwrap();
        let body = axum::body::to_bytes(rest.into_body(), 1 << 20)
            .await
            .unwrap();
        assert_eq!(&body[..], b"56789");
        assert!(
            control.stop_requested(),
            "the end of the file ends the session"
        );
    }

    // Issue 234: after the numbered names, a random name; the stem is never
    // full.
    #[tokio::test]
    async fn a_full_stem_gets_a_random_name() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["a.txt", "a-1.txt", "a-2.txt"] {
            std::fs::write(dir.path().join(name), "x").unwrap();
        }
        let (path, _) = create_unique_with(dir.path(), "a.txt", 3).await.unwrap();
        let name = path.file_name().unwrap().to_str().unwrap().to_string();
        assert!(name.starts_with("a-") && name.ends_with(".txt"), "{name}");
        assert_eq!(name.len(), "a-12345678.txt".len(), "{name}");
        assert_eq!(files_in(dir.path()).len(), 4);
    }

    // Issue 234: a download error has no error detail of the host.
    #[tokio::test]
    async fn a_download_error_has_no_host_detail() {
        use tower::ServiceExt;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("gone.bin");
        std::fs::write(&file, b"data").unwrap();
        let config = ShareConfig::download(&file);
        let token = config.token.clone();
        let app = ShareApp::new(config).unwrap();
        std::fs::remove_file(&file).unwrap();
        let response = app
            .router()
            .oneshot(
                http::Request::builder()
                    .uri(format!("/s/{token}/file"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 404);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&body);
        assert!(!body.contains("os error"), "{body}");
        assert!(!body.contains(dir.path().to_str().unwrap()), "{body}");
        assert!(body.contains("not available"), "{body}");
    }

    // Issue 271: `If-None-Match: *` and a weak tag give 304; each response
    // of a share has `Cache-Control: no-store`.
    #[tokio::test]
    async fn a_download_answers_a_weak_tag_and_is_not_stored() {
        use tower::ServiceExt;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("a.txt");
        std::fs::write(&file, b"abc").unwrap();
        let mut config = ShareConfig::download(&file);
        let token = config.token.clone();
        let app = ShareApp::new(config.clone()).unwrap();
        let get = |path: String, inm: Option<String>| {
            let mut b = http::Request::builder().uri(path);
            if let Some(v) = inm {
                b = b.header("if-none-match", v);
            }
            app.router()
                .oneshot(b.body(axum::body::Body::empty()).unwrap())
        };
        let full = get(format!("/s/{token}/file"), None).await.unwrap();
        assert_eq!(full.headers()[header::CACHE_CONTROL], "no-store");
        let etag = full.headers()[header::ETAG].to_str().unwrap().to_string();
        for inm in [
            "*".to_string(),
            format!("W/{etag}"),
            format!("\"x\", {etag}"),
        ] {
            let response = get(format!("/s/{token}/file"), Some(inm.clone()))
                .await
                .unwrap();
            assert_eq!(response.status(), 304, "{inm}");
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        }
        let landing = get(format!("/s/{token}/"), None).await.unwrap();
        assert_eq!(landing.headers()[header::CACHE_CONTROL], "no-store");

        config.gate = Gate::pin();
        let app = ShareApp::new(config).unwrap();
        let locked = app
            .router()
            .oneshot(
                http::Request::builder()
                    .uri(format!("/s/{token}/"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(locked.headers()[header::CACHE_CONTROL], "no-store");
        let dir = tempfile::tempdir().unwrap();
        let config = ShareConfig::upload(dir.path());
        let token = config.token.clone();
        let app = ShareApp::new(config).unwrap();
        let landing = app
            .router()
            .oneshot(
                http::Request::builder()
                    .uri(format!("/s/{token}/"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(landing.headers()[header::CACHE_CONTROL], "no-store");
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
                // A tokio File writes in the background: the flush waits for
                // the write (CI run 41569743059 read an empty file).
                tokio::io::AsyncWriteExt::flush(&mut file).await.unwrap();
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

    /// Issue 194: a POST to a gated upload with no cookie gets 403 and
    /// saves nothing; a GET gets the page with 200; a wrong PIN gets 403.
    #[tokio::test]
    async fn a_locked_post_gets_403_and_saves_nothing() {
        use tower::ServiceExt;
        let dir = tempfile::tempdir().unwrap();
        let mut config = ShareConfig::upload(dir.path());
        config.gate = Gate::pin();
        let token = config.token.clone();
        let app = ShareApp::new(config).unwrap();
        let body = multipart(&[("a.bin", 100)]);
        let response = app
            .router()
            .oneshot(upload_request(&token, axum::body::Body::from(body)))
            .await
            .unwrap();
        assert_eq!(response.status(), 403);
        assert!(files_in(dir.path()).is_empty());
        let router = app.router();
        assert_eq!(
            send(&router, "GET", &format!("/s/{token}/"), "").await.0,
            200
        );
        let (status, _) = send(&router, "POST", UNLOCK_PATH, "password=wrong&next=/").await;
        assert_eq!(status, 403);
        assert_eq!(crate::gate::locked_status("HEAD"), 200);
        assert_eq!(crate::gate::locked_status("PUT"), 403);
    }

    // Issue 229: an unlock POST of another site gets 403, and the count of
    // wrong codes does not change.
    #[tokio::test]
    async fn an_unlock_from_another_site_is_refused() {
        use tower::ServiceExt;
        let dir = tempfile::tempdir().unwrap();
        let mut config = ShareConfig::upload(dir.path());
        config.gate = Gate::pin();
        let gate = config.gate.clone();
        let app = ShareApp::new(config).unwrap();
        for _ in 0..crate::gate::MAX_FAILURES {
            let request = http::Request::builder()
                .method("POST")
                .uri(UNLOCK_PATH)
                .header("host", "x.trycloudflare.com")
                .header("origin", "https://evil.example")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(axum::body::Body::from("password=000000&next=/"))
                .unwrap();
            let response = app.router().oneshot(request).await.unwrap();
            assert_eq!(response.status(), 403);
        }
        assert!(!gate.locked_out());
        let pin = gate.pin_display().unwrap().to_string();
        let request = http::Request::builder()
            .method("POST")
            .uri(UNLOCK_PATH)
            .header("host", "x.trycloudflare.com")
            .header("origin", "https://x.trycloudflare.com")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(axum::body::Body::from(format!("password={pin}&next=/")))
            .unwrap();
        let response = app.router().oneshot(request).await.unwrap();
        assert_eq!(response.status(), 303);
    }

    /// podssh #105: a FIFO put at the path of the shared file after the
    /// start gets 404 at once (an open of a FIFO blocked the request).
    #[tokio::test]
    async fn a_fifo_in_place_of_the_shared_file_does_not_block() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("a.bin");
        std::fs::write(&file, b"data").unwrap();
        let config = ShareConfig::download(&file);
        let token = config.token.clone();
        let app = ShareApp::new(config).unwrap();
        std::fs::remove_file(&file).unwrap();
        let fifo = std::ffi::CString::new(file.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o644) }, 0);
        let (status, _) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            send(&app.router(), "GET", &format!("/s/{token}/file"), ""),
        )
        .await
        .expect("no block");
        assert_eq!(status, 404);
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
