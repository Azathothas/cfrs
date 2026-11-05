//! In-process origins: static file serving, SPA fallback, fixed status, and the
//! hello-world page.
//!
//! These never dial anything. The tunnel layer calls
//! `InProcessResponse::respond` and writes the reply straight back down the
//! visitor's channel. That keeps `static:` and `spa:` working in a sandbox
//! where nothing can listen.

use std::path::{Component, Path, PathBuf};

use crate::util::http::{RequestHead, ResponseWriter};

/// Serve a directory over HTTP.
#[derive(Debug, Clone)]
pub struct StaticDir {
    /// Root directory. Paths are resolved inside it.
    pub dir: PathBuf,
    /// When true, unknown paths fall back to `index` instead of 404.
    pub spa: bool,
    /// The file served for directory requests and for SPA fallback.
    pub index: String,
}

impl StaticDir {
    /// Build a static origin rooted at `dir`.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            spa: false,
            index: "index.html".to_string(),
        }
    }

    /// Enable single-page-app fallback.
    pub fn spa(mut self, on: bool) -> Self {
        self.spa = on;
        self
    }

    /// Answer one request.
    ///
    /// Each file that is sent (the request path, a directory index and the
    /// SPA index) goes through `StaticDir::resolve`: the root check, the
    /// dotfile rule and the file-type check apply to each one.
    pub fn respond<W: ResponseWriter>(
        &self,
        req: &RequestHead,
        writer: &mut W,
    ) -> std::io::Result<()> {
        let rel = req.path.trim_start_matches('/');
        let rel = if rel.is_empty() {
            self.index.as_str()
        } else {
            rel
        };

        match self.resolve(rel) {
            Some((path, false)) => return send_file(req, &path, writer),
            Some((_, true)) => {
                let index = format!("{}/{}", rel.trim_end_matches('/'), self.index);
                if let Some((path, false)) = self.resolve(&index) {
                    return send_file(req, &path, writer);
                }
            }
            None => {}
        }
        if self.spa {
            if let Some((path, false)) = self.resolve(&self.index) {
                return send_file(req, &path, writer);
            }
        }
        writer.status(404).text("404 not found")
    }

    /// Resolve a relative path inside the root, refusing anything that escapes.
    ///
    /// The traversal check is the important part: a request for
    /// `../../etc/passwd` must not reach outside the served directory. Path
    /// components are checked lexically, and then the path is **canonicalised**,
    /// because a lexical check alone does not survive a symlink.
    ///
    /// A component that starts with a dot (`.env`, `.git`, `.well-known`) is
    /// refused, as in `podnet serve`: such names often hold secrets.
    fn resolve(&self, rel: &str) -> Option<(PathBuf, bool)> {
        let decoded = percent_decode(rel);
        let candidate = Path::new(&decoded);

        let mut out = self.dir.clone();
        for component in candidate.components() {
            match component {
                Component::Normal(part) => {
                    if part.as_encoded_bytes().starts_with(b".") {
                        return None;
                    }
                    out.push(part)
                }
                // Reject ParentDir and RootDir outright rather than trying to
                // normalise them away.
                Component::ParentDir | Component::RootDir | Component::CurDir => {
                    if component == Component::CurDir {
                        continue;
                    }
                    return None;
                }
                Component::Prefix(_) => return None,
            }
        }

        // Resolve symlinks and compare the *resolved* path against the *resolved*
        // root. `starts_with` on the constructed path is a component-prefix
        // comparison and does not look at what the path points at, so a symlink
        // inside the served tree pointing outside it passes: with
        // `static:/srv/www` and `/srv/www/leak -> /etc/shadow`, a request for
        // `/leak` yields the components of `/srv/www/leak`, which starts with
        // `/srv/www`, and the file is then read. Canonicalising is what makes
        // the claim true rather than merely plausible.
        let root = std::fs::canonicalize(&self.dir).ok()?;
        let resolved = std::fs::canonicalize(&out).ok()?;
        if !resolved.starts_with(&root) {
            return None;
        }

        // podssh #105: only a regular file or a directory. A read of a FIFO
        // blocks, and a socket or a device is not a file to serve.
        let meta = std::fs::metadata(&resolved).ok()?;
        if !meta.is_file() && !meta.is_dir() {
            return None;
        }
        Some((resolved, meta.is_dir()))
    }
}

/// The canned page cloudflared's `--hello-world` serves.
pub const HELLO_WORLD: &str = "<!DOCTYPE html>\n\
<html lang=\"en\">\n\
<head><meta charset=\"utf-8\"><title>podnet</title></head>\n\
<body>\n\
<h1>podnet</h1>\n\
<p>An anonymous Cloudflare quick tunnel, served from Rust.</p>\n\
</body>\n\
</html>\n";

/// Answer with a fixed status and no body.
pub fn fixed_status<W: ResponseWriter>(code: u16, writer: &mut W) -> std::io::Result<()> {
    let phrase = http_phrase(code);
    writer
        .status(code)
        .header("Content-Length", "0")
        .raw_head(code, phrase, &[])
}

/// Reply with the hello-world page.
pub fn hello_world<W: ResponseWriter>(writer: &mut W) -> std::io::Result<()> {
    writer.status(200).html(HELLO_WORLD)
}

fn send_file<W: ResponseWriter>(
    req: &RequestHead,
    path: &Path,
    writer: &mut W,
) -> std::io::Result<()> {
    // Open first, then check the open handle: a FIFO that is put in place
    // after resolve() does not block the open (O_NONBLOCK), and fstat
    // refuses it. Each later read uses this handle, not the path.
    use std::os::unix::fs::OpenOptionsExt;
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
    {
        Ok(f) => f,
        Err(_) => return writer.status(404).text("404 not found"),
    };
    let meta = match file.metadata() {
        Ok(m) if m.is_file() => m,
        _ => return writer.status(404).text("404 not found"),
    };

    let mime = content_type(path);
    // Honour a conditional request so a browser does not refetch unchanged
    // assets on every reload.
    if let (Some(inm), Some(mtime)) = (req.header("if-none-match"), meta.modified().ok()) {
        let tag = format!(
            "\"{}\"",
            mtime
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        );
        if crate::util::http::etag_matches(inm, &tag) {
            return writer
                .status(304)
                .header("ETag", &tag)
                .header("Content-Length", "0")
                .raw_head(304, "Not Modified", &[]);
        }
    }

    // Issue 276: stream the file from the open handle. The whole file is
    // not read into memory. Issue 296: the writer gets the handle, so a
    // writer that sends the body later reads the file then.
    writer
        .status(200)
        .header("Content-Type", mime)
        .body_file(meta.len(), file)
}

/// Guess a content type from the extension.
pub fn content_type(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "wasm" => "application/wasm",
        "txt" | "md" => "text/plain; charset=utf-8",
        "xml" => "application/xml",
        "pdf" => "application/pdf",
        "woff2" => "font/woff2",
        _ => "application/octet-stream",
    }
}

/// Minimal percent-decoding for request paths.
pub fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(b) => {
                        out.push(b);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The reason phrase for a status code, for the small set we emit by hand.
pub fn http_phrase(code: u16) -> &'static str {
    match code {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        426 => "Upgrade Required",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Status",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `ResponseWriter` that records what was written, for assertions.
    #[derive(Default)]
    struct Recorder {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    impl ResponseWriter for Recorder {
        fn status(&mut self, code: u16) -> &mut Self {
            self.status = code;
            self
        }
        fn header(&mut self, name: &str, value: &str) -> &mut Self {
            self.headers.push((name.to_string(), value.to_string()));
            self
        }
        fn body(&mut self, b: &[u8]) -> std::io::Result<()> {
            self.body.extend_from_slice(b);
            Ok(())
        }
    }

    // #276: a file is sent in chunks, not read into memory in one piece.
    #[test]
    fn a_file_is_sent_in_chunks() {
        #[derive(Default)]
        struct Chunks {
            status: u16,
            calls: usize,
            largest: usize,
            total: usize,
        }
        impl ResponseWriter for Chunks {
            fn status(&mut self, code: u16) -> &mut Self {
                self.status = code;
                self
            }
            fn header(&mut self, _: &str, _: &str) -> &mut Self {
                self
            }
            fn body(&mut self, b: &[u8]) -> std::io::Result<()> {
                self.calls += 1;
                self.largest = self.largest.max(b.len());
                self.total += b.len();
                Ok(())
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let size = 1024 * 1024 + 7;
        std::fs::write(dir.path().join("big.bin"), vec![7u8; size]).unwrap();
        let mut out = Chunks::default();
        StaticDir::new(dir.path())
            .respond(&req("/big.bin"), &mut out)
            .unwrap();
        assert_eq!(out.status, 200);
        assert_eq!(out.total, size);
        assert!(
            out.largest <= crate::util::http::BODY_CHUNK,
            "{}",
            out.largest
        );
        assert!(out.calls > 1);
    }

    // podssh #105: a FIFO in the root is not served (a read blocks).
    #[test]
    fn a_fifo_is_not_resolved() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "a").unwrap();
        let fifo = std::ffi::CString::new(dir.path().join("f").to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o644) }, 0);
        let site = StaticDir {
            dir: dir.path().to_path_buf(),
            spa: false,
            index: "index.html".into(),
        };
        assert!(site.resolve("a.txt").is_some());
        assert!(site.resolve("f").is_none());
    }

    // #276: a name that starts with a dot is not served.
    #[test]
    fn a_dotfile_is_not_served() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".env"), "SECRET=1").unwrap();
        std::fs::create_dir(dir.path().join(".git")).unwrap();
        std::fs::write(dir.path().join(".git/config"), "SECRET").unwrap();
        std::fs::write(dir.path().join("a.b"), "ok").unwrap();
        let site = StaticDir::new(dir.path());
        for path in ["/.env", "/.git/config", "/%2eenv", "/.git/"] {
            let mut rec = Recorder::default();
            site.respond(&req(path), &mut rec).unwrap();
            assert_eq!(rec.status, 404, "{path}");
            assert!(!String::from_utf8_lossy(&rec.body).contains("SECRET"));
        }
        let mut rec = Recorder::default();
        site.respond(&req("/a.b"), &mut rec).unwrap();
        assert_eq!(rec.status, 200);
        assert_eq!(rec.body, b"ok");
    }

    // #276: the SPA index is resolved as each other file. A FIFO index does
    // not block the request, and a link out of the root is not served.
    #[test]
    fn the_spa_index_goes_through_resolve() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = std::ffi::CString::new(dir.path().join("index.html").to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o644) }, 0);
        let site = StaticDir::new(dir.path()).spa(true);
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = site.clone();
        std::thread::spawn(move || {
            let mut rec = Recorder::default();
            worker.respond(&req("/deep/route"), &mut rec).unwrap();
            let _ = tx.send(rec.status);
        });
        let status = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("a FIFO index blocks the request");
        assert_eq!(status, 404);

        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret.html"), "SECRET").unwrap();
        let root = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("secret.html"),
            root.path().join("index.html"),
        )
        .unwrap();
        std::fs::create_dir(root.path().join("sub")).unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("secret.html"),
            root.path().join("sub/index.html"),
        )
        .unwrap();
        let site = StaticDir::new(root.path()).spa(true);
        for path in ["/", "/deep/route", "/sub/"] {
            let mut rec = Recorder::default();
            site.respond(&req(path), &mut rec).unwrap();
            assert_eq!(rec.status, 404, "{path}");
            assert!(!String::from_utf8_lossy(&rec.body).contains("SECRET"));
        }
    }

    // #276: send_file checks the open handle, so a FIFO path does not block.
    #[test]
    fn send_file_refuses_a_fifo_without_a_block() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        let fifo = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o644) }, 0);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut rec = Recorder::default();
            send_file(&req("/f"), &path, &mut rec).unwrap();
            let _ = tx.send(rec.status);
        });
        let status = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("a FIFO blocks send_file");
        assert_eq!(status, 404);
    }

    fn req(path: &str) -> RequestHead {
        RequestHead {
            method: "GET".to_string(),
            path: path.to_string(),
            headers: Vec::new(),
        }
    }

    fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("podnet-static-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("mkdir");
        d
    }

    #[test]
    fn serves_an_index_file() {
        let d = tmpdir("index");
        std::fs::write(d.join("index.html"), b"<h1>hi</h1>").unwrap();
        let s = StaticDir::new(&d);
        let mut rec = Recorder::default();
        s.respond(&req("/"), &mut rec).unwrap();
        assert_eq!(rec.status, 200);
        assert_eq!(rec.body, b"<h1>hi</h1>");
    }

    #[test]
    fn serves_a_named_file_with_its_type() {
        let d = tmpdir("named");
        std::fs::write(d.join("a.css"), b"body{}").unwrap();
        let s = StaticDir::new(&d);
        let mut rec = Recorder::default();
        s.respond(&req("/a.css"), &mut rec).unwrap();
        assert_eq!(rec.status, 200);
        assert!(
            rec.headers
                .iter()
                .any(|(k, v)| k == "Content-Type" && v.starts_with("text/css")),
            "headers were {:?}",
            rec.headers
        );
    }

    #[test]
    fn missing_paths_404_without_spa() {
        let d = tmpdir("missing");
        std::fs::write(d.join("index.html"), b"idx").unwrap();
        let s = StaticDir::new(&d);
        let mut rec = Recorder::default();
        s.respond(&req("/nope"), &mut rec).unwrap();
        assert_eq!(rec.status, 404);
    }

    #[test]
    fn spa_falls_back_to_index() {
        let d = tmpdir("spa");
        std::fs::write(d.join("index.html"), b"app").unwrap();
        let s = StaticDir::new(&d).spa(true);
        let mut rec = Recorder::default();
        s.respond(&req("/deep/route"), &mut rec).unwrap();
        assert_eq!(rec.status, 200);
        assert_eq!(rec.body, b"app");
    }

    #[test]
    fn traversal_out_of_the_root_is_refused() {
        let d = tmpdir("traverse");
        std::fs::write(d.join("index.html"), b"idx").unwrap();
        let secret = d.parent().unwrap().join("podnet-secret-outside");
        std::fs::write(&secret, b"SECRET").unwrap();

        let s = StaticDir::new(&d);
        // Both the raw and the percent-encoded form must be refused.
        for attack in ["/../podnet-secret-outside", "/%2e%2e/podnet-secret-outside"] {
            let mut rec = Recorder::default();
            s.respond(&req(attack), &mut rec).unwrap();
            assert_eq!(rec.status, 404, "{attack} should not be served");
            assert!(
                !String::from_utf8_lossy(&rec.body).contains("SECRET"),
                "{attack} leaked file content"
            );
        }
        let _ = std::fs::remove_file(&secret);
    }

    #[test]
    fn a_symlink_out_of_the_root_is_refused() {
        // The lexical traversal check cannot see a symlink, so a link inside the
        // served tree pointing outside it passes the component check and then
        // reads the target. The fix is to canonicalise before comparing roots,
        // and this is the test for it: it fails on any implementation that only
        // checks the path it constructed.
        let d = tmpdir("symlink");
        std::fs::write(d.join("index.html"), b"idx").unwrap();
        let outside = d.parent().unwrap().join("podnet-symlink-target");
        std::fs::write(&outside, b"SECRET").unwrap();

        let link = d.join("leak");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, &link).unwrap();

        let s = StaticDir::new(&d);
        let mut rec = Recorder::default();
        s.respond(&req("/leak"), &mut rec).unwrap();
        assert_ne!(
            rec.status, 200,
            "a symlink out of the served root must not be served"
        );
        assert!(
            !String::from_utf8_lossy(&rec.body).contains("SECRET"),
            "the symlink leaked file content from outside the root"
        );

        // A symlink that stays inside the root is still served: the point is to
        // keep the origin, not to ban links.
        let inner = d.join("real.html");
        std::fs::write(&inner, b"inside").unwrap();
        let inner_link = d.join("alias");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&inner, &inner_link).unwrap();

        let mut rec = Recorder::default();
        s.respond(&req("/alias"), &mut rec).unwrap();
        assert_eq!(rec.status, 200, "a link inside the root should still work");
        assert!(String::from_utf8_lossy(&rec.body).contains("inside"));

        let _ = std::fs::remove_file(&outside);
    }

    #[test]
    fn content_types_cover_the_common_cases() {
        assert_eq!(
            content_type(Path::new("a.html")),
            "text/html; charset=utf-8"
        );
        assert_eq!(content_type(Path::new("a.wasm")), "application/wasm");
        assert_eq!(
            content_type(Path::new("a.unknownext")),
            "application/octet-stream"
        );
    }

    #[test]
    fn percent_decoding_handles_escapes_and_plus() {
        assert_eq!(percent_decode("a%20b"), "a b");
        assert_eq!(percent_decode("a+b"), "a b");
        assert_eq!(percent_decode("%zz"), "%zz");
    }
}
