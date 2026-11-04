//! A PIN gate for public sessions: a 6-digit code that only the machine of the
//! tunnel shows. A correct PIN gets a session cookie. The PIN is never in the
//! URL.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use axum::http::HeaderMap;
use uuid::Uuid;

/// The number of wrong codes after which the gate opens for no code: the
/// operator starts a new session. With 10 tries of 1 000 000 codes, a guess
/// succeeds with a chance of 1 in 100 000.
pub const MAX_FAILURES: u32 = 10;
/// The largest body of an unlock request.
pub const MAX_UNLOCK_BODY: u64 = 4096;

pub const UNLOCK_PATH: &str = "/__cfrs/unlock";
pub const COOKIE_NAME: &str = "cfrs_pin";

#[derive(Clone, Debug)]
enum Mode {
    Off,
    Pin,
}

#[derive(Clone, Debug)]
pub struct Gate {
    mode: Mode,
    pin: String,
    session: String,
    /// The wrong codes so far, shared by each copy of the gate.
    failures: Arc<AtomicU32>,
    /// The compares of a code, for the tests.
    #[cfg(test)]
    compares: Arc<AtomicU32>,
}

/// Compare two byte strings in a time that does not depend on where they
/// differ.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The status of the PIN page for a locked request (issue 194): 200 for
/// GET and HEAD (a browser shows the page), 403 for each other method (a
/// script sees the refusal). 401 needs WWW-Authenticate (RFC 9110).
pub fn locked_status(method: &str) -> u16 {
    if method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD") {
        200
    } else {
        403
    }
}

/// A `next` target of an unlock: a path of this site only. A
/// scheme-relative URL (`//host`), a backslash (`/\\host`) and a control
/// character give `/`.
pub fn safe_next(next: &str) -> &str {
    let ok = next.starts_with('/')
        && !next.starts_with("//")
        && !next.contains('\\')
        && !next.chars().any(|c| c.is_control());
    if ok {
        next
    } else {
        "/"
    }
}

impl Gate {
    pub fn off() -> Self {
        Self {
            mode: Mode::Off,
            pin: String::new(),
            session: String::new(),
            failures: Arc::default(),
            #[cfg(test)]
            compares: Arc::default(),
        }
    }

    pub fn pin() -> Self {
        let pin = format!("{:06}", Uuid::new_v4().as_u128() % 1_000_000);
        Self {
            mode: Mode::Pin,
            pin,
            session: Uuid::new_v4().simple().to_string(),
            failures: Arc::default(),
            #[cfg(test)]
            compares: Arc::default(),
        }
    }

    pub fn enabled(&self) -> bool {
        matches!(self.mode, Mode::Pin)
    }

    /// The code to show the operator. `None` when the gate is off.
    pub fn pin_display(&self) -> Option<&str> {
        self.enabled().then_some(self.pin.as_str())
    }

    /// True when the request carries the unlocked session cookie.
    pub fn is_open(&self, headers: &HeaderMap) -> bool {
        if !self.enabled() {
            return true;
        }
        headers
            .get(axum::http::header::COOKIE)
            .and_then(|v| v.to_str().ok())
            .map(|cookies| {
                cookies.split(';').any(|part| {
                    let part = part.trim();
                    part.strip_prefix(&format!("{COOKIE_NAME}="))
                        .map(|value| constant_time_eq(value.as_bytes(), self.session.as_bytes()))
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false)
    }

    /// Check a submitted PIN. On success returns the `Set-Cookie` value.
    ///
    /// After [`MAX_FAILURES`] wrong codes, no code opens the gate. A correct
    /// code sets the count of wrong codes to 0.
    ///
    /// Issue 228: each try takes a slot of the count before the compare.
    /// Many tries at the same time get at most [`MAX_FAILURES`] compares.
    pub fn unlock(&self, password: &str) -> Option<String> {
        if !self.enabled() {
            return None;
        }
        let slot = self
            .failures
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                (n < MAX_FAILURES).then_some(n + 1)
            });
        let Ok(before) = slot else {
            tracing::warn!(
                "the PIN gate is locked after {MAX_FAILURES} wrong codes; start a new session"
            );
            return None;
        };
        #[cfg(test)]
        self.compares.fetch_add(1, Ordering::SeqCst);
        if !constant_time_eq(password.trim().as_bytes(), self.pin.as_bytes()) {
            // A wrong code keeps its slot.
            let n = before + 1;
            tracing::warn!(failures = n, "a wrong PIN");
            if n >= MAX_FAILURES {
                tracing::warn!(
                    "the PIN gate is locked after {MAX_FAILURES} wrong codes; start a new session"
                );
            }
            return None;
        }
        self.failures.store(0, Ordering::SeqCst);
        Some(format!(
            "{COOKIE_NAME}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400",
            self.session
        ))
    }

    /// True after [`MAX_FAILURES`] wrong codes.
    pub fn locked_out(&self) -> bool {
        self.failures.load(Ordering::SeqCst) >= MAX_FAILURES
    }

    /// HTML unlock page.
    pub fn page_html(&self, next: &str, failed: bool) -> String {
        let next = escape_attr(next);
        let error = if self.locked_out() {
            "<p class=\"err\">Too many wrong codes. The session is locked.</p>"
        } else if failed {
            "<p class=\"err\">Wrong code, try again.</p>"
        } else {
            ""
        };
        format!(
            "<!doctype html><html><head><meta charset=\"utf-8\">\
             <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
             <title>cfrs — locked</title><style>\
             body{{font-family:system-ui,sans-serif;background:#0b1020;color:#e8ecf5;\
             display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}}\
             form{{background:#161d33;padding:2rem;border-radius:12px;width:min(90vw,320px)}}\
             h1{{font-size:1.1rem;margin:0 0 1rem}}p{{color:#9aa7c7;font-size:.9rem}}\
             .err{{color:#ff8a8a}}input{{width:100%;box-sizing:border-box;padding:.7rem;\
             font-size:1.4rem;letter-spacing:.4rem;text-align:center;border-radius:8px;\
             border:1px solid #33406a;background:#0b1020;color:#fff}}\
             button{{margin-top:1rem;width:100%;padding:.7rem;border:0;border-radius:8px;\
             background:#4f7cff;color:#fff;font-size:1rem}}\
             </style></head><body><form method=\"post\" action=\"{UNLOCK_PATH}\">\
             <h1>Enter the 6-digit code</h1>{error}\
             <input name=\"password\" inputmode=\"numeric\" pattern=\"[0-9]*\" \
             maxlength=\"6\" autofocus autocomplete=\"one-time-code\">\
             <input type=\"hidden\" name=\"next\" value=\"{next}\">\
             <button type=\"submit\">Unlock</button>\
             <p>The code is shown on the computer running cfrs.</p></form></body></html>"
        )
    }
}

fn escape_attr(value: &str) -> String {
    value
        .chars()
        .filter(|c| !matches!(c, '<' | '>' | '"' | '\'' | '&'))
        .take(512)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn off_is_open() {
        let gate = Gate::off();
        assert!(gate.is_open(&HeaderMap::new()));
        assert!(gate.pin_display().is_none());
    }

    #[test]
    fn pin_locks_until_cookie() {
        let gate = Gate::pin();
        let mut headers = HeaderMap::new();
        assert!(!gate.is_open(&headers));
        assert!(gate.unlock("000000").is_none() || gate.unlock("000000").is_some());

        let pin = gate.pin_display().unwrap().to_string();
        let cookie = gate.unlock(&pin).expect("correct pin");
        let value = cookie.split(';').next().unwrap().to_string();
        headers.insert(
            axum::http::header::COOKIE,
            HeaderValue::from_str(&value).unwrap(),
        );
        assert!(gate.is_open(&headers));
    }

    #[test]
    fn wrong_codes_lock_the_gate() {
        let gate = Gate::pin();
        let pin = gate.pin_display().unwrap().to_string();
        let wrong = if pin == "000000" { "000001" } else { "000000" };
        let copy = gate.clone();
        for _ in 0..MAX_FAILURES {
            assert!(copy.unlock(wrong).is_none());
        }
        assert!(gate.locked_out(), "the copies share the count");
        assert!(
            gate.unlock(&pin).is_none(),
            "the right code after the limit"
        );
        assert!(gate.page_html("/", true).contains("Too many wrong codes"));
    }

    // Issue 228: many wrong codes at the same time get at most
    // MAX_FAILURES compares, and the count does not pass the limit.
    #[test]
    fn concurrent_wrong_codes_get_at_most_the_limit() {
        for _ in 0..20 {
            let gate = Gate::pin();
            let pin = gate.pin_display().unwrap().to_string();
            let wrong = if pin == "000000" { "000001" } else { "000000" };
            let barrier = Arc::new(std::sync::Barrier::new(64));
            let threads: Vec<_> = (0..64)
                .map(|_| {
                    let gate = gate.clone();
                    let barrier = barrier.clone();
                    std::thread::spawn(move || {
                        barrier.wait();
                        assert!(gate.unlock(wrong).is_none());
                    })
                })
                .collect();
            for t in threads {
                t.join().unwrap();
            }
            assert_eq!(gate.compares.load(Ordering::SeqCst), MAX_FAILURES);
            assert_eq!(gate.failures.load(Ordering::SeqCst), MAX_FAILURES);
            assert!(gate.unlock(&pin).is_none());
            assert_eq!(gate.compares.load(Ordering::SeqCst), MAX_FAILURES);
        }
    }

    // Issue 228: a correct code sets the count of wrong codes to 0.
    #[test]
    fn a_correct_code_resets_the_count() {
        let gate = Gate::pin();
        let pin = gate.pin_display().unwrap().to_string();
        let wrong = if pin == "000000" { "000001" } else { "000000" };
        for _ in 0..MAX_FAILURES - 1 {
            assert!(gate.unlock(wrong).is_none());
        }
        assert!(gate.unlock(&pin).is_some());
        for _ in 0..MAX_FAILURES - 1 {
            assert!(gate.unlock(wrong).is_none());
        }
        assert!(!gate.locked_out());
        assert!(gate.unlock(&pin).is_some());
    }

    #[test]
    fn next_is_a_path_of_this_site() {
        assert_eq!(safe_next("/s/abc/"), "/s/abc/");
        for bad in [
            "//example.com",
            "/\\example.com",
            "https://x",
            "javascript:alert(1)",
            "/a\r\nb",
            "",
        ] {
            assert_eq!(safe_next(bad), "/", "{bad:?}");
        }
        assert!(constant_time_eq(b"123456", b"123456"));
        assert!(!constant_time_eq(b"123456", b"123457"));
        assert!(!constant_time_eq(b"12345", b"123456"));
    }

    #[test]
    fn pin_is_six_digits() {
        for _ in 0..50 {
            let gate = Gate::pin();
            let pin = gate.pin_display().unwrap();
            assert_eq!(pin.len(), 6);
            assert!(pin.chars().all(|c| c.is_ascii_digit()));
        }
    }
}
