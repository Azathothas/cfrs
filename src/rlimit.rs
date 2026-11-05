//! The limit of open files (issue 126). A server command of podnet holds one
//! descriptor for each connection; the soft limit of a shell or a container
//! (often 1024) is then low. podnet raises the soft limit to the hard limit
//! at start, with a ceiling of [`CEILING`].

use std::sync::OnceLock;

/// The highest soft limit that podnet sets: a hard limit can be "unlimited".
pub const CEILING: u64 = 1 << 20;

/// The limit of open files, and the soft limit before podnet raised it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoFile {
    pub soft: u64,
    pub hard: u64,
    /// The soft limit before the raise, when podnet raised it.
    pub raised_from: Option<u64>,
}

static RAISED: OnceLock<Option<u64>> = OnceLock::new();

// rlim_t is not u64 on each target.
#[allow(clippy::unnecessary_cast)]
fn get() -> Option<(u64, u64)> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes one rlimit.
    (unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } == 0)
        .then_some((limit.rlim_cur as u64, limit.rlim_max as u64))
}

/// The soft limit that podnet sets for `soft` and `hard`.
pub fn target(soft: u64, hard: u64) -> u64 {
    hard.min(CEILING).max(soft)
}

/// Raise the soft limit to the hard limit (at most [`CEILING`]). Call it
/// once at start, not for a command that runs a program of the user: the
/// program gets the limit. A failure changes nothing.
pub fn raise() {
    let raised = (|| {
        let (soft, hard) = get()?;
        let want = target(soft, hard);
        if want == soft {
            return None;
        }
        let limit = libc::rlimit {
            rlim_cur: want as libc::rlim_t,
            rlim_max: hard as libc::rlim_t,
        };
        // SAFETY: setrlimit reads one rlimit.
        (unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) } == 0).then_some(soft)
    })();
    let _ = RAISED.set(raised);
}

/// The limit now.
pub fn now() -> Option<NoFile> {
    let (soft, hard) = get()?;
    Some(NoFile {
        soft,
        hard,
        raised_from: RAISED.get().copied().flatten(),
    })
}

/// The text for an error of too many open files (EMFILE, ENFILE), else
/// `None`.
pub fn hint(err: &std::io::Error) -> Option<String> {
    matches!(err.raw_os_error(), Some(libc::EMFILE) | Some(libc::ENFILE)).then(|| {
        let soft = now()
            .map(|n| n.soft.to_string())
            .unwrap_or_else(|| "?".into());
        format!("too many open files (the limit is {soft}); raise it with ulimit -n")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_target_is_the_hard_limit_with_a_ceiling() {
        assert_eq!(target(1024, 4096), 4096);
        assert_eq!(target(1024, u64::MAX), CEILING);
        assert_eq!(target(4096, 4096), 4096);
        assert_eq!(target(1 << 21, u64::MAX), 1 << 21);
    }

    #[test]
    fn the_hint_names_the_limit() {
        let err = std::io::Error::from_raw_os_error(libc::EMFILE);
        assert!(hint(&err).unwrap().contains("ulimit -n"));
        assert!(hint(&std::io::Error::from_raw_os_error(libc::ECONNREFUSED)).is_none());
    }
}
