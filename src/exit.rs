//! Exit codes.
//!
//! [`TABLE`] is the one list of the exit codes. `podnet man exit-status`
//! renders it, and `main` maps each error to a code with [`code_of`].
//!
//! The codes follow sysexits.h, so that a script can tell the usage error of
//! podnet from the failure of another program:
//!
//! * 64 (`EX_USAGE`): a bad command line, before podnet does anything.
//! * 69 (`EX_UNAVAILABLE`): a service or a network path is not available:
//!   the edge, the quick-tunnel service, the WARP API or its MASQUE endpoint.
//! * 78 (`EX_CONFIG`): a configuration that cannot be used: a variable of the
//!   environment (for example `PODNET_EDGE`) or a configuration file.
//!
//! An error with no class exits 1. `podnet pod` and `podnet warp run` give the
//! status of the program that they run, and 3 when no backend can run it.

/// The class of a failure. Attach it to an error with [`fault`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// A bad command line.
    Usage,
    /// A service or a network path is not available.
    Unavailable,
    /// A configuration that cannot be used.
    Config,
    /// A service refused for now and says when to try again (issue 210:
    /// a quick-tunnel provision with HTTP 429).
    TempFail,
    /// A wait ended at its time limit (124, as timeout(1)).
    Timeout,
}

impl Fault {
    /// The exit code of this class.
    pub fn code(self) -> i32 {
        match self {
            Fault::Usage => USAGE,
            Fault::Unavailable => UNAVAILABLE,
            Fault::Config => CONFIG,
            Fault::TempFail => TEMPFAIL,
            Fault::Timeout => TIMEOUT,
        }
    }
}

pub const SUCCESS: i32 = 0;
pub const FAILURE: i32 = 1;
pub const NO_BACKEND: i32 = 3;
pub const USAGE: i32 = 64;
pub const UNAVAILABLE: i32 = 69;
pub const CONFIG: i32 = 78;
/// A refusal for now (EX_TEMPFAIL): a quick-tunnel provision with HTTP
/// 429 (issue 210), or `--detach` lost the pipe to its parent.
pub const TEMPFAIL: i32 = 75;
/// `--detach`: the instance was not ready in time (as timeout(1)).
pub const TIMEOUT: i32 = 124;

/// One row of the table of exit codes.
#[derive(Clone, Copy, Debug)]
pub struct ExitCode {
    pub code: i32,
    pub name: &'static str,
    pub meaning: &'static str,
}

/// Each exit code of podnet.
pub const TABLE: &[ExitCode] = &[
    ExitCode {
        code: SUCCESS,
        name: "success",
        meaning: "The command completed. A server command (tunnel, serve, share, proxy) exits 0 when it is stopped with Ctrl-C or when --run-for ends.",
    },
    ExitCode {
        code: FAILURE,
        name: "failure",
        meaning: "A failure that has no other code. With --check: a check of an origin or of the network failed (a bad flag or configuration has its own code).",
    },
    ExitCode {
        code: NO_BACKEND,
        name: "no-backend",
        meaning: "podnet pod and podnet warp run: no backend can run on this host, the program is not in PATH (or cannot run), or the setup of the backend failed. pod doctor gives 3 when no backend can run.",
    },
    ExitCode {
        code: USAGE,
        name: "usage",
        meaning: "A bad command line: an unknown command or flag, a missing or bad value. Nothing was done.",
    },
    ExitCode {
        code: UNAVAILABLE,
        name: "unavailable",
        meaning: "A service or a network path is not available: no edge leg worked, the quick-tunnel service, the WARP API or the MASQUE endpoint did not answer.",
    },
    ExitCode {
        code: TEMPFAIL,
        name: "tempfail",
        meaning: "The quick-tunnel service refused a provision for now (HTTP 429): the error report (PODNET_ERROR_PROGRAM) has retry_after_s. Also: --detach lost the pipe to the command that started it. Try again later.",
    },
    ExitCode {
        code: CONFIG,
        name: "config",
        meaning: "A configuration that cannot be used: a variable of the environment such as PODNET_EDGE, a configuration file given with --config, a tunnel token or a credentials file (as a flag or as a key of the file), or a roots file of --ca-file.",
    },
    ExitCode {
        code: TIMEOUT,
        name: "timeout",
        meaning: "--detach: the instance was not ready in --ready-timeout seconds (it is stopped), as timeout(1) exits.",
    },
];

/// An error with a [`Fault`] class. Its text is the text of the error.
#[derive(Debug)]
pub struct Faulted {
    pub fault: Fault,
    inner: anyhow::Error,
}

/// The text is the outermost message of the error; the causes come through
/// `source`, so that `{:#}` and the report give the whole chain.
impl std::fmt::Display for Faulted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl std::error::Error for Faulted {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.inner.source()
    }
}

/// Give `err` the class `fault`.
pub fn fault(fault: Fault, err: anyhow::Error) -> anyhow::Error {
    anyhow::Error::new(Faulted { fault, inner: err })
}

/// Extension for `Result`: `.fault(Fault::Config)`.
pub trait ResultExt<T> {
    fn fault(self, fault: Fault) -> anyhow::Result<T>;
}

impl<T, E: Into<anyhow::Error>> ResultExt<T> for Result<T, E> {
    fn fault(self, class: Fault) -> anyhow::Result<T> {
        self.map_err(|e| fault(class, e.into()))
    }
}

/// The exit code for `err`: the class of the outermost [`Faulted`] error in
/// its chain, else [`FAILURE`].
pub fn code_of(err: &anyhow::Error) -> i32 {
    err.chain()
        .find_map(|e| e.downcast_ref::<Faulted>())
        .map(|f| f.fault.code())
        .unwrap_or(FAILURE)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Issue 254: the table lists the codes in ascending order.
    #[test]
    fn the_codes_ascend() {
        assert!(TABLE.windows(2).all(|w| w[0].code < w[1].code));
    }
    use anyhow::Context;

    #[test]
    fn a_class_survives_context() {
        let err = fault(Fault::Config, anyhow::anyhow!("bad PODNET_EDGE"));
        let err = Err::<(), _>(err)
            .context("starting the tunnel")
            .unwrap_err();
        assert_eq!(code_of(&err), CONFIG);
        assert_eq!(format!("{err:#}"), "starting the tunnel: bad PODNET_EDGE");
        assert_eq!(code_of(&anyhow::anyhow!("plain")), FAILURE);
    }

    #[test]
    fn a_class_keeps_the_causes() {
        let cause = Err::<(), _>(std::io::Error::from(std::io::ErrorKind::ConnectionRefused))
            .context("connecting to 127.0.0.1:9")
            .context("provisioning quick tunnel")
            .unwrap_err();
        let err = fault(Fault::Unavailable, cause);
        assert_eq!(
            format!("{err:#}"),
            "provisioning quick tunnel: connecting to 127.0.0.1:9: connection refused"
        );
        assert_eq!(err.chain().count(), 3);
        assert_eq!(code_of(&err), UNAVAILABLE);
    }

    #[test]
    fn each_class_has_a_row_of_the_table() {
        for class in [Fault::Usage, Fault::Unavailable, Fault::Config] {
            assert!(TABLE.iter().any(|row| row.code == class.code()));
        }
        let mut codes: Vec<i32> = TABLE.iter().map(|r| r.code).collect();
        codes.dedup();
        assert_eq!(codes.len(), TABLE.len(), "no code is listed two times");
    }
}
