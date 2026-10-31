//! The command line of the cfrs binary: exit codes, usage messages and the
//! generated manual. No test here uses the network.

use std::process::{Command, Output};

fn cfrs(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_cfrs"))
        .args(args)
        .env_remove("CFRS_ERROR_PROGRAM")
        .env_remove("CFRS_EDGE")
        .env("PAGER", "cat")
        .output()
        .expect("cfrs runs")
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn help_and_version_exit_0() {
    for args in [&["--help"][..], &["--version"], &["tunnel", "--help"]] {
        let out = cfrs(args);
        assert_eq!(out.status.code(), Some(0), "cfrs {args:?}");
    }
}

#[test]
fn a_usage_error_exits_64() {
    let out = cfrs(&["tunel"]);
    assert_eq!(out.status.code(), Some(64));
}

/// A flag with no value and an unknown flag give different messages.
#[test]
fn a_missing_value_is_not_an_unknown_flag() {
    let missing = cfrs(&["tunnel", "--protocol"]);
    assert_eq!(missing.status.code(), Some(64));
    let text = stderr(&missing);
    assert!(
        text.contains("a value is required for '--protocol"),
        "{text}"
    );
    assert!(!text.contains("unexpected argument"), "{text}");

    let unknown = cfrs(&["tunnel", "--protocl", "quic"]);
    assert_eq!(unknown.status.code(), Some(64));
    let text = stderr(&unknown);
    assert!(text.contains("unexpected argument '--protocl'"), "{text}");
    assert!(
        text.contains("--protocol"),
        "clap names the nearest flag: {text}"
    );
}

#[test]
fn a_bad_configuration_exits_78() {
    let out = Command::new(env!("CARGO_BIN_EXE_cfrs"))
        .args(["tunnel", "--url", "http://127.0.0.1:9"])
        .env_remove("CFRS_ERROR_PROGRAM")
        .env("CFRS_EDGE", "not-an-address")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(78), "{}", stderr(&out));
    assert!(stderr(&out).contains("CFRS_EDGE"), "{}", stderr(&out));

    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing.yml");
    let out = cfrs(&["tunnel", "--config", missing.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(78), "{}", stderr(&out));
}

/// Each `.B` line of the man page has text, and each long flag of
/// `cfrs man --json` is in the page.
#[test]
fn the_man_page_names_each_flag() {
    let roff = cfrs(&["man", "--roff"]);
    assert_eq!(roff.status.code(), Some(0));
    let roff = String::from_utf8(roff.stdout).unwrap();
    for line in roff.lines() {
        if let Some(rest) = line.strip_prefix(".B") {
            if rest.is_empty() || rest.starts_with(' ') {
                assert!(!rest.trim().is_empty(), "an empty .B line");
            }
        }
    }

    let json = cfrs(&["man", "--json"]);
    assert_eq!(json.status.code(), Some(0));
    let json: serde_json::Value = serde_json::from_slice(&json.stdout).expect("valid JSON");
    let mut flags = 0;
    for command in json["commands"].as_array().unwrap() {
        for arg in command["args"].as_array().unwrap() {
            if arg["positional"] == false {
                let long = format!("\\-\\-{}", arg["id"].as_str().unwrap().replace('-', "\\-"));
                assert!(roff.contains(&long), "the man page has no {long}");
                flags += 1;
            }
        }
    }
    assert!(flags > 50, "only {flags} flags");

    let table = &json["exit_status"];
    for (code, name) in [
        (0, "success"),
        (64, "usage"),
        (69, "unavailable"),
        (78, "config"),
    ] {
        assert!(
            table
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["code"] == code && row["name"] == name),
            "no row {code} ({name})"
        );
    }
}

#[test]
fn ports_json_is_one_object() {
    let out = cfrs(&["ports", "--json"]);
    assert_eq!(out.status.code(), Some(0));
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
    assert!(json["ports"].is_array(), "{json}");
}
