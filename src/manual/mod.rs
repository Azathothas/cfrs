//! `cfrs man`: the manual of this binary, generated from its command tree.
//!
//! The manual must be enough on a host that has only the binary: no man(1),
//! no groff, no pager, no network. Thus cfrs writes it itself, as plain text.
//! [`model::build`] makes it from the clap command tree, which `--help` also
//! uses, and from the tables of [`facts`] and [`crate::exit`]. The tests check
//! those tables against the code.
//!
//! * `cfrs man` pages the text on a terminal, else writes it to stdout.
//! * `--no-pager` writes it to stdout, also on a terminal.
//! * `--roff` writes a man(7) page, for `man -l -` or a man directory.
//! * `--json` writes the manual as one JSON object, for a program.
//! * `cfrs man SECTION` writes one section: a command (`tunnel`, `warp run`)
//!   or a topic (`environment`, `files`, `exit-status`, `examples`, `pod`).

pub mod facts;
pub mod model;
pub mod pager;
pub mod roff;
pub mod text;

use model::{Manual, TOPICS};

/// What the command line asked for.
#[derive(Clone, Debug, Default)]
pub struct Request {
    pub section: Option<String>,
    pub no_pager: bool,
    pub roff: bool,
    pub json: bool,
}

/// The bytes for `req`, or the refusal for a request that cannot be served.
pub fn body(manual: &Manual, req: &Request) -> Result<String, String> {
    if req.json && req.roff {
        return Err("--json and --roff are two forms of the manual; give one".into());
    }
    let Some(section) = req.section.as_deref() else {
        return Ok(if req.json {
            serde_json::to_string_pretty(manual).unwrap_or_default() + "\n"
        } else if req.roff {
            roff::render(manual)
        } else {
            text::render(manual)
        });
    };
    if let Some(c) = manual.command(section) {
        return Ok(if req.json {
            serde_json::to_string_pretty(c).unwrap_or_default() + "\n"
        } else if req.roff {
            roff::render_command(manual, c)
        } else {
            text::command(manual, c)
        });
    }
    let topic = section.to_ascii_lowercase().replace(' ', "-");
    let json =
        |value: serde_json::Value| serde_json::to_string_pretty(&value).unwrap_or_default() + "\n";
    match topic.as_str() {
        "environment" if req.json => Ok(json(serde_json::json!(manual.environment))),
        "files" if req.json => Ok(json(serde_json::json!(manual.files))),
        "exit-status" if req.json => Ok(json(serde_json::json!(manual.exit_status))),
        "examples" if req.json => Ok(json(serde_json::json!(manual.examples))),
        "pod" if req.json => Ok(json(serde_json::json!({ "usage": manual.pod_usage }))),
        "environment" | "files" | "exit-status" | "examples" | "pod" => {
            let body = match topic.as_str() {
                "environment" => text::environment(manual),
                "files" => text::files(manual),
                "exit-status" => text::exit_status(manual),
                "examples" => text::examples(manual),
                _ => text::fill(&manual.pod_usage, 4),
            };
            if req.roff {
                Ok(roff::render_section(manual, &topic, |out| {
                    out.push_str(".nf\n");
                    out.push_str(&roff::escape(&body));
                    out.push_str("\n.fi\n");
                }))
            } else {
                Ok(body)
            }
        }
        _ => Err(format!(
            "no section {section:?}. Sections: the commands ({}) and the topics ({})",
            manual
                .commands
                .iter()
                .filter(|c| !c.path.is_empty())
                .map(|c| c.name())
                .collect::<Vec<_>>()
                .join(", "),
            TOPICS.join(", ")
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> clap::Command {
        clap::Command::new("cfrs")
            .version("1.0 (abc)")
            .about("about cfrs")
            .subcommand(
                clap::Command::new("tunnel")
                    .about("Expose a service")
                    .arg(clap::Arg::new("url").long("url").help("HTTP origin"))
                    .arg(
                        clap::Arg::new("protocol")
                            .long("protocol")
                            .default_value("auto")
                            .value_parser(["auto", "quic", "http2"]),
                    ),
            )
            .subcommand(
                clap::Command::new("net").subcommand(
                    clap::Command::new("ts-shims").about("Write shims").arg(
                        clap::Arg::new("out")
                            .long("out")
                            .short('o')
                            .value_name("DIR"),
                    ),
                ),
            )
    }

    #[test]
    fn the_text_has_each_command_and_flag() {
        let m = model::build(sample());
        let t = text::render(&m);
        assert!(t.starts_with("CFRS(1)"));
        assert!(t.contains("cfrs tunnel"), "{t}");
        assert!(
            t.contains("--url <url>") || t.contains("--url <URL>"),
            "{t}"
        );
        assert!(t.contains("Default: auto."), "{t}");
        assert!(t.contains("Values: auto, quic, http2."), "{t}");
        assert!(t.contains("-o, --out <DIR>"), "{t}");
        assert!(t.contains("EXIT STATUS") && t.contains("64 (usage)"));
        assert!(
            t.lines().all(|l| l.len() <= text::WIDTH + 2),
            "a line is too long"
        );
        assert!(t.is_ascii());
    }

    #[test]
    fn sections_are_found_by_command_path_and_topic() {
        let m = model::build(sample());
        let req = |s: &str| Request {
            section: Some(s.into()),
            ..Request::default()
        };
        assert!(body(&m, &req("net ts-shims")).unwrap().contains("--out"));
        assert!(body(&m, &req("net/ts-shims")).unwrap().contains("--out"));
        assert!(body(&m, &req("exit-status"))
            .unwrap()
            .contains("78 (config)"));
        assert!(body(&m, &req("nothing"))
            .unwrap_err()
            .contains("no section"));
        let both = Request {
            roff: true,
            json: true,
            ..Request::default()
        };
        assert!(body(&m, &both).is_err());
    }

    #[test]
    fn the_roff_page_uses_standard_macros_and_escapes() {
        let m = model::build(sample());
        let r = roff::render(&m);
        assert!(r.starts_with(".TH CFRS 1"));
        for line in r.lines().filter(|l| l.starts_with('.')) {
            let mac = line.split_whitespace().next().unwrap();
            assert!(
                [
                    ".TH", ".SH", ".SS", ".TP", ".PP", ".RS", ".RE", ".nf", ".fi", ".B", ".I",
                    ".BR"
                ]
                .contains(&mac),
                "non-standard macro {mac}"
            );
        }
        assert!(r.contains("\\-\\-url"), "hyphens are escaped");
        assert_eq!(roff::escape(".x"), "\\&.x");
    }

    #[test]
    fn the_json_is_one_object_with_the_tables() {
        let m = model::build(sample());
        let j: serde_json::Value = serde_json::from_str(
            &body(
                &m,
                &Request {
                    json: true,
                    ..Request::default()
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert!(j["commands"].as_array().unwrap().len() >= 3);
        assert!(j["environment"].as_array().unwrap().len() > 5);
        assert_eq!(j["exit_status"][0]["code"], 0);
    }

    #[test]
    fn fill_keeps_the_width() {
        let long = "word ".repeat(100);
        for line in text::fill(&long, 8).lines() {
            assert!(line.len() <= text::WIDTH, "{}", line.len());
            assert!(line.starts_with("        word"));
        }
    }
}
