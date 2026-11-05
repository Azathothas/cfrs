# podnet: the studies of 2026-11-05

These reports are the input of the plan in `TODO/` and of the rulings of
2026-11-05 in `docs/decisions.md`. They describe the code at commit
3bed023 (cfrs 0.3.0-beta.12 and one fix). Line numbers in them refer to
that commit. The record in `TODO/` is the plan; these reports are the
evidence behind it.

## The goal

* Rename the project `cfrs` to `podnet`. podnet is the main CLI and crate.
  The Cloudflare tunnel part becomes one adapter among others.
* The crate `pod-netns` becomes the netns crate of podnet (library only).
* podnet runs where cfrs runs (restricted sandboxes, containers with no
  `CAP_NET_ADMIN`, proxy-only egress) and gives networking there, with
  more networks and more features.
* With all the pieces, podnet is also a router, a file server, a file
  transfer tool and a git host.
* Overlay networks (Tailscale, Firezone and others) come later.
* Plan tracking is in the repository (the TODO model of podssh), not in
  GitHub issues.
* No feature or capability of the code may be lost. Compatibility for
  users of cfrs is not required (beta).
* One static binary for each target; no change by the server provider is
  necessary; the user brings the network; the defaults work.

## The reports

| Report | Subject |
| --- | --- |
| `rename.md` | Each place of the name, the self-update chain, the exact rename steps, a trial on a copy |
| `architecture.md` | File sizes, the module graph, the 8 crates, the adapter traits, the order of steps |
| `parity-checklist.md` | Each command, flag, variable, JSON document and live step, to tick after each step |
| `capabilities.md` | Router, file server, file transfer, git hosting: what exists, what is missing |
| `mwan-field.md` | The multi-WAN experiment, the lab kit bugs, the field report of beta.12 |
| `vn.md` | The vn virtual network prototype: what to port |
| `podssh.md` | The TODO model of podssh, its overlays, its conventions |
| `podssh-copy.md` | What podnet copies from podssh, and in which order |

The field report itself is in `docs/reports/field-report-2026-11-05.md`.
The attachments (the mwan program, the lab kit, the vn kit) are not in the
repository. The lab kit holds private keys of WARP devices.
