# Issues

Each GitHub issue of the record, with its entries. The State starts with the
state on GitHub: `open`, `closed` or `deleted`. `TODO/github.txt` lists the
numbers: each number from #311 on, and each open number before #311. The
record does not hold the closed issues before #311; their text is on GitHub
or in `docs/reports/`. `TODO/RULES.md` gives the rules.

| Issue | Subject | State | Entries |
| --- | --- | --- | --- |
| #89 | tracking: dev work in a sandbox with basic networking, and launch once and forget | open (deferred: the tracking issue of the owner) | T-001 |
| #140 | warp proxy: add --l4, one HTTP/3 CONNECT per flow, no IP stack | open (deferred: a captured request of an official client) | T-002 |
| #149 | warp: enrol through a Zero Trust team token | open (deferred: a captured exchange of the official client) | T-003 |
| #151 | tls: send an encrypted ClientHello on the hops that publish a config | open (deferred: no HPKE in ring, no ECH config on the hops) | T-004 |
| #161 | Publish the library and the CLI on crates.io (deferred) | open (deferred: publish nothing now) | T-005 |
| #222 | crates.io: the workspace version is a prerelease, and the beta requirement cannot match a stable pod-netns | open (deferred: the first stable release) | T-006 |
| #224 | crates.io: the crate name cfrs is registered to another project | closed (the owner chose and reserved `podnet`) | T-007 |
| #311 | live: two runs in a row failed | closed | T-136 |
| #316 | live: two runs in a row failed | closed | T-138 |
| #317 | COORD-001: a test of the fallback channel | closed (a COORD issue between sessions; no work) | none |
| #319 | [gh action] requested: a run of ci.yml | closed (a request of a run; run 42183709673) | none |
| #320 | COORD-002: podnet took pod-dns and pod-services of v0.4.0 | open (a COORD issue between sessions) | T-137 |
| #321 | COORD-003: podnet moved each podcrates tag to v0.5.0 | open (a COORD issue between sessions) | T-137 |
| #322 | COORD-004: pod-dns: name the DoH server in the debug line | open (a COORD issue between sessions) | T-137 |
| #323 | [gh action] requested: a run of ci.yml | closed (run 42222918056 at 61c70aa: success) | none |
| #324 | [gh action] requested: a run of live.yml | closed (run 42222905277 at 61c70aa: failure, T-141) | none |
| #325 | live: two runs in a row failed | closed (live run 42226303514 at 3db91c7) | T-141 |
| #326 | [gh action] requested: a run of live.yml | closed (run 42226303514 at 3db91c7: success) | none |
| #327 | [gh action] requested: a run of ci.yml | closed (run 42245546264 at 581e4a5: success) | none |

#312 to #315 and #318 are pull requests.
