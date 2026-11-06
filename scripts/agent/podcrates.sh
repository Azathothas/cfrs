#!/bin/sh
# The state of PodUtils/podcrates for podnet, with no message from the
# podcrates session (docs/maintenance.md, "Shared crates"). It reads the
# read-only mirror and raw.githubusercontent.com.
#
#   sh scripts/agent/podcrates.sh
#
# It prints: the releases of podcrates; the hand-offs for podnet
# (adoption/podnet/CRATE.patch on main); the files of podnet that a crate
# imported (the blocks `repo PodUtils/podnet` of crates/*/SOURCES), which
# are frozen until podnet takes the crate unless the block says `taken`;
# and the open COORD issues of podcrates.
set -u
api=https://forge.web.pkgforge.dev/github/repos/PodUtils/podcrates
raw=https://raw.githubusercontent.com/PodUtils/podcrates
n="n=$$$(date +%s)"

get() { curl -qfsSL "$1" 2> /dev/null; }

echo "== releases"
get "$api/releases?per_page=10&$n" |
    python3 -I -c 'import json,sys
for r in json.load(sys.stdin): print(r["tag_name"], r["published_at"])'

echo "== hand-offs for podnet (adoption/podnet on main)"
get "$api/contents/adoption/podnet?$n" |
    python3 -I -c 'import json,sys
for f in json.load(sys.stdin): print(f["name"])'
printf 'trial base (adoption/podnet/commit): '
get "$raw/main/adoption/podnet/commit" || echo "none"

echo "== files of podnet in the crates (crates/*/SOURCES)"
crates=$(get "$api/contents/crates?$n" |
    python3 -I -c 'import json,sys
for f in json.load(sys.stdin): print(f["name"])')
for c in $crates; do
    get "$raw/main/crates/$c/SOURCES" |
        awk -v c="$c" '
            /^repo / { inblock = ($2 == "PodUtils/podnet"); if (inblock) print c ": from podnet " $3; next }
            inblock && /^taken/ { print c ": " $0; next }
            inblock && /^(file|dir) / { print c ":   " ($1 == "file" ? $3 : $2) }'
done

echo "== open COORD issues of podcrates"
get "$api/issues?state=open&per_page=50&$n" |
    python3 -I -c 'import json,sys
for i in json.load(sys.stdin):
    if i["title"].startswith("COORD-"): print("#%d %s" % (i["number"], i["title"]))'
