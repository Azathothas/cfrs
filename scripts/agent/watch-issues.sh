#!/bin/sh
# Print one line for each new issue of PodUtils/podnet, each 60 s, without
# end (run it under the Monitor tool; re-arm it when the monitor expires).
# The first run records the issues that exist and prints nothing for them.
#
#   sh scripts/agent/watch-issues.sh [STATE_DIR]
#
# STATE_DIR keeps seen-issues.txt (default: $TMPDIR/podnet-agent). The reads
# go through forge.web.pkgforge.dev (the read-only GitHub API mirror of
# CLAUDE.md); the n= parameter defeats its cache.
set -u
here=$(cd "$(dirname "$0")" && pwd)
state=${1:-${TMPDIR:-/tmp}/podnet-agent}
mkdir -p "$state"
seen=$state/seen-issues.txt
touch "$seen"
n=0
while true; do
    n=$((n + 1))
    announce=0
    [ -s "$seen" ] && announce=1
    if body=$(curl -qfsS --max-time 30 "https://forge.web.pkgforge.dev/github/repos/PodUtils/podnet/issues?state=all&per_page=100&sort=created&direction=desc&n=$n$$" 2> /dev/null); then
        printf '%s' "$body" | python3 -I "$here/new-issues.py" "$seen" "$announce"
    fi
    sleep 60
done
