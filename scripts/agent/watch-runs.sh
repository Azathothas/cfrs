#!/bin/sh
# Print each workflow run of a commit when it ends (with its failed jobs and
# steps), and exit when MIN_RUNS or more runs exist and each one ended.
#
#   sh scripts/agent/watch-runs.sh FULL_SHA [MIN_RUNS]
#
# FULL_SHA must have 40 characters: the API does not match a short SHA.
# A push to main starts ci, live, deny and secrets: MIN_RUNS 4.
set -u
sha=$1
min=${2:-1}
here=$(cd "$(dirname "$0")" && pwd)
[ "${#sha}" -eq 40 ] || { echo "watch-runs.sh: give the full SHA (git rev-parse HEAD)"; exit 2; }
api=https://forge.web.pkgforge.dev/github/repos/Azathothas/podnet/actions
done_ids=""
n=0
while true; do
    n=$((n + 1))
    body=$(curl -qfsS --max-time 30 "$api/runs?head_sha=$sha&per_page=50&n=$n$$" 2> /dev/null) || { sleep 45; continue; }
    out=$(printf '%s' "$body" | python3 -I "$here/runs.py" "$done_ids")
    total=0
    pending=1
    while read -r kind a b c d; do
        case "$kind" in
            RUN)
                done_ids="$done_ids $a"
                echo "$b run $a: $c $d"
                if [ "$c" != success ]; then
                    curl -qfsS --max-time 30 "$api/runs/$a/jobs?per_page=50&n=$$" 2> /dev/null |
                        python3 -I "$here/runs.py" --jobs
                fi
                ;;
            STATE) total=$a; pending=$b ;;
        esac
    done << LINES
$out
LINES
    if [ "$total" -ge "$min" ] && [ "$pending" -eq 0 ]; then
        echo "ALL DONE for $sha"
        exit 0
    fi
    sleep 45
done
