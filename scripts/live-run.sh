#!/bin/sh
# Run a command of the live check and print its output with the tunnel
# hosts (not api.trycloudflare.com), the UUIDs and the WARP device ids
# masked: the log of CI is public. Do not send the stdout of this script to
# /dev/null: it holds the ::add-mask:: commands.
#
#   sh scripts/live-run.sh NAME COMMAND [ARGUMENT...]
#
# stdout goes to NAME.out and stderr to NAME.err. The script gives an
# ::add-mask:: command to GitHub Actions for each value, then prints the two
# files. The exit code is the exit code of COMMAND.
set -u
name=${1:?usage: live-run.sh NAME COMMAND [ARGUMENT...]}
shift
"$@" > "$name.out" 2> "$name.err"
rc=$?
cat "$name.out" "$name.err" |
    grep -oE '[a-z0-9-]+\.trycloudflare\.com|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|t\.[0-9a-f-]{8,}|ephm1\.[A-Za-z0-9._-]+' |
    grep -vxE 'api\.trycloudflare\.com' |
    sort -u |
    while read -r value; do
        echo "::add-mask::$value"
    done
cat "$name.out"
cat "$name.err" >&2
exit "$rc"
