#!/bin/sh
# Run N trials of `cfrs demo --exit-on-verify` (a quick tunnel end to end),
# keep one log for each trial, and print the failure rate. Exit 1 when a
# trial failed.
#
#   N=200 sh scripts/soak.sh [BINARY] [-- ARGUMENTS OF cfrs demo]
set -u
bin=${1:-cfrs}
[ "$#" -gt 0 ] && shift
[ "${1:-}" = "--" ] && shift
n=${N:-20}
dir=${SOAK_DIR:-soak-$(date -u +%Y%m%dT%H%M%SZ)}
mkdir -p "$dir"
failed=0
i=1
while [ "$i" -le "$n" ]; do
    log="$dir/trial-$i.log"
    if RUST_LOG=${RUST_LOG:-cfrs=info} timeout "${SOAK_TIMEOUT:-180}" "$bin" demo --exit-on-verify "$@" > "$log" 2>&1; then
        echo "trial $i: ok"
    else
        failed=$((failed + 1))
        echo "trial $i: FAILED ($(grep '^cfrs: ' "$log" | head -1))"
    fi
    i=$((i + 1))
done
echo "soak: $failed of $n trials failed; the logs are in $dir"
[ "$failed" -eq 0 ]
