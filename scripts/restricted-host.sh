#!/bin/sh
# Run the tests of the workspace as on a host that refuses bind(AF_INET)
# (issue 217). scripts/deny-bind.c is preloaded in each test binary (the
# cargo runner), not in cargo or rustc: bind() of AF_INET and AF_INET6
# fails with EACCES. A test that needs the loopback must skip
# (tests/test_host/mod.rs), not fail and not wait for a time limit.
#
#   sh scripts/restricted-host.sh [ARGUMENTS OF cargo test]
#
# Exit 1 when a test fails, or when no test skipped (the preload did not
# take effect).
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

cc -shared -fPIC -O2 -o "$work/deny-bind.so" "$root/scripts/deny-bind.c" -ldl
printf '#!/bin/sh\nLD_PRELOAD="%s${LD_PRELOAD:+:$LD_PRELOAD}" exec "$@"\n' "$work/deny-bind.so" > "$work/runner"
chmod +x "$work/runner"

host=$(rustc -vV | sed -n 's/^host: //p')
runner_variable="CARGO_TARGET_$(echo "$host" | tr 'a-z-' 'A-Z_')_RUNNER"

status=0
env "$runner_variable=$work/runner" cargo test --locked --workspace "$@" > "$work/test.log" 2>&1 || status=$?
cat "$work/test.log"

skips=$(grep -c '^skipping, this host denies bind(AF_INET)' "$work/test.log" || true)
echo "restricted-host: $skips tests skipped (bind(AF_INET) refused); cargo test exit $status"
if [ "$status" -ne 0 ]; then
    exit 1
fi
if [ "$skips" -eq 0 ]; then
    echo "restricted-host: no test skipped; the preload did not take effect"
    exit 1
fi
