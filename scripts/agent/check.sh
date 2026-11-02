#!/bin/sh
# The checks of CLAUDE.md before each push: fmt, clippy and the tests. Print
# each exit code, and the first faults; exit 1 on a fault. With the argument
# notest, the tests are skipped.
#
#   sh scripts/agent/check.sh [notest]
set -u
cd "$(dirname "$0")/../.."
log=${TMPDIR:-/tmp}/cfrs-check
mkdir -p "$log"
rc=0
cargo fmt --all --check > "$log/fmt.log" 2>&1; f=$?
echo "fmt $f"; [ "$f" -eq 0 ] || { rc=1; head -20 "$log/fmt.log"; }
cargo clippy --workspace --all-targets -- -D warnings > "$log/clippy.log" 2>&1; c=$?
echo "clippy $c"; [ "$c" -eq 0 ] || { rc=1; grep -E "^(error|warning)" -A6 "$log/clippy.log" | head -40; }
if [ "${1:-}" != notest ]; then
    timeout 1500 cargo test --workspace > "$log/test.log" 2>&1; t=$?
    echo "test $t"; [ "$t" -eq 0 ] || { rc=1; grep -E "FAILED|panicked|failed" "$log/test.log" | head -30; }
fi
exit "$rc"
