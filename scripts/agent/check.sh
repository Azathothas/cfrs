#!/bin/sh
# The checks of CLAUDE.md before each push: fmt, clippy and the tests, the
# check of the work record (cargo todo check), the size of the Rust files
# (scripts/check-size.py) and the layers of the modules
# (scripts/check-layers.py). Print each exit code, and the first faults;
# exit 1 on a fault. With the argument notest, the tests are skipped.
#
#   sh scripts/agent/check.sh [notest]
set -u
cd "$(dirname "$0")/../.." || exit 1
log=${TMPDIR:-/tmp}/podnet-check
mkdir -p "$log"
rc=0
cargo fmt --all --check > "$log/fmt.log" 2>&1; f=$?
echo "fmt $f"; [ "$f" -eq 0 ] || { rc=1; head -20 "$log/fmt.log"; }
cargo clippy --workspace --all-targets -- -D warnings > "$log/clippy.log" 2>&1; c=$?
echo "clippy $c"; [ "$c" -eq 0 ] || { rc=1; grep -E "^(error|warning)" -A6 "$log/clippy.log" | head -40; }
cargo run -q -p podnet-todo -- check > "$log/record.log" 2>&1; r=$?
echo "record $r"; [ "$r" -eq 0 ] || { rc=1; head -20 "$log/record.log"; }
python3 -I scripts/check-size.py > "$log/size.log" 2>&1; s=$?
echo "size $s"; [ "$s" -eq 0 ] || { rc=1; grep -v "^check-size:" "$log/size.log" | head -20; }
python3 -I scripts/check-layers.py > "$log/layers.log" 2>&1; l=$?
echo "layers $l"; [ "$l" -eq 0 ] || { rc=1; grep -v "^check-layers:" "$log/layers.log" | head -20; }
if [ "${1:-}" != notest ]; then
    timeout 1500 cargo test --workspace > "$log/test.log" 2>&1; t=$?
    echo "test $t"; [ "$t" -eq 0 ] || { rc=1; grep -E "FAILED|panicked|failed" "$log/test.log" | head -30; }
fi
exit "$rc"
