#!/bin/sh
# Check that each BINARY is static: no NEEDED entry and no program
# interpreter. Exit 1 at the first binary that is not static.
#
#   sh scripts/check-static.sh BINARY...
set -eu
[ "$#" -gt 0 ] || { echo "usage: check-static.sh BINARY..." >&2; exit 2; }
for b in "$@"; do
    if readelf -d "$b" 2> /dev/null | grep -q NEEDED; then
        echo "$b: dynamic dependencies:" >&2
        readelf -d "$b" | grep NEEDED >&2
        exit 1
    fi
    if readelf -l "$b" 2> /dev/null | grep -q INTERP; then
        echo "$b: asks for a program interpreter" >&2
        exit 1
    fi
    echo "static: $b ($(wc -c < "$b") bytes)"
done
