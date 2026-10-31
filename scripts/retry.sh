#!/bin/sh
# Run COMMAND up to 3 times, 10 s and then 20 s apart. A fault of the
# network (DNS, a mirror) does not stop a job at the first try.
#
#   sh scripts/retry.sh COMMAND [ARGUMENT...]
set -u
[ "$#" -gt 0 ] || { echo "usage: retry.sh COMMAND [ARGUMENT...]" >&2; exit 2; }
delay=10
for try in 1 2 3; do
    "$@" && exit 0
    rc=$?
    [ "$try" -eq 3 ] && { echo "retry.sh: $1 failed 3 times (exit $rc)" >&2; exit "$rc"; }
    echo "retry.sh: $1 failed (exit $rc); try $((try + 1)) in $delay s" >&2
    sleep "$delay"
    delay=$((delay * 2))
done
