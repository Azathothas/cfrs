#!/bin/sh
# The short release check: run a release binary of podnet on its own platform.
#
#   sh scripts/release-short.sh BINARY [--net]
#
# Offline: the version (with the commit of PODNET_BUILD_COMMIT when it is set),
# the help, the address plan and the in-process TCP proof of the userspace
# stack, and the podnet pod doctor (exit 0, or 3 when no backend can run in
# this container). With --net: a quick tunnel that serves the built-in
# origin, and a fetch of its public URL (three attempts, because the
# quick-tunnel service can refuse a burst).
set -eu

bin=${1:?usage: release-short.sh BINARY [--net]}
net=${2:-}

version=$("$bin" --version)
echo "version: $version"
case "$version" in
    "podnet "*) ;;
    *) echo "the version line does not start with 'podnet '" >&2; exit 1 ;;
esac
if [ -n "${PODNET_BUILD_COMMIT:-}" ]; then
    case "$version" in
        *"($PODNET_BUILD_COMMIT)") ;;
        *) echo "the version line does not name the commit $PODNET_BUILD_COMMIT" >&2; exit 1 ;;
    esac
fi
"$bin" --help > /dev/null
"$bin" net addresses > /dev/null
"$bin" net demo | grep -q '^PROOF'
echo "net demo: ok"
rc=0
"$bin" pod doctor --json > /dev/null || rc=$?
case "$rc" in
    0 | 3) echo "pod doctor: exit $rc" ;;
    *) echo "pod doctor: exit $rc" >&2; exit 1 ;;
esac

if [ "$net" = --net ]; then
    for try in 1 2 3; do
        if timeout 240 "$bin" demo --exit-on-verify; then
            echo "quick tunnel: ok"
            exit 0
        fi
        echo "quick tunnel: attempt $try failed" >&2
        sleep 20
    done
    echo "quick tunnel: failed three times" >&2
    exit 1
fi
