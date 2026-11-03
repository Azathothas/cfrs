#!/bin/sh
# Run a command in the IPv6-only namespace of scripts/v6only/up.sh, as the
# user that calls it, with no proxy variable (the proxies of the runner are
# on IPv4 and are not the network under test).
#
#   sh scripts/v6only/run.sh CMD [ARG...]
set -eu
exec sudo ip netns exec v6only sudo -u "$(id -un)" env \
    -u HTTPS_PROXY -u https_proxy -u HTTP_PROXY -u http_proxy \
    -u ALL_PROXY -u all_proxy -u NO_PROXY -u no_proxy \
    HOME="$HOME" PATH="$PATH" "$@"
