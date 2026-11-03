#!/bin/sh
# Install the static Linux binary of cfrs from a GitHub release (issue 160).
#
#   curl -fsSL https://raw.githubusercontent.com/Azathothas/cfrs/main/scripts/install.sh | sh
#   wget -qO- https://raw.githubusercontent.com/Azathothas/cfrs/main/scripts/install.sh | sh
#
# The script is POSIX sh. It finds a downloader (curl, wget, busybox wget,
# aria2c, httpie, python3, python, perl), the target of this machine, and
# the release. It checks the binary against SHA256SUMS of the release
# (sha256sum, shasum, openssl, busybox or python), and the cosign signature
# of SHA256SUMS when cosign is installed. Then it installs the binary.
#
# Variables:
#   CFRS_VERSION       The release: latest (the newest, also a prerelease;
#                      the default), or a tag (v0.3.0-beta.7, or 0.3.0-beta.7).
#   CFRS_INSTALL_DIR   The directory of the binary. Default: $XDG_BIN_HOME,
#                      else ~/.local/bin, else /usr/local/bin for root.
#   CFRS_POD_NETNS=1   Also install pod-netns.
#   CFRS_REPO          OWNER/NAME of the releases (Azathothas/cfrs).
#   CFRS_NO_VERIFY=1   Install with no SHA256 check (no tool for it).
#   CFRS_DOWNLOADER    Use this downloader (one of the list above).
#   NO_COLOR           No colors.
#   DEBUG              set -x.
set -eu

main() {
    if [ -n "${DEBUG:-}" ]; then set -x; fi
    repo=${CFRS_REPO:-Azathothas/cfrs}
    version=${CFRS_VERSION:-latest}

    if [ -z "${NO_COLOR:-}" ] && [ -t 2 ]; then
        red=$(printf '\033[0;31m'); green=$(printf '\033[0;32m')
        yellow=$(printf '\033[0;33m'); blue=$(printf '\033[0;34m'); reset=$(printf '\033[0m')
    else
        red=; green=; yellow=; blue=; reset=
    fi

    if command -v hash > /dev/null 2>&1; then hash -r > /dev/null 2>&1 || true; fi

    case $(uname -s 2> /dev/null || echo unknown) in
        Linux) ;;
        *) fail "cfrs has Linux binaries only (this system: $(uname -s 2> /dev/null || echo unknown))" ;;
    esac

    target=$(detect_target)
    downloader=$(detect_downloader) || fail "no downloader: install curl or wget"
    info "downloader: $downloader; target: $target"

    tmp=$(make_temp)
    trap 'rm -rf "$tmp"' EXIT INT TERM HUP

    tag=$(resolve_tag "$version")
    base="https://github.com/$repo/releases/download/$tag"
    info "release: $tag"

    names="cfrs"
    if [ "${CFRS_POD_NETNS:-}" = 1 ]; then names="cfrs pod-netns"; fi

    fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS" || fail "no SHA256SUMS in $tag"
    verify_signature "$base" "$tmp"
    for name in $names; do
        file="$name-$target"
        fetch "$base/$file" "$tmp/$file" || fail "no $file in $tag"
        check_sum "$tmp/SHA256SUMS" "$tmp" "$file"
    done

    dir=$(install_dir)
    for name in $names; do
        file="$name-$target"
        chmod 0755 "$tmp/$file"
        # A copy in the directory, then a rename: a running binary is not
        # changed in place.
        cp "$tmp/$file" "$dir/.$name.new.$$"
        mv -f "$dir/.$name.new.$$" "$dir/$name"
        ok "installed $dir/$name"
    done
    "$dir/cfrs" --version || fail "$dir/cfrs does not run on this machine"
    path_hint "$dir"
}

info() { printf '%s\n' "${blue}cfrs install:${reset} $*" >&2; }
ok() { printf '%s\n' "${green}cfrs install:${reset} $*" >&2; }
warn() { printf '%s\n' "${yellow}cfrs install:${reset} $*" >&2; }
fail() {
    printf '%s\n' "${red}cfrs install: $*${reset}" >&2
    exit 1
}

# The Rust target of the release for this machine.
detect_target() {
    machine=$(uname -m 2> /dev/null || echo unknown)
    case "$machine" in
        x86_64 | amd64)
            # A 64-bit kernel can run a 32-bit system: the binary is
            # static, so the 64-bit one runs on both.
            echo x86_64-unknown-linux-musl ;;
        aarch64 | arm64 | armv8*) echo aarch64-unknown-linux-musl ;;
        armv7* | armhf) echo armv7-unknown-linux-musleabihf ;;
        armv6* | arm) echo arm-unknown-linux-musleabihf ;;
        i386 | i486 | i586 | i686 | x86) echo i686-unknown-linux-musl ;;
        riscv64) echo riscv64gc-unknown-linux-musl ;;
        ppc64le) echo powerpc64le-unknown-linux-musl ;;
        loongarch64 | loong64) echo loongarch64-unknown-linux-musl ;;
        *) fail "no cfrs binary for the machine $machine" ;;
    esac
}

# The first downloader that this machine has.
detect_downloader() {
    for tool in ${CFRS_DOWNLOADER:-curl wget busybox aria2c http python3 python perl}; do
        if ! command -v "$tool" > /dev/null 2>&1; then continue; fi
        case "$tool" in
            busybox) busybox wget --help > /dev/null 2>&1 || continue ;;
            perl) perl -MHTTP::Tiny -e 'exit(HTTP::Tiny->can_ssl ? 0 : 1)' > /dev/null 2>&1 || continue ;;
        esac
        echo "$tool"
        return 0
    done
    return 1
}

# Download URL to FILE with the downloader. HTTPS only.
fetch() {
    url=$1
    out=$2
    case "$downloader" in
        curl) curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o "$out" "$url" ;;
        wget) wget -q -O "$out" "$url" ;;
        busybox) busybox wget -q -O "$out" "$url" ;;
        aria2c) aria2c -q --allow-overwrite=true -d "$(dirname "$out")" -o "$(basename "$out")" "$url" ;;
        http) http --check-status -Fdq -o "$out" GET "$url" ;;
        python3 | python)
            "$downloader" -c 'import sys
try:
    from urllib.request import urlopen
except ImportError:
    from urllib2 import urlopen
data = urlopen(sys.argv[1], timeout=60).read()
open(sys.argv[2], "wb").write(data)' "$url" "$out" ;;
        perl)
            perl -MHTTP::Tiny -e 'my $r = HTTP::Tiny->new(verify_SSL => 1)->mirror($ARGV[0], $ARGV[1]);
exit($r->{success} ? 0 : 1)' "$url" "$out" ;;
        *) return 1 ;;
    esac
    [ -s "$out" ]
}

# A new private temporary directory.
make_temp() {
    if command -v mktemp > /dev/null 2>&1; then
        mktemp -d 2> /dev/null && return 0
    fi
    d="${TMPDIR:-/tmp}/cfrs-install.$$"
    (umask 077 && mkdir "$d") || fail "cannot make $d"
    echo "$d"
}

# The tag of VERSION: latest is the newest release of the API, prereleases
# too (cfrs has prereleases only, and /releases/latest skips them).
resolve_tag() {
    case "$1" in
        latest)
            fetch "https://api.github.com/repos/$repo/releases?per_page=1" "$tmp/releases.json" ||
                fail "cannot read the releases of $repo; set CFRS_VERSION=vX.Y.Z"
            t=$(tr ',' '\n' < "$tmp/releases.json" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)
            [ -n "$t" ] || fail "no release of $repo; set CFRS_VERSION=vX.Y.Z"
            echo "$t" ;;
        v*) echo "$1" ;;
        *) echo "v$1" ;;
    esac
}

# The SHA256 of FILE.
sha256_of() {
    if command -v sha256sum > /dev/null 2>&1; then
        sha256sum "$1" | cut -d ' ' -f 1
    elif command -v shasum > /dev/null 2>&1; then
        shasum -a 256 "$1" | cut -d ' ' -f 1
    elif command -v openssl > /dev/null 2>&1; then
        openssl dgst -sha256 "$1" | sed 's/^.*= *//'
    elif command -v busybox > /dev/null 2>&1 && busybox sha256sum "$1" > /dev/null 2>&1; then
        busybox sha256sum "$1" | cut -d ' ' -f 1
    elif command -v python3 > /dev/null 2>&1; then
        python3 -c 'import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$1"
    else
        return 1
    fi
}

# Check FILE in DIR against the SUMS file.
check_sum() {
    want=$(awk -v f="$3" '$2 == f || $2 == "*" f { print $1 }' "$1")
    [ -n "$want" ] || fail "$3 is not in SHA256SUMS"
    if ! got=$(sha256_of "$2/$3"); then
        if [ "${CFRS_NO_VERIFY:-}" = 1 ]; then
            warn "no SHA256 tool: $3 is not checked (CFRS_NO_VERIFY=1)"
            return 0
        fi
        fail "no SHA256 tool (sha256sum, shasum, openssl, busybox, python3); set CFRS_NO_VERIFY=1 to install with no check"
    fi
    [ "$got" = "$want" ] || fail "the SHA256 of $3 is $got, not $want"
    ok "SHA256 of $3: ok"
}

# The cosign signature of SHA256SUMS, when cosign is installed: the
# certificate must name release.yml of the repository at the tag.
verify_signature() {
    if ! command -v cosign > /dev/null 2>&1; then
        info "no cosign: the signature of SHA256SUMS is not checked (cfrs update checks it)"
        return 0
    fi
    fetch "$1/SHA256SUMS.sigstore.json" "$2/SHA256SUMS.sigstore.json" ||
        fail "no SHA256SUMS.sigstore.json in $tag"
    cosign verify-blob --bundle "$2/SHA256SUMS.sigstore.json" \
        --certificate-identity "https://github.com/$repo/.github/workflows/release.yml@refs/tags/$tag" \
        --certificate-oidc-issuer https://token.actions.githubusercontent.com \
        "$2/SHA256SUMS" > /dev/null 2>&1 || fail "the cosign signature of SHA256SUMS is not valid"
    ok "the cosign signature of SHA256SUMS: ok"
}

# The directory of the binary.
install_dir() {
    if [ -n "${CFRS_INSTALL_DIR:-}" ]; then
        mkdir -p "$CFRS_INSTALL_DIR" 2> /dev/null || true
        [ -d "$CFRS_INSTALL_DIR" ] && [ -w "$CFRS_INSTALL_DIR" ] ||
            fail "CFRS_INSTALL_DIR ($CFRS_INSTALL_DIR) is not a writable directory"
        echo "$CFRS_INSTALL_DIR"
        return 0
    fi
    if [ "$(id -u 2> /dev/null || echo 1)" = 0 ] && [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
        echo /usr/local/bin
        return 0
    fi
    for d in "${XDG_BIN_HOME:-}" "${HOME:+$HOME/.local/bin}"; do
        [ -n "$d" ] || continue
        mkdir -p "$d" 2> /dev/null || true
        if [ -d "$d" ] && [ -w "$d" ]; then
            echo "$d"
            return 0
        fi
    done
    fail "no writable directory for the binary; set CFRS_INSTALL_DIR"
}

# Say how to put DIR in PATH when it is not there.
path_hint() {
    case ":${PATH:-}:" in
        *":$1:"* | *":$1/:"*) ;;
        *)
            warn "$1 is not in PATH. Add this line to your shell profile:"
            printf '\n    export PATH="%s:$PATH"\n\n' "$1" >&2
            ;;
    esac
}

main "$@"
