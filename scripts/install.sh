#!/bin/sh
# Install the static Linux binary of cfrs from a GitHub release (issue 160).
#
#   s=$(curl -fsSL https://raw.githubusercontent.com/Azathothas/cfrs/main/scripts/install.sh) && sh -c "$s"
#   s=$(wget -qO- https://raw.githubusercontent.com/Azathothas/cfrs/main/scripts/install.sh) && sh -c "$s"
#
# Do not use `curl ... | sh` in a script: a pipe has the exit status of sh,
# and sh exits 0 when curl fails (issue 165).
#
# The script is POSIX sh. It finds a downloader (curl, wget, aria2c,
# httpie, python3, python, perl, and last busybox wget, which does not check
# TLS certificates: a warning says so), the target of this machine, and
# the release. It checks the binary against SHA256SUMS of the release
# (sha256sum, shasum, openssl, busybox or python), and the cosign signature
# of SHA256SUMS when cosign is installed. It runs the new binary in the
# install directory; only then does it replace the old binary.
#
# Variables:
#   CFRS_VERSION       The release: latest (the newest, also a prerelease;
#                      the default), or a tag (v0.3.0-beta.7, or 0.3.0-beta.7).
#                      latest reads the GitHub API, else releases.atom (no
#                      quota). A tag needs neither.
#   CFRS_INSTALL_DIR   The directory of the binary. Default: /usr/local/bin
#                      for root, else $XDG_BIN_HOME, else ~/.local/bin.
#   CFRS_POD_NETNS=1   Also install pod-netns.
#   CFRS_REPO          OWNER/NAME of the releases (Azathothas/cfrs).
#   CFRS_NO_VERIFY=1   Install with no SHA256 check (no tool for it).
#   CFRS_DOWNLOADER    Use this downloader (one of the list above).
#   GITHUB_TOKEN       Sent to api.github.com only (curl, wget), for its
#   GH_TOKEN           quota on a shared address. Not sent to other hosts.
#   NO_COLOR           No colors.
#   DEBUG              set -x.
#
# INT, TERM and HUP stop the script and remove its files. SIGKILL cannot be
# caught: a temporary directory can then stay.
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
    if ! downloader=$(detect_downloader); then
        if [ -n "${CFRS_DOWNLOADER:-}" ]; then
            fail "CFRS_DOWNLOADER=$CFRS_DOWNLOADER: not found or not usable (valid: curl wget aria2c http python3 python perl busybox)"
        fi
        fail "no downloader: install curl or wget"
    fi
    info "downloader: $downloader; target: $target"
    warn_insecure

    # The directory first: a bad directory fails before the downloads.
    dir=$(install_dir)

    tmp=$(make_temp)
    new_files=
    trap cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    trap 'exit 129' HUP

    tag=$(resolve_tag "$version")
    base="https://github.com/$repo/releases/download/$tag"
    info "release: $tag"

    names="cfrs"
    if [ "${CFRS_POD_NETNS:-}" = 1 ]; then names="cfrs pod-netns"; fi

    get "$base/SHA256SUMS" "$tmp/SHA256SUMS" SHA256SUMS
    verify_signature "$base" "$tmp"
    for name in $names; do
        file="$name-$target"
        get "$base/$file" "$tmp/$file" "$file"
        check_sum "$tmp/SHA256SUMS" "$tmp" "$file"
    done

    # A copy in the directory, a run of the copy, then a rename: a binary
    # that does not run does not replace the old one (issues 169, 175), and a
    # running binary is not changed in place. The run is in the directory of
    # the binary, because /tmp is often noexec.
    for name in $names; do
        file="$name-$target"
        new="$dir/.$name.new.$$"
        new_files="$new_files $new"
        chmod 0755 "$tmp/$file"
        cp "$tmp/$file" "$new"
        if ! shown=$(run_version "$new"); then
            fail "$file does not run on this machine (uname -m: $(uname -m 2> /dev/null || echo unknown)); $dir/$name is not changed"
        fi
        if [ "$name" = cfrs ]; then version_line=$shown; fi
    done
    for name in $names; do
        mv -f "$dir/.$name.new.$$" "$dir/$name"
        ok "installed $dir/$name"
    done
    new_files=
    printf '%s\n' "$version_line"
    path_hint "$dir"
}

# Remove the files of this run.
cleanup() {
    rm -rf "$tmp"
    # shellcheck disable=SC2086 # a list of paths with no spaces of ours
    [ -z "${new_files:-}" ] || rm -f $new_files
}

# The output of FILE --version, with no stdin, in at most 10 s.
run_version() {
    if command -v timeout > /dev/null 2>&1; then
        timeout 10 "$1" --version < /dev/null
    else
        "$1" --version < /dev/null
    fi
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

# True when busybox has TLS (its ssl_client helper): a busybox wget with no
# TLS sends an https URL as plain HTTP (issue 174).
busybox_tls() {
    busybox --list 2> /dev/null | grep -qx ssl_client || command -v ssl_client > /dev/null 2>&1
}

# The first downloader that this machine has. busybox wget goes last: it
# does not check TLS certificates (issue 174). A wget that is the busybox
# applet (Alpine) is busybox too.
detect_downloader() {
    for tool in ${CFRS_DOWNLOADER:-curl wget aria2c http python3 python perl busybox}; do
        if ! command -v "$tool" > /dev/null 2>&1; then continue; fi
        case "$tool" in
            wget)
                if wget --help 2>&1 | head -n 2 | grep -q BusyBox; then
                    busybox_tls || continue
                    echo wget-busybox
                    return 0
                fi
                ;;
            busybox)
                busybox wget --help > /dev/null 2>&1 || continue
                busybox_tls || continue
                ;;
            perl) perl -MHTTP::Tiny -e 'exit(HTTP::Tiny->can_ssl ? 0 : 1)' > /dev/null 2>&1 || continue ;;
        esac
        echo "$tool"
        return 0
    done
    return 1
}

# The warning of a downloader that does not check TLS certificates.
warn_insecure() {
    case "$downloader" in
        busybox | wget-busybox)
            warn "busybox wget does not check TLS certificates: a host on the path can change the files."
            if command -v cosign > /dev/null 2>&1; then
                warn "cosign checks the signature of SHA256SUMS, so a changed file is refused."
            else
                warn "SHA256SUMS comes the same way, so its check does not protect you. Install curl, wget, python3 or cosign, or check the binary with: sha256sum -c SHA256SUMS (from a trusted copy)."
            fi
            ;;
    esac
}

# Download URL to FILE with the downloader. HTTPS only. The status is the
# status of the downloader; a file that is empty is an error too.
fetch() {
    url=$1
    out=$2
    rm -f "$out"
    download "$url" "$out" || return $?
    [ -s "$out" ]
}

# Download URL to FILE for WHAT, or fail with a message that tells a
# missing file from a failed download.
get() {
    rc=0
    fetch "$1" "$2" || rc=$?
    [ "$rc" = 0 ] && return 0
    case "$downloader:$rc" in
        curl:22 | wget:8) fail "no $3 in $tag" ;;
    esac
    fail "the download of $3 failed (exit $rc of $downloader; is github.com reachable?): $1"
}

# A request to the GitHub API, with GITHUB_TOKEN or GH_TOKEN (curl and
# wget). The token goes to api.github.com only.
fetch_api() {
    token=${GITHUB_TOKEN:-${GH_TOKEN:-}}
    rm -f "$2"
    case "$downloader:${token:+t}" in
        curl:t) curl -fsSL --proto '=https' --tlsv1.2 -H "Authorization: Bearer $token" -o "$2" "$1" || return $? ;;
        wget:t) wget -q --https-only --header="Authorization: Bearer $token" -O "$2" "$1" || return $? ;;
        *) download "$1" "$2" || return $? ;;
    esac
    [ -s "$2" ]
}

# The download itself, by the downloader.
download() {
    url=$1
    out=$2
    case "$downloader" in
        curl) curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 --retry 3 -o "$out" "$url" ;;
        wget) wget -q --https-only -O "$out" "$url" ;;
        wget-busybox) wget -q -O "$out" "$url" ;;
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
# too (cfrs has prereleases only, and /releases/latest skips them). When
# the API fails (403 on a shared address, issue 166), releases.atom gives
# the newest tag.
resolve_tag() {
    case "$1" in
        latest)
            t=
            if fetch_api "https://api.github.com/repos/$repo/releases?per_page=1" "$tmp/releases.json" 2> "$tmp/api.err"; then
                t=$(tr ',' '\n' < "$tmp/releases.json" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)
            fi
            if [ -z "$t" ]; then
                info "the GitHub API did not answer; reading releases.atom"
                if fetch "https://github.com/$repo/releases.atom" "$tmp/releases.atom" 2> "$tmp/atom.err"; then
                    t=$(tr '>' '\n' < "$tmp/releases.atom" | sed -n 's#.*/releases/tag/\([^"<]*\)".*#\1#p' | head -n 1)
                fi
            fi
            if [ -z "$t" ]; then
                tail -n 3 "$tmp/api.err" "$tmp/atom.err" >&2 2> /dev/null || true
                fail "cannot read the releases of $repo (the API and releases.atom); set CFRS_VERSION=vX.Y.Z"
            fi
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
    get "$1/SHA256SUMS.sigstore.json" "$2/SHA256SUMS.sigstore.json" SHA256SUMS.sigstore.json
    if ! cosign verify-blob --bundle "$2/SHA256SUMS.sigstore.json" \
        --certificate-identity "https://github.com/$repo/.github/workflows/release.yml@refs/tags/$tag" \
        --certificate-oidc-issuer https://token.actions.githubusercontent.com \
        "$2/SHA256SUMS" > "$2/cosign.log" 2>&1; then
        tail -n 5 "$2/cosign.log" >&2
        fail "the cosign signature of SHA256SUMS is not valid (the lines above are the output of cosign)"
    fi
    ok "the cosign signature of SHA256SUMS: ok"
}

# True when DIR is a directory where this user can make a file. `[ -w ]`
# of busybox sh says yes for root on a read-only file system (issue 175).
writable_dir() {
    [ -d "$1" ] || return 1
    probe="$1/.cfrs-probe.$$"
    (: > "$probe") 2> /dev/null || return 1
    rm -f "$probe"
}

# The directory of the binary, as an absolute path.
install_dir() {
    if [ -n "${CFRS_INSTALL_DIR:-}" ]; then
        mkdir -p "$CFRS_INSTALL_DIR" 2> /dev/null || true
        writable_dir "$CFRS_INSTALL_DIR" ||
            fail "CFRS_INSTALL_DIR ($CFRS_INSTALL_DIR) is not a writable directory"
        (cd "$CFRS_INSTALL_DIR" && pwd -P)
        return 0
    fi
    if [ "$(id -u 2> /dev/null || echo 1)" = 0 ] && writable_dir /usr/local/bin; then
        echo /usr/local/bin
        return 0
    fi
    for d in "${XDG_BIN_HOME:-}" "${HOME:+$HOME/.local/bin}"; do
        [ -n "$d" ] || continue
        mkdir -p "$d" 2> /dev/null || true
        if writable_dir "$d"; then
            (cd "$d" && pwd -P)
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
