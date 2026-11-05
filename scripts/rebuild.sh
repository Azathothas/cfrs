#!/bin/sh
# Rebuild the binaries of a release and compare them with its SHA256SUMS
# (issue 162).
#
#   sh scripts/rebuild.sh TAG [TARGET]
#
# TARGET is x86_64-unknown-linux-musl or aarch64-unknown-linux-musl (the
# targets that release.yml builds in the pinned image of images/build), by
# default the one of this machine. The script needs git, curl, sha256sum
# and docker (or podman: CONTAINER=podman).
#
# The source is the tag, in a new directory at a path that is not the one
# of release.yml (/work), and the build runs in the image of
# images/build/Dockerfile of the tag, pinned to a digest, with the same
# command and variables as release.yml. The binary must have the SHA-256
# of SHA256SUMS. Exit 0 when it matches, 1 when it does not.
set -eu

tag=${1:?usage: rebuild.sh TAG [TARGET]}
case "$(uname -m)" in
    x86_64 | amd64) host=x86_64-unknown-linux-musl ;;
    aarch64 | arm64) host=aarch64-unknown-linux-musl ;;
    *) host="" ;;
esac
target=${2:-$host}
case "$target" in
    x86_64-unknown-linux-musl | aarch64-unknown-linux-musl) ;;
    *)
        echo "rebuild.sh: give TARGET x86_64-unknown-linux-musl or aarch64-unknown-linux-musl" >&2
        exit 64
        ;;
esac
[ "$target" = "$host" ] || echo "rebuild.sh: $target on a $(uname -m) host runs the image under emulation" >&2
repo=${PODNET_REPO:-PodUtils/podnet}
engine=${CONTAINER:-docker}

dir=$(mktemp -d)
cleanup() { rm -rf "$dir" 2> /dev/null || true; }
trap cleanup EXIT INT TERM

# A path of its own: a binary that kept the path of its source would
# differ here.
src="$dir/rebuild-of-$tag"
git clone --quiet --depth 1 --branch "$tag" "https://github.com/$repo" "$src"
commit=$(git -C "$src" rev-parse HEAD)
image=$(tr -d '\r' < "$src/images/build/Dockerfile" |
    sed -n 's/^FROM[[:space:]]\{1,\}\([^[:space:]]\{1,\}\).*/\1/p')
case "$image" in
    *@sha256:*) ;;
    *)
        echo "rebuild.sh: images/build/Dockerfile of $tag names no image pinned to a digest" >&2
        exit 1
        ;;
esac
echo "rebuild.sh: $tag ($commit), $target, in $image"
if [ "$engine" = docker ] && [ -f "$src/scripts/pull-image.sh" ]; then
    image=$(sh "$src/scripts/pull-image.sh" "$image")
else
    "$engine" pull "$image" > /dev/null
fi

# The command of release.yml, at another path in the container.
"$engine" run --rm -v "$src:/rebuild/$tag" -w "/rebuild/$tag" \
    -e CARGO_BUILD_JOBS=4 -e RUSTFLAGS=-Ctarget-feature=+crt-static \
    -e PODNET_BUILD_COMMIT="$commit" \
    "$image" \
    cargo build --locked --release --target "$target"
# The container wrote target/ as root: give it back to this user, so that
# the cleanup can remove it.
"$engine" run --rm -v "$src:/rebuild/$tag" "$image" \
    chown -R "$(id -u):$(id -g)" "/rebuild/$tag" || true

curl -fsSL -o "$dir/SHA256SUMS" "https://github.com/$repo/releases/download/$tag/SHA256SUMS"
failed=0
b=podnet
want=$(awk -v f="$b-$target" '$2 == f { print $1 }' "$dir/SHA256SUMS")
got=$(sha256sum "$src/target/$target/release/$b" | cut -d ' ' -f 1)
if [ -n "$want" ] && [ "$got" = "$want" ]; then
    echo "same   $b-$target $got"
else
    echo "DIFF   $b-$target: rebuilt $got, SHA256SUMS ${want:-none}"
    if command -v objdump > /dev/null 2>&1; then
        objdump -h "$src/target/$target/release/$b" | sed -n '1,40p'
    fi
    failed=1
fi
if [ "$failed" = 0 ]; then
    echo "rebuild.sh: the binaries of $tag are reproduced"
fi
exit "$failed"
