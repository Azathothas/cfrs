#!/bin/sh
# Register QEMU's handler of binfmt_misc for ARCH (riscv64, arm, loong64,
# ppc64le), so that
# this host runs a static binary of ARCH: what docker/setup-qemu-action does,
# from the image of images/binfmt, pinned to its digest and pulled through
# the mirrors of scripts/pull-image.sh, with no third-party action .
#
#   sh scripts/binfmt.sh riscv64
set -eu

arch=${1:-}
case "$arch" in
    '' | *[!a-z0-9_]*)
        echo "usage: binfmt.sh ARCH (got '$arch')" >&2
        exit 64
        ;;
esac
here=$(dirname "$0")
ref=$(tr -d '\r' < "$here/../images/binfmt/Dockerfile" | sed -n 's/^FROM[[:space:]]\{1,\}\([^[:space:]]\{1,\}\).*/\1/p')
case "$ref" in
    *@sha256:*) ;;
    *)
        echo "binfmt.sh: images/binfmt/Dockerfile names no image pinned to a digest" >&2
        exit 1
        ;;
esac
image=$(sh "$here/pull-image.sh" "$ref")
# The kernel's list of handlers, which systemd mounts on a runner. On a host
# with none mounted, a handler would live only in the container that
# registers it.
if [ ! -e /proc/sys/fs/binfmt_misc/status ]; then
    sudo=
    [ "$(id -u)" = 0 ] || sudo=sudo
    $sudo mount -t binfmt_misc binfmt_misc /proc/sys/fs/binfmt_misc
fi
docker run --privileged --rm "$image" --install "$arch"
# The kernel lists each handler that it took. The name of the handler is the
# name of the QEMU binary, which differs from the platform name for some.
case "$arch" in
    loong64) name=loongarch64 ;;
    *) name=$arch ;;
esac
handler=/proc/sys/fs/binfmt_misc/qemu-$name
if [ ! -e "$handler" ]; then
    echo "binfmt.sh: the kernel lists no $handler" >&2
    exit 1
fi
echo "binfmt.sh: $handler, from $image"
head -n 2 "$handler"
