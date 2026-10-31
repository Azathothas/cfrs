#!/bin/sh
# Pull an image pinned to a digest, and print the reference that served it,
# for `docker run` .
#
#   ref=$(sh scripts/pull-image.sh "$BUILD_IMAGE")
#   docker run --rm "$ref" ...
#
# Docker Hub refuses pulls with no account past a limit for each address,
# and a runner of CI shares its address ("toomanyrequests"). Then the same
# digest comes from a mirror: Google's mirror of Docker Hub, then Amazon's
# gallery of the official images, or the GitHub registry for the others. A
# pull by digest checks the digest of the manifest and of each layer, so a
# mirror gives the same bytes or none. Two rounds, 30 s apart, for a fault
# of the network; the limit itself lasts longer than a job.
#
# PULL_DRY=1 prints each reference that would be tried, and pulls nothing.
# PULL_PLATFORM=linux/riscv64 pulls that platform of the index, for a run
# with the same --platform : a digest that holds the host's platform
# cannot take another's ("cannot overwrite digest").
set -u

ref=${1:-}
case "$ref" in
    *@sha256:*) ;;
    *)
        echo "usage: pull-image.sh IMAGE@sha256:DIGEST (got '$ref')" >&2
        exit 64
        ;;
esac
digest=${ref##*@}
name=${ref%@*}
# Once the digest is named, a tag says nothing.
case "${name##*/}" in
    *:*) name=${name%:*} ;;
esac
# The registry and the path in it: docker.io/library/rust, or rust alone.
first=${name%%/*}
case "$first" in
    "$name") registry=docker.io; path=$name ;;
    *.* | *:* | localhost) registry=$first; path=${name#*/} ;;
    *) registry=docker.io; path=$name ;;
esac
case "$path" in
    */*) ;;
    *) path=library/$path ;;
esac

tries="$registry/$path@$digest mirror.gcr.io/$path@$digest"
case "$path" in
    library/*) tries="$tries public.ecr.aws/docker/$path@$digest" ;;
    *) tries="$tries ghcr.io/$path@$digest" ;;
esac

if [ -n "${PULL_DRY:-}" ]; then
    for try in $tries; do
        echo "$try"
    done
    exit 0
fi

err=$(mktemp)
trap 'rm -f "$err"' EXIT
for round in 1 2; do
    for try in $tries; do
        if timeout 900 docker pull -q ${PULL_PLATFORM:+--platform "$PULL_PLATFORM"} "$try" >/dev/null 2>"$err"; then
            [ "$try" = "$registry/$path@$digest" ] || echo "pull-image.sh: $try served $ref" >&2
            echo "$try"
            exit 0
        fi
        echo "pull-image.sh: $try: $(tail -n 1 "$err")" >&2
    done
    [ "$round" = 2 ] || sleep 30
done
echo "pull-image.sh: no registry served $ref" >&2
exit 1
