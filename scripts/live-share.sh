#!/bin/sh
# Large uploads to `cfrs share` through one quick tunnel (issue 92). For each
# size in SIZES (MiB): a multipart upload with curl -F; the answer must be
# 200 and the file must be on disk with its size. Then an upload with a
# Content-Length over --max-request must get 413, and the session page must
# still answer. The log of CI is public: the tunnel host is masked before it
# can be printed.
#
#   sh scripts/live-share.sh CFRS PROTOCOL [SIZES]
#
# SIZES is a list such as "20 64" (default "20 64"). The script prints one
# line for each upload: "share PROTOCOL MiB: status, seconds".
set -eu
cfrs=$1
protocol=$2
sizes=${3:-20 64}
dir=$(mktemp -d)
mkdir "$dir/in"
trap 'kill $(jobs -p) 2> /dev/null || true' EXIT

mask() {
    sed -E 's/[a-z0-9-]+\.trycloudflare\.com/<tunnel>.trycloudflare.com/g; s#/s/[A-Za-z0-9_-]+#/s/<id>#g'
}
log() {
    mask < "$dir/share.err" | tail -25
}

RUST_LOG=cfrs=debug "$cfrs" share --dir "$dir/in" --protocol "$protocol" --transport direct \
    --json --no-verify --idle-secs 0 --max-request 90000000 \
    > "$dir/share.out" 2> "$dir/share.err" &
i=0
until grep -q '"url"' "$dir/share.out" 2> /dev/null; do
    i=$((i + 1))
    if [ "$i" -gt 90 ]; then
        log
        echo "share is not ready after 90 s"
        exit 1
    fi
    sleep 1
done
url=$(jq -r 'select(.url) | .url' "$dir/share.out" | head -1)
url=${url%/}
host=${url#https://}
host=${host%%/*}
echo "::add-mask::$host"
echo "::add-mask::$url"
i=0
until curl -fsS -o /dev/null --max-time 10 "$url/"; do
    i=$((i + 1))
    [ "$i" -lt 30 ] || { echo "the session page does not answer"; log; exit 1; }
    sleep 2
done

n=0
for s in $sizes; do
    n=$((n + 1))
    head -c "$((s * 1048576))" /dev/urandom > "$dir/f$n.bin"
    start=$(date +%s.%N)
    code=$(curl -sS --max-time 300 -o "$dir/answer.txt" -w '%{http_code}' \
        -F "files=@$dir/f$n.bin" "$url/upload") || code=fail
    end=$(date +%s.%N)
    echo "share $protocol $s MiB: $code, $(echo "$start $end" | awk '{ printf "%.2f s", $2 - $1 }')"
    if [ "$code" != 200 ]; then
        mask < "$dir/answer.txt" | head -5
        log
        exit 1
    fi
    cmp "$dir/f$n.bin" "$dir/in/f$n.bin" || { echo "the file on disk is not the file sent"; exit 1; }
done

# Over --max-request: 413 from cfrs. curl sends the header and waits for the
# answer before the body (Expect: 100-continue).
head -c 95000000 /dev/zero > "$dir/big.bin"
code=$(curl -sS --max-time 120 -o "$dir/answer.txt" -w '%{http_code}' \
    -F "files=@$dir/big.bin" "$url/upload") || code=fail
echo "share $protocol 95 MB over --max-request: $code"
[ "$code" = 413 ] || { mask < "$dir/answer.txt" | head -5; log; exit 1; }
grep -q "at most" "$dir/answer.txt"
[ ! -e "$dir/in/big.bin" ]

curl -fsS --max-time 30 -o /dev/null "$url/" || { echo "the session page does not answer after the uploads"; log; exit 1; }
echo "share $protocol: the session answers after the uploads"
if grep -q "edge closed the connection" "$dir/share.err"; then
    echo "share $protocol: an edge connection closed during the uploads:"
    grep "edge closed the connection" "$dir/share.err" | mask
fi
