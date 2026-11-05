# The image of podnet (issue 160): the static binary of a release on an
# empty base. release.yml builds it for each Linux architecture from the
# files of the release, and pushes ghcr.io/<owner>/podnet:<tag>.
#
# The context has: podnet and the empty directories state/ and
# tmp/. There is no shell and no CA file: podnet uses its compiled-in roots.
FROM scratch
COPY --chmod=0755 podnet /usr/local/bin/
COPY --chown=65534:65534 state/ /var/lib/podnet/
COPY --chown=65534:65534 tmp/ /tmp/
ENV PODNET_STATE_DIR=/var/lib/podnet \
    HOME=/var/lib/podnet \
    TMPDIR=/tmp
USER 65534:65534
WORKDIR /var/lib/podnet
VOLUME ["/var/lib/podnet"]
ENTRYPOINT ["/usr/local/bin/podnet"]
CMD ["--help"]
