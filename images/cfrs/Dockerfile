# The image of cfrs (issue 160): the static binaries of a release on an
# empty base. release.yml builds it for each Linux architecture from the
# files of the release, and pushes ghcr.io/<owner>/cfrs:<tag>.
#
# The context has: cfrs, pod-netns, and the empty directories state/ and
# tmp/. There is no shell and no CA file: cfrs uses its compiled-in roots.
FROM scratch
COPY --chmod=0755 cfrs pod-netns /usr/local/bin/
COPY --chown=65534:65534 state/ /var/lib/cfrs/
COPY --chown=65534:65534 tmp/ /tmp/
ENV CFRS_STATE_DIR=/var/lib/cfrs \
    HOME=/var/lib/cfrs \
    TMPDIR=/tmp
USER 65534:65534
WORKDIR /var/lib/cfrs
VOLUME ["/var/lib/cfrs"]
ENTRYPOINT ["/usr/local/bin/cfrs"]
CMD ["--help"]
