# The image that builds the static Linux binaries of podnet (release.yml). This
# line is the one place that names it; the workflow reads it. The digest is
# that of the multi-platform index (linux/amd64 and linux/arm64), so two runs
# of one commit use one compiler, on each architecture.
FROM docker.io/library/rust:1-alpine@sha256:0cce0a5e0e8ba67b455257a3a02a1d99005f382748789d6464460028810f1627
