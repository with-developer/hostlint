# The release image of hostlint: the static binary of a release on a minimal base (CA certificates for --push,
# no shell, no package manager). The .github/workflows/container.yml workflow builds it from the verified
# release archives; ctx/ holds linux-amd64/hostlint and linux-arm64/hostlint.
#
# Scan the host it runs on by mounting its root read-only (hostlint only reads):
#   docker run --rm -v /:/host:ro ghcr.io/with-developer/hostlint scan --root /host
FROM gcr.io/distroless/static-debian12@sha256:d75cdd72874d4790092fcb1b058493ecf6bb5bf2b2b897045b00ff01d91843f2
ARG TARGETARCH
COPY linux-${TARGETARCH}/hostlint /usr/local/bin/hostlint
USER 0:0
ENTRYPOINT ["/usr/local/bin/hostlint"]
CMD ["--help"]
