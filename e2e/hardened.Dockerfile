# The e2e "hardened" variant: a supported distribution after harden.sh.
ARG BASE=debian:12
FROM ${BASE}
COPY harden.sh /tmp/harden.sh
RUN sh /tmp/harden.sh && rm /tmp/harden.sh
