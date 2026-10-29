# Native ARM64 peer only; no host dependencies. The official image's v6.5.1
# tag currently contains a development package, so install the exact stable
# package from the project's own repository over the compatible Trixie image.
FROM cznic/knot-resolver@sha256:9aa19d24179b173768a48713feeb2be782f9c29395f0d6a1470a9257e81287fc

ADD --checksum=sha256:31133b9063c9b2ee86a70d044c8d83b99939e8895fc930d64f123228ddf63869 \
    https://pkg.labs.nic.cz/knot-resolver/pool/main/k/knot-resolver/knot-resolver6_6.5.1-cznic.1~trixie_arm64.deb \
    /tmp/stable.deb

RUN dpkg --force-downgrade -i /tmp/stable.deb \
    && rm /tmp/stable.deb \
    && test "$(dpkg-query -W -f='${Version}' knot-resolver6)" = '6.5.1-cznic.1~trixie' \
    && kresd -V | grep -Fx 'Knot Resolver, version 6.5.1'

LABEL org.opencontainers.image.source="https://gitlab.nic.cz/knot/knot-resolver" \
    org.opencontainers.image.revision="dc7030fd6bf93e22feb52f8956477f8c55626441" \
    org.opencontainers.image.version="6.5.1"
