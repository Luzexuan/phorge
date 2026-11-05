# Build the explicit local binary image first (scripts/build-images.sh).
# This avoids depending on transient BuildKit cache for eight service images.
ARG BINARY_IMAGE=team-management/gorge-builder:f1130b7
ARG RUNTIME_BASE_IMAGE=docker.io/library/alpine@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8
FROM ${BINARY_IMAGE} AS builder
FROM ${RUNTIME_BASE_IMAGE}
RUN apk add --no-cache ca-certificates \
    && adduser -D -u 10001 gorge \
    && install -d -o gorge -g gorge -m 0755 /var/lib/gorge/files
ARG SERVICE=gorge-render
ARG PORT=8140
ARG SOURCE_REVISION
LABEL org.opencontainers.image.source="https://github.com/soulteary/gorge" \
      org.opencontainers.image.revision=${SOURCE_REVISION}
COPY internal/imagetransform/policy.xml /etc/gorge/image/policy.xml
COPY --from=builder /out/${SERVICE} /usr/local/bin/${SERVICE}
RUN ln -s /usr/local/bin/${SERVICE} /usr/local/bin/gorge-service
ENV GORGE_HEALTHCHECK_PORT=${PORT}
EXPOSE ${PORT}
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -qO- "http://127.0.0.1:${GORGE_HEALTHCHECK_PORT}/healthz" || exit 1
USER gorge
ENTRYPOINT ["gorge-service"]
