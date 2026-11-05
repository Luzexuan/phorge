ARG GO_BASE_IMAGE=docker.io/library/golang@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414
FROM ${GO_BASE_IMAGE}
ARG GO_VERSION=1.27.2
ARG GOPROXY=https://proxy.golang.org,direct
ARG SOURCE_REVISION
LABEL org.opencontainers.image.source="https://github.com/soulteary/gorge" \
      org.opencontainers.image.revision=${SOURCE_REVISION}
ENV GOTOOLCHAIN=go${GO_VERSION} GOMAXPROCS=2 GOFLAGS=-p=2 CGO_ENABLED=0
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN mkdir -p /out && go build -trimpath -ldflags="-s -w" -o /out/ \
    ./cmd/gorge-render ./cmd/gorge-conduit ./cmd/gorge-notification \
    ./cmd/gorge-file-storage ./cmd/gorge-webhook ./cmd/gorge-taskqueue \
    ./cmd/gorge-worker ./cmd/gorge-db-api
