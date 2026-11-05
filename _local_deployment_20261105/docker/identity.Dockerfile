# Build pinned identity source, including explicitly recorded local patches,
# with bounded compiler parallelism.
# Digests align with the Phorge acceptance build lock. Go toolchains match each
# upstream project's declared minimum/toolchain, without changing its go.mod.
FROM docker.io/library/golang@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS build
ARG GOTOOLCHAIN=go1.27.1
ARG MAIN_PACKAGE=.
ARG VERSION
ARG COMMIT
ENV GOTOOLCHAIN=${GOTOOLCHAIN} CGO_ENABLED=0 GOMAXPROCS=2 GOFLAGS=-p=2
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,id=identity-go-modules,target=/go/pkg/mod,sharing=locked go mod download
COPY . .
RUN --mount=type=cache,id=identity-go-modules,target=/go/pkg/mod,sharing=locked --mount=type=cache,id=identity-go-build,target=/root/.cache/go-build,sharing=locked go build -trimpath -ldflags "-w -s -X github.com/soulteary/version-kit/v4.Version=${VERSION} -X github.com/soulteary/version-kit/v4.Commit=${COMMIT}" -o /out/identity-service ${MAIN_PACKAGE}
RUN mkdir -p /out/templates && if [ -d src/internal/web/templates ]; then cp -a src/internal/web/templates/. /out/templates/; fi

FROM docker.io/library/alpine@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8
RUN apk add --no-cache ca-certificates curl && addgroup -g 10001 -S identity && adduser -u 10001 -S -D -G identity -H -s /sbin/nologin identity
COPY --from=build /out/identity-service /bin/identity-service
COPY --from=build /out/templates /app/web/templates
WORKDIR /app
USER 10001:10001
ENTRYPOINT ["/bin/identity-service"]
