FROM node:25-alpine AS ui-build
# Node is pinned by mise.toml [tools] node (24); keep this image in sync so CI,
# local builds and release images compile the UI with the same toolchain.

WORKDIR /ui
COPY ui/package.json ui/package-lock.json ./
# Registry connections can be reset transiently on shared CI runners.  Keep
# dependency installation bounded and retry only through npm's network-aware
# backoff; deterministic lockfile/configuration failures still fail the build.
RUN npm ci \
    --fetch-retries=5 \
    --fetch-retry-factor=2 \
    --fetch-retry-mintimeout=1000 \
    --fetch-retry-maxtimeout=60000
COPY ui/ ./
# Source maps ship original TypeScript on a public route, so they stay off
# unless explicitly requested for debugging a release (hidden: emitted but
# unreferenced). No ARG means no maps, matching local `npm run check`.
ARG SAFE_ZONE_UI_SOURCEMAPS=false
ENV SAFE_ZONE_UI_SOURCEMAPS=${SAFE_ZONE_UI_SOURCEMAPS}
RUN npm run check

# Go toolchain version is owned by mise.toml [tools] go (single source of truth).
FROM golang:1.26.10-alpine AS build

ARG SERVICE=core-api
ARG VERSION=dev
ARG GIT_COMMIT=unknown
ARG BUILD_TIME=unknown
ARG IMAGE_TAG=unreleased
ARG SOURCE_REPO=unknown

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=ui-build /ui/dist ./internal/api/app/dist

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
  -ldflags="-s -w -X safe-zone/internal/buildinfo.Version=${VERSION} -X safe-zone/internal/buildinfo.GitCommit=${GIT_COMMIT} -X safe-zone/internal/buildinfo.BuildTime=${BUILD_TIME} -X safe-zone/internal/buildinfo.ImageTag=${IMAGE_TAG} -X safe-zone/internal/buildinfo.SourceRepo=${SOURCE_REPO}" \
  -o /out/service ./cmd/${SERVICE}

FROM alpine:3.24

ARG SERVICE=core-api
ARG VERSION=dev
ARG GIT_COMMIT=unknown
ARG BUILD_TIME=unknown
ARG IMAGE_TAG=unreleased
ARG SOURCE_REPO=unknown

WORKDIR /app
# Local mode writes generated admin secrets to ./tmp; without this the
# non-root app user cannot create the directory under root-owned /app.
RUN apk upgrade --no-cache && \
    addgroup -S app && adduser -S app -G app && \
    mkdir -p /app/data && chown -R app:app /app/data && \
    install -d -m 0750 -o app -g app /app/tmp

LABEL org.opencontainers.image.title="safe-zone-${SERVICE}" \
  org.opencontainers.image.version="${VERSION}" \
  org.opencontainers.image.revision="${GIT_COMMIT}" \
  org.opencontainers.image.created="${BUILD_TIME}" \
  org.opencontainers.image.source="${SOURCE_REPO}" \
  org.opencontainers.image.vendor="Quorix" \
  safe-zone.image.tag="${IMAGE_TAG}" \
  safe-zone.service="${SERVICE}"

COPY --from=build --chown=app:app /out/service /app/service

USER app

ENV SAFE_ZONE_HEALTHCHECK_PORT=8080
ENV SAFE_ZONE_HEALTHCHECK_PATH=/readyz

HEALTHCHECK --interval=10s --timeout=3s --retries=5 CMD sh -c 'wget -qO- "http://127.0.0.1:${SAFE_ZONE_HEALTHCHECK_PORT}${SAFE_ZONE_HEALTHCHECK_PATH}" >/dev/null 2>&1 || exit 1'

EXPOSE 8080 8081

ENTRYPOINT ["/app/service"]
