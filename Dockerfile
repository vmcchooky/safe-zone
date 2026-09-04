FROM node:26-alpine AS ui-build

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
RUN npm run check

FROM golang:1.27.0-alpine AS build

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
RUN apk upgrade --no-cache && \
    addgroup -S app && adduser -S app -G app && \
    mkdir -p /app/data && chown -R app:app /app/data

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
ENV SAFE_ZONE_HEALTHCHECK_PATH=/healthz

HEALTHCHECK --interval=10s --timeout=3s --retries=5 CMD sh -c 'wget -qO- "http://127.0.0.1:${SAFE_ZONE_HEALTHCHECK_PORT}${SAFE_ZONE_HEALTHCHECK_PATH}" >/dev/null 2>&1 || exit 1'

EXPOSE 8080 8081

ENTRYPOINT ["/app/service"]
