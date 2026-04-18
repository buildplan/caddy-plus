# 1. GLOBAL ARGS
ARG GO_VERSION=1.26
ARG CADDY_VERSION=2
ARG OAUTH_VERSION=7.15.1
ARG PROXY_VERSION
ARG BOUNCER_VERSION
ARG CF_VERSION

# --- Stage 1: Builder (Caddy + Plugins) ---
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS builder

# REDECLARE ARGS
ARG CADDY_VERSION
ARG PROXY_VERSION
ARG BOUNCER_VERSION
ARG CF_VERSION
ARG TARGETARCH
ARG TARGETOS

# Install git and xcaddy
RUN apk add --no-cache git && \
    go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest

WORKDIR /app

# Run xcaddy with BuildKit caching AND vulnerability fixes
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    GOOS=${TARGETOS} GOARCH=${TARGETARCH} xcaddy build v${CADDY_VERSION} \
    --output /go/bin/caddy \
    --with github.com/lucaslorentz/caddy-docker-proxy/v2@v${PROXY_VERSION} \
    --with github.com/hslatman/caddy-crowdsec-bouncer/appsec@v${BOUNCER_VERSION} \
    --with github.com/hslatman/caddy-crowdsec-bouncer/http@v${BOUNCER_VERSION} \
    --with github.com/hslatman/caddy-crowdsec-bouncer/layer4@v${BOUNCER_VERSION} \
    --with github.com/caddy-dns/cloudflare@v${CF_VERSION} \
    --with github.com/WeidiDeng/caddy-cloudflare-ip \
    --with google.golang.org/grpc@latest \
    --with github.com/smallstep/certificates/ca@latest \
    --with github.com/go-jose/go-jose/v3@latest \
    --with github.com/go-jose/go-jose/v4@latest \
    --with go.opentelemetry.io/otel@latest \
    --with go.opentelemetry.io/otel/sdk@latest \
    --with go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp@latest \
    --with go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp@latest \
    --with go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp@latest

# --- Stage 2: Oauth2-Proxy Source ---
FROM quay.io/oauth2-proxy/oauth2-proxy:v${OAUTH_VERSION} AS oauth_source

# --- Stage 3: Final Image ---
FROM caddy:${CADDY_VERSION}-alpine

ARG CADDY_VERSION
ARG PROXY_VERSION
ARG BOUNCER_VERSION
ARG CF_VERSION
ARG OAUTH_VERSION

# Install dependencies and patch OS vulnerabilities
RUN apk upgrade --no-cache && \
    apk add --no-cache ca-certificates tzdata mailcap python3 py3-pip && \
    pip install supervisor --break-system-packages --no-cache-dir && \
    apk del py3-pip

# Copy binaries
COPY --from=builder /go/bin/caddy /usr/bin/caddy
COPY --from=oauth_source /bin/oauth2-proxy /usr/bin/oauth2-proxy

# Copy Config & Scripts
COPY supervisord.conf /etc/supervisord.conf
COPY start-oauth.sh /usr/bin/start-oauth.sh
RUN chmod +x /usr/bin/start-oauth.sh

# Run Supervisor
CMD ["supervisord", "-c", "/etc/supervisord.conf"]

# Metadata
LABEL org.opencontainers.image.title="caddy-plus" \
      org.opencontainers.image.description="Custom Caddy with CrowdSec, OAuth2 Proxy, Caddy-Docker-Proxy, Cloudflare DNS, and Cloudflare IP Source" \
      org.opencontainers.image.source="https://github.com/buildplan/caddy-plus" \
      org.opencontainers.image.version="${CADDY_VERSION}-oidc${OAUTH_VERSION}-b${BOUNCER_VERSION}-cf${CF_VERSION}-p${PROXY_VERSION}"
