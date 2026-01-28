# 1. GLOBAL ARGS
ARG GO_VERSION=1.25
ARG CADDY_VERSION=2
ARG OAUTH_VERSION=7.14.2

# --- Stage 1: Builder (Caddy + Plugins) ---
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS builder

# REDECLARE ARGS
ARG CADDY_VERSION
ARG PROXY_VERSION
ARG BOUNCER_VERSION
ARG CF_VERSION
ARG TARGETARCH
ARG TARGETOS

# Install git
RUN apk add --no-cache git

# Install git and xcaddy
RUN apk add --no-cache git && \
    go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest

WORKDIR /app

RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} xcaddy build v${CADDY_VERSION} \
    --output /go/bin/caddy \
    --with github.com/lucaslorentz/caddy-docker-proxy/v2@v${PROXY_VERSION} \
    --with github.com/hslatman/caddy-crowdsec-bouncer/appsec@v${BOUNCER_VERSION} \
    --with github.com/hslatman/caddy-crowdsec-bouncer/http@v${BOUNCER_VERSION} \
    --with github.com/hslatman/caddy-crowdsec-bouncer/layer4@v${BOUNCER_VERSION} \
    --with github.com/caddy-dns/cloudflare@v${CF_VERSION} \
    --with github.com/WeidiDeng/caddy-cloudflare-ip

# --- Stage 2: Oauth2-Proxy Source ---
FROM quay.io/oauth2-proxy/oauth2-proxy:v${OAUTH_VERSION} AS oauth_source

# --- Stage 3: Final Image ---
FROM caddy:${CADDY_VERSION}-alpine

ARG CADDY_VERSION
ARG PROXY_VERSION
ARG BOUNCER_VERSION
ARG CF_VERSION
ARG OAUTH_VERSION

# Install dependencies
RUN apk add --no-cache ca-certificates tzdata mailcap python3 py3-pip && \
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
      org.opencontainers.image.description="Custom Caddy with CrowdSec, OAuth2 Proxy, Caddy-Docker-Proxy ,Cloudflare DNS, and Cloudflare IP Source" \
      org.opencontainers.image.source="https://github.com/buildplan/caddy-plus" \
      org.opencontainers.image.version="${CADDY_VERSION}-oidc${OAUTH_VERSION}-b${BOUNCER_VERSION}-cf${CF_VERSION}"
