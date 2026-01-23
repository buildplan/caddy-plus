# 1. GLOBAL ARGS
ARG GO_VERSION=1.25
ARG CADDY_VERSION=2

# --- Stage 1: Builder ---
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS builder

# 2. REDECLARE ARGS FOR BUILDER
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

# 3. Build with Cross-Compilation Support
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} xcaddy build v${CADDY_VERSION} \
    --output /go/bin/caddy \
    --with github.com/lucaslorentz/caddy-docker-proxy/v2@v${PROXY_VERSION} \
    --with github.com/hslatman/caddy-crowdsec-bouncer/appsec@v${BOUNCER_VERSION} \
    --with github.com/hslatman/caddy-crowdsec-bouncer/http@v${BOUNCER_VERSION} \
    --with github.com/hslatman/caddy-crowdsec-bouncer/layer4@v${BOUNCER_VERSION} \
    --with github.com/caddy-dns/cloudflare@v${CF_VERSION} \
    --with github.com/WeidiDeng/caddy-cloudflare-ip

# --- Stage 2: Final Image ---
FROM caddy:${CADDY_VERSION}-alpine

# 4. REDECLARE ARGS FOR FINAL STAGE
ARG CADDY_VERSION
ARG PROXY_VERSION
ARG BOUNCER_VERSION
ARG CF_VERSION

# Install dependencies for Production
RUN apk add --no-cache ca-certificates tzdata mailcap

COPY --from=builder /go/bin/caddy /usr/bin/caddy

# Metadata
LABEL org.opencontainers.image.title="cfs-caddy" \
      org.opencontainers.image.description="Custom Caddy with CrowdSec, Caddy-Docker-Proxy ,Cloudflare DNS, and Cloudflare IP Source" \
      org.opencontainers.image.source="https://github.com/buildplan/caddy-plus" \
      org.opencontainers.image.version="${CADDY_VERSION}-b${BOUNCER_VERSION}-cf${CF_VERSION}-p${PROXY_VERSION}"
