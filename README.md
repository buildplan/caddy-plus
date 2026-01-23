# cfs-caddy

[![Built with xcaddy](https://img.shields.io/badge/Built%20with-xcaddy-00ADD8?style=flat&logo=go&logoColor=white)](https://github.com/caddyserver/xcaddy)
[![CrowdSec Bouncer](https://img.shields.io/badge/CrowdSec-Bouncer-orange?style=flat&logo=shield&logoColor=white)](https://github.com/hslatman/caddy-crowdsec-bouncer)
[![Cloudflare DNS](https://img.shields.io/badge/Cloudflare-DNS-F38020?style=flat&logo=cloudflare&logoColor=white)](https://github.com/caddy-dns/cloudflare)

A custom Caddy build that includes CrowdSec for security and Cloudflare plugins for DNS automation and proxy compatibility.

## Included Plugins

This image is built with the following modules:

* **[CrowdSec Bouncer](https://github.com/hslatman/caddy-crowdsec-bouncer):** HTTP & AppSec Web Application Firewall (WAF).
* **[Cloudflare DNS](https://github.com/caddy-dns/cloudflare):** DNS-01 ACME challenge support.
* **[Cloudflare IP Source](https://github.com/WeidiDeng/caddy-cloudflare-ip):** Dynamic trusted proxy configuration for Cloudflare ranges.

## Usage

### Docker Compose

```yaml
services:
  caddy:
    image: ghcr.io/buildplan/cfs-caddy:latest
    container_name: caddy
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
      - "443:443/udp"
    environment:
      - CF_API_TOKEN=your_cloudflare_api_token
      - CROWDSEC_API_KEY=your_crowdsec_local_api_key
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile
      - caddy_data:/data
      - caddy_config:/config

volumes:
  caddy_data:
  caddy_config:
```

### Example Caddyfile

This configuration enables the DNS challenge for SSL, trusts Cloudflare's proxy IPs (so CrowdSec sees the real visitor IP), and activates the WAF.

```Caddyfile
{
    # Automatically trust Cloudflare proxy IPs using the installed plugin
    servers {
        trusted_proxies cloudflare
    }

    # CrowdSec Configuration
    crowdsec {
        api_url http://crowdsec:8080
        api_key {env.CROWDSEC_API_KEY}
        appsec_url http://crowdsec:7422
    }
}

# Reusable snippet for Cloudflare DNS Challenge
(cloudflare_tls) {
    tls {
        dns cloudflare {env.CF_API_TOKEN}
        resolvers 1.1.1.1
    }
}

example.com {
    import cloudflare_tls

    route {
        crowdsec
        appsec
        reverse_proxy app:3000
    }
}
```

## Environment Variables

| Variable | Description |
| --- | --- |
| `CF_API_TOKEN` | Cloudflare API Token with `Zone:DNS:Edit` permission. |
| `CROWDSEC_API_KEY` | Local API Key generated from your CrowdSec instance (`cscli bouncers add caddy`). |
