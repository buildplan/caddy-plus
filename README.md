# caddy-plus

[![Built with xcaddy](https://img.shields.io/badge/Built%20with-xcaddy-00ADD8?style=flat&logo=go&logoColor=white)](https://github.com/caddyserver/xcaddy)
[![CrowdSec Bouncer](https://img.shields.io/badge/CrowdSec-Bouncer-orange?style=flat&logo=shield&logoColor=white)](https://github.com/hslatman/caddy-crowdsec-bouncer)
[![Docker Proxy](https://img.shields.io/badge/Docker-Proxy-blue?style=flat&logo=docker&logoColor=white)](https://github.com/lucaslorentz/caddy-docker-proxy)
[![Cloudflare DNS](https://img.shields.io/badge/Cloudflare-DNS-F38020?style=flat&logo=cloudflare&logoColor=white)](https://github.com/caddy-dns/cloudflare)
[![OAuth2 Proxy](https://img.shields.io/badge/OAuth2-Proxy-green?style=flat&logo=openid&logoColor=white)](https://github.com/oauth2-proxy/oauth2-proxy)

[![Build and Push Caddy-plus](https://github.com/buildplan/caddy-plus/actions/workflows/build-and-push.yml/badge.svg)](https://github.com/buildplan/caddy-plus/actions/workflows/build-and-push.yml)

A fully automated, secure reverse proxy stack in a single Docker image.

**caddy-plus** integrates five key components into one container:

1. **[Caddy:](https://caddyserver.com/)** The ultimate server with automatic HTTPS.
2. **[Caddy Docker Proxy:](https://github.com/lucaslorentz/caddy-docker-proxy)** Auto-generates Caddy configuration from Docker labels (no manual Caddyfile editing).
3. **[CrowdSec Bouncer:](https://github.com/hslatman/caddy-crowdsec-bouncer)** Adds IP blocking and a Web Application Firewall (WAF) to every site you host.
4. **[Cloudflare DNS:](https://github.com/caddy-dns/cloudflare)** Enables DNS-01 challenges for Wildcard SSL certificates and internal servers.
5. **[OAuth2 Proxy (OIDC):](https://oauth2-proxy.github.io/oauth2-proxy/)** Provides a "Zero Trust" authentication layer (SSO) for your applications using providers like PocketID, Google, or GitHub.

The image is automatically rebuilt and updated on GHCR whenever there is a new release of Caddy or any of its plugins.

## How It Works

This setup provides a fully automated, secure reverse proxy stack managed by **Supervisor**:

1. **Process Management (`supervisord`):** The container runs Supervisor as the entry point. It manages two processes: `caddy` and `oauth2-proxy`. If you do not provide OAuth configuration, `oauth2-proxy` enters a dormant "sleep mode" to consume zero resources while keeping the container healthy.
2. **Dynamic Config (`caddy-docker-proxy`):** Caddy connects to the Docker socket. When you launch a new container with specific labels, Caddy automatically provisions SSL certificates and routes traffic.
3. **IP Blocker (`crowdsec`):** Acts like a front-desk security guard. It checks the IP of every visitor against CrowdSec's global blocklist.
4. **WAF (`appsec`):** Inspects the *content* of requests to block SQL injection, XSS, and known exploits.
5. **Authentication (`forward_auth`):** If enabled via labels, Caddy pauses the request, asks `oauth2-proxy` if the user is logged in, and redirects them to your Identity Provider (IdP) if they are not.

## How to Use This Image

Follow these steps to integrate this Caddy image into your Docker setup.

### Step 1: Create the Network

Create the network **externally** first. This ensures the network name is exactly `caddy_net` and prevents Docker Compose from adding random prefixes (like `myproject_caddy_net`) that break the proxy discovery.

```bash
docker network create caddy_net
```

### Step 2: Deploy Caddy, OIDC, and CrowdSec

In your `docker-compose.yml`, use the image `ghcr.io/buildplan/caddy-plus:latest`.

**Critical Requirement:** You must mount the Docker socket so the proxy can detect your containers. You also need a shared volume for logs so CrowdSec can read Caddy's access logs.

> **Note:** You do **not** need to mount a `Caddyfile`. We configure global settings (like API keys) using labels on the Caddy container itself.
> **Note on Ports:** Since we use Cloudflare DNS for SSL challenges, **Port 80 is optional**. You only need Port 443 open to accept traffic from Cloudflare. This can be done for UFW based firewall with:

```bash
# Allow Cloudflare IPv4
for ip in $(curl -s https://www.cloudflare.com/ips-v4); do sudo ufw allow from $ip to any port 443; done

# Allow Cloudflare IPv6
for ip in $(curl -s https://www.cloudflare.com/ips-v6); do sudo ufw allow from $ip to any port 443; done
```

#### Example docker compose

```yaml
services:
  caddy:
    image: ghcr.io/buildplan/caddy-plus:latest
    container_name: caddy
    restart: unless-stopped
    ports:
      - "80:80"   # Optional: Only needed for http->https redirects
      - "443:443" # Required: HTTPS Traffic
      - "443:443/udp" # HTTP/3 Support
    environment:
      # EXACT MATCH: Must match the external network name from Step 1
      - CADDY_INGRESS_NETWORKS=caddy_net
      # Cloudflare Token for DNS challenges & Real IP resolution
      - CF_API_TOKEN=your_cloudflare_token

      # --- OIDC / OAUTH CONFIGURATION (Optional) ---
      # If these are omitted, the OIDC process sleeps and Caddy acts as a standard proxy.
      - OAUTH2_PROXY_PROVIDER=oidc
      - OAUTH2_PROXY_OIDC_ISSUER_URL=https://auth.yourdomain.com
      - OAUTH2_PROXY_CLIENT_ID=your_client_id
      - OAUTH2_PROXY_CLIENT_SECRET=your_client_secret
      # Generate with: python3 -c 'import os,base64; print(base64.urlsafe_b64encode(os.urandom(32)).decode())'
      - OAUTH2_PROXY_COOKIE_SECRET=your_32_byte_secret
      # Allow redirects to your subdomains (prevents "Invalid Redirect" errors)
      - OAUTH2_PROXY_WHITELIST_DOMAINS=.yourdomain.com
      # (Optional) Share login cookie across all subdomains for SSO
      - OAUTH2_PROXY_COOKIE_DOMAINS=.yourdomain.com
      # (Optional) Skip the intermediate "Sign in with..." button
      - OAUTH2_PROXY_SKIP_PROVIDER_BUTTON=true
      # (Optional) Use PKCE (Recommended for security)
      - OAUTH2_PROXY_CODE_CHALLENGE_METHOD=S256

    networks:
      - caddy_net
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock # REQUIRED for auto-discovery
      - caddy_data:/data
      # Mount a volume for logs so CrowdSec can read them
      - ./caddy_logs:/var/log/caddy

    # GLOBAL CONFIGURATION VIA LABELS
    labels:
      caddy.email: "you@example.com"

      # 1. Global Logging Configuration
      # We tell Caddy to write logs to a file that CrowdSec can see
      caddy.log.output: "file /var/log/caddy/access.log"
      caddy.log.format: "json"
      caddy.log.level: "INFO"

      # 2. CrowdSec Configuration
      # This creates the global { crowdsec { ... } } block
      caddy.crowdsec.api_url: "http://crowdsec:8080"
      caddy.crowdsec.api_key: "YOUR_BOUNCER_KEY_HERE" # See Step 3
      caddy.crowdsec.appsec_url: "http://crowdsec:7422"

      # 3. Cloudflare Trusted Proxies (Global Option)
      # This ensures CrowdSec sees real IPs, not Cloudflare's
      caddy.servers.trusted_proxies: "cloudflare"

      # 4. Define Reusable Snippet: (cloudflare_tls)
      # Other containers can import this to get DNS-01 SSL certs
      caddy_0: "(cloudflare_tls)"
      caddy_0.tls.dns: "cloudflare {env.CF_API_TOKEN}"
      caddy_0.tls.resolvers: "1.1.1.1"

      # 5. Define Reusable Snippet: (oidc)
      # This snippet handles the authentication logic
      caddy_1: "(oidc)"
      # Define a matcher: Protect everything EXCEPT the auth endpoints themselves
      caddy_1.@protected: "not path /oauth2/*"
      # Forward traffic to the internal oauth2-proxy process
      caddy_1.forward_auth: "@protected localhost:4180"
      caddy_1.forward_auth.uri: "/oauth2/auth"
      caddy_1.forward_auth.header_up: "X-Real-IP {remote_host}"
      caddy_1.forward_auth.copy_headers: "X-Auth-Request-User X-Auth-Request-Email"

      # THE REDIRECT MAGIC: If user is not logged in (401), redirect to sign-in page (302)
      caddy_1.forward_auth.0_@error: "status 401"
      caddy_1.forward_auth.0_handle_response: "@error"
      caddy_1.forward_auth.0_handle_response.0_redir: "* /oauth2/sign_in?rd={scheme}://{host}{uri}"

      # Handle the /oauth2/* endpoints locally (Sign-in, Callback, Sign-out)
      caddy_1.handle: "/oauth2/*"
      caddy_1.handle.reverse_proxy: "localhost:4180"
      # IMPORTANT: Underscores are used for array syntax in labels
      caddy_1.handle.reverse_proxy.header_up_0: "X-Real-IP {remote_host}"
      caddy_1.handle.reverse_proxy.header_up_1: "X-Forwarded-Uri {uri}"

  crowdsec:
    image: crowdsecurity/crowdsec:latest
    container_name: crowdsec
    environment:
      - COLLECTIONS=crowdsecurity/caddy crowdsecurity/appsec-virtual-patching crowdsecurity/appsec-generic-rules
      # Listen on all interfaces so Caddy can reach it
      - CROWDSEC_LAPI_LISTEN_URI=0.0.0.0:8080
    networks:
      - caddy_net
    volumes:
      - ./crowdsec-db:/var/lib/crowdsec/data
      - ./crowdsec-config:/etc/crowdsec
      # Mount the custom acquisition file (Created in Step 3)
      - ./crowdsec-config/acquis.yaml:/etc/crowdsec/acquis.yaml
      # Shared logs volume
      - ./caddy_logs:/var/log/caddy

networks:
  caddy_net:
    external: true # <--- External network created in step 1

volumes:
  caddy_data:
  crowdsec-db:
```

### Step 3: Configure CrowdSec Log Reading

You need to tell CrowdSec to read the file that Caddy is writing to.

Create a file named `acquis.yaml` inside your `./crowdsec-config/` directory:

```yaml
# ./crowdsec-config/acquis.yaml
filenames:
  - /var/log/caddy/access.log
labels:
  type: caddy
```

*Note: You also need to create the log file on the host initially to ensure permissions are correct:*

```bash
mkdir -p caddy_logs
touch caddy_logs/access.log
chmod 666 caddy_logs/access.log
```

### Step 4: Get a Bouncer API Key

Your Caddy bouncer needs a key to talk to the CrowdSec agent.
Start the CrowdSec container, then run:

```bash
docker exec crowdsec cscli bouncers add caddy-bouncer
```

Copy the API key generated and paste it into the `caddy.crowdsec.api_key` label in your `docker-compose.yml` (Step 2).

### Step 5: Enable AppSec in CrowdSec

To use the WAF features, enable the AppSec engine in CrowdSec.

* **Create the AppSec config:** Inside your mounted CrowdSec config folder (e.g., `./crowdsec-config/acquis.d/`), create a file named `appsec.yaml`:

```yaml
# ./crowdsec-config/acquis.d/appsec.yaml
listen_addr: 0.0.0.0:7422
appsec_config: crowdsecurity/appsec-default
name: caddy-appsec-listener
source: appsec
labels:
  type: appsec
```

* **Restart CrowdSec:**

```bash
docker restart crowdsec
```

### Step 6: Deploy a Protected Container

With `caddy-docker-proxy`, you add labels to the containers you want to expose.

**Crucial:** You must add `caddy.log.output` to your service labels. This tells Caddy to write the access logs for *this specific site* to the default log file we configured in Step 1.

**DNS Tip:** To avoid manually creating DNS records for every new service, add a wildcard `A` record (`*`) in Cloudflare pointing to your server IP.

Here is an example `whoami` service using **Cloudflare DNS**, **CrowdSec**, and **OIDC Authentication**.

```yaml
services:
  whoami:
    image: traefik/whoami
    networks:
      - caddy_net
    labels:
      # 1. Define the domain
      caddy: "whoami.example.com"
      
      # 2. Import Snippets
      # This enables DNS-01 SSL
      caddy.import_0: "cloudflare_tls"
      # This enables OIDC Authentication
      caddy.import_1: "oidc"
      
      # 3. Enable Logging (REQUIRED for CrowdSec)
      caddy.log.output: "file /var/log/caddy/access.log"
      caddy.log.format: "json"
      
      # 4. Enable Security (CrowdSec + AppSec)
      caddy.route.0_crowdsec: "" 
      caddy.route.1_appsec: ""
      
      # 5. Security Headers
      caddy.header.Strict-Transport-Security: "max-age=31536000; includeSubDomains"
      caddy.header.X-Frame-Options: "SAMEORIGIN"
      caddy.header.X-Content-Type-Options: "nosniff"
      
      # 6. Reverse Proxy (Protected by everything above)
      caddy.route.2_reverse_proxy: "{{upstreams 80}}"

networks:
  caddy_net:
    external: true
```

**Explanation of Labels:**

* `caddy.servers.trusted_proxies`: (Step 1) Tells Caddy to trust Cloudflare IPs so it can see the real client IP.
* `caddy_0: (cloudflare_tls)`: (Step 1) Defines a reusable snippet for DNS configuration.
* `caddy.import`: (Step 5) Applies that snippet to your specific container.
* `caddy.log.output`: Enables access logging for this site.

**Identity Provider Configuration (PocketID/Google):**
When using OIDC, you must whitelist the redirect URL in your IdP settings.

* **Redirect URI Format:** `https://<YOUR_APP_DOMAIN>/oauth2/callback`
* Example: `https://whoami.example.com/oauth2/callback`

### Step 7: Verify

1. **Start the stack:** `docker compose up -d`

Visit your site to generate some logs or from CLI:

```bash
curl -I [https://whoami.example.com](https://whoami.example.com)
```

#### Check CrowdSec Metrics

Verify that CrowdSec is reading the logs and AppSec is receiving data.

```bash
docker exec crowdsec cscli metrics
```

* Look for **Acquisition Metrics**: Should show `file:/var/log/caddy/access.log` with "Lines read" > 0.
* Look for **Parser Metrics**: Should show `crowdsecurity/caddy-logs`.

#### Check OIDC

* If OIDC is configured, you should be redirected to your login provider.
* After login, you should see your app.
* `whoami` should display headers like `X-Auth-Request-Email`.

#### Check Status

Since this container runs multiple processes, use `supervisorctl` to check health:

```bash
docker exec caddy supervisorctl status
# Output should show:
# caddy            RUNNING   pid 7, uptime 0:05:00
# oauth2-proxy     RUNNING   pid 8, uptime 0:05:00
```

---

## Debugging

### View the Generated Caddyfile

Since the configuration is generated in-memory via Docker labels, you can't open a file to check it. Use this command to see what Caddy is actually using:

```bash
docker logs caddy 2>&1 | grep "New Caddyfile" | tail -n 1 | sed 's/.*"caddyfile":"//' | sed 's/"}$//' | sed 's/\\n/\n/g' | sed 's/\\t/\t/g'
```

### CLI Options

#### CrowdSec

The Caddy binary includes the CrowdSec CLI for health checks.

```bash
# Check if an IP is currently banned
docker exec caddy caddy crowdsec check 1.2.3.4

# Check connection health
docker exec caddy caddy crowdsec health
```

```text
$ docker exec caddy caddy crowdsec --help

Commands related to the CrowdSec integration (experimental)

The subcommands can help assessing the status of the CrowdSec integration.

Output of the commands can change, so shouldn't be relied upon (yet).

Usage:
  caddy crowdsec [command]

Available Commands:
  check       Checks an IP to be banned or not
  health      Checks CrowdSec integration health
  info        Shows CrowdSec runtime information
  ping        Pings the CrowdSec LAPI endpoint

Flags:
  -a, --adapter string   Name of config adapter to apply (when --config is used)
      --address string   The address to use to reach the admin API endpoint, if not the default
  -c, --config string    Configuration file to use to parse the admin address, if --address is not used
  -h, --help             help for crowdsec
  -v, --version          version for crowdsec

Use "caddy crowdsec [command] --help" for more information about a command.
```

#### caddy-docker-proxy

For documentation on **Docker Proxy labels**, visit: [https://github.com/lucaslorentz/caddy-docker-proxy](https://github.com/lucaslorentz/caddy-docker-proxy)

caddy-docker-proxy extends caddy's CLI with the command `caddy docker-proxy`.

```text
$ docker exec caddy caddy help docker-proxy

Usage:
  caddy docker-proxy <command> [flags]

Flags:
      --caddyfile-path string              Path to a base Caddyfile that will be extended with docker sites
      --controller-network string          Network allowed to configure caddy server in CIDR notation. Ex: 10.200.200.0/24
      --docker-apis-version string         Docker socket apis version comma separate
      --docker-certs-path string           Docker socket certs path comma separate
      --docker-sockets string              Docker sockets comma separate
      --envfile string                     Environment file with environment variables in the KEY=VALUE format
      --event-throttle-interval duration   Interval to throttle caddyfile updates triggered by docker events (default 100ms)
  -h, --help                               help for docker-proxy
      --ingress-networks string            Comma separated name of ingress networks connecting caddy servers to containers.
                                           When not defined, networks attached to controller container are considered ingress networks
      --label-prefix string                Prefix for Docker labels (default "caddy")
      --mode string                        Which mode this instance should run: standalone | controller | server (default "standalone")
      --polling-interval duration          Interval caddy should manually check docker for a new caddyfile (default 30s)
      --process-caddyfile                  Process Caddyfile before loading it, removing invalid servers (default true)
      --proxy-service-tasks                Proxy to service tasks instead of service load balancer (default true)
      --scan-stopped-containers            Scan stopped containers and use its labels for caddyfile generation
```

Those flags can also be set via environment variables:

```yaml
CADDY_DOCKER_CADDYFILE_PATH=<string>
CADDY_DOCKER_ENVFILE=<string>
CADDY_CONTROLLER_NETWORK=<string>
CADDY_INGRESS_NETWORKS=<string>
CADDY_DOCKER_SOCKETS=<string>
CADDY_DOCKER_CERTS_PATH=<string>
CADDY_DOCKER_APIS_VERSION=<string>
CADDY_DOCKER_LABEL_PREFIX=<string>
CADDY_DOCKER_MODE=<string>
CADDY_DOCKER_POLLING_INTERVAL=<duration>
CADDY_DOCKER_PROCESS_CADDYFILE=<bool>
CADDY_DOCKER_PROXY_SERVICE_TASKS=<bool>
CADDY_DOCKER_SCAN_STOPPED_CONTAINERS=<bool>
CADDY_DOCKER_NO_SCOPE=<bool, default scope used>
```

---

## Included Plugins & Docs

* **[Caddy Docker Proxy](https://github.com/lucaslorentz/caddy-docker-proxy):** Dynamic configuration using Docker labels.
* **[CrowdSec Bouncer](https://github.com/hslatman/caddy-crowdsec-bouncer):** Security module for Caddy.
* **[Cloudflare DNS](https://github.com/caddy-dns/cloudflare):** DNS provider for solving ACME challenges.
* **[Cloudflare IP](https://github.com/WeidiDeng/caddy-cloudflare-ip):** Real visitor IP restoration when behind Cloudflare Proxy.
* **[OAuth2 Proxy](https://www.google.com/url?sa=E&source=gmail&q=https://oauth2-proxy.github.io/oauth2-proxy/):** Identity aware proxy for OIDC authentication.

## Credits & Licenses

This project is licensed under the [Apache License 2.0](LICENSE).

It integrates the following open-source software, which are gratefully acknowledged:

* **[Caddy](https://github.com/caddyserver/caddy)** - Apache 2.0
* **[OAuth2 Proxy](https://github.com/oauth2-proxy/oauth2-proxy)** - MIT License
* **[Caddy Docker Proxy](https://github.com/lucaslorentz/caddy-docker-proxy)** - MIT License
* **[CrowdSec Caddy Bouncer](https://github.com/hslatman/caddy-crowdsec-bouncer)** - Apache 2.0
* **[Caddy Cloudflare DNS](https://github.com/caddy-dns/cloudflare)** - Apache 2.0
* **[Supervisor](https://github.com/Supervisor/supervisor)** - Supervisor License (BSD-like)

*For full license text, please visit the respective repositories linked above.*
