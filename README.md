# nginx Security Hardening Script

A single Bash script that applies a strong, sensible security baseline to an
nginx installation on Debian and Ubuntu. It writes security headers, hardens
TLS settings, sets buffer and timeout limits, defines rate-limiting zones, and
generates a ready-to-use example server block — all with conflict detection and
automatic rollback if the resulting configuration is invalid.

The script can run fully unattended from a configuration file, or interactively
with prompts.

## Features

- **Security headers** — HSTS, Content-Security-Policy, X-Frame-Options,
  X-Content-Type-Options, Referrer-Policy, Permissions-Policy, and the
  Cross-Origin isolation headers, written to `conf.d/security-headers.conf`.
- **Core hardening** — `server_tokens off`, connection timeouts, request-buffer
  limits, and a modern TLS profile (TLS 1.2/1.3 only, strong cipher suite),
  written to `conf.d/hardening.conf`.
- **Rate limiting** — pre-defined `limit_req` and `limit_conn` zones for general
  traffic, login endpoints, per-IP, and per-server use.
- **Conflict detection** — every directive and rate-limit zone is checked
  against your existing configuration first. Anything already defined elsewhere
  is written as a commented `[SKIP]` line instead of being duplicated, so nginx
  never fails on a repeated directive. The scan covers `conf.d`, `sites-enabled`,
  `sites-available`, and `snippets`, including site files that have no `.conf`
  extension.
- **Safe by default** — the existing configuration is backed up before any
  change. If `nginx -t` fails afterwards, the script removes the files it created
  and restores the backup, leaving nginx in a valid state.
- **DH parameters** — generates `dhparam.pem` for stronger DHE ciphers and wires
  it into the SSL configuration.
- **Server header removal** — if the `headers-more` module is available (via
  `nginx-extras`), the `Server` and `X-Powered-By` headers are cleared.
- **Example server block** — a complete, commented HTTPS server block is written
  in a disabled state for you to adapt and enable.

## Requirements

- Debian 12/13 or Ubuntu 22.04+ (other Debian-based distributions should work).
- nginx 1.18 or newer. The script can install nginx for you if it is missing.
- Root privileges (`sudo`).
- `openssl` (for DH parameter generation) and `curl` (for header verification).

## Installation

```bash
git clone https://github.com/sheloab/hardening-nginx-script.git
cd hardening-nginx-script
chmod +x hardening_nginx_v4.sh
```

## Usage

### Unattended (recommended)

Copy the example configuration, edit it, and pass it to the script:

```bash
cp hardening_nginx.conf.example hardening_nginx.conf
nano hardening_nginx.conf
sudo ./hardening_nginx_v4.sh hardening_nginx.conf
```

If a file named `hardening_nginx.conf` is present next to the script, it is used
automatically:

```bash
sudo ./hardening_nginx_v4.sh
```

### Interactive

Run without a configuration file to be prompted for the domain, strict-CSP
choice, and HSTS preload choice:

```bash
sudo ./hardening_nginx_v4.sh
```

### Help

```bash
./hardening_nginx_v4.sh --help
```

## Configuration options

All options live in `hardening_nginx.conf`. Defaults are shown below.

| Option | Default | Description |
|---|---|---|
| `NON_INTERACTIVE` | `yes` | Run without prompts, using the values in the file. |
| `DOMAIN` | `example.com` | Domain used in the example server block and log paths. |
| `STRICT_CSP` | `no` | `yes` uses a locked-down CSP that blocks inline scripts and styles. |
| `HSTS_PRELOAD` | `no` | Add `preload` to HSTS. Enable only when the whole domain is HTTPS-only. |
| `HSTS_MAX_AGE` | `31536000` | HSTS lifetime in seconds (one year). |
| `INSTALL_NGINX_IF_MISSING` | `yes` | Install nginx automatically if it is not present. |
| `INSTALL_HEADERS_MORE` | `yes` | Install `nginx-extras` to enable removal of the `Server` header. |
| `GENERATE_DHPARAM` | `yes` | Generate `dhparam.pem`. |
| `DHPARAM_BITS` | `2048` | DH parameter size. |
| `ENABLE_RATE_LIMIT` | `yes` | Write the rate-limiting zones. |
| `CLIENT_MAX_BODY_SIZE` | `100m` | Maximum request body size. |
| `RESOLVERS` | `1.1.1.1 1.0.0.1 valid=300s` | DNS resolvers for OCSP stapling. |
| `CREATE_EXAMPLE_SERVER` | `yes` | Write the disabled example server block. |

## Files created

- `/etc/nginx/conf.d/security-headers.conf` — the response headers.
- `/etc/nginx/conf.d/hardening.conf` — core and TLS hardening directives.
- `/etc/nginx/conf.d/secure-site-example.conf.disabled` — example server block.
- `/etc/nginx/dhparam.pem` — DH parameters (if enabled).
- `/etc/nginx/backups/<timestamp>/` — a backup of the previous configuration.

## Important: header inheritance

In nginx, `add_header` directives are **not** inherited into a `server` or
`location` block that defines its own `add_header`. If one of your virtual hosts
sets any header of its own, it will lose the global security headers. To keep
them, re-include the headers file inside that block:

```nginx
include /etc/nginx/conf.d/security-headers.conf;
```

The example server block demonstrates this pattern.

## Verifying the result

After running, test your live site with:

- https://securityheaders.com
- https://www.ssllabs.com/ssltest/

The script also checks the headers on `localhost` at the end of the run and
prints which ones are present.

## Rollback

Every run backs up the current configuration to
`/etc/nginx/backups/<timestamp>/`. If the new configuration does not pass
`nginx -t`, the script deletes the files it just created and restores the
backup, so a failed run cannot leave nginx broken. To roll back manually, copy
the files from the relevant backup directory and reload nginx.

## License

Released under the MIT License. See [LICENSE](LICENSE) for details.
