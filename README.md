# nginx Security Hardening Script

A single Bash script that applies a strong, sensible security baseline to an
nginx installation on Debian and Ubuntu. It writes security headers, hardens
TLS settings, sets buffer and timeout limits, defines rate-limiting zones,
blocks bots and scanners (banning them with fail2ban), and generates a
ready-to-use example server block — all with conflict detection and automatic
rollback if the resulting configuration is invalid.

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
- **Bot & scanner blocker** — classifies every request by user-agent and drops
  scanners, HTTP scripts, empty user-agents, unknown bots and (optionally)
  AI-training crawlers, SEO scrapers and search engines with `444` (the
  connection is closed without an answer). Requests for hidden files such as
  `/.env` or `/.git/config` are refused.
- **fail2ban bans** — dropped bots, honeypot hits and hidden-file probes are
  banned on the first request. Bans are enforced **inside nginx**, so they hit
  the real visitor even when the site sits behind a CDN.
- **Cloudflare mode** — nginx takes the visitor's address from
  `CF-Connecting-IP`, so logs, rate limits and bans apply to the visitor, and
  Cloudflare's own addresses are never banned.
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
- `openssl` (for DH parameter generation) and `curl` (for header verification
  and for downloading Cloudflare's current address list).
- fail2ban for the bans. The script can install it for you.

## Installation

```bash
git clone https://github.com/sheloab/hardening-nginx-script.git
cd hardening-nginx-script
chmod +x hardening_nginx_v5.sh
```

## Usage

### Unattended (recommended)

Copy the example configuration, edit it, and pass it to the script:

```bash
cp hardening_nginx.conf.example hardening_nginx.conf
nano hardening_nginx.conf
sudo ./hardening_nginx_v5.sh hardening_nginx.conf
```

If a file named `hardening_nginx.conf` is present next to the script, it is used
automatically:

```bash
sudo ./hardening_nginx_v5.sh
```

### Interactive

Run without a configuration file to be prompted for the domain, the
strict-CSP and HSTS preload choices, and the bot-blocker options:

```bash
sudo ./hardening_nginx_v5.sh
```

### Help

```bash
./hardening_nginx_v5.sh --help
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
| `ENABLE_BOT_BLOCKER` | `yes` | Install the bot & scanner blocker. |
| `BLOCK_AI_CRAWLERS` | `yes` | Also drop AI-training crawlers and SEO scrapers. |
| `BLOCK_SEARCH_ENGINES` | `no` | Also drop search engines and link previews (private sites only). |
| `BOT_AUTO_INCLUDE` | `no` | Add the bot snippet to every `server{}` block in `sites-enabled`. |
| `ENABLE_FAIL2BAN` | `yes` | Ban the IPs of dropped bots and hidden-file probes. |
| `INSTALL_FAIL2BAN` | `yes` | Install fail2ban if it is missing. |
| `BAN_TIME` | `604800` | Ban length in seconds (seven days). |
| `BAN_IGNORE_IPS` | *(empty)* | Your own IPs/ranges: never dropped, logged or banned. |
| `BEHIND_CLOUDFLARE` | `no` | Trust `CF-Connecting-IP` and never ban Cloudflare's addresses. |

## Bot & scanner blocker

### Protecting a site

The blocker acts on a site once its `server{}` block includes the snippet:

```nginx
server {
    server_name example.com;
    include /etc/nginx/snippets/bot-response.conf;
    ...
}
```

`BOT_AUTO_INCLUDE=yes` adds this line to every server block in `sites-enabled`
for you, right after its `server_name` line. Like every other change, it is
undone if the new configuration fails `nginx -t`.

Dropped requests are written to `/var/log/nginx/bots/bots.log`, which is where
fail2ban finds them. A server block that has **its own** `access_log` does not
inherit that log, so it needs one more line (the automatic include adds it for
you):

```nginx
access_log /var/log/nginx/bots/bots.log bot_log if=$bot_block;
```

### Who is dropped

| Class | Examples | Dropped |
|---|---|---|
| Scanners and scripts | sqlmap, Nikto, nuclei, curl, wget, python-requests, Go-http-client, headless browsers, empty user-agent | always |
| Unknown bots | any other user-agent containing *bot*, *crawler*, *spider*, *scraper* | always |
| AI / SEO crawlers | GPTBot, CCBot, Bytespider, AhrefsBot, SemrushBot | `BLOCK_AI_CRAWLERS=yes` |
| Search engines and previews | Googlebot, Bingbot, DuckDuckBot, Slackbot, TelegramBot | `BLOCK_SEARCH_ENGINES=yes` |
| Normal browsers | everything else | never |

Requests from `127.0.0.1`, `::1` and `BAN_IGNORE_IPS` are never dropped, so
local health checks with `curl` keep working.

**Note:** `curl`, `wget` and HTTP libraries are treated as scanners. If an
external monitor, webhook or API client of yours uses one of them, add its
address to `BAN_IGNORE_IPS` or give its user-agent a rule in `custom.conf`.

### Your own rules

`/etc/nginx/bot-lists/custom.conf` is read before every other list and is never
overwritten by the script:

```nginx
"~*MyUptimeMonitor"     "";      # treat as a normal visitor
"~*SomeAnnoyingBot"     "bad";   # drop it
```

Classes are `good`, `bad`, `scanner`, `unknown_bot`, or `""` (normal visitor).
The other lists (`good-bots.conf`, `bad-bots.conf`, `scanners.conf`,
`unknown-bots.conf`) are refreshed on every run.

### Bans

Two fail2ban jails are installed, both banning on the first hit:

- **nginx-bot** — every request the blocker dropped, plus honeypot hits.
- **nginx-probe** — requests for hidden files (`/.env`, `/.git/...`), found as
  `access forbidden by rule` in any `/var/log/nginx/*error.log`.
  `/.well-known/` is never counted.

A ban adds `"<ip> 1;"` to `/etc/nginx/bot-deny.conf` and reloads nginx; every
site that includes the snippet then drops that address. The list survives
re-runs of the script.

```bash
sudo fail2ban-client status nginx-bot
sudo fail2ban-client set nginx-bot unbanip 203.0.113.9   # example address, see below
```

Both jails set `backend = auto`. Many hardened systems set
`backend = systemd` in fail2ban's `[DEFAULT]`; a jail that inherits it ignores
its `logpath` and silently reads nothing. At the end of the run the script
checks that each jail is reading its log files and says so.

### Honeypot

The example server block answers paths that only attack tools ask for
(`/wp-admin`, `/wp-login.php`, `/xmlrpc.php`, `/phpmyadmin`) with `444` and logs
them to `honeypot.log`, so the first hit is banned. Remove that block if the
site really runs WordPress or phpMyAdmin.

## Behind Cloudflare

With `BEHIND_CLOUDFLARE=yes` the script:

- writes `conf.d/cloudflare-realip.conf` (`set_real_ip_from` for every
  Cloudflare range plus `real_ip_header CF-Connecting-IP`). The ranges are
  downloaded from cloudflare.com at run time, with a built-in copy as fallback;
  re-run the script to refresh them.
- adds Cloudflare's ranges to both jails' `ignoreip`, so a Cloudflare edge
  address can never be banned (that would cut off every visitor routed through
  it).

Restricting ports 80/443 to Cloudflare's addresses is a firewall task and is
not done by this script.

## Files created

- `/etc/nginx/conf.d/security-headers.conf` — the response headers.
- `/etc/nginx/conf.d/hardening.conf` — core and TLS hardening directives.
- `/etc/nginx/conf.d/secure-site-example.conf.disabled` — example server block.
- `/etc/nginx/dhparam.pem` — DH parameters (if enabled).
- `/etc/nginx/backups/<timestamp>/` — a backup of the previous configuration.

With the bot blocker:

- `/etc/nginx/conf.d/bot-classifier.conf`, `/etc/nginx/conf.d/bot-logformat.conf`
- `/etc/nginx/snippets/bot-response.conf` — the snippet to include per site.
- `/etc/nginx/bot-lists/` — the user-agent lists, including your `custom.conf`.
- `/etc/nginx/bot-deny.conf` — banned addresses (managed by fail2ban).
- `/etc/nginx/conf.d/cloudflare-realip.conf` — with `BEHIND_CLOUDFLARE=yes`.
- `/var/log/nginx/bots/` — `bots.log` and `honeypot.log`, rotated by
  `/etc/logrotate.d/nginx-bots`.
- `/etc/fail2ban/jail.d/nginx-bot.conf`, `/etc/fail2ban/jail.d/nginx-probe.conf`,
  `/etc/fail2ban/filter.d/nginx-bot.conf`, `/etc/fail2ban/filter.d/nginx-probe.conf`,
  `/etc/fail2ban/action.d/nginx-bot-deny.conf`

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

The script also checks the headers on `localhost` at the end of the run, counts
the server blocks protected by the bot blocker, and confirms that the fail2ban
jails are reading their logs.

## Rollback

Every run backs up the current configuration to
`/etc/nginx/backups/<timestamp>/` (`nginx.conf`, `conf.d`, `snippets`,
`bot-lists`, `sites-available`, `sites-enabled`). If the new configuration does
not pass `nginx -t`, the script deletes the files it just created and restores
the backup, so a failed run cannot leave nginx broken. The fail2ban files are
tested on their own (`fail2ban-client -t`) and put back if that test fails. To
roll back manually, copy the files from the relevant backup directory and
reload nginx.

## Upgrading from v4 or from the separate bot blocker

Run v5 the same way. It replaces its own generated files and keeps
`bot-deny.conf`, `custom.conf` and your site files (unless `BOT_AUTO_INCLUDE=yes`).
The variables used by the older bot blocker (`$bot_class`, `$bot_action`,
`$bot_label`, `$bot_log_file`, `$ip_blocked`) are still defined, so server blocks
written for it keep working.

## About the IP addresses in this repository

No address in this repository belongs to the author or to any real visitor.
Every address is one of these:

| Address | What it is |
|---|---|
| `203.0.113.9`, `198.51.100.7`, `203.0.113.0/24` | **Fake example addresses.** They come from the blocks that RFC 5737 reserves for documentation (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), which are never assigned to anyone and never routed on the internet. Replace them with your own values. |
| `127.0.0.1`, `127.0.0.0/8`, `::1` | Localhost: the server itself. Never banned. |
| `1.1.1.1`, `1.0.0.1` | Cloudflare's public DNS resolvers: the default for `RESOLVERS` (OCSP stapling). Change them if you prefer another resolver. |
| `173.245.48.0/20`, `2400:cb00::/32`, ... | Cloudflare's published proxy ranges, built in as a fallback for `BEHIND_CLOUDFLARE=yes`. At run time the script downloads the current list from `https://www.cloudflare.com/ips-v4` and `/ips-v6`. |

## License

Released under the MIT License. See [LICENSE](LICENSE) for details.
