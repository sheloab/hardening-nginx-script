#!/usr/bin/env bash
# ============================================================
#  NGINX SECURITY HARDENING SCRIPT
#  Compatible With : Debian 12/13, Ubuntu 22.04+ | Nginx 1.18+
#  Version         : 5.0
#
#  Changes vs v4.0:
#   [NEW-1]  bot & scanner blocker merged in (was a separate script):
#            user-agent classes, silent 444 drop, per-site snippet,
#            bot-lists/custom.conf for your own rules (never overwritten)
#   [NEW-2]  fail2ban jails that ban dropped bots and hidden-file
#            probes inside nginx itself, so bans hit the visitor even
#            behind a CDN (an iptables ban would hit the CDN's edge)
#   [NEW-3]  Cloudflare mode: real visitor IP (CF-Connecting-IP), and
#            Cloudflare's own addresses are never banned
#   [NEW-4]  optional: add the bot snippet to every enabled site
#   [FIX-8]  jails set backend = auto: a [DEFAULT] backend of systemd
#            silently ignores logpath and the jail reads nothing
#   [FIX-9]  rollback also restores snippets/, bot-lists/ and sites
#   [FIX-10] example server: http2 syntax follows the nginx version;
#            the hidden-file rule leaves /.well-known/ (ACME) reachable
#
#  Changes in v4.0:
#   [FIX-1] headers-more detected via modules-enabled (not nginx -V)
#   [FIX-2] rollback removes generated files before restoring backup
#   [FIX-3] conflict scan covers extensionless site files, not *.conf only
#   [FIX-4] reload falls back to restart, then to `nginx -s reload`
#   [FIX-5] example server uses `listen ... ssl` + `http2 on;` (1.25+)
#   [FIX-6] optional config file for non-interactive runs
#   [FIX-7] IPv6-disabled hosts: comment out Debian's default-site
#           `listen [::]:80 default_server;` before any apt install
#           (nginx -t / package postinst error 97)
#   [NEW]   modernised header defaults (X-XSS-Protection 0, no global
#           Cache-Control, dropped obsolete block-all-mixed-content)
#
#  Usage:
#    sudo ./hardening_nginx_v5.sh [config-file]
#    sudo ./hardening_nginx_v5.sh --help
# ============================================================
set -u

# ── COLORS ───────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; WHITE='\033[1;37m'; NC='\033[0m'

# ── GLOBALS ───────────────────────────────────────────────────
NGINX_DIR="/etc/nginx"
NGINX_CONF="$NGINX_DIR/nginx.conf"
SECURITY_CONF="$NGINX_DIR/conf.d/security-headers.conf"
HARDENING_CONF="$NGINX_DIR/conf.d/hardening.conf"
EXAMPLE_CONF="$NGINX_DIR/conf.d/secure-site-example.conf.disabled"
DHPARAM_FILE="$NGINX_DIR/dhparam.pem"
BACKUP_DIR="$NGINX_DIR/backups/$(date +%Y%m%d_%H%M%S)"
LOG_FILE="/var/log/nginx_security_setup.log"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

# Bot blocker / fail2ban / Cloudflare
BOT_DIR="$NGINX_DIR/bot-lists"
SNIPPETS_DIR="$NGINX_DIR/snippets"
BOT_CLASSIFIER_CONF="$NGINX_DIR/conf.d/bot-classifier.conf"
BOT_LOG_CONF="$NGINX_DIR/conf.d/bot-logformat.conf"
BOT_SNIPPET="$SNIPPETS_DIR/bot-response.conf"
BOT_DENY_FILE="$NGINX_DIR/bot-deny.conf"
CF_REALIP_CONF="$NGINX_DIR/conf.d/cloudflare-realip.conf"
BOT_LOG_DIR="/var/log/nginx/bots"
BOT_LOGROTATE="/etc/logrotate.d/nginx-bots"
F2B_DIR="/etc/fail2ban"

HAS_HEADERS_MORE=false
SKIP_COUNT=0
ADD_COUNT=0
CREATED_FILES=()          # files we create — removed on rollback
CF_RANGES=()              # Cloudflare ranges, filled by load_cloudflare_ranges
F2B_STATUS="off"          # off | ok | failed | missing — for the summary

# ── CONFIG DEFAULTS (overridable by config file / prompts) ────
NON_INTERACTIVE="no"
DOMAIN="example.com"
STRICT_CSP="no"
HSTS_PRELOAD="no"
HSTS_MAX_AGE="31536000"
INSTALL_NGINX_IF_MISSING="yes"
INSTALL_HEADERS_MORE="yes"
GENERATE_DHPARAM="yes"
DHPARAM_BITS="2048"
ENABLE_RATE_LIMIT="yes"
CLIENT_MAX_BODY_SIZE="100m"
RESOLVERS="1.1.1.1 1.0.0.1 valid=300s"
CREATE_EXAMPLE_SERVER="yes"

ENABLE_BOT_BLOCKER="yes"
BLOCK_AI_CRAWLERS="yes"
BLOCK_SEARCH_ENGINES="no"
BOT_AUTO_INCLUDE="no"
ENABLE_FAIL2BAN="yes"
INSTALL_FAIL2BAN="yes"
BAN_TIME="604800"
BAN_IGNORE_IPS=""
BEHIND_CLOUDFLARE="no"

# Cloudflare edge ranges, used when https://www.cloudflare.com/ips-v4 and
# /ips-v6 cannot be fetched at run time.
CF_FALLBACK_V4="173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22
141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22
198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 104.24.0.0/14 172.64.0.0/13 131.0.72.0/22"
CF_FALLBACK_V6="2400:cb00::/32 2606:4700::/32 2803:f800::/32 2405:b500::/32
2405:8100::/32 2a06:98c0::/29 2c0f:f248::/32"

# nginx config files to scan for existing directives (NOT mime.types etc.)
# Fills the global SCAN_PATHS array with existing files/dirs to grep.
SCAN_PATHS=()
build_scan_paths() {
    SCAN_PATHS=()
    [ -f "$NGINX_CONF" ] && SCAN_PATHS+=("$NGINX_CONF")
    for d in "$NGINX_DIR/conf.d" "$NGINX_DIR/sites-enabled" \
             "$NGINX_DIR/sites-available" "$NGINX_DIR/snippets"; do
        [ -d "$d" ] && SCAN_PATHS+=("$d")
    done
}

# True if the headers-more filter module is available (loaded or compiled in).
has_headers_more() {
    shopt -s nullglob
    local mods=("$NGINX_DIR"/modules-enabled/*headers-more* "$NGINX_DIR"/modules-enabled/*headers_more*)
    shopt -u nullglob
    [ ${#mods[@]} -gt 0 ] && return 0
    nginx -V 2>&1 | grep -qiE 'headers.more'
}

# True if IPv6 is off (ipv6.disable=1 at boot, or disabled via sysctl).
ipv6_disabled() {
    [ ! -e /proc/sys/net/ipv6 ] && return 0
    [ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null)" = "1" ]
}

# True if the running nginx is at least version $1 (e.g. 1.25.1).
nginx_version_ge() {
    local v; v=$(nginx -v 2>&1 | sed -nE 's#.*nginx/([0-9.]+).*#\1#p')
    [ -n "$v" ] && [ "$(printf '%s\n%s\n' "$1" "$v" | sort -V | head -1)" = "$1" ]
}

# True if $1 is an IPv4/IPv6 address or CIDR range.
is_ip_or_cidr() {
    [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]] ||
    [[ "$1" =~ ^[0-9A-Fa-f:]*:[0-9A-Fa-f:.]*(/[0-9]{1,3})?$ ]]
}

is_yes() { [[ "$1" =~ ^[Yy]([Ee][Ss])?$ ]]; }

# ── log ───────────────────────────────────────────────────────
log() {
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE" 2>/dev/null
    echo -e "$1"
}

usage() {
    cat <<EOF
Usage: sudo $0 [config-file]

Hardens an nginx install: security headers, TLS settings, buffer/timeout
limits, rate-limit zones, a bot & scanner blocker with fail2ban bans, and
a disabled example server block.

  config-file   Optional. Shell file sourced for settings (see
                hardening_nginx.conf.example). Defaults to
                ./hardening_nginx.conf if present. Without one, the
                script prompts interactively.

Options:
  -h, --help    Show this help and exit.
EOF
}

# ── CONFLICT-DETECTION HELPERS ────────────────────────────────
# Grep the real nginx config set, excluding our own generated files
# and the backups directory. Scans extensionless site files too.
EXCLUDES=(--exclude="hardening.conf" --exclude="security-headers.conf"
          --exclude="bot-classifier.conf" --exclude="bot-logformat.conf"
          --exclude="cloudflare-realip.conf" --exclude="bot-response.conf"
          --exclude="*.disabled" --exclude-dir="backups" --exclude-dir="bot-lists")

directive_exists() {
    build_scan_paths
    grep -rqsE "^[[:space:]]*${1}[[:space:]]" "${EXCLUDES[@]}" "${SCAN_PATHS[@]}" 2>/dev/null
}

zone_exists() {
    build_scan_paths
    grep -rqsE "^[[:space:]]*limit_(req|conn)_zone.*zone=${1}[;:]" "${EXCLUDES[@]}" "${SCAN_PATHS[@]}" 2>/dev/null
}

logformat_exists() {
    build_scan_paths
    grep -rqsE "^[[:space:]]*log_format[[:space:]]+${1}[[:space:]]" "${EXCLUDES[@]}" "${SCAN_PATHS[@]}" 2>/dev/null
}

safe_write() {
    local directive="$1" value="$2" file="$3"
    if directive_exists "$directive"; then
        printf "# [SKIP - already defined elsewhere]: %s %s;\n" "$directive" "$value" >> "$file"
        echo -e "  ${YELLOW}⚠ SKIP${NC}  ${WHITE}${directive}${NC}"
        ((SKIP_COUNT++)) || true
    else
        printf "%s %s;\n" "$directive" "$value" >> "$file"
        echo -e "  ${GREEN}+ ADD${NC}   ${WHITE}${directive}${NC}"
        ((ADD_COUNT++)) || true
    fi
}

safe_zone() {
    local zone_name="$1" zone_line="$2" file="$3"
    if zone_exists "$zone_name"; then
        printf "# [SKIP - zone '%s' already exists]: %s\n" "$zone_name" "$zone_line" >> "$file"
        echo -e "  ${YELLOW}⚠ SKIP${NC}  ${WHITE}zone=${zone_name}${NC}"
        ((SKIP_COUNT++)) || true
    else
        printf "%s\n" "$zone_line" >> "$file"
        echo -e "  ${GREEN}+ ADD${NC}   ${WHITE}zone=${zone_name}${NC}"
        ((ADD_COUNT++)) || true
    fi
}

# ── print_banner ──────────────────────────────────────────────
print_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║        NGINX SECURITY HARDENING SCRIPT  v5.0             ║"
    echo "║        Debian / Ubuntu | Nginx 1.18+                     ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# ── load_config ───────────────────────────────────────────────
load_config() {
    local cf="$1"
    if [ -z "$cf" ] && [ -f "$SCRIPT_DIR/hardening_nginx.conf" ]; then
        cf="$SCRIPT_DIR/hardening_nginx.conf"
    fi
    if [ -n "$cf" ]; then
        if [ ! -f "$cf" ]; then
            echo -e "${RED}[✗] Config file not found: $cf${NC}"; exit 1
        fi
        # shellcheck disable=SC1090
        source "$cf"
        echo -e "${GREEN}[✔] Loaded config: $cf${NC}"
    fi
}

# ── STEP 1: check_root ────────────────────────────────────────
check_root() {
    echo -e "${BLUE}[*] Checking privileges...${NC}"
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[✗] Must be run as root!${NC}"
        echo -e "${YELLOW}    Try: sudo bash $0${NC}"; exit 1
    fi
    echo -e "${GREEN}[✔] Running as root - OK${NC}"
}

# ── STEP 2: check_nginx ───────────────────────────────────────
check_nginx() {
    echo -e "\n${BLUE}[*] Checking Nginx installation...${NC}"
    if ! command -v nginx &>/dev/null; then
        echo -e "${RED}[✗] Nginx is not installed.${NC}"
        local do_install="$INSTALL_NGINX_IF_MISSING"
        if [[ "$NON_INTERACTIVE" != "yes" ]]; then
            echo -e "${YELLOW}[?] Install now? (y/n) [${do_install}]: ${NC}"
            read -r ans; ans="${ans:-$do_install}"
            [[ "$ans" =~ ^[Yy]([Ee][Ss])?$ ]] && do_install="yes" || do_install="no"
        fi
        if [[ "$do_install" == "yes" ]]; then
            apt-get update -qq && apt-get install -y nginx \
                || { echo -e "${RED}[✗] Install failed.${NC}"; exit 1; }
            echo -e "${GREEN}[✔] Nginx installed${NC}"
        else
            echo -e "${RED}[✗] Nginx required. Exiting.${NC}"; exit 1
        fi
    fi
    local ver; ver=$(nginx -v 2>&1 | awk -F'/' '{print $2}')
    echo -e "${GREEN}[✔] Nginx found — Version: $ver${NC}"
}

# ── STEP 3: backup_config ─────────────────────────────────────
backup_config() {
    echo -e "\n${BLUE}[*] Backing up existing configuration...${NC}"
    mkdir -p "$BACKUP_DIR"
    [ -f "$NGINX_CONF" ] && cp -a "$NGINX_CONF" "$BACKUP_DIR/"
    local d
    for d in conf.d sites-available sites-enabled snippets bot-lists; do
        [ -d "$NGINX_DIR/$d" ] && cp -a "$NGINX_DIR/$d" "$BACKUP_DIR/" 2>/dev/null
    done
    echo -e "${GREEN}[✔] Backup saved: $BACKUP_DIR${NC}"
    log "Backup created: $BACKUP_DIR"
}

# ── validate_options ──────────────────────────────────────────
# Stop before touching anything if an option would produce a broken config.
validate_options() {
    local ip bad=0
    for ip in $BAN_IGNORE_IPS; do
        if ! is_ip_or_cidr "$ip"; then
            echo -e "${RED}[✗] BAN_IGNORE_IPS: '$ip' is not an IP address or CIDR range${NC}"; bad=1
        fi
    done
    [[ "$BAN_TIME" =~ ^-?[0-9]+$ ]] || { echo -e "${RED}[✗] BAN_TIME must be a number of seconds${NC}"; bad=1; }
    [ $bad -eq 0 ] || exit 1
}

# ── STEP 4: get_user_input ────────────────────────────────────
get_user_input() {
    if [[ "$NON_INTERACTIVE" == "yes" ]]; then
        echo -e "\n${CYAN}[*] Non-interactive mode — using config values${NC}"
    else
        echo -e "\n${CYAN}══════════════════════════════════════════${NC}"
        echo -e "${WHITE}  CONFIGURATION OPTIONS${NC}"
        echo -e "${CYAN}══════════════════════════════════════════${NC}"

        echo -e "${YELLOW}[?] Domain name [${DOMAIN}]:${NC}"
        read -r ans; DOMAIN="${ans:-$DOMAIN}"

        echo -e "${YELLOW}[?] Strict CSP? May break inline scripts (y/n) [${STRICT_CSP}]:${NC}"
        read -r ans; ans="${ans:-$STRICT_CSP}"
        [[ "$ans" =~ ^[Yy] ]] && STRICT_CSP="yes" || STRICT_CSP="no"

        printf "${YELLOW}[?] HSTS preload? Only if 100%% HTTPS (y/n) [${HSTS_PRELOAD}]:${NC}\n"
        read -r ans; ans="${ans:-$HSTS_PRELOAD}"
        [[ "$ans" =~ ^[Yy] ]] && HSTS_PRELOAD="yes" || HSTS_PRELOAD="no"

        echo -e "${YELLOW}[?] Block bots & scanners (and ban them with fail2ban)? (y/n) [${ENABLE_BOT_BLOCKER}]:${NC}"
        read -r ans; ans="${ans:-$ENABLE_BOT_BLOCKER}"
        [[ "$ans" =~ ^[Yy] ]] && ENABLE_BOT_BLOCKER="yes" || ENABLE_BOT_BLOCKER="no"

        if [[ "$ENABLE_BOT_BLOCKER" == "yes" ]]; then
            echo -e "${YELLOW}[?] Is the site behind Cloudflare? (y/n) [${BEHIND_CLOUDFLARE}]:${NC}"
            read -r ans; ans="${ans:-$BEHIND_CLOUDFLARE}"
            [[ "$ans" =~ ^[Yy] ]] && BEHIND_CLOUDFLARE="yes" || BEHIND_CLOUDFLARE="no"

            echo -e "${YELLOW}[?] Also block search engines (private site, no SEO)? (y/n) [${BLOCK_SEARCH_ENGINES}]:${NC}"
            read -r ans; ans="${ans:-$BLOCK_SEARCH_ENGINES}"
            [[ "$ans" =~ ^[Yy] ]] && BLOCK_SEARCH_ENGINES="yes" || BLOCK_SEARCH_ENGINES="no"

            echo -e "${YELLOW}[?] Your own IPs that must never be banned (space-separated) [${BAN_IGNORE_IPS}]:${NC}"
            read -r ans; BAN_IGNORE_IPS="${ans:-$BAN_IGNORE_IPS}"

            echo -e "${YELLOW}[?] Protect every enabled site now (adds one include line per server block)? (y/n) [${BOT_AUTO_INCLUDE}]:${NC}"
            read -r ans; ans="${ans:-$BOT_AUTO_INCLUDE}"
            [[ "$ans" =~ ^[Yy] ]] && BOT_AUTO_INCLUDE="yes" || BOT_AUTO_INCLUDE="no"
        fi
        validate_options
    fi

    echo -e "${CYAN}──────────────────────────────────────────${NC}"
    echo -e "  ${WHITE}Domain      :${NC} $DOMAIN"
    echo -e "  ${WHITE}Strict CSP  :${NC} $STRICT_CSP"
    echo -e "  ${WHITE}HSTS Preload:${NC} $HSTS_PRELOAD"
    echo -e "  ${WHITE}Bot blocker :${NC} $ENABLE_BOT_BLOCKER"
    if [[ "$ENABLE_BOT_BLOCKER" == "yes" ]]; then
        echo -e "  ${WHITE}  fail2ban  :${NC} $ENABLE_FAIL2BAN"
        echo -e "  ${WHITE}  Cloudflare:${NC} $BEHIND_CLOUDFLARE"
        echo -e "  ${WHITE}  AI/SEO    :${NC} block=$BLOCK_AI_CRAWLERS   search engines: block=$BLOCK_SEARCH_ENGINES"
        echo -e "  ${WHITE}  Never ban :${NC} 127.0.0.1 ::1 ${BAN_IGNORE_IPS}"
    fi
    echo -e "${CYAN}──────────────────────────────────────────${NC}"
}

# ── STEP 5: check_headers_more_module ─────────────────────────
# [FIX-1] Debian/Ubuntu load modules from modules-enabled/, which does
# NOT show up in `nginx -V`. Check that directory first.
check_headers_more_module() {
    echo -e "\n${BLUE}[*] Checking headers-more module...${NC}"

    if has_headers_more; then
        echo -e "${GREEN}[✔] headers-more module available${NC}"
        HAS_HEADERS_MORE=true; return
    fi

    if [[ "$INSTALL_HEADERS_MORE" == "yes" ]]; then
        echo -e "${YELLOW}[!] Not found. Installing nginx-extras...${NC}"
        apt-get update -qq >/dev/null 2>&1
        apt-get install -y nginx-extras >/dev/null 2>&1
        if has_headers_more; then
            echo -e "${GREEN}[✔] nginx-extras installed — headers-more available${NC}"
            HAS_HEADERS_MORE=true; return
        fi
    fi

    echo -e "${YELLOW}[!] headers-more unavailable — Server header stays visible${NC}"
    HAS_HEADERS_MORE=false
}

# ── STEP 6: preflight_scan ────────────────────────────────────
preflight_scan() {
    echo -e "\n${BLUE}[*] Pre-flight scan — existing directives...${NC}"
    local list=(
        server_tokens autoindex client_body_timeout client_header_timeout
        keepalive_timeout send_timeout client_body_buffer_size
        client_header_buffer_size client_max_body_size large_client_header_buffers
        ssl_protocols ssl_ciphers ssl_prefer_server_ciphers ssl_session_timeout
        ssl_session_cache ssl_session_tickets ssl_dhparam resolver
        resolver_timeout log_format
    )
    for d in "${list[@]}"; do
        if directive_exists "$d"; then
            echo -e "  ${YELLOW}[EXISTS]${NC} $d — will be skipped"
        else
            echo -e "  ${GREEN}[FREE]  ${NC} $d — will be added"
        fi
    done
    build_scan_paths
    if directive_exists "ssl_protocols" && \
       grep -rqsE "^[[:space:]]*ssl_protocols.*(TLSv1\.1|TLSv1[[:space:]])" \
           "${EXCLUDES[@]}" "${SCAN_PATHS[@]}" 2>/dev/null; then
        echo -e "  ${RED}⚠ WARNING: existing ssl_protocols includes TLSv1/TLSv1.1${NC}"
        echo -e "  ${YELLOW}  → update it to: ssl_protocols TLSv1.2 TLSv1.3;${NC}"
    fi
}

# ── STEP 7: create_security_headers ───────────────────────────
create_security_headers() {
    echo -e "\n${BLUE}[*] Writing security headers...${NC}"

    local hsts="max-age=${HSTS_MAX_AGE}; includeSubDomains"
    [[ "$HSTS_PRELOAD" =~ ^[Yy]([Ee][Ss])?$ ]] && hsts="$hsts; preload"

    local csp
    if [[ "$STRICT_CSP" =~ ^[Yy]([Ee][Ss])?$ ]]; then
        csp="default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; media-src 'self'; object-src 'none'; frame-src 'none'; form-action 'self'; base-uri 'self'; frame-ancestors 'none'; upgrade-insecure-requests"
    else
        csp="default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; object-src 'none'; frame-src 'self'; form-action 'self'; base-uri 'self'; frame-ancestors 'self'; upgrade-insecure-requests"
    fi

    mkdir -p "$NGINX_DIR/conf.d"
    CREATED_FILES+=("$SECURITY_CONF")
    cat > "$SECURITY_CONF" <<EOF
# ============================================================
#  NGINX SECURITY HEADERS
#  Generated : $(date)
#  Domain    : $DOMAIN
#
#  NOTE: nginx add_header does NOT inherit into a server{} or
#  location{} block that defines its OWN add_header. If a vhost
#  sets any add_header, re-include this file inside that block:
#       include /etc/nginx/conf.d/security-headers.conf;
# ============================================================

add_header Strict-Transport-Security "${hsts}" always;
add_header Content-Security-Policy "${csp}" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "accelerometer=(), autoplay=(), camera=(), display-capture=(), encrypted-media=(), fullscreen=(self), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), usb=()" always;
add_header Cross-Origin-Resource-Policy "same-origin" always;
add_header Cross-Origin-Opener-Policy "same-origin" always;
# COEP breaks third-party embeds (YouTube, Maps). Enable only if needed:
# add_header Cross-Origin-Embedder-Policy "require-corp" always;
# X-XSS-Protection: modern guidance is "0" (the legacy filter caused bugs).
add_header X-XSS-Protection "0" always;
add_header X-Permitted-Cross-Domain-Policies "none" always;
add_header X-DNS-Prefetch-Control "off" always;

# Cache-Control is intentionally NOT set globally — a global "no-store"
# disables caching for static assets and CDNs. Set it per-location, e.g.:
#   location /account { add_header Cache-Control "no-store" always; }
EOF

    if [ "$HAS_HEADERS_MORE" = true ]; then
        cat >> "$SECURITY_CONF" <<'HEOF'

# Hide server identity (requires headers-more / nginx-extras)
more_clear_headers "Server";
more_clear_headers "X-Powered-By";
HEOF
        echo -e "${GREEN}  [+] more_clear_headers enabled${NC}"
    else
        cat >> "$SECURITY_CONF" <<'HEOF'

# headers-more not installed — Server header cannot be removed.
# Install nginx-extras and uncomment:
# more_clear_headers "Server";
# more_clear_headers "X-Powered-By";
HEOF
    fi
    echo -e "${GREEN}[✔] $SECURITY_CONF${NC}"
    log "Security headers written"
}

# ── STEP 8: harden_nginx_conf ─────────────────────────────────
harden_nginx_conf() {
    echo -e "\n${BLUE}[*] Writing core hardening...${NC}"
    SKIP_COUNT=0; ADD_COUNT=0
    CREATED_FILES+=("$HARDENING_CONF")

    cat > "$HARDENING_CONF" <<EOF
# ============================================================
#  NGINX CORE HARDENING   (http{} context, via conf.d include)
#  Generated : $(date)
#  [SKIP] lines were already defined elsewhere and skipped.
# ============================================================

# ── SERVER TOKENS ──
EOF
    safe_write "server_tokens" "off" "$HARDENING_CONF"

    printf "\n# ── BASIC ──\n" >> "$HARDENING_CONF"
    safe_write "autoindex"             "off"  "$HARDENING_CONF"
    safe_write "client_body_timeout"   "10s"  "$HARDENING_CONF"
    safe_write "client_header_timeout" "10s"  "$HARDENING_CONF"
    safe_write "keepalive_timeout"     "65s"  "$HARDENING_CONF"
    safe_write "send_timeout"          "10s"  "$HARDENING_CONF"

    printf "\n# ── BUFFERS ──\n" >> "$HARDENING_CONF"
    safe_write "client_body_buffer_size"     "1k"   "$HARDENING_CONF"
    safe_write "client_header_buffer_size"   "1k"   "$HARDENING_CONF"
    safe_write "client_max_body_size"        "$CLIENT_MAX_BODY_SIZE" "$HARDENING_CONF"
    safe_write "large_client_header_buffers" "4 8k" "$HARDENING_CONF"

    printf "\n# ── SSL/TLS ──\n" >> "$HARDENING_CONF"
    safe_write "ssl_protocols" "TLSv1.2 TLSv1.3" "$HARDENING_CONF"
    safe_write "ssl_ciphers" "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256" "$HARDENING_CONF"
    safe_write "ssl_prefer_server_ciphers" "off"           "$HARDENING_CONF"
    safe_write "ssl_session_timeout"       "1d"            "$HARDENING_CONF"
    safe_write "ssl_session_cache"         "shared:SSL:10m" "$HARDENING_CONF"
    safe_write "ssl_session_tickets"       "off"           "$HARDENING_CONF"

    if directive_exists "ssl_dhparam"; then
        echo "# [SKIP - already defined]: ssl_dhparam $DHPARAM_FILE;" >> "$HARDENING_CONF"
        echo -e "  ${YELLOW}⚠ SKIP${NC}  ${WHITE}ssl_dhparam${NC}"; ((SKIP_COUNT++)) || true
    elif [ -f "$DHPARAM_FILE" ]; then
        echo "ssl_dhparam $DHPARAM_FILE;" >> "$HARDENING_CONF"
        echo -e "  ${GREEN}+ ADD${NC}   ${WHITE}ssl_dhparam${NC}"; ((ADD_COUNT++)) || true
    else
        echo "# ssl_dhparam $DHPARAM_FILE;  # PENDING: enabled after generation" >> "$HARDENING_CONF"
        echo -e "  ${YELLOW}ℹ DEFER${NC} ${WHITE}ssl_dhparam${NC}"
    fi

    printf "\n# ── RESOLVER (for OCSP stapling in server blocks) ──\n" >> "$HARDENING_CONF"
    safe_write "resolver"         "$RESOLVERS" "$HARDENING_CONF"
    safe_write "resolver_timeout" "5s"         "$HARDENING_CONF"
    cat >> "$HARDENING_CONF" <<'HEOF'
# OCSP stapling must live in the SSL server{} block (needs the cert):
#   ssl_stapling on;
#   ssl_stapling_verify on;
#   ssl_trusted_certificate /path/to/chain.pem;
HEOF

    if [[ "$ENABLE_RATE_LIMIT" == "yes" ]]; then
        printf "\n# ── RATE LIMIT ZONES ──\n" >> "$HARDENING_CONF"
        echo -e "  ${CYAN}[Rate limit zones]${NC}"
        safe_zone "general"   'limit_req_zone  $binary_remote_addr zone=general:10m rate=10r/s;' "$HARDENING_CONF"
        safe_zone "login"     'limit_req_zone  $binary_remote_addr zone=login:10m   rate=3r/m;'  "$HARDENING_CONF"
        safe_zone "perip"     'limit_conn_zone $binary_remote_addr zone=perip:10m;'               "$HARDENING_CONF"
        safe_zone "perserver" 'limit_conn_zone $server_name        zone=perserver:10m;'           "$HARDENING_CONF"
    fi

    printf "\n# ── LOG FORMAT ──\n" >> "$HARDENING_CONF"
    if logformat_exists "security"; then
        echo "# [SKIP - log_format 'security' already defined]" >> "$HARDENING_CONF"
        echo -e "  ${YELLOW}⚠ SKIP${NC}  ${WHITE}log_format security${NC}"; ((SKIP_COUNT++)) || true
    else
        cat >> "$HARDENING_CONF" <<'HEOF'
log_format security '$remote_addr - $remote_user [$time_local] '
                    '"$request" $status $body_bytes_sent '
                    '"$http_referer" "$http_user_agent" $request_time';
HEOF
        echo -e "  ${GREEN}+ ADD${NC}   ${WHITE}log_format security${NC}"; ((ADD_COUNT++)) || true
    fi

    echo -e "  ${GREEN}Added: $ADD_COUNT${NC} | ${YELLOW}Skipped: $SKIP_COUNT${NC}"
    echo -e "${GREEN}[✔] $HARDENING_CONF${NC}"
    log "Hardening written (added=$ADD_COUNT, skipped=$SKIP_COUNT)"
}

# ── STEP 9: generate_dhparam ──────────────────────────────────
generate_dhparam() {
    [[ "$GENERATE_DHPARAM" == "yes" ]] || { echo -e "\n${YELLOW}[!] dhparam generation disabled${NC}"; return; }
    echo -e "\n${BLUE}[*] DH parameters...${NC}"
    if [ -f "$DHPARAM_FILE" ]; then
        echo -e "${GREEN}[✔] $DHPARAM_FILE exists — skipping${NC}"; return
    fi
    echo -e "${YELLOW}[!] Generating ${DHPARAM_BITS}-bit DH params (may take a while)...${NC}"
    if openssl dhparam -out "$DHPARAM_FILE" "$DHPARAM_BITS" 2>/dev/null; then
        echo -e "${GREEN}[✔] $DHPARAM_FILE${NC}"
        if grep -q "# ssl_dhparam.*PENDING" "$HARDENING_CONF" 2>/dev/null && ! directive_exists "ssl_dhparam"; then
            sed -i "s|# ssl_dhparam.*PENDING.*|ssl_dhparam $DHPARAM_FILE;|" "$HARDENING_CONF"
            echo -e "${GREEN}  [+] ssl_dhparam enabled in hardening.conf${NC}"
        fi
    else
        echo -e "${YELLOW}[!] DH generation failed — ssl_dhparam left disabled${NC}"
    fi
}

# ── STEP 10: load_cloudflare_ranges ───────────────────────────
# Cloudflare's current edge ranges from cloudflare.com; the built-in copy
# is used if the download fails or looks wrong.
load_cloudflare_ranges() {
    CF_RANGES=()
    local v4 v6 r
    if command -v curl &>/dev/null; then
        v4=$(curl -fsS --max-time 10 https://www.cloudflare.com/ips-v4 2>/dev/null)
        v6=$(curl -fsS --max-time 10 https://www.cloudflare.com/ips-v6 2>/dev/null)
    fi
    local good=()
    for r in ${v4:-} ${v6:-}; do
        is_ip_or_cidr "$r" && [[ "$r" == */* ]] && good+=("$r")
    done
    # shellcheck disable=SC2086
    if [ "$(printf '%s\n' ${v4:-} | grep -c /)" -ge 10 ] && [ ${#good[@]} -ge 15 ]; then
        CF_RANGES=("${good[@]}")
        echo -e "  ${GREEN}✔${NC} Cloudflare ranges: ${#CF_RANGES[@]} (downloaded from cloudflare.com)"
    else
        # shellcheck disable=SC2206
        CF_RANGES=($CF_FALLBACK_V4 $CF_FALLBACK_V6)
        echo -e "  ${YELLOW}⚠${NC} Cloudflare ranges: download failed — using the built-in list (${#CF_RANGES[@]})"
    fi
}

# ── STEP 11: setup_cloudflare_realip ──────────────────────────
# Behind Cloudflare every request arrives from a Cloudflare edge address.
# real_ip makes $remote_addr the visitor again, so logs, rate limits,
# bot bans and allow/deny rules all apply to the visitor, not the edge.
setup_cloudflare_realip() {
    is_yes "$BEHIND_CLOUDFLARE" || return 0
    echo -e "\n${BLUE}[*] Cloudflare: real visitor IP...${NC}"
    load_cloudflare_ranges
    if ! nginx -V 2>&1 | grep -q -- '--with-http_realip_module'; then
        echo -e "  ${YELLOW}⚠${NC} nginx has no realip module — visitor IPs stay as Cloudflare's"
        return 0
    fi
    if directive_exists "real_ip_header"; then
        echo -e "  ${YELLOW}⚠ SKIP${NC}  real_ip_header is already set elsewhere — check it trusts all of:"
        printf '         %s\n' "${CF_RANGES[@]}"
        return 0
    fi
    CREATED_FILES+=("$CF_REALIP_CONF")
    {
        echo "# Cloudflare edge ranges: requests from these carry the visitor's"
        echo "# address in CF-Connecting-IP. Generated $(date); refresh by re-running"
        echo "# the hardening script (source: https://www.cloudflare.com/ips/)."
        printf 'set_real_ip_from %s;\n' "${CF_RANGES[@]}"
        echo "real_ip_header CF-Connecting-IP;"
    } > "$CF_REALIP_CONF"
    echo -e "${GREEN}[✔] $CF_REALIP_CONF${NC}"
    log "Cloudflare real_ip written (${#CF_RANGES[@]} ranges)"
}

# ── STEP 12: create_bot_lists ─────────────────────────────────
# User-agent patterns per class. Matching is case-insensitive (~*); the
# first matching pattern wins, and custom.conf is read first.
create_bot_lists() {
    mkdir -p "$BOT_DIR"
    CREATED_FILES+=("$BOT_DIR/good-bots.conf" "$BOT_DIR/bad-bots.conf"
                    "$BOT_DIR/scanners.conf" "$BOT_DIR/unknown-bots.conf")

    if [ ! -f "$BOT_DIR/custom.conf" ]; then
        CREATED_FILES+=("$BOT_DIR/custom.conf")
        cat > "$BOT_DIR/custom.conf" << 'EOF'
# Your own user-agent rules. Read before every other list and never
# overwritten by the hardening script. Classes: "good", "bad", "scanner",
# "unknown_bot", or "" (treat as a normal visitor). Examples:
# "~*MyUptimeMonitor"                 "";
# "~*SomeAnnoyingBot"                 "bad";
EOF
    fi

    cat > "$BOT_DIR/good-bots.conf" << 'EOF'
# ── GOOGLE ────────────────────────────────────────────────────
"~*Googlebot"                       "good";
"~*Googlebot-Image"                 "good";
"~*Googlebot-News"                  "good";
"~*Googlebot-Video"                 "good";
"~*Google-Read-Aloud"               "good";
"~*Google-InspectionTool"           "good";
"~*GoogleOther"                     "good";
"~*Storebot-Google"                 "good";
"~*AdsBot-Google"                   "good";
"~*Mediapartners-Google"            "good";
"~*FeedFetcher-Google"              "good";

# ── MICROSOFT BING ────────────────────────────────────────────
"~*bingbot"                         "good";
"~*Bingbot"                         "good";
"~*BingPreview"                     "good";
"~*MicrosoftPreview"                "good";
"~*adidxbot"                        "good";

# ── YAHOO ─────────────────────────────────────────────────────
"~*Slurp"                           "good";
"~*Y!J-ASR"                         "good";

# ── DUCKDUCKGO ────────────────────────────────────────────────
"~*DuckDuckBot"                     "good";
"~*DuckDuckGo"                      "good";

# ── APPLE ─────────────────────────────────────────────────────
"~*Applebot"                        "good";

# ── BAIDU ─────────────────────────────────────────────────────
"~*Baiduspider"                     "good";
"~*Baiduspider-image"               "good";

# ── YANDEX ────────────────────────────────────────────────────
"~*YandexBot"                       "good";
"~*YandexImages"                    "good";
"~*YandexVideo"                     "good";
"~*YandexNews"                      "good";
"~*YandexMobileBot"                 "good";

# ── OTHER SEARCH ENGINES ──────────────────────────────────────
"~*Yeti"                            "good";
"~*NaverBot"                        "good";
"~*Sogou"                           "good";
"~*SeznamBot"                       "good";
"~*Exabot"                          "good";

# ── SOCIAL MEDIA PREVIEW ──────────────────────────────────────
"~*facebookexternalhit"             "good";
"~*Twitterbot"                      "good";
"~*LinkedInBot"                     "good";
"~*Slackbot"                        "good";
"~*TelegramBot"                     "good";
"~*WhatsApp"                        "good";
"~*Discordbot"                      "good";
"~*redditbot"                       "good";
"~*Pinterest"                       "good";

# ── UPTIME MONITORS ───────────────────────────────────────────
"~*UptimeRobot"                     "good";
"~*Pingdom"                         "good";
"~*StatusCake"                      "good";
"~*Site24x7"                        "good";
"~*GTmetrix"                        "good";

# ── WEB VALIDATORS ────────────────────────────────────────────
"~*W3C_Validator"                   "good";
"~*W3C-checklink"                   "good";
"~*W3C_CSS_Validator"               "good";
EOF

    cat > "$BOT_DIR/bad-bots.conf" << 'EOF'
# ── AI / LLM TRAINING CRAWLERS ────────────────────────────────
"~*GPTBot"                          "bad";
"~*ChatGPT-User"                    "bad";
"~*OAI-SearchBot"                   "bad";
"~*OpenAI"                          "bad";
"~*CCBot"                           "bad";
"~*cohere-ai"                       "bad";
"~*PerplexityBot"                   "bad";
"~*Amazonbot"                       "bad";
"~*Bytespider"                      "bad";
"~*Diffbot"                         "bad";
"~*ImagesiftBot"                    "bad";
"~*YouBot"                          "bad";
"~*iaskspider"                      "bad";
"~*Meta-ExternalAgent"              "bad";
"~*FacebookBot"                     "bad";
"~*AI2Bot"                          "bad";
"~*Google-Extended"                 "bad";
"~*Applebot-Extended"               "bad";
"~*friendlycrawler"                 "bad";
"~*omgili"                          "bad";
"~*omgilibot"                       "bad";
"~*Webzio-Extended"                 "bad";
"~*DataForSeoBot"                   "bad";

# ── SEO / MARKETING SCRAPERS ──────────────────────────────────
"~*SemrushBot"                      "bad";
"~*SemrushBot-SA"                   "bad";
"~*AhrefsBot"                       "bad";
"~*MJ12bot"                         "bad";
"~*DotBot"                          "bad";
"~*BLEXBot"                         "bad";
"~*MegaIndex"                       "bad";
"~*SeekportBot"                     "bad";
"~*AspiegelBot"                     "bad";
"~*PetalBot"                        "bad";
"~*rogerbot"                        "bad";
"~*ScreamingFrogSEOSpider"          "bad";
"~*Screaming Frog"                  "bad";
"~*SEOkicks-Robot"                  "bad";
"~*linkdexbot"                      "bad";
"~*Barkrowler"                      "bad";
"~*BacklinkCrawler"                 "bad";
"~*Cliqzbot"                        "bad";
"~*Neevabot"                        "bad";
"~*mojeekbot"                       "bad";
"~*Mojeek"                          "bad";
"~*SISTRIX"                         "bad";
"~*NetcraftSurveyAgent"             "bad";

# ── DATA AGGREGATORS ──────────────────────────────────────────
"~*archive.org_bot"                 "bad";
"~*ia_archiver"                     "bad";
"~*heritrix"                        "bad";
"~*Cocolyzebot"                     "bad";
"~*SurdotlyBot"                     "bad";
"~*AwarioRssBot"                    "bad";
"~*AwarioSmartBot"                  "bad";
"~*VelenPublicWebCrawler"           "bad";
"~*Cincraw"                         "bad";
"~*BUbiNG"                          "bad";
"~*Panscient"                       "bad";
"~*GrapeshotCrawler"                "bad";
"~*Mediatoolkitbot"                 "bad";
"~*contentking"                     "bad";
EOF

    cat > "$BOT_DIR/scanners.conf" << 'EOF'
# ── VULNERABILITY SCANNERS ────────────────────────────────────
"~*Nikto"                           "scanner";
"~*nikto"                           "scanner";
"~*sqlmap"                          "scanner";
"~*SQLMap"                          "scanner";
"~*Nmap"                            "scanner";
"~*nmap"                            "scanner";
"~*masscan"                         "scanner";
"~*Masscan"                         "scanner";
"~*zgrab"                           "scanner";
"~*ZGrab"                           "scanner";
"~*nuclei"                          "scanner";
"~*Nuclei"                          "scanner";
"~*acunetix"                        "scanner";
"~*Acunetix"                        "scanner";
"~*w3af"                            "scanner";
"~*skipfish"                        "scanner";
"~*Havij"                           "scanner";
"~*havij"                           "scanner";
"~*Hydra"                           "scanner";
"~*hydra"                           "scanner";
"~*DirBuster"                       "scanner";
"~*dirbuster"                       "scanner";
"~*gobuster"                        "scanner";
"~*ffuf"                            "scanner";
"~*wfuzz"                           "scanner";
"~*feroxbuster"                     "scanner";
"~*WPScan"                          "scanner";
"~*wpscan"                          "scanner";
"~*joomscan"                        "scanner";
"~*droopescan"                      "scanner";
"~*Metasploit"                      "scanner";
"~*OWASP ZAP"                       "scanner";
"~*Nessus"                          "scanner";
"~*OpenVAS"                         "scanner";
"~*Burp Suite"                      "scanner";
"~*AppSpider"                       "scanner";
"~*NetSparker"                      "scanner";
"~*Probely"                         "scanner";

# ── HEADLESS / AUTOMATION TOOLS ───────────────────────────────
"~*HeadlessChrome"                  "scanner";
"~*headlesschrome"                  "scanner";
"~*PhantomJS"                       "scanner";
"~*phantomjs"                       "scanner";
"~*Selenium"                        "scanner";
"~*selenium"                        "scanner";
"~*puppeteer"                       "scanner";
"~*Puppeteer"                       "scanner";

# ── SCRIPTING / HTTP LIBRARIES ────────────────────────────────
"~*libwww-perl"                     "scanner";
"~*python-requests"                 "scanner";
"~*python-urllib"                   "scanner";
"~*Python-urllib"                   "scanner";
"~*python/"                         "scanner";
"~*Python/"                         "scanner";
"~*Go-http-client"                  "scanner";
"~*Ruby"                            "scanner";
"~*Perl"                            "scanner";
"~*curl/"                           "scanner";
"~*wget/"                           "scanner";
"~*Wget/"                           "scanner";
"~*java/"                           "scanner";
"~*Java/"                           "scanner";
"~*PHP/"                            "scanner";
"~*axios"                           "scanner";
"~*node-fetch"                      "scanner";
"~*got/"                            "scanner";
"~*aiohttp"                         "scanner";
"~*httpx"                           "scanner";
"~*okhttp"                          "scanner";
"~*scrapy"                          "scanner";
"~*Scrapy"                          "scanner";

# ── KNOWN MALICIOUS TOOLS ─────────────────────────────────────
"~*HTTrack"                         "scanner";
"~*WebCopier"                       "scanner";
"~*WebStripper"                     "scanner";
"~*WebReaper"                       "scanner";
"~*WebSauger"                       "scanner";
"~*WebZIP"                          "scanner";
"~*Offline Explorer"                "scanner";
"~*Teleport"                        "scanner";
"~*BlackWidow"                      "scanner";
"~*Zeus"                            "scanner";
"~*NetAnts"                         "scanner";
"~*GetRight"                        "scanner";
"~*GetWeb"                          "scanner";
"~*GrabNet"                         "scanner";
"~*EmailCollector"                  "scanner";
"~*EmailSiphon"                     "scanner";
"~*EmailWolf"                       "scanner";
"~*ExtractorPro"                    "scanner";
"~*FlashGet"                        "scanner";
"~*InterGET"                        "scanner";
"~*LeechFTP"                        "scanner";
"~*LexiBot"                         "scanner";
"~*lftp"                            "scanner";
"~*SuperBot"                        "scanner";
"~*TurnitinBot"                     "scanner";
"~*VoidEYE"                         "scanner";
"~*kmccrew"                         "scanner";
"~*DataCha0s"                       "scanner";
"~*DBLbot"                          "scanner";
"~*DittoSpyder"                     "scanner";
"~*EroCrawler"                      "scanner";
"~*Indy Library"                    "scanner";
"~*larbin"                          "scanner";
"~*lwp-trivial"                     "scanner";
"~*moget"                           "scanner";
"~*Net Vampire"                     "scanner";
"~*NICErsPRO"                       "scanner";
"~*PageGrabber"                     "scanner";
"~*ReGet"                           "scanner";
"~*Rippers"                         "scanner";
"~*SiteSnagger"                     "scanner";
"~*SmartDownload"                   "scanner";
"~*suzuran"                         "scanner";
"~*tAkeOut"                         "scanner";
"~*Web Sucker"                      "scanner";
"~*WebAuto"                         "scanner";
"~*WebFetch"                        "scanner";
"~*WebLeacher"                      "scanner";
"~*WebWhacker"                      "scanner";
"~*Xaldon WebSpider"                "scanner";
EOF

    cat > "$BOT_DIR/unknown-bots.conf" << 'EOF'
# Any other user-agent that calls itself a bot/crawler/spider.
"~*[Bb]ot[^a-z]"                    "unknown_bot";
"~*[Cc]rawler"                      "unknown_bot";
"~*[Ss]pider[^a-z]"                 "unknown_bot";
"~*[Ss]craper"                      "unknown_bot";
"~*[Ff]etcher"                      "unknown_bot";
"~*[Ii]ndexer"                      "unknown_bot";
"~*[Hh]arvest"                      "unknown_bot";
"~*[Dd]ownloader"                   "unknown_bot";
EOF
    echo -e "  ${GREEN}✔${NC} Lists: good $(grep -c '"good"' "$BOT_DIR/good-bots.conf") · bad $(grep -c '"bad"' "$BOT_DIR/bad-bots.conf") · scanners $(grep -c '"scanner"' "$BOT_DIR/scanners.conf") · unknown-bot patterns $(grep -c '"unknown_bot"' "$BOT_DIR/unknown-bots.conf")"
}

# ── STEP 13: setup_bot_blocker ────────────────────────────────
# conf.d/ is http{} context  → map, geo, log_format, access_log
# snippets/ is included in server{} → if, return, location
setup_bot_blocker() {
    [[ "$ENABLE_BOT_BLOCKER" == "yes" ]] || { echo -e "\n${YELLOW}[!] Bot blocker disabled${NC}"; return 0; }
    echo -e "\n${BLUE}[*] Bot & scanner blocker...${NC}"
    mkdir -p "$SNIPPETS_DIR" "$BOT_LOG_DIR"
    chown root:adm "$BOT_LOG_DIR" 2>/dev/null; chmod 0750 "$BOT_LOG_DIR"
    create_bot_lists

    # fail2ban's ban list, read by the geo below. Kept across runs (live bans).
    if [ ! -f "$BOT_DENY_FILE" ]; then
        CREATED_FILES+=("$BOT_DENY_FILE")
        printf '# Managed by fail2ban (action nginx-bot-deny): "<ip> 1;" per banned address.\n' > "$BOT_DENY_FILE"
    fi

    local drop_bad=0 drop_good=0 ip trusted=""
    is_yes "$BLOCK_AI_CRAWLERS"   && drop_bad=1
    is_yes "$BLOCK_SEARCH_ENGINES" && drop_good=1
    for ip in $BAN_IGNORE_IPS; do trusted+=$(printf '    %-40s 1;\n' "$ip"); trusted+=$'\n'; done

    CREATED_FILES+=("$BOT_CLASSIFIER_CONF")
    cat > "$BOT_CLASSIFIER_CONF" << EOF
# ============================================================
#  BOT CLASSIFIER   (http{} context: map and geo only)
#  Generated : $(date)
#  Lists     : $BOT_DIR/*.conf (custom.conf is yours)
#  Use it    : include $BOT_SNIPPET;  inside each server{}
# ============================================================

# ── user-agent → class ──
map \$http_user_agent \$bot_class {
    default         "";

    include $BOT_DIR/custom.conf;
    include $BOT_DIR/good-bots.conf;
    include $BOT_DIR/bad-bots.conf;
    include $BOT_DIR/scanners.conf;
    include $BOT_DIR/unknown-bots.conf;

    # Empty / blank user-agent = scanner
    ""              "scanner";
    " "             "scanner";
    "-"             "scanner";
}

# ── classes dropped with 444 (set by the hardening script options) ──
map \$bot_class \$bot_drop_class {
    default         0;
    "scanner"       1;
    "unknown_bot"   1;
    "bad"           $drop_bad;     # AI / SEO crawlers   (BLOCK_AI_CRAWLERS)
    "good"          $drop_good;     # search engines      (BLOCK_SEARCH_ENGINES)
}

# ── never dropped, logged or banned: localhost and your own IPs ──
geo \$bot_trusted {
    default         0;
    127.0.0.0/8     1;
    ::1             1;
${trusted}}

# 1 = drop this request (and log it for fail2ban)
map "\$bot_trusted\$bot_drop_class" \$bot_block {
    default         0;
    "01"            1;
}

# ── addresses banned by fail2ban (jails nginx-bot / nginx-probe) ──
geo \$ip_blocked {
    default 0;
    include $BOT_DENY_FILE;
}

# ── kept for server blocks written for the older bot blocker ──
map \$bot_class \$bot_action {
    default         0;
    "good"          1;
    "bad"           2;
    "scanner"       3;
    "unknown_bot"   4;
}
map \$bot_class \$bot_label {
    default         "HUMAN";
    "good"          "GOOD_BOT";
    "bad"           "BAD_BOT";
    "scanner"       "SCANNER";
    "unknown_bot"   "UNKNOWN_BOT";
}
# File NAME only: nginx prefixes a path that starts with a variable, so
# keep the directory static:  access_log $BOT_LOG_DIR/\$bot_log_file bot_log;
map \$bot_class \$bot_log_file {
    default         humans.log;
    "good"          good-bots.log;
    "bad"           bad-bots.log;
    "scanner"       scanners.log;
    "unknown_bot"   unknown-bots.log;
}
EOF
    echo -e "  ${GREEN}✔${NC} $BOT_CLASSIFIER_CONF"

    CREATED_FILES+=("$BOT_LOG_CONF")
    {
        echo "# ============================================================"
        echo "#  BOT LOG   (http{} context)"
        echo "#  One line per dropped request — read by fail2ban (nginx-bot)."
        echo "# ============================================================"
        if logformat_exists "bot_log"; then
            echo "# [SKIP - log_format 'bot_log' already defined elsewhere]"
            echo -e "  ${YELLOW}⚠ SKIP${NC}  log_format bot_log (keep it as: [\$time_local] LABEL IP=\$remote_addr ...)" >&2
        else
            cat << 'EOF'
log_format bot_log '[$time_local] $bot_label '
                   'IP=$remote_addr '
                   'STATUS=$status '
                   'UA="$http_user_agent" '
                   'REQ="$request" '
                   'REF="$http_referer" '
                   'HOST="$host"';
EOF
        fi
        echo
        echo "# Inherited by every server{} that has NO access_log of its own. A server"
        echo "# with its own access_log needs this same line inside it (see the snippet)."
        # An http-level access_log replaces nginx's built-in default log, so keep
        # the standard one when nginx.conf does not declare it.
        if ! grep -qsE '^[[:space:]]*access_log[[:space:]]' "$NGINX_CONF"; then
            echo "access_log /var/log/nginx/access.log;"
        fi
        echo "access_log $BOT_LOG_DIR/bots.log bot_log if=\$bot_block;"
    } > "$BOT_LOG_CONF"
    echo -e "  ${GREEN}✔${NC} $BOT_LOG_CONF"

    CREATED_FILES+=("$BOT_SNIPPET")
    cat > "$BOT_SNIPPET" << EOF
# ============================================================
#  BOT RESPONSE   (server{} context)
#  Add inside every server{} block to protect:
#      include $BOT_SNIPPET;
#  If that server{} has its own access_log, add this line too, or the
#  drops it makes are not logged and fail2ban cannot ban them:
#      access_log $BOT_LOG_DIR/bots.log bot_log if=\$bot_block;
# ============================================================

# Banned by fail2ban → drop without an answer
if (\$ip_blocked) {
    return 444;
}

# Scanners, scripts, empty user-agents, unknown bots (+ AI/SEO crawlers and
# search engines when blocked) → drop without an answer
if (\$bot_block) {
    return 444;
}

# Hidden files (/.env, /.git/config, ...): no browser asks for them. Each hit
# is logged as "access forbidden by rule" for the nginx-probe jail.
# /.well-known/ stays reachable (ACME certificates, security.txt).
location ~ /\.(?!well-known/) {
    deny all;
}
EOF
    echo -e "  ${GREEN}✔${NC} $BOT_SNIPPET"

    if [ ! -f "$BOT_LOGROTATE" ]; then
        CREATED_FILES+=("$BOT_LOGROTATE")
        cat > "$BOT_LOGROTATE" << EOF
$BOT_LOG_DIR/*.log {
    daily
    rotate 30
    missingok
    notifempty
    compress
    delaycompress
    create 0640 www-data adm
    sharedscripts
    postrotate
        invoke-rc.d nginx rotate >/dev/null 2>&1
    endscript
}
EOF
        echo -e "  ${GREEN}✔${NC} $BOT_LOGROTATE"
    fi
    log "Bot blocker written (drop AI/SEO=$drop_bad, drop search engines=$drop_good)"
}

# ── STEP 14: auto_include_bot_snippet  [NEW-4] ────────────────
# Adds the snippet to every server{} block in sites-enabled that lacks it,
# right after its server_name line. A block with its own server-level
# access_log also gets the bots.log line. Undone by the rollback if
# nginx -t fails.
auto_include_bot_snippet() {
    [[ "$ENABLE_BOT_BLOCKER" == "yes" ]] && is_yes "$BOT_AUTO_INCLUDE" || return 0
    echo -e "\n${BLUE}[*] Adding the bot snippet to enabled sites...${NC}"
    local f real tmp n
    shopt -s nullglob
    for f in "$NGINX_DIR"/sites-enabled/*; do
        real=$(readlink -f "$f"); [ -f "$real" ] || continue
        tmp=$(mktemp)
        awk -v inc="    include $BOT_SNIPPET;" \
            -v logl="    access_log $BOT_LOG_DIR/bots.log bot_log if=\$bot_block;" '
            function flush(   i, done) {
                for (i = 1; i <= nb; i++) {
                    print blk[i]
                    if (!has_inc && !done && (i == (sn ? sn : 1))) {
                        print inc
                        if (own_log) print logl
                        done = 1; added++
                    }
                }
                nb = 0; has_inc = 0; own_log = 0; sn = 0
            }
            {
                code = $0; sub(/#.*/, "", code)
                if (!inblk && code ~ /^[ \t]*server[ \t]*\{/) { inblk = 1; depth = 0 }
                if (!inblk) { print; next }
                blk[++nb] = $0
                if (depth == 1 && !sn && code ~ /^[ \t]*server_name[ \t]/) sn = nb
                if (depth == 1 && code ~ /^[ \t]*access_log[ \t]/) own_log = 1
                if (code ~ /bot-response\.conf/) has_inc = 1
                o = gsub(/\{/, "{", code); c = gsub(/\}/, "}", code); depth += o - c
                if (depth <= 0) { inblk = 0; flush() }
            }
            END { if (inblk) flush(); print added + 0 > "/dev/stderr" }
        ' "$real" > "$tmp" 2> "$tmp.n"
        n=$(cat "$tmp.n" 2>/dev/null); n=${n:-0}
        if [ "$n" -gt 0 ] && ! cmp -s "$tmp" "$real"; then
            cat "$tmp" > "$real"
            echo -e "  ${GREEN}+ ADD${NC}   ${WHITE}$real${NC} ($n server block(s))"
            log "Bot snippet added to $real ($n blocks)"
        else
            echo -e "  ${CYAN}=${NC}       $real (already protected)"
        fi
        rm -f "$tmp" "$tmp.n"
    done
    shopt -u nullglob
}

# ── STEP 15: create_example_server ────────────────────────────
create_example_server() {
    [[ "$CREATE_EXAMPLE_SERVER" == "yes" ]] || return
    echo -e "\n${BLUE}[*] Writing example server block (disabled)...${NC}"
    CREATED_FILES+=("$EXAMPLE_CONF")

    # [FIX-10] `http2 on;` exists from nginx 1.25.1; older versions take it on listen.
    local listen_ssl listen_ssl6 http2_line="" v6=""
    if nginx_version_ge 1.25.1; then
        listen_ssl="listen      443 ssl;"; listen_ssl6="listen      [::]:443 ssl;"
        http2_line="    http2       on;"
    else
        listen_ssl="listen      443 ssl http2;"; listen_ssl6="listen      [::]:443 ssl http2;"
    fi
    # [FIX-7] an IPv6 listener stops nginx on a host with IPv6 turned off
    ipv6_disabled && v6="# [IPv6 disabled] "

    local bot_block robots
    if [[ "$ENABLE_BOT_BLOCKER" == "yes" ]]; then
        bot_block="    # Bot & scanner blocker (and the hidden-file rule)
    include $BOT_SNIPPET;"
        if [[ "$ENABLE_FAIL2BAN" == "yes" ]]; then
            bot_block+="

    # Honeypot: paths only attack tools ask for — first hit = banned.
    # Remove this block if the site really runs WordPress or phpMyAdmin.
    location ~* ^/(wp-admin|wp-login\\.php|xmlrpc\\.php|phpmyadmin|pma)(/|\$) {
        access_log $BOT_LOG_DIR/honeypot.log bot_log;
        return 444;
    }"
        fi
    else
        bot_block="    if (\$http_user_agent ~* (nmap|nikto|sqlmap|acunetix|havij|appscan)) { return 403; }

    # Hidden files (/.env, /.git/...); /.well-known/ stays reachable for ACME
    location ~ /\\.(?!well-known/) { deny all; access_log off; log_not_found off; }"
    fi

    if is_yes "$BLOCK_SEARCH_ENGINES"; then
        robots='User-agent: *\nDisallow: /\n'
    elif is_yes "$BLOCK_AI_CRAWLERS" && [[ "$ENABLE_BOT_BLOCKER" == "yes" ]]; then
        robots='User-agent: GPTBot\nUser-agent: ChatGPT-User\nUser-agent: CCBot\nUser-agent: Google-Extended\nUser-agent: Applebot-Extended\nUser-agent: PerplexityBot\nUser-agent: Bytespider\nUser-agent: Meta-ExternalAgent\nDisallow: /\n\nUser-agent: *\nAllow: /\n'
    else
        robots='User-agent: *\nAllow: /\n'
    fi

    cat > "$EXAMPLE_CONF" <<EOF
# ============================================================
#  EXAMPLE SECURE SERVER BLOCK  (rename to activate)
#  Replace $DOMAIN with your domain.
# ============================================================

server {
    listen      80;
    ${v6}listen      [::]:80;
    server_name $DOMAIN www.$DOMAIN;
$( [[ "$ENABLE_BOT_BLOCKER" == "yes" ]] && echo "    include $BOT_SNIPPET;" )
    return 301  https://\$host\$request_uri;
}

server {
    $listen_ssl
    ${v6}$listen_ssl6
$http2_line
    server_name $DOMAIN www.$DOMAIN;

    ssl_certificate         /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key     /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    ssl_trusted_certificate /etc/letsencrypt/live/$DOMAIN/chain.pem;

    ssl_stapling        on;
    ssl_stapling_verify on;

    include /etc/nginx/conf.d/security-headers.conf;

$bot_block

    limit_req  zone=general burst=20 nodelay;
    limit_conn perip 10;
    limit_conn perserver 100;

    root  /var/www/$DOMAIN/html;
    index index.html index.htm;

    if (\$request_method !~ ^(GET|HEAD|POST|PUT|DELETE|OPTIONS|PATCH)\$) { return 405; }

    location = /robots.txt {
        default_type text/plain;
        return 200 "$robots";
    }

    location ~* \\.(bak|conf|dist|env|inc|ini|log|sh|sql|swp|tar|gz|zip)\$ { deny all; }

    location /login {
        limit_req zone=login burst=5 nodelay;
        # re-include headers because this block would otherwise drop them:
        include /etc/nginx/conf.d/security-headers.conf;
    }

    location / { try_files \$uri \$uri/ =404; }

    access_log /var/log/nginx/${DOMAIN}_access.log security;
$( [[ "$ENABLE_BOT_BLOCKER" == "yes" ]] && echo "    access_log $BOT_LOG_DIR/bots.log bot_log if=\$bot_block;" )
    error_log  /var/log/nginx/${DOMAIN}_error.log  warn;
}
EOF
    echo -e "${GREEN}[✔] $EXAMPLE_CONF${NC}"
    echo -e "${YELLOW}    Activate: mv $EXAMPLE_CONF ${EXAMPLE_CONF/.disabled/}${NC}"
}

# ── STEP 16: check_include ────────────────────────────────────
check_include() {
    echo -e "\n${BLUE}[*] Verifying conf.d include...${NC}"
    if grep -q "include /etc/nginx/conf.d/" "$NGINX_CONF" 2>/dev/null; then
        echo -e "${GREEN}[✔] conf.d already included${NC}"
    else
        sed -i '/http\s*{/a\    include /etc/nginx/conf.d/*.conf;' "$NGINX_CONF"
        echo -e "${GREEN}[✔] Added conf.d include to nginx.conf${NC}"
    fi
}

# ── STEP 3b: disable_ipv6_default_listener  [FIX-7] ───────────
# With IPv6 off, Debian's default site line `listen [::]:80 default_server;`
# makes nginx fail with
# "socket() [::]:80 failed (97: Address family not supported by protocol)".
# Runs after backup_config and before check_headers_more_module, so the
# nginx-extras install can start nginx and finish configuring its packages.
disable_ipv6_default_listener() {
    ipv6_disabled || return 0
    echo -e "\n${BLUE}[*] IPv6 disabled — checking for 'listen [::]:80 default_server'...${NC}"
    build_scan_paths
    local f
    while IFS= read -r f; do
        sed -i --follow-symlinks -E \
            's/^([[:space:]]*)(listen[[:space:]]+\[::\]:80[[:space:]]+default_server)/\1# [IPv6 disabled] \2/' "$f"
        echo -e "  ${GREEN}+ FIX${NC}   ${WHITE}${f}${NC}"
        log "Commented out 'listen [::]:80 default_server' in $f"
    done < <(grep -rlsE '^[[:space:]]*listen[[:space:]]+\[::\]:80[[:space:]]+default_server' \
                 "${EXCLUDES[@]}" "${SCAN_PATHS[@]}" 2>/dev/null)
}

# ── restore_backup  [FIX-2, FIX-9] ────────────────────────────
restore_backup() {
    echo -e "${YELLOW}[*] Rolling back...${NC}"
    # Remove files we created this run so they can't linger and break -t.
    for f in "${CREATED_FILES[@]}"; do rm -f "$f"; done
    if [ -d "$BACKUP_DIR" ]; then
        [ -f "$BACKUP_DIR/nginx.conf" ] && cp -a "$BACKUP_DIR/nginx.conf" "$NGINX_CONF"
        local d
        for d in conf.d snippets bot-lists sites-available sites-enabled; do
            if [ -d "$BACKUP_DIR/$d" ]; then
                rm -rf "${NGINX_DIR:?}/$d"
                cp -a "$BACKUP_DIR/$d" "$NGINX_DIR/$d"
            fi
        done
        echo -e "${GREEN}[✔] Backup restored from $BACKUP_DIR${NC}"
    else
        echo -e "${RED}[✗] Backup dir not found: $BACKUP_DIR${NC}"
    fi
}

# ── STEP 17: test_nginx ───────────────────────────────────────
test_nginx() {
    echo -e "\n${BLUE}[*] Testing configuration...${NC}"
    local out; out=$(nginx -t 2>&1); echo "$out"
    if echo "$out" | grep -q "successful"; then
        echo -e "${GREEN}[✔] Config test PASSED${NC}"; return 0
    else
        echo -e "${RED}[✗] Config test FAILED — restoring backup${NC}"
        restore_backup
        nginx -t >/dev/null 2>&1 \
            && echo -e "${GREEN}[✔] Restored config is valid${NC}" \
            || echo -e "${RED}[✗] Restored config still invalid — check manually${NC}"
        return 1
    fi
}

# ── STEP 18: reload_nginx  [FIX-4] ────────────────────────────
reload_nginx() {
    echo -e "\n${BLUE}[*] Reloading Nginx...${NC}"
    if systemctl reload nginx 2>/dev/null; then
        echo -e "${GREEN}[✔] Reloaded (systemctl)${NC}"; log "reloaded"
    elif systemctl restart nginx 2>/dev/null; then
        echo -e "${GREEN}[✔] Restarted (systemctl)${NC}"; log "restarted"
    elif nginx -s reload 2>/dev/null; then
        echo -e "${GREEN}[✔] Reloaded (nginx -s reload)${NC}"; log "reloaded via signal"
    else
        echo -e "${RED}[✗] Reload failed — check: systemctl status nginx${NC}"
    fi
}

# ── STEP 19: setup_fail2ban  [NEW-2, FIX-8] ───────────────────
# Runs after nginx passed its test. A broken fail2ban config is rolled
# back on its own and never touches the (already valid) nginx setup.
setup_fail2ban() {
    [[ "$ENABLE_BOT_BLOCKER" == "yes" && "$ENABLE_FAIL2BAN" == "yes" ]] || return 0
    echo -e "\n${BLUE}[*] fail2ban: ban dropped bots and hidden-file probes...${NC}"

    if ! command -v fail2ban-client &>/dev/null; then
        if [[ "$INSTALL_FAIL2BAN" == "yes" ]]; then
            echo -e "  ${YELLOW}[!] Installing fail2ban...${NC}"
            apt-get update -qq >/dev/null 2>&1
            apt-get install -y fail2ban >/dev/null 2>&1
        fi
        command -v fail2ban-client &>/dev/null || {
            F2B_STATUS="missing"
            echo -e "  ${YELLOW}⚠${NC} fail2ban not installed — bots are dropped but not banned"; return 0; }
    fi

    # Every logpath must exist, or fail2ban refuses to start the jail.
    local lf
    for lf in "$BOT_LOG_DIR/bots.log" "$BOT_LOG_DIR/honeypot.log"; do
        [ -f "$lf" ] || { touch "$lf"; chown www-data:adm "$lf" 2>/dev/null; chmod 0640 "$lf"; }
    done
    compgen -G "/var/log/nginx/*error.log" >/dev/null || touch /var/log/nginx/error.log

    local ignore="127.0.0.1/8 ::1"
    [ -n "$BAN_IGNORE_IPS" ] && ignore+=" $BAN_IGNORE_IPS"
    if is_yes "$BEHIND_CLOUDFLARE"; then
        [ ${#CF_RANGES[@]} -gt 0 ] || load_cloudflare_ranges
        ignore+=" ${CF_RANGES[*]}"
    fi

    local files=("$F2B_DIR/action.d/nginx-bot-deny.conf" "$F2B_DIR/filter.d/nginx-bot.conf"
                 "$F2B_DIR/filter.d/nginx-probe.conf" "$F2B_DIR/jail.d/nginx-bot.conf"
                 "$F2B_DIR/jail.d/nginx-probe.conf")
    local f2b_backup="$BACKUP_DIR/fail2ban" f
    mkdir -p "$f2b_backup" "$F2B_DIR/action.d" "$F2B_DIR/filter.d" "$F2B_DIR/jail.d"
    for f in "${files[@]}"; do [ -f "$f" ] && cp -a "$f" "$f2b_backup/"; done

    cat > "$F2B_DIR/action.d/nginx-bot-deny.conf" << EOF
# Ban inside nginx: add "<ip> 1;" to the geo \$ip_blocked list ($BOT_DENY_FILE),
# then reload. Works behind a CDN, where an iptables ban would hit the CDN.
[Definition]
actionstart = touch $BOT_DENY_FILE
actionstop  =
actioncheck =
actionban   = grep -qxF '<ip> 1;' $BOT_DENY_FILE || echo '<ip> 1;' >> $BOT_DENY_FILE; nginx -t -q && nginx -s reload
actionunban = grep -vxF '<ip> 1;' $BOT_DENY_FILE > $BOT_DENY_FILE.tmp; cat $BOT_DENY_FILE.tmp > $BOT_DENY_FILE; rm -f $BOT_DENY_FILE.tmp; nginx -t -q && nginx -s reload
EOF

    cat > "$F2B_DIR/filter.d/nginx-bot.conf" << 'EOF'
# Lines written by nginx (log_format bot_log) for dropped requests, e.g.
# (203.0.113.9 is a fake documentation address, RFC 5737)
# [01/Jan/2026:00:00:00 +0000] SCANNER IP=203.0.113.9 STATUS=444 UA="..." REQ="..."
# bots.log only receives requests that were dropped; honeypot.log only
# receives requests for honeypot paths. Every line is a ban.
[Definition]
failregex = ^\s*\S+ IP=<HOST>\s
ignoreregex =
datepattern = ^\[%%d/%%b/%%Y:%%H:%%M:%%S %%z\]
EOF

    cat > "$F2B_DIR/filter.d/nginx-probe.conf" << 'EOF'
# nginx "access forbidden by rule" = a request for a hidden/blocked file
# (/.env, /.git/...). No human browses to those; scanners that fake a browser
# user-agent are caught here. /.well-known/ is excluded.
[Definition]
failregex = \[error\] \d+#\d+: \*\d+ access forbidden by rule, client: <HOST>, server: \S*, request: "\w+ (?!/\.well-known/)
ignoreregex =
datepattern = ^%%Y/%%m/%%d %%H:%%M:%%S
EOF

    cat > "$F2B_DIR/jail.d/nginx-bot.conf" << EOF
# Requests nginx dropped as bots/scanners, and honeypot hits: banned on the
# first one. backend = auto, because a [DEFAULT] backend of systemd ignores
# logpath and the jail would silently read nothing.
[nginx-bot]
enabled  = true
backend  = auto
filter   = nginx-bot
logpath  = $BOT_LOG_DIR/bots.log
           $BOT_LOG_DIR/honeypot.log
maxretry = 1
findtime = 600
bantime  = $BAN_TIME
action   = nginx-bot-deny
ignoreip = $ignore
EOF

    cat > "$F2B_DIR/jail.d/nginx-probe.conf" << EOF
# Requests for hidden files (/.env, /.git/...) in any nginx error log.
[nginx-probe]
enabled  = true
backend  = auto
filter   = nginx-probe
logpath  = /var/log/nginx/*error.log
maxretry = 1
findtime = 600
bantime  = $BAN_TIME
action   = nginx-bot-deny
ignoreip = $ignore
EOF

    local out; out=$(fail2ban-client -t 2>&1)
    if ! grep -q "configuration test is successful" <<<"$out"; then
        echo "$out" | tail -5
        echo -e "  ${RED}[✗] fail2ban config test FAILED — restoring its previous files${NC}"
        echo -e "  ${YELLOW}    (the error may come from another jail; fix it, then re-run)${NC}"
        F2B_STATUS="failed"
        for f in "${files[@]}"; do
            if [ -f "$f2b_backup/$(basename "$f")" ]; then cp -a "$f2b_backup/$(basename "$f")" "$f"; else rm -f "$f"; fi
        done
        return 0
    fi

    if fail2ban-client ping >/dev/null 2>&1; then
        fail2ban-client reload >/dev/null 2>&1
    else
        systemctl enable --now fail2ban >/dev/null 2>&1 || fail2ban-client start >/dev/null 2>&1
    fi
    sleep 2

    # [FIX-8] prove each jail is really reading its files
    local j lp
    F2B_STATUS="ok"
    for j in nginx-bot nginx-probe; do
        lp=$(fail2ban-client get "$j" logpath 2>&1)
        if grep -q "/var/log/nginx" <<<"$lp"; then
            echo -e "  ${GREEN}✔${NC} jail $j reads: $(grep -oE '/var/log/nginx/[^ ]+' <<<"$lp" | tr '\n' ' ')"
        else
            echo -e "  ${RED}✗${NC} jail $j is not reading any log — check: fail2ban-client status $j"
            F2B_STATUS="failed"
        fi
    done
    log "fail2ban jails nginx-bot / nginx-probe configured"
}

# ── STEP 20: verify_headers ───────────────────────────────────
verify_headers() {
    echo -e "\n${BLUE}[*] Verifying headers on localhost...${NC}"
    command -v curl &>/dev/null || { echo -e "${YELLOW}[!] curl not installed${NC}"; return; }
    sleep 1  # let reloaded workers take over before probing
    local resp; resp=$(curl -skI --max-time 5 http://localhost 2>/dev/null)
    [ -z "$resp" ] && resp=$(curl -skI --max-time 5 https://localhost 2>/dev/null)
    [ -z "$resp" ] && { echo -e "${YELLOW}[!] No response from localhost${NC}"; return; }

    local headers=(Strict-Transport-Security Content-Security-Policy X-Frame-Options
        X-Content-Type-Options Referrer-Policy Permissions-Policy
        Cross-Origin-Resource-Policy Cross-Origin-Opener-Policy X-XSS-Protection
        X-Permitted-Cross-Domain-Policies X-DNS-Prefetch-Control)
    local p=0 f=0
    for h in "${headers[@]}"; do
        if echo "$resp" | grep -qi "^${h}:"; then
            echo -e "  ${GREEN}✔${NC} $h"; ((p++)) || true
        else
            echo -e "  ${RED}✗${NC} $h"; ((f++)) || true
        fi
    done
    echo -e "  ${GREEN}Found: $p${NC} | ${RED}Missing: $f${NC}"
    [ $f -gt 0 ] && echo -e "  ${YELLOW}Missing headers usually appear once an SSL server block serves a page.${NC}"
}

# ── STEP 21: verify_bot_blocker ───────────────────────────────
verify_bot_blocker() {
    [[ "$ENABLE_BOT_BLOCKER" == "yes" ]] || return 0
    echo -e "\n${BLUE}[*] Sites protected by the bot blocker...${NC}"
    local n; n=$(nginx -T 2>/dev/null | grep -cE "^[[:space:]]*include[[:space:]]+$BOT_SNIPPET;")
    if [ "${n:-0}" -gt 0 ]; then
        echo -e "  ${GREEN}✔${NC} $n server block(s) include $BOT_SNIPPET"
    else
        echo -e "  ${YELLOW}⚠${NC} No server block includes it yet. Add inside each server{}:"
        echo -e "      include $BOT_SNIPPET;"
        echo -e "  (or re-run with BOT_AUTO_INCLUDE=yes)"
    fi
}

print_summary() {
    echo -e "\n${GREEN}╔══════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║            SETUP COMPLETE                 ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
    echo -e "  Files: security-headers.conf, hardening.conf, secure-site-example.conf.disabled"
    if [[ "$ENABLE_BOT_BLOCKER" == "yes" ]]; then
        echo -e "  Bots : bot-classifier.conf, bot-logformat.conf, snippets/bot-response.conf, bot-lists/"
        echo -e "         your own rules: $BOT_DIR/custom.conf"
        echo -e "  Logs : $BOT_LOG_DIR/bots.log (dropped), honeypot.log"
        case "$F2B_STATUS" in
            ok)      echo -e "  Bans : fail2ban-client status nginx-bot | nginx-probe   (list: $BOT_DENY_FILE)" ;;
            failed)  echo -e "  ${RED}Bans : NOT active — fail2ban setup failed (see above). Bots are dropped, not banned.${NC}" ;;
            missing) echo -e "  ${YELLOW}Bans : NOT active — fail2ban is not installed. Bots are dropped, not banned.${NC}" ;;
        esac
    fi
    echo -e "  Backup: $BACKUP_DIR"
    echo -e "  Test:  https://securityheaders.com  |  https://ssllabs.com/ssltest"
}

# ── MAIN ──────────────────────────────────────────────────────
main() {
    case "${1:-}" in -h|--help) usage; exit 0 ;; esac
    print_banner
    load_config "${1:-}"
    check_root
    validate_options
    check_nginx
    backup_config
    disable_ipv6_default_listener
    get_user_input
    check_headers_more_module
    preflight_scan
    create_security_headers
    harden_nginx_conf
    generate_dhparam
    setup_cloudflare_realip
    setup_bot_blocker
    auto_include_bot_snippet
    create_example_server
    check_include
    if test_nginx; then
        reload_nginx
        setup_fail2ban
        verify_headers
        verify_bot_blocker
        print_summary
    else
        echo -e "\n${RED}[✗] SETUP FAILED — original config restored.${NC}"
        echo -e "${YELLOW}[!] Log: $LOG_FILE${NC}"
        exit 1
    fi
}

main "$@"
