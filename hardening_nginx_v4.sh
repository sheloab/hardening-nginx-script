#!/usr/bin/env bash
# ============================================================
#  NGINX SECURITY HARDENING SCRIPT
#  Compatible With : Debian 12/13, Ubuntu 22.04+ | Nginx 1.18+
#  Version         : 4.0
#
#  Changes vs v3.0:
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
#    sudo ./hardening_nginx_v4.sh [config-file]
#    sudo ./hardening_nginx_v4.sh --help
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

HAS_HEADERS_MORE=false
SKIP_COUNT=0
ADD_COUNT=0
CREATED_FILES=()          # files we create — removed on rollback

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
limits, rate-limit zones, and a disabled example server block.

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
          --exclude="*.disabled" --exclude-dir="backups")

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
    echo "║        NGINX SECURITY HARDENING SCRIPT  v4.0             ║"
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
    [ -f "$NGINX_CONF" ]                && cp    "$NGINX_CONF"                "$BACKUP_DIR/"
    [ -d "$NGINX_DIR/conf.d" ]          && cp -r "$NGINX_DIR/conf.d"          "$BACKUP_DIR/" 2>/dev/null
    [ -d "$NGINX_DIR/sites-available" ] && cp -r "$NGINX_DIR/sites-available" "$BACKUP_DIR/" 2>/dev/null
    [ -d "$NGINX_DIR/sites-enabled" ]   && cp -r "$NGINX_DIR/sites-enabled"   "$BACKUP_DIR/" 2>/dev/null
    echo -e "${GREEN}[✔] Backup saved: $BACKUP_DIR${NC}"
    log "Backup created: $BACKUP_DIR"
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
    fi

    echo -e "${CYAN}──────────────────────────────────────────${NC}"
    echo -e "  ${WHITE}Domain      :${NC} $DOMAIN"
    echo -e "  ${WHITE}Strict CSP  :${NC} $STRICT_CSP"
    echo -e "  ${WHITE}HSTS Preload:${NC} $HSTS_PRELOAD"
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

# ── STEP 10: create_example_server ────────────────────────────
create_example_server() {
    [[ "$CREATE_EXAMPLE_SERVER" == "yes" ]] || return
    echo -e "\n${BLUE}[*] Writing example server block (disabled)...${NC}"
    CREATED_FILES+=("$EXAMPLE_CONF")
    cat > "$EXAMPLE_CONF" <<EOF
# ============================================================
#  EXAMPLE SECURE SERVER BLOCK  (rename to activate)
#  Replace $DOMAIN with your domain.
# ============================================================

server {
    listen      80;
    listen      [::]:80;
    server_name $DOMAIN www.$DOMAIN;
    return 301  https://\$host\$request_uri;
}

server {
    listen      443 ssl;
    listen      [::]:443 ssl;
    http2       on;
    server_name $DOMAIN www.$DOMAIN;

    ssl_certificate         /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key     /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    ssl_trusted_certificate /etc/letsencrypt/live/$DOMAIN/chain.pem;

    ssl_stapling        on;
    ssl_stapling_verify on;

    include /etc/nginx/conf.d/security-headers.conf;

    limit_req  zone=general burst=20 nodelay;
    limit_conn perip 10;
    limit_conn perserver 100;

    root  /var/www/$DOMAIN/html;
    index index.html index.htm;

    if (\$request_method !~ ^(GET|HEAD|POST|PUT|DELETE|OPTIONS|PATCH)\$) { return 405; }
    if (\$http_user_agent ~* (nmap|nikto|sqlmap|acunetix|havij|appscan)) { return 403; }

    location ~ /\\. { deny all; access_log off; log_not_found off; }
    location ~* \\.(bak|conf|dist|env|inc|ini|log|sh|sql|swp|tar|gz|zip)\$ { deny all; }

    location /login {
        limit_req zone=login burst=5 nodelay;
        # re-include headers because this block would otherwise drop them:
        include /etc/nginx/conf.d/security-headers.conf;
    }

    location / { try_files \$uri \$uri/ =404; }

    access_log /var/log/nginx/${DOMAIN}_access.log security;
    error_log  /var/log/nginx/${DOMAIN}_error.log  warn;
}
EOF
    echo -e "${GREEN}[✔] $EXAMPLE_CONF${NC}"
    echo -e "${YELLOW}    Activate: mv $EXAMPLE_CONF ${EXAMPLE_CONF/.disabled/}${NC}"
}

# ── STEP 11: check_include ────────────────────────────────────
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

# ── restore_backup  [FIX-2] ───────────────────────────────────
restore_backup() {
    echo -e "${YELLOW}[*] Rolling back...${NC}"
    # Remove files we created this run so they can't linger and break -t.
    for f in "${CREATED_FILES[@]}"; do rm -f "$f"; done
    if [ -d "$BACKUP_DIR" ]; then
        [ -f "$BACKUP_DIR/nginx.conf" ] && cp "$BACKUP_DIR/nginx.conf" "$NGINX_CONF"
        if [ -d "$BACKUP_DIR/conf.d" ]; then
            rm -rf "$NGINX_DIR/conf.d"
            cp -r "$BACKUP_DIR/conf.d" "$NGINX_DIR/conf.d"
        fi
        echo -e "${GREEN}[✔] Backup restored from $BACKUP_DIR${NC}"
    else
        echo -e "${RED}[✗] Backup dir not found: $BACKUP_DIR${NC}"
    fi
}

# ── STEP 12: test_nginx ───────────────────────────────────────
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

# ── STEP 13: reload_nginx  [FIX-4] ────────────────────────────
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

# ── STEP 14: verify_headers ───────────────────────────────────
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

print_summary() {
    echo -e "\n${GREEN}╔══════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║            SETUP COMPLETE                 ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
    echo -e "  Files: security-headers.conf, hardening.conf, secure-site-example.conf.disabled"
    echo -e "  Backup: $BACKUP_DIR"
    echo -e "  Test:  https://securityheaders.com  |  https://ssllabs.com/ssltest"
}

# ── MAIN ──────────────────────────────────────────────────────
main() {
    case "${1:-}" in -h|--help) usage; exit 0 ;; esac
    print_banner
    load_config "${1:-}"
    check_root
    check_nginx
    backup_config
    disable_ipv6_default_listener
    get_user_input
    check_headers_more_module
    preflight_scan
    create_security_headers
    harden_nginx_conf
    generate_dhparam
    create_example_server
    check_include
    if test_nginx; then
        reload_nginx
        verify_headers
        print_summary
    else
        echo -e "\n${RED}[✗] SETUP FAILED — original config restored.${NC}"
        echo -e "${YELLOW}[!] Log: $LOG_FILE${NC}"
        exit 1
    fi
}

main "$@"
