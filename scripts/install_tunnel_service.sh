#!/usr/bin/env bash
# =============================================================================
# Cloudflare Tunnel — systemd service (Docker bilan ishlaydi)
#
# Qanday ishlaydi:
#   1. Host machine'da cloudflared systemd service bo'lib ishlaydi
#   2. URL aniqlanganda .env faylini yangilaydi
#   3. `docker compose restart target-monitor` bajaradi
#   4. Server reboot bo'lsa — ikkala service ham avtomatik qayta ishga tushadi
#
# O'rnatish (VPS'da):
#   chmod +x scripts/install_tunnel_service.sh
#   sudo ./scripts/install_tunnel_service.sh
# =============================================================================

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }
section() { echo -e "\n${CYAN}━━━ $* ━━━${NC}"; }

# ─── Sozlamalar ───────────────────────────────────────────────────────────────
APP_DIR="$(cd "$(dirname "$0")/.." && pwd)"
APP_PORT="${APP_PORT:-8000}"
SERVICE_USER="${SUDO_USER:-$(whoami)}"
CF_SERVICE="cloudflared-h1tunnel"
URL_LOG="/var/log/${CF_SERVICE}.url"
WRAPPER="/usr/local/bin/cloudflared-h1tunnel-wrapper"
COMPOSE_BIN=""

# ─── Root tekshiruvi ──────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    error "sudo bilan ishlatilsin: sudo $0"
fi

# =============================================================================
# 1. Talab qilinadigan dasturlar
# =============================================================================
section "Talab qilinadigan dasturlarni tekshirish"

# docker compose topish
if docker compose version &>/dev/null 2>&1; then
    COMPOSE_BIN="docker compose"
    info "docker compose: $(docker compose version --short)"
elif command -v docker-compose &>/dev/null; then
    COMPOSE_BIN="docker-compose"
    info "docker-compose: $(docker-compose --version)"
else
    error "docker compose topilmadi. Avval Docker o'rnating."
fi

# Docker daemon ishlayotganini tekshirish
if ! docker info &>/dev/null; then
    error "Docker daemon ishlamayapti: sudo systemctl start docker"
fi

# =============================================================================
# 2. cloudflared o'rnatish
# =============================================================================
section "cloudflared o'rnatish"

install_cloudflared() {
    if command -v cloudflared &>/dev/null; then
        info "cloudflared mavjud: $(cloudflared --version)"
        return
    fi
    ARCH="$(uname -m)"
    case "$ARCH" in
        x86_64)  CF_ARCH="amd64" ;;
        aarch64) CF_ARCH="arm64" ;;
        armv7l)  CF_ARCH="arm"   ;;
        *)       error "Arxitektura qo'llab-quvvatlanmaydi: $ARCH" ;;
    esac
    info "Yuklab olinmoqda (arch: $CF_ARCH)..."
    curl -fsSL \
        "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${CF_ARCH}" \
        -o /usr/local/bin/cloudflared
    chmod +x /usr/local/bin/cloudflared
    info "O'rnatildi: $(cloudflared --version)"
}

install_cloudflared

# =============================================================================
# 3. Wrapper script — URL aniqlanganda .env + docker restart
# =============================================================================
section "Wrapper script yaratish"

cat > "$WRAPPER" <<WRAPPER_SCRIPT
#!/usr/bin/env bash
# Cloudflare Quick Tunnel wrapper — Docker bilan ishlaydi
# Avtomatik yaratilgan: install_tunnel_service.sh

APP_DIR="${APP_DIR}"
APP_PORT="${APP_PORT}"
URL_LOG="${URL_LOG}"
COMPOSE_BIN="${COMPOSE_BIN}"
SERVICE_USER="${SERVICE_USER}"

run_as_user() {
    if [[ "\$(whoami)" == "\$SERVICE_USER" ]]; then
        "\$@"
    else
        sudo -u "\$SERVICE_USER" "\$@"
    fi
}

update_env_and_restart() {
    local url="\$1"
    local env_file="\$APP_DIR/.env"
    local env_bak="\$APP_DIR/.env.tunnel_bak"

    # Oldingi URL bilan bir xil bo'lsa — restart kerak emas
    local old_url=""
    if [[ -f "\$URL_LOG" ]]; then
        old_url="\$(cat "\$URL_LOG")"
    fi
    if [[ "\$old_url" == "\$url" ]]; then
        echo "[tunnel] URL o'zgarmadi, restart kerak emas."
        return
    fi

    echo "[tunnel] Yangi URL aniqlandi: \$url"
    echo "\$url" > "\$URL_LOG"

    # .env mavjudligini tekshirish
    if [[ ! -f "\$env_file" ]]; then
        echo "[tunnel] WARN: \$env_file topilmadi, .env yangilanmadi"
        return
    fi

    # Backup
    cp "\$env_file" "\$env_bak"

    # MINI_APP_URL va RELAY_PUBLIC_URL ni yangilash
    if grep -q "^MINI_APP_URL=" "\$env_file"; then
        sed -i "s|^MINI_APP_URL=.*|MINI_APP_URL=\${url}/miniapp/|" "\$env_file"
    else
        echo "MINI_APP_URL=\${url}/miniapp/" >> "\$env_file"
    fi

    if grep -q "^RELAY_PUBLIC_URL=" "\$env_file"; then
        sed -i "s|^RELAY_PUBLIC_URL=.*|RELAY_PUBLIC_URL=\${url}/relay|" "\$env_file"
    else
        echo "RELAY_PUBLIC_URL=\${url}/relay" >> "\$env_file"
    fi

    echo "[tunnel] .env yangilandi:"
    echo "  MINI_APP_URL=\${url}/miniapp/"
    echo "  RELAY_PUBLIC_URL=\${url}/relay"

    # Docker container'ni restart qilish
    echo "[tunnel] Docker container qayta ishga tushirilmoqda..."
    cd "\$APP_DIR"
    if run_as_user \$COMPOSE_BIN restart target-monitor 2>&1; then
        echo "[tunnel] ✅ Docker container muvaffaqiyatli qayta ishga tushirildi"
    else
        echo "[tunnel] WARN: Docker restart amalga oshmadi. Qo'lda bajaring:"
        echo "  cd \$APP_DIR && \$COMPOSE_BIN restart target-monitor"
    fi
}

echo "[tunnel] Cloudflare Tunnel ishga tushirilmoqda..."
echo "[tunnel] FastAPI manziliga ulanish: http://localhost:\${APP_PORT}"

# Tunnel ishga tushirish va URL'ni ushlash
cloudflared tunnel --no-autoupdate --url "http://localhost:\${APP_PORT}" 2>&1 | while IFS= read -r line; do
    echo "\$line"
    # URL topilganida .env va Docker'ni yangilash
    if echo "\$line" | grep -qoP 'https://[a-z0-9\-]+\.trycloudflare\.com'; then
        url="\$(echo "\$line" | grep -oP 'https://[a-z0-9\-]+\.trycloudflare\.com' | head -1)"
        update_env_and_restart "\$url"
    fi
done
WRAPPER_SCRIPT

chmod +x "$WRAPPER"
info "Wrapper yaratildi: $WRAPPER"

# =============================================================================
# 4. systemd service
# =============================================================================
section "systemd service o'rnatish: $CF_SERVICE"

cat > "/etc/systemd/system/${CF_SERVICE}.service" <<EOF
[Unit]
Description=Cloudflare Tunnel for h1-target-monitor (Docker)
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service

[Service]
Type=simple
User=root
ExecStart=${WRAPPER}
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${CF_SERVICE}

[Install]
WantedBy=multi-user.target
EOF

touch "$URL_LOG"
info "Service fayli: /etc/systemd/system/${CF_SERVICE}.service"

# =============================================================================
# 5. Docker Compose'ni ishga tushirish (agar hali ishlamayapti bo'lsa)
# =============================================================================
section "Docker Compose tekshirish"

cd "$APP_DIR"
if sudo -u "$SERVICE_USER" $COMPOSE_BIN ps --status running 2>/dev/null | grep -q "target-monitor"; then
    info "target-monitor container allaqachon ishlayapti ✓"
else
    info "Docker Compose ishga tushirilmoqda..."
    sudo -u "$SERVICE_USER" $COMPOSE_BIN up -d --build || \
        warn "Docker Compose ishga tushmadi — .env va Dockerfile ni tekshiring"
fi

# =============================================================================
# 6. Tunnel service'ni ishga tushirish
# =============================================================================
section "Cloudflare Tunnel ishga tushirilmoqda"

systemctl daemon-reload
systemctl enable "$CF_SERVICE"
systemctl restart "$CF_SERVICE"

# URL paydo bo'lishini kutish
info "HTTPS URL kutilmoqda (max 30 soniya)..."
TUNNEL_URL=""
for i in $(seq 1 30); do
    if [[ -s "$URL_LOG" ]]; then
        TUNNEL_URL="$(cat "$URL_LOG")"
        break
    fi
    sleep 1
done

# =============================================================================
# 7. Natija
# =============================================================================
section "O'rnatish tugadi"

echo ""
if [[ -n "$TUNNEL_URL" ]]; then
    echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  ✅  Hamma narsa tayyor!                             ║${NC}"
    echo -e "${GREEN}╠══════════════════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}║  🌐  HTTPS URL: ${TUNNEL_URL}${NC}"
    echo -e "${GREEN}╠══════════════════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}║  Mini App: ${TUNNEL_URL}/miniapp/              ║${NC}"
    echo -e "${GREEN}║  Relay:    ${TUNNEL_URL}/relay                  ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
else
    warn "URL hali aniqlanmadi (biroz kuting):"
    warn "  journalctl -u ${CF_SERVICE} -f"
fi

echo ""
echo -e "${CYAN}━━━ Foydali buyruqlar ━━━${NC}"
echo ""
echo "  # Joriy HTTPS URL:"
echo "  cat ${URL_LOG}"
echo ""
echo "  # Tunnel loglari:"
echo "  journalctl -u ${CF_SERVICE} -f"
echo ""
echo "  # Docker holati:"
echo "  cd ${APP_DIR} && ${COMPOSE_BIN} ps"
echo "  cd ${APP_DIR} && ${COMPOSE_BIN} logs -f target-monitor"
echo ""
echo "  # Tunnel'ni qayta ishga tushirish:"
echo "  systemctl restart ${CF_SERVICE}"
echo ""
echo "  # Hammani to'xtatish:"
echo "  systemctl stop ${CF_SERVICE}"
echo "  cd ${APP_DIR} && ${COMPOSE_BIN} down"
echo ""
echo -e "${YELLOW}⚠️  Quick Tunnel URL server reboot'da o'zgaradi.${NC}"
echo -e "${YELLOW}   Lekin bu script URL o'zgarganda Docker'ni avtomatik restart qiladi.${NC}"
echo ""
