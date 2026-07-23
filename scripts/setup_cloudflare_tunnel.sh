#!/usr/bin/env bash
# =============================================================================
# Cloudflare Tunnel + h1-target-monitor HTTPS Setup
# VPS'da bir marta ishga tushiring:
#   chmod +x scripts/setup_cloudflare_tunnel.sh
#   ./scripts/setup_cloudflare_tunnel.sh
# =============================================================================

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

APP_PORT=8000
APP_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TUNNEL_URL_FILE="$APP_DIR/.cloudflare_tunnel_url"
CLOUDFLARED_BIN="/usr/local/bin/cloudflared"
SERVICE_NAME="cloudflared-h1monitor"

# =============================================================================
# 1. cloudflared o'rnatish
# =============================================================================
install_cloudflared() {
    if command -v cloudflared &>/dev/null; then
        info "cloudflared allaqachon o'rnatilgan: $(cloudflared --version)"
        return
    fi

    info "cloudflared yuklab olinmoqda..."
    ARCH="$(uname -m)"
    case "$ARCH" in
        x86_64)  CF_ARCH="amd64" ;;
        aarch64) CF_ARCH="arm64" ;;
        armv7l)  CF_ARCH="arm"   ;;
        *)       error "Qo'llab-quvvatlanmaydigan arxitektura: $ARCH" ;;
    esac

    LATEST_URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${CF_ARCH}"
    curl -fsSL "$LATEST_URL" -o /tmp/cloudflared
    chmod +x /tmp/cloudflared

    if sudo mv /tmp/cloudflared "$CLOUDFLARED_BIN" 2>/dev/null; then
        info "cloudflared /usr/local/bin ga o'rnatildi"
    else
        # sudo yo'q bo'lsa — home directoryga o'rnatamiz
        mkdir -p "$HOME/.local/bin"
        mv /tmp/cloudflared "$HOME/.local/bin/cloudflared"
        export PATH="$HOME/.local/bin:$PATH"
        CLOUDFLARED_BIN="$HOME/.local/bin/cloudflared"
        info "cloudflared ~/.local/bin ga o'rnatildi"
    fi

    cloudflared --version
}

# =============================================================================
# 2. FastAPI ilovasi ishlab turganini tekshirish
# =============================================================================
check_app_running() {
    if curl -sf "http://localhost:${APP_PORT}/api/health" &>/dev/null; then
        info "FastAPI ilova port ${APP_PORT} da ishlayapti ✓"
    else
        warn "FastAPI ilova hali ishlamayapti. Boshqa terminal oynada:"
        warn "  cd $APP_DIR"
        warn "  source .venv/bin/activate"
        warn "  uvicorn main:app --host 127.0.0.1 --port ${APP_PORT}"
        warn ""
        warn "Tunnel hozir ham ishga tushiriladi — ilova keyinroq start bo'ladi"
    fi
}

# =============================================================================
# 3. Quick tunnel (Cloudflare akkaunt shart emas)
# =============================================================================
start_quick_tunnel() {
    info "Cloudflare Quick Tunnel ishga tushirilmoqda..."
    info "Bu bepul, lekin URL har safar o'zgaradi."
    info ""
    info "Permanent tunnel uchun: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/"
    info ""

    # URL ni ushlash uchun background'da ishlatamiz
    LOG_FILE="/tmp/cloudflared_tunnel.log"

    cloudflared tunnel --url "http://localhost:${APP_PORT}" \
        --no-autoupdate \
        2>&1 | tee "$LOG_FILE" &

    CLOUDFLARED_PID=$!
    echo "$CLOUDFLARED_PID" > /tmp/cloudflared.pid

    # URL paydo bo'lishini kutamiz (max 30 soniya)
    info "HTTPS URL kutilmoqda..."
    for i in $(seq 1 30); do
        TUNNEL_URL=$(grep -oP 'https://[a-z0-9\-]+\.trycloudflare\.com' "$LOG_FILE" 2>/dev/null | head -1 || true)
        if [[ -n "$TUNNEL_URL" ]]; then
            echo "$TUNNEL_URL" > "$TUNNEL_URL_FILE"
            echo ""
            echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
            echo -e "${GREEN}║  ✅  HTTPS tunnel tayyor!                        ║${NC}"
            echo -e "${GREEN}╠══════════════════════════════════════════════════╣${NC}"
            echo -e "${GREEN}║  🌐  URL: ${TUNNEL_URL}${NC}"
            echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
            echo ""
            info ".env faylida quyidagilarni yangilang:"
            echo ""
            echo "  MINI_APP_URL=${TUNNEL_URL}/miniapp/"
            echo "  RELAY_PUBLIC_URL=${TUNNEL_URL}/relay"
            echo ""
            info "Keyin FastAPI ni qayta ishga tushiring."
            return 0
        fi
        sleep 1
    done

    error "URL aniqlanmadi. $LOG_FILE ni tekshiring."
}

# =============================================================================
# 4. systemd service (optional — persistent)
# =============================================================================
install_systemd_service() {
    if ! command -v systemctl &>/dev/null; then
        warn "systemd mavjud emas — service o'rnatilmaydi"
        return
    fi

    read -rp "Cloudflare tunnelni systemd service sifatida o'rnatsinmi? (y/N): " answer
    if [[ "${answer,,}" != "y" ]]; then
        return
    fi

    UNIT_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
    sudo tee "$UNIT_FILE" > /dev/null <<EOF
[Unit]
Description=Cloudflare Tunnel for h1-target-monitor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$(whoami)
ExecStart=${CLOUDFLARED_BIN} tunnel --url http://localhost:${APP_PORT} --no-autoupdate
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable "$SERVICE_NAME"
    sudo systemctl start "$SERVICE_NAME"
    info "systemd service o'rnatildi va ishga tushirildi: $SERVICE_NAME"
    info "Status: sudo systemctl status $SERVICE_NAME"
}

# =============================================================================
# main
# =============================================================================
main() {
    echo ""
    echo "╔══════════════════════════════════════════════════╗"
    echo "║   h1-target-monitor — Cloudflare HTTPS Setup    ║"
    echo "╚══════════════════════════════════════════════════╝"
    echo ""

    install_cloudflared
    check_app_running
    start_quick_tunnel
    install_systemd_service
}

main "$@"
