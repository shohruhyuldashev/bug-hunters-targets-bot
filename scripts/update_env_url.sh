#!/usr/bin/env bash
# =============================================================================
# .env faylida MINI_APP_URL va RELAY_PUBLIC_URL ni yangilash
# Foydalanish:
#   ./scripts/update_env_url.sh https://xyz.trycloudflare.com
# =============================================================================

set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ENV_FILE="$SCRIPT_DIR/../.env"

if [[ -z "${1:-}" ]]; then
    echo -e "${RED}[ERROR]${NC} URL kiriting:"
    echo "  $0 https://xyz.trycloudflare.com"
    exit 1
fi

BASE_URL="${1%/}"  # trailing slash olib tashlaymiz

if [[ ! "$BASE_URL" =~ ^https:// ]]; then
    echo -e "${RED}[ERROR]${NC} URL https:// bilan boshlanishi kerak"
    exit 1
fi

if [[ ! -f "$ENV_FILE" ]]; then
    echo -e "${RED}[ERROR]${NC} .env fayli topilmadi: $ENV_FILE"
    echo "Avval: cp .env.example .env"
    exit 1
fi

# Backup
cp "$ENV_FILE" "${ENV_FILE}.bak"
echo -e "${GREEN}[INFO]${NC}  Backup: ${ENV_FILE}.bak"

# Yangilash
sed -i "s|^MINI_APP_URL=.*|MINI_APP_URL=${BASE_URL}/miniapp/|" "$ENV_FILE"
sed -i "s|^RELAY_PUBLIC_URL=.*|RELAY_PUBLIC_URL=${BASE_URL}/relay|" "$ENV_FILE"

# Agar bu qatorlar mavjud bo'lmasa — qo'shish
grep -q "^MINI_APP_URL=" "$ENV_FILE" || echo "MINI_APP_URL=${BASE_URL}/miniapp/" >> "$ENV_FILE"
grep -q "^RELAY_PUBLIC_URL=" "$ENV_FILE" || echo "RELAY_PUBLIC_URL=${BASE_URL}/relay" >> "$ENV_FILE"

echo -e "${GREEN}[INFO]${NC}  .env yangilandi:"
echo "  MINI_APP_URL=${BASE_URL}/miniapp/"
echo "  RELAY_PUBLIC_URL=${BASE_URL}/relay"
echo ""
echo -e "${GREEN}[INFO]${NC}  FastAPI ni qayta ishga tushiring:"
echo "  systemctl restart h1-monitor  # yoki"
echo "  uvicorn main:app --host 127.0.0.1 --port 8000"
