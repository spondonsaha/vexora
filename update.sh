#!/usr/bin/env bash
# Stop containers, back up compose + wordlists, pull latest code, rebuild, and
# bring the stack back up. DB migrations run automatically on API startup (§12).
set -euo pipefail
cd "$(dirname "$0")"

stamp="$(date +%Y%m%d-%H%M%S)"
backup_dir="backups/${stamp}"

echo "==> Stopping stack"
docker compose down

mkdir -p "${backup_dir}"
for path in docker-compose.yml .env wordlists custom-templates; do
    if [ -e "${path}" ]; then
        cp -R "${path}" "${backup_dir}/" || true
    fi
done
echo "==> Backed up configuration to ${backup_dir}"

echo "==> Pulling latest code"
git pull --ff-only

echo "==> Rebuilding images sequentially"
./build.sh

echo "==> Starting stack (migrations run on API boot)"
docker compose up -d

echo "==> Update complete"
