#!/usr/bin/env bash
# Sequential image build. Building tool images in parallel races on Docker's
# image store, so we build one service at a time (§12).
set -euo pipefail
cd "$(dirname "$0")"

services=(api worker client mcp-server)

echo "==> Building self-hosted tool images"
bash "$(dirname "$0")/build-tools.sh"

echo "==> Building ${#services[@]} service image(s) sequentially"
for svc in "${services[@]}"; do
    echo "==> Building ${svc} ..."
    docker compose build "${svc}"
done

echo "==> All images built. Start the stack with: docker compose up -d"
