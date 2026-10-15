#!/usr/bin/env bash
# Build the self-hosted recon tool images (tools/*/Dockerfile).
# These tools have no reliable public image, so we build them locally and the
# worker (which shares the host Docker socket) runs them by tag.
set -euo pipefail
cd "$(dirname "$0")"

declare -A tools=(
  [assetfinder]="recon/assetfinder:latest"
  [waybackurls]="recon/waybackurls:latest"
  [ct]="recon/ct:latest"
  [sublist3r]="recon/sublist3r:latest"
  [findomain]="recon/findomain:latest"
  [domainaudit]="recon/domainaudit:latest"
  [takeover]="recon/takeover:latest"
  [nuclei]="recon/nuclei:latest"
  [sqlmap]="recon/sqlmap:latest"
  [jsrecon]="recon/jsrecon:latest"
  [openredirect]="recon/openredirect:latest"
)

echo "==> Building ${#tools[@]} tool image(s)"
for name in "${!tools[@]}"; do
  tag="${tools[$name]}"
  echo "==> Building ${name} -> ${tag} ..."
  docker build -t "${tag}" "tools/${name}"
done

echo "==> All tool images built."
