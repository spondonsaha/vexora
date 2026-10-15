#!/bin/sh
# Certificate Transparency (CT) subdomain source.
# Usage: ct <root-domain>
#
# Queries multiple CT logs and merges the results:
#   1. Cert Spotter v1 API (reliable; crt.sh's own API is frequently 502)
#   2. crt.sh JSON API (primary CT search, kept as a fallback)
# Exits 0 even when every source is unavailable so the workflow never fails.
set -u

root="${1:?usage: ct <root-domain>}"

fetch_certspotter() {
  curl -sS --max-time 30 \
    "https://api.certspotter.com/v1/issuances?domain=${root}&include_subdomains=true&expand=dns_names" \
    2>/dev/null
}

fetch_crtsh() {
  curl -sS --max-time 30 \
    "https://crt.sh/?q=%25.${root}&output=json" \
    2>/dev/null
}

normalize() {
  tr '[:upper:]' '[:lower:]' \
    | sed 's/^\*\.//; s/^\.//; s/\.$//' \
    | tr -d '\r' \
    | grep -E '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$' \
    || true
}

{
  body="$(fetch_certspotter || true)"
  if printf '%s' "$body" | jq -e 'type == "array"' >/dev/null 2>&1; then
    printf '%s' "$body" | jq -r '.[].dns_names[]?'
  fi

  body="$(fetch_crtsh || true)"
  if printf '%s' "$body" | jq -e 'type == "array"' >/dev/null 2>&1; then
    printf '%s' "$body" | jq -r '.[].name_value'
  fi
} | normalize | sort -u

exit 0
