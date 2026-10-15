#!/usr/bin/env python3
"""Harvest archived URLs for a domain.

The upstream tomnomnom/waybackurls binary queries ``http://web.archive.org`` and
``http://index.commoncrawl.org``, which are frequently unreachable or throttled.
When those requests fail the tool silently prints nothing, so URL discovery
reports zero results. This implementation talks to both APIs over HTTPS, caps
each request with a timeout, abandons work after an overall deadline, and still
prints whatever it collected. It intentionally depends only on the standard
library so the image stays tiny.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.parse
import urllib.request

USER_AGENT = "recon-waybackurls/1.0 (+https://example.invalid)"
DEFAULT_LIMIT = 5000
DEFAULT_TIMEOUT = 90.0
DEFAULT_DEADLINE = 240.0


def log(message: str) -> None:
    sys.stderr.write(message + "\n")
    sys.stderr.flush()


def http_get(url: str, timeout: float) -> bytes:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def get_wayback(domain: str, limit: int, timeout: float) -> list[str]:
    query = urllib.parse.urlencode(
        {
            "url": domain,
            "matchType": "domain",
            "fl": "original",
            "collapse": "urlkey",
            "limit": limit,
        }
    )
    raw = http_get(f"https://web.archive.org/cdx/search/cdx?{query}", timeout)
    urls: list[str] = []
    for line in raw.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if line.startswith(("http://", "https://")):
            urls.append(line)
    return urls


def get_commoncrawl(domain: str, limit: int, timeout: float) -> list[str]:
    collections = json.loads(http_get("https://index.commoncrawl.org/collinfo.json", timeout))
    index_id = collections[0]["id"]
    query = urllib.parse.urlencode(
        {"url": f"{domain}/*", "output": "json", "limit": limit}
    )
    raw = http_get(f"https://index.commoncrawl.org/{index_id}-index?{query}", timeout)
    urls: list[str] = []
    for line in raw.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        url = record.get("url")
        if isinstance(url, str) and url.startswith(("http://", "https://")):
            urls.append(url)
    return urls


SOURCES = (
    ("wayback", get_wayback),
    ("commoncrawl", get_commoncrawl),
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Harvest archived URLs for a domain over HTTPS.")
    parser.add_argument("domain", help="root domain to harvest, e.g. example.com")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT, help=f"max URLs per source (default {DEFAULT_LIMIT})")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help=f"per-request timeout seconds (default {DEFAULT_TIMEOUT:g})")
    parser.add_argument("--deadline", type=float, default=DEFAULT_DEADLINE, help=f"overall wall-clock budget seconds (default {DEFAULT_DEADLINE:g})")
    args = parser.parse_args()

    domain = args.domain.strip().lower()
    if not domain:
        return

    deadline = time.monotonic() + max(1.0, args.deadline)
    seen: set[str] = set()
    out: list[str] = []

    for name, fetcher in SOURCES:
        remaining = deadline - time.monotonic()
        if remaining <= 1.0:
            log(f"{name}: skipped, time budget reached")
            continue
        try:
            found = fetcher(domain, args.limit, min(args.timeout, remaining))
        except Exception as exc:  # noqa: BLE001 - network/parse failures are expected
            log(f"{name}: {type(exc).__name__}: {exc}")
            continue
        added = 0
        for url in found:
            if url in seen:
                continue
            seen.add(url)
            out.append(url)
            added += 1
        log(f"{name}: {added} url(s)")

    for url in out:
        sys.stdout.write(url + "\n")
    sys.stdout.flush()
    log(f"total: {len(out)} url(s)")


if __name__ == "__main__":
    main()
