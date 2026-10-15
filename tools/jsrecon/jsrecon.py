#!/usr/bin/env python3
"""jsrecon - fetch JavaScript assets and extract high-signal artifacts.

Reads JavaScript URLs (one per line, gathered during URL discovery) on stdin and
writes JSON lines on stdout:

  * per-file events: {"event":"file","url":...,"ok":true,"bytes":123,"findings":7}
  * per-file errors: {"event":"file","url":...,"ok":false,"error":"..."}
  * findings:        {"url":...,"host":...,"type":"aws_key","value":"AKIA...","context":"..."}

Only the standard library is used so the image is small and builds offline.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

MAX_BYTES = 5 * 1024 * 1024  # per-file download cap
USER_AGENT = "Mozilla/5.0 (compatible; jsrecon/1.0)"

# (finding type, compiled pattern, group). When group is 1 the first capture
# group is stored; otherwise the whole match is used. Ordered roughly from most
# to least specific so the UI can rank them.
PATTERNS: list[tuple[str, re.Pattern[str], int]] = [
    ("aws_key", re.compile(r"(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}"), 0),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), 0),
    ("google_oauth", re.compile(r"[0-9]+-[0-9a-z_]{32}\.apps\.googleusercontent\.com"), 0),
    (
        "github_token",
        re.compile(
            r"ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|ghu_[A-Za-z0-9]{36}"
            r"|ghs_[A-Za-z0-9]{36}|ghr_[A-Za-z0-9]{36}"
            r"|github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}"
        ),
        0,
    ),
    ("slack_token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,72}"), 0),
    ("stripe_key", re.compile(r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}"), 0),
    ("twilio_key", re.compile(r"SK[0-9a-fA-F]{32}"), 0),
    ("sendgrid_key", re.compile(r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}"), 0),
    ("mailgun_key", re.compile(r"key-[0-9a-zA-Z]{32}"), 0),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"), 0),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"), 0),
    (
        "firebase",
        re.compile(
            r"https://[A-Za-z0-9\-]+\.firebaseio\.com"
            r"|https://[A-Za-z0-9\-]+\.firebase\.com"
            r"|https://[A-Za-z0-9\-]+\.firebaseapp\.com"
        ),
        0,
    ),
    ("s3_bucket", re.compile(r"[A-Za-z0-9._\-]+\.s3(?:[.\-][A-Za-z0-9\-]+)?\.amazonaws\.com|s3://[A-Za-z0-9._\-]+"), 0),
    ("email", re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"), 0),
    (
        "internal_ip",
        re.compile(
            r"10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"
            r"|172\.(?:1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}"
            r"|192\.168\.[0-9]{1,3}\.[0-9]{1,3}"
        ),
        0,
    ),
    ("graphql", re.compile(r"/[A-Za-z0-9/_\-]*graphql[A-Za-z0-9/_\-]*"), 0),
    (
        "admin_route",
        re.compile(
            r"/[A-Za-z0-9_/\-]*(?:admin|dashboard|manage|config|settings"
            r"|internal|private|debug|api/v[0-9])[A-Za-z0-9_/\-]*"
        ),
        0,
    ),
    ("api_endpoint", re.compile(r"/(?:api|v[0-9]+)/[A-Za-z0-9_/.\-]*"), 0),
    ("url", re.compile(r"https?://[^\"'`\s<>\\]+"), 0),
    (
        "credential",
        re.compile(
            r"(?i)(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key"
            r"|auth[_-]?token|client[_-]?secret|private[_-]?key|token)"
            r"\s*[:=]\s*[\"']([^\"']{4,120})[\"']"
        ),
        1,
    ),
    ("js_variable", re.compile(r"var\s+[A-Za-z_$][A-Za-z0-9_$]*\s*=\s*[\"'][^\"']{1,160}[\"']"), 0),
]

HOST_RE = re.compile(r"https?://([A-Za-z0-9.\-]+)")
PRINT_LOCK = threading.Lock()


def emit(obj: dict) -> None:
    line = json.dumps(obj, ensure_ascii=False)
    with PRINT_LOCK:
        sys.stdout.write(line + "\n")
        sys.stdout.flush()


def snippet(text: str, start: int, end: int, pad: int = 40) -> str:
    a = max(0, start - pad)
    b = min(len(text), end + pad)
    cleaned = re.sub(r"\s+", " ", text[a:b]).strip()
    return cleaned[:200]


def is_in_scope(host: str, root: str) -> bool:
    if not root:
        return False
    host = host.lower().strip(".")
    root = root.lower().strip(".")
    return host == root or host.endswith("." + root)


def host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def extract(text: str, root: str) -> list[tuple[str, str, str]]:
    findings: list[tuple[str, str, str]] = []
    for ftype, pattern, group in PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(group) if group else match.group(0)
            value = value.strip()
            if not value or len(value) > 512:
                continue
            findings.append((ftype, value, snippet(text, match.start(), match.end())))

    # "hidden subdomains": any host referenced by an absolute URL that is in scope.
    for match in HOST_RE.finditer(text):
        host = match.group(1).lower()
        if is_in_scope(host, root):
            findings.append(("subdomain", host, snippet(text, match.start(1), match.end(1))))
    return findings


def fetch(url: str, timeout: float) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data = response.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        data = data[:MAX_BYTES]
    return data.decode("utf-8", errors="replace")


def process(url: str, root: str, deadline: float, timeout: float) -> None:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        emit({"event": "file", "url": url, "ok": False, "error": "skipped: time budget reached"})
        return
    try:
        body = fetch(url, min(timeout, remaining))
    except Exception as exc:  # noqa: BLE001 - report and continue
        emit({"event": "file", "url": url, "ok": False, "error": str(exc)[:200]})
        return

    host = host_of(url)
    seen: set[tuple[str, str]] = set()
    count = 0
    for ftype, value, context in extract(body, root):
        key = (ftype, value)
        if key in seen:
            continue
        seen.add(key)
        count += 1
        emit({"url": url, "host": host, "type": ftype, "value": value, "context": context})

    emit({"event": "file", "url": url, "ok": True, "bytes": len(body), "findings": count})


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract secrets, endpoints and other artifacts from JavaScript files.")
    parser.add_argument("--root", default="", help="in-scope root domain for subdomain filtering")
    parser.add_argument("--workers", type=int, default=8, help="concurrent downloads (default 8)")
    parser.add_argument("--timeout", type=float, default=10.0, help="per-request timeout seconds (default 10)")
    parser.add_argument(
        "--deadline",
        type=float,
        default=150.0,
        help="overall wall-clock budget in seconds; the run stops gracefully when reached (default 150)",
    )
    args = parser.parse_args()

    urls = [line.strip() for line in sys.stdin if line.strip()]
    if not urls:
        return

    workers = max(1, min(args.workers, 32))
    deadline = time.monotonic() + max(1.0, args.deadline)

    # Do not use the executor as a context manager: on the deadline some download
    # threads may be stuck in a dead host's TCP/TLS handshake, and joining them
    # would hang us until the worker's tool timeout. Instead we stop waiting,
    # report what we have, and exit the process.
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=workers)
    futures = [pool.submit(process, url, args.root, deadline, args.timeout) for url in urls]
    try:
        for _ in concurrent.futures.as_completed(futures, timeout=max(0.0, deadline - time.monotonic())):
            pass
    except concurrent.futures.TimeoutError:
        pass
    finally:
        pool.shutdown(wait=False)

    emit({"event": "done", "urls": len(urls)})
    with PRINT_LOCK:
        sys.stdout.flush()
    sys.stderr.flush()
    os._exit(0)


if __name__ == "__main__":
    main()
