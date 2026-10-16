#!/usr/bin/env python3
"""WhatWeb technology fingerprinter adapter for Vexora.

Reads target URLs from stdin (one per line), runs WhatWeb against each with a
JSON log, and writes normalized technology records to stdout as JSON lines:

    printf 'https://example.com\\n' | whatweb_adapter.py

Each detection:
    {"event":"tech","url","name","version","category":"","source":"whatweb"}

A trailing summary line is emitted once all targets are processed:
    {"event":"done","count":<int>,"targets":<int>}

WhatWeb is invoked with a configurable aggression level (WHATWEB_AGGRESSION,
default 1; WhatWeb accepts only 1, 3 or 4). Failures on an individual target are
reported as {"event":"error",...} and never abort the run.
"""
import json
import os
import re
import subprocess
import sys
import tempfile

AGGRESSION = os.environ.get("WHATWEB_AGGRESSION", "1")
if AGGRESSION not in ("1", "3", "4"):
    AGGRESSION = "1"
PER_TARGET_TIMEOUT = int(os.environ.get("WHATWEB_TARGET_TIMEOUT", "90"))

# WhatWeb plugins that describe the response rather than a technology; without
# this filter every target would report Country/IP/Title/etc. as "technologies".
# The cookie plugins (Cookies/HttpOnly/SecureCookie/...) report individual
# cookie names (sessions, CSRF tokens, OIDC nonces) which are per-request noise.
NON_TECH_PLUGINS = {
    "title", "ip", "country", "ipcountry", "allow", "uncommonheaders", "script",
    "html5", "email", "redirectlocation", "httpstatus", "meta-author",
    "open-graph-protocol", "requestconfig", "cookies", "cookie", "frame",
    "x-ua-compatible", "httponly", "securecookie", "secure-cookie", "samesite",
    "robots", "strict-transport-security", "x-frame-options",
    "content-security-policy", "passwordfield", "httpheaders", "set-cookie",
    "microsoftofficewebserver", "meta-refresh", "meta-refresh-redirect",
    "frameset", "object", "x-xss-protection", "x-content-type-options",
    "referrer-policy", "permissions-policy", "x-dns-prefetch-control",
    "x-permitted-cross-domain-policies", "via-proxy", "via", "link",
    "server-timing", "expect-ct", "www-authenticate", "authentication",
    "content-language", "x-robots-tag", "hsts", "oidc", "openidconnect",
    "content-type", "access-control-allow-origin",
}

# Defensive filter for framework session/internal tokens that leak through as
# "technology" names (e.g. .AspNetCore.Correlation.<rand>, OIDC nonces). These
# change on every request and would otherwise flood the results with junk.
JUNK_NAME_RE = re.compile(
    r"aspnetcore|correlation|openidconnect|antiforgery|nonce|oidc|"
    r"__requestverificationtoken|^x-ms-|^oh\.|^esctx$|^fpc$|"
    r"^stsservicecookie$|^jsessionid$|^x-ms-gateway-slice$",
    re.IGNORECASE,
)


def log(obj):
    sys.stdout.write(json.dumps(obj, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def _first_version(info):
    v = info.get("version")
    if isinstance(v, list) and v:
        return str(v[0])
    if isinstance(v, str):
        return v
    return ""


_VERSION_RE = re.compile(r"^(?P<name>.+?)[\s/]+(?P<version>[0-9][0-9A-Za-z._\-+]*)$")


def _split_name_version(value):
    """Split a value like 'nginx/1.24.0' or 'WordPress 6.4.3' into name+version."""
    value = value.strip()
    if "://" in value:
        return value, ""
    match = _VERSION_RE.match(value)
    if match:
        return match.group("name").strip(), match.group("version").strip()
    return value, ""


_JUNK_CHARS = re.compile(r"[;=(){}<>/]")
_TWO_LETTERS = re.compile(r"[A-Za-z]{2}")


def _is_junk(tech_name, version=""):
    """True for session/internal/header-value tokens that are never a technology."""
    name = tech_name.strip()
    if len(name) < 2:
        return True
    if JUNK_NAME_RE.search(name):
        return True
    # Framework session/internal tokens are long random strings.
    if len(name) > 60:
        return True
    # Header values, rules, MIME fragments and redirect targets are not tech.
    if _JUNK_CHARS.search(name):
        return True
    if name in {"/", "-", "0", "1", "none", "text/html"}:
        return True
    # Must contain at least two consecutive letters (rules out numbers/punct).
    if not _TWO_LETTERS.search(name):
        return True
    return False


def plugin_entries(name, info):
    """Yield (technology, version) pairs for a single WhatWeb plugin result."""
    if name.lower() in NON_TECH_PLUGINS:
        return
    if not isinstance(info, dict):
        info = {}
    pairs = []
    version = _first_version(info)
    if version:
        pairs.append((str(name), version))
    else:
        strings = info.get("string")
        if isinstance(strings, list) and strings:
            pairs = [
                _split_name_version(s)
                for s in strings
                if isinstance(s, str) and s.strip()
            ]
        elif isinstance(strings, str) and strings.strip():
            pairs.append(_split_name_version(strings))
        else:
            # Plugin matched with no detail: still record the plugin name.
            pairs.append((str(name), ""))
    for tech_name, tech_version in pairs:
        if not _is_junk(tech_name, tech_version):
            yield tech_name, tech_version


def detect(url):
    """Run WhatWeb for one URL and return a list of (name, version) pairs."""
    fd, path = tempfile.mkstemp(suffix=".json", prefix="whatweb-")
    os.close(fd)
    try:
        subprocess.run(
            [
                "whatweb",
                "--aggression", AGGRESSION,
                "--log-json", path,
                "--quiet",
                "--no-errors",
                url,
            ],
            capture_output=True,
            timeout=PER_TARGET_TIMEOUT,
        )
        try:
            with open(path) as fh:
                data = json.load(fh)
        except (ValueError, OSError):
            return []
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass

    results = []
    if not isinstance(data, list):
        return results
    seen = set()
    for entry in data:
        if not isinstance(entry, dict):
            continue
        plugins = entry.get("plugins")
        if not isinstance(plugins, dict):
            continue
        for name, info in plugins.items():
            for tech_name, version in plugin_entries(name, info):
                key = (tech_name.lower(), version)
                if tech_name and key not in seen:
                    seen.add(key)
                    results.append((tech_name, version))
    return results


def main():
    urls = [line.strip() for line in sys.stdin if line.strip()]
    count = 0
    for url in urls:
        try:
            for name, version in detect(url):
                log({
                    "event": "tech",
                    "url": url,
                    "name": name,
                    "version": version,
                    "category": "",
                    "source": "whatweb",
                })
                count += 1
        except Exception as exc:  # noqa: BLE001 - keep scanning remaining targets
            log({"event": "error", "url": url, "message": str(exc)})
    log({"event": "done", "count": count, "targets": len(urls)})


if __name__ == "__main__":
    main()
