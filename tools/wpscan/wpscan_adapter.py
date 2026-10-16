#!/usr/bin/env python3
"""WPScan WordPress fingerprinter adapter for Vexora.

Reads target URLs from stdin (one per line), runs WPScan against each in JSON
mode, and writes normalized technology records to stdout as JSON lines:

    printf 'https://wordpress-site.com\\n' | wpscan_adapter.py

Each detection:
    {"event":"tech","url","name","version","category":"","source":"wpscan"}

WordPress core, the main theme, installed plugins and themes are reported as
separate technologies (category "cms" / "wordpress-plugin" / "wordpress-theme").
A trailing summary line is emitted once all targets are processed:
    {"event":"done","count":<int>,"targets":<int>}

Set WPSCAN_API_TOKEN to enrich results with vulnerability data. Non-WordPress
targets are reported as {"event":"skip",...} and never abort the run.
"""
import json
import os
import subprocess
import sys

API_TOKEN = os.environ.get("WPSCAN_API_TOKEN", "").strip()
PER_TARGET_TIMEOUT = int(os.environ.get("WPSCAN_TARGET_TIMEOUT", "300"))


def log(obj):
    sys.stdout.write(json.dumps(obj, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def _version(obj):
    if isinstance(obj, dict):
        v = obj.get("version")
        if isinstance(v, dict):
            n = v.get("number")
            if isinstance(n, str):
                return n.strip()
        if isinstance(v, str):
            return v.strip()
    return ""


def detect(url):
    """Run WPScan for one URL and return a list of (name, version, category)."""
    args = [
        "wpscan",
        "--url", url,
        "--format", "json",
        "--no-banner",
        "--random-user-agent",
        "--disable-tls-checks",
    ]
    if API_TOKEN:
        args += ["--api-token", API_TOKEN]

    proc = subprocess.run(args, capture_output=True, text=True, timeout=PER_TARGET_TIMEOUT)
    out = proc.stdout or ""
    start = out.find("{")
    if start < 0:
        raise RuntimeError((proc.stderr or "").strip()[:300] or "wpscan produced no JSON output")
    data = json.loads(out[start:])

    results = []
    core = _version(data.get("version"))
    if core:
        results.append(("WordPress", core, "cms"))
    elif data.get("version") is not None:
        results.append(("WordPress", "", "cms"))

    main_theme = data.get("main_theme")
    if isinstance(main_theme, dict) and main_theme.get("slug"):
        results.append(("WordPress Theme: " + str(main_theme["slug"]), _version(main_theme), "wordpress-theme"))

    plugins = data.get("plugins")
    if isinstance(plugins, dict):
        for slug, info in plugins.items():
            results.append(("WordPress Plugin: " + str(slug), _version(info), "wordpress-plugin"))

    themes = data.get("themes")
    if isinstance(themes, dict):
        for slug, info in themes.items():
            results.append(("WordPress Theme: " + str(slug), _version(info), "wordpress-theme"))

    return results


def main():
    urls = [line.strip() for line in sys.stdin if line.strip()]
    count = 0
    for url in urls:
        try:
            entries = detect(url)
            if not entries:
                log({"event": "skip", "url": url, "message": "not detected as WordPress"})
            for name, version, category in entries:
                log({
                    "event": "tech",
                    "url": url,
                    "name": name,
                    "version": version,
                    "category": category,
                    "source": "wpscan",
                })
                count += 1
        except Exception as exc:  # noqa: BLE001 - keep scanning remaining targets
            log({"event": "error", "url": url, "message": str(exc)})
    log({"event": "done", "count": count, "targets": len(urls)})


if __name__ == "__main__":
    main()
