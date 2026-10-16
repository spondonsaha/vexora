#!/usr/bin/env python3
"""CMSeeK CMS deep-scan adapter for Vexora.

Reads target URLs from stdin (one per line), drives CMSeeK's list-mode scan in
batch mode, then reads the structured `Result/<host>/cms.json` files it writes
and emits normalized technology records as JSON lines:

    printf 'https://example.com\\n' | cmseek_adapter.py

Each detection:
    {"event":"tech","url","name","version","category":"cms","source":"cmseek"}

A trailing summary line is emitted once all targets are processed:
    {"event":"done","count":<int>,"targets":<int>}

CMSeeK performs CMS, version and (deep) plugin/theme enumeration. Targets whose
CMS cannot be identified are reported as {"event":"skip",...}.
"""
import glob
import json
import os
import shutil
import subprocess
import sys

CMSEEK_DIR = os.environ.get("CMSEEK_DIR", "/opt/CMSeeK")
PER_RUN_TIMEOUT = int(os.environ.get("CMSEEK_TIMEOUT", "600"))
LIST_FILE = "/tmp/cmseek_targets.txt"
RESULT_DIR = os.path.join(CMSEEK_DIR, "Result")


def log(obj):
    sys.stdout.write(json.dumps(obj, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def run_cmseek(urls):
    shutil.rmtree(RESULT_DIR, ignore_errors=True)
    with open(LIST_FILE, "w") as fh:
        for url in urls:
            fh.write(url + "\n")

    args = [
        "python3", "-W", "ignore", "cmseek.py",
        "-l", LIST_FILE,
        "--batch",
        "-r",
        "--follow-redirect",
    ]
    try:
        subprocess.run(
            args,
            cwd=CMSEEK_DIR,
            capture_output=True,
            timeout=PER_RUN_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        pass

    results = []
    for path in glob.glob(os.path.join(RESULT_DIR, "*", "cms.json")):
        try:
            with open(path) as fh:
                data = json.load(fh)
        except (ValueError, OSError):
            continue
        if isinstance(data, dict):
            results.append(data)
    return results


def version_of(data):
    for key in ("wp_version", "cms_version", "version"):
        value = data.get(key)
        if value:
            return str(value).strip()
    for key, value in data.items():
        if key.endswith("_version") and value:
            return str(value).strip()
    return ""


def main():
    urls = [line.strip() for line in sys.stdin if line.strip()]
    count = 0
    try:
        results = run_cmseek(urls)
    except Exception as exc:  # noqa: BLE001
        log({"event": "error", "url": "", "message": str(exc)})
        log({"event": "done", "count": 0, "targets": len(urls)})
        return

    for data in results:
        url = str(data.get("url") or "").strip()
        name = str(data.get("cms_name") or "").strip()
        if not url or not name:
            continue
        log({
            "event": "tech",
            "url": url,
            "name": name,
            "version": version_of(data),
            "category": "cms",
            "source": "cmseek",
        })
        count += 1

    if count == 0 and urls:
        log({"event": "skip", "url": "", "message": "no CMS identified for the supplied targets"})
    log({"event": "done", "count": count, "targets": len(urls)})


if __name__ == "__main__":
    main()
