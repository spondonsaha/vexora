#!/usr/bin/env python3
"""Domain & DNS security configuration auditor.

Inspired by HackTricks' "Domain & DNS Security Auditor" (tools.hacktricks.wiki/
domain-config). Runs one section at a time and prints a JSON report to stdout:

    audit.py <dns|email|headers|tls> <domain>

Report shape:
    {"section": "...", "title": "...", "score": 0-100,
     "checks": [{"id","title","status":"pass|warn|fail|info","detail"}]}
"""
import datetime
import json
import random
import socket
import ssl
import string
import sys
import warnings

import dns.exception
import dns.query
import dns.resolver
import dns.zone

warnings.filterwarnings("ignore")

try:
    import requests
    import urllib3

    urllib3.disable_warnings()
except Exception:  # pragma: no cover
    requests = None


# Docker's embedded DNS proxy strips DNSSEC records (DNSKEY/DS). Query public
# resolvers directly for accurate results; fall back to the system resolver.
PUBLIC_RESOLVER = dns.resolver.Resolver(configure=False)
PUBLIC_RESOLVER.nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
PUBLIC_RESOLVER.timeout = 4
PUBLIC_RESOLVER.lifetime = 8


def resolve(name, rtype):
    for resolver in (PUBLIC_RESOLVER, dns.resolver):
        try:
            return resolver.resolve(name, rtype, lifetime=8)
        except Exception:
            continue
    return None


def check(cid, title, status, detail=""):
    return {"id": cid, "title": title, "status": status, "detail": detail}


def score(checks):
    graded = [c for c in checks if c["status"] in ("pass", "warn", "fail")]
    if not graded:
        return 0
    points = 0.0
    for c in graded:
        points += {"pass": 1.0, "warn": 0.5, "fail": 0.0}[c["status"]]
    return round(points / len(graded) * 100)


def txt_records(domain, name=None):
    """Return concatenated TXT records for a name (name defaults to domain)."""
    target = name or domain
    ans = resolve(target, "TXT")
    if ans is None:
        return []
    out = []
    for r in ans:
        out.append(b"".join(r.strings).decode("utf-8", "replace"))
    return out


def query(domain, rtype):
    ans = resolve(domain, rtype)
    if ans is None:
        return []
    return [str(r) for r in ans]


# ---------------------------------------------------------------------------
# DNS & DNSSEC
# ---------------------------------------------------------------------------
def audit_dns(domain):
    checks = []

    ns = query(domain, "NS")
    if ns:
        checks.append(check("ns", "Nameservers (NS)", "pass", ", ".join(ns)))
    else:
        checks.append(check("ns", "Nameservers (NS)", "fail", "no NS records returned"))

    mx = query(domain, "MX")
    checks.append(check("mx", "Mail exchangers (MX)", "info" if mx else "warn",
                        ", ".join(mx) if mx else "no MX records"))

    soa = query(domain, "SOA")
    checks.append(check("soa", "Start of authority (SOA)", "pass" if soa else "warn",
                        soa[0] if soa else "no SOA record"))

    caa = query(domain, "CAA")
    if caa:
        checks.append(check("caa", "CAA (certificate authority authorization)", "pass", ", ".join(caa)))
    else:
        checks.append(check("caa", "CAA (certificate authority authorization)", "warn",
                            "no CAA record — any CA may issue certificates for this domain"))

    dnskey = query(domain, "DNSKEY")
    ds = query(domain, "DS")
    if dnskey:
        detail = "DNSKEY present"
        if ds:
            detail += "; DS published at parent"
        checks.append(check("dnssec", "DNSSEC signing", "pass", detail))
    else:
        checks.append(check("dnssec", "DNSSEC signing", "fail",
                            "no DNSKEY — zone is not DNSSEC-signed"))

    # Wildcard DNS
    label = "".join(random.choices(string.ascii_lowercase + string.digits, k=20))
    wild = query(f"{label}.{domain}", "A") + query(f"{label}.{domain}", "AAAA")
    checks.append(check("wildcard", "Wildcard DNS",
                        "warn" if wild else "pass",
                        "wildcard resolves (all names match)" if wild else "no wildcard resolution"))

    # Zone transfer (AXFR) against each nameserver
    axfr_open = []
    for server in ns[:3]:
        server = server.rstrip(".")
        try:
            dns.zone.from_xfr(dns.query.xfr(server, domain, timeout=5, lifetime=8))
            axfr_open.append(server)
        except Exception:
            continue
    if axfr_open:
        checks.append(check("axfr", "Zone transfer (AXFR)", "fail",
                            "AXFR succeeded against: " + ", ".join(axfr_open)))
    else:
        checks.append(check("axfr", "Zone transfer (AXFR)", "pass",
                            "no nameserver allowed a full zone transfer"))

    return "DNS & DNSSEC", checks


# ---------------------------------------------------------------------------
# Email security (SPF / DKIM / DMARC / MTA-STS / TLS-RPT)
# ---------------------------------------------------------------------------
DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "k2", "mail",
                  "dkim", "s1", "s2", "smtp", "mandrill", "amazonses", "zoho"]


def _dkim_key_present(records):
    """True only for a DKIM TXT record carrying a non-empty public key (p=)."""
    for rec in records:
        low = rec.lower()
        if "v=dkim1" not in low and "p=" not in low:
            continue
        for part in low.split(";"):
            part = part.strip()
            if part.startswith("p=") and part[2:].strip():
                return True
    return False


def audit_email(domain):
    checks = []

    spf = [t for t in txt_records(domain) if t.lower().startswith("v=spf1")]
    if not spf:
        checks.append(check("spf", "SPF (Sender Policy Framework)", "fail", "no v=spf1 record"))
    else:
        record = spf[0]
        tail = record.strip().split()[-1].lower() if record.strip() else ""
        if tail == "-all":
            checks.append(check("spf", "SPF (Sender Policy Framework)", "pass", record))
        elif tail == "~all":
            checks.append(check("spf", "SPF (Sender Policy Framework)", "warn",
                                f"soft fail (~all): {record}"))
        elif tail in ("+all", "?all"):
            checks.append(check("spf", "SPF (Sender Policy Framework)", "fail",
                                f"permissive ({tail}): {record}"))
        else:
            checks.append(check("spf", "SPF (Sender Policy Framework)", "warn",
                                f"no strict -all: {record}"))

    dmarc = [t for t in txt_records(domain, f"_dmarc.{domain}") if t.lower().startswith("v=dmarc1")]
    if not dmarc:
        checks.append(check("dmarc", "DMARC", "fail", "no v=DMARC1 record at _dmarc"))
    else:
        record = dmarc[0]
        policy = "none"
        for part in record.split(";"):
            part = part.strip()
            if part.lower().startswith("p="):
                policy = part[2:].strip().lower()
        if policy == "reject":
            checks.append(check("dmarc", "DMARC", "pass", record))
        elif policy == "quarantine":
            checks.append(check("dmarc", "DMARC", "warn", f"p=quarantine: {record}"))
        else:
            checks.append(check("dmarc", "DMARC", "fail", f"p=none (monitor only): {record}"))

    label = "".join(random.choices(string.ascii_lowercase + string.digits, k=20))
    wildcard_dkim = {t.lower() for t in txt_records(domain, f"{label}._domainkey.{domain}")}

    found_selectors = []
    for sel in DKIM_SELECTORS:
        recs = [r for r in txt_records(domain, f"{sel}._domainkey.{domain}")
                if r.lower() not in wildcard_dkim]
        if _dkim_key_present(recs):
            found_selectors.append(sel)
    if found_selectors:
        checks.append(check("dkim", "DKIM", "pass", "keys found for: " + ", ".join(found_selectors)))
    else:
        checks.append(check("dkim", "DKIM", "warn",
                            "no DKIM key found for common selectors (selector may be custom)"))
    if wildcard_dkim:
        checks.append(check("dkim-wildcard", "DKIM wildcard TXT", "info",
                            "a wildcard TXT exists under _domainkey; DKIM selectors cannot be "
                            "reliably enumerated"))

    mta = [t for t in txt_records(domain, f"_mta-sts.{domain}") if t.lower().startswith("v=stsv1")]
    checks.append(check("mta-sts", "MTA-STS", "pass" if mta else "warn",
                        mta[0] if mta else "no MTA-STS record"))

    tlsrpt = [t for t in txt_records(domain, f"_smtp._tls.{domain}") if t.lower().startswith("v=tlsrptv1")]
    checks.append(check("tls-rpt", "TLS-RPT", "pass" if tlsrpt else "info",
                        tlsrpt[0] if tlsrpt else "no TLS-RPT record"))

    return "Email security (SPF/DKIM/DMARC)", checks


# ---------------------------------------------------------------------------
# HTTP security headers & CSP
# ---------------------------------------------------------------------------
SECURITY_HEADERS = [
    ("hsts", "Strict-Transport-Security", "Strict-Transport-Security"),
    ("csp", "Content-Security-Policy", "Content-Security-Policy"),
    ("xfo", "X-Frame-Options", "X-Frame-Options"),
    ("xcto", "X-Content-Type-Options", "X-Content-Type-Options"),
    ("referrer", "Referrer-Policy", "Referrer-Policy"),
    ("permissions", "Permissions-Policy", "Permissions-Policy"),
]


def audit_headers(domain):
    checks = []
    if requests is None:
        return "HTTP security headers & CSP", [check("http", "HTTP fetch", "info", "requests unavailable")]

    resp = None
    for url in (f"https://{domain}", f"http://{domain}"):
        try:
            resp = requests.get(url, timeout=12, verify=False, allow_redirects=True)
            checks.append(check("http", "HTTP reachability", "pass", f"{url} -> {resp.status_code}"))
            break
        except Exception as exc:
            checks.append(check("http", "HTTP reachability", "warn", f"{url}: {exc}"))
    if resp is None:
        return "HTTP security headers & CSP", checks

    headers = {k.lower(): v for k, v in resp.headers.items()}

    for cid, title, header in SECURITY_HEADERS:
        value = headers.get(header.lower())
        if cid == "hsts" and value:
            checks.append(check(cid, title, "pass", value))
        elif cid == "csp" and value:
            issues = [t for t in ("'unsafe-inline'", "'unsafe-eval'", "*") if t in value]
            if issues:
                checks.append(check(cid, title, "warn", "permissive directive(s): " + ", ".join(issues)))
            else:
                checks.append(check(cid, title, "pass", value))
        elif cid == "xcto" and value:
            status = "pass" if "nosniff" in value.lower() else "warn"
            checks.append(check(cid, title, status, value))
        elif value:
            checks.append(check(cid, title, "pass", value))
        else:
            severity = "warn" if cid in ("hsts", "csp", "xcto") else "info"
            checks.append(check(cid, title, severity, "header not set"))

    if "x-frame-options" not in headers and "content-security-policy" not in headers:
        checks.append(check("clickjacking", "Clickjacking protection", "warn",
                            "neither X-Frame-Options nor CSP frame-ancestors is set"))

    server = headers.get("server")
    if server:
        checks.append(check("server", "Server banner disclosure", "info", server))

    cookie_flags = []
    for cookie in resp.cookies:
        if not cookie.secure:
            cookie_flags.append(cookie.name)
    if cookie_flags:
        checks.append(check("cookies", "Cookie Secure flag", "warn",
                            "cookies without Secure: " + ", ".join(cookie_flags)))

    return "HTTP security headers & CSP", checks


# ---------------------------------------------------------------------------
# TLS / SSL configuration
# ---------------------------------------------------------------------------
def _try_tls_version(domain, version, maximum=False):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        if maximum:
            ctx.maximum_version = version
            ctx.minimum_version = version
        else:
            ctx.minimum_version = version
    except Exception:
        return False
    try:
        with socket.create_connection((domain, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain):
                return True
    except Exception:
        return False


def audit_tls(domain):
    checks = []

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
    except Exception as exc:
        return "TLS / SSL", [check("tls", "TLS handshake", "fail", f"port 443: {exc}")]

    checks.append(check("tls", "TLS handshake", "pass", f"{cipher[0]} ({cipher[1]})"))

    not_after = cert.get("notAfter")
    if not_after:
        expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        days = (expiry - datetime.datetime.utcnow()).days
        if days < 0:
            checks.append(check("cert-expiry", "Certificate expiry", "fail", f"expired {abs(days)} days ago"))
        elif days < 30:
            checks.append(check("cert-expiry", "Certificate expiry", "warn", f"expires in {days} days"))
        else:
            checks.append(check("cert-expiry", "Certificate expiry", "pass", f"expires in {days} days"))

    issuer = dict(x[0] for x in cert.get("issuer", []))
    checks.append(check("cert-issuer", "Certificate issuer", "info", issuer.get("organizationName", "unknown")))

    legacy = []
    if _try_tls_version(domain, ssl.TLSVersion.TLSv1, maximum=True):
        legacy.append("TLS 1.0")
    if _try_tls_version(domain, ssl.TLSVersion.TLSv1_1, maximum=True):
        legacy.append("TLS 1.1")
    if legacy:
        checks.append(check("tls-versions", "Legacy TLS versions", "fail", "enabled: " + ", ".join(legacy)))
    else:
        checks.append(check("tls-versions", "Legacy TLS versions", "pass", "TLS 1.0/1.1 disabled"))

    checks.append(check("tls-modern", "Modern TLS (1.2/1.3)",
                        "pass" if _try_tls_version(domain, ssl.TLSVersion.TLSv1_2) else "warn",
                        "TLS 1.2/1.3 supported"))

    return "TLS / SSL", checks


SECTIONS = {
    "dns": audit_dns,
    "email": audit_email,
    "headers": audit_headers,
    "tls": audit_tls,
}


def main():
    if len(sys.argv) < 3 or sys.argv[1] not in SECTIONS:
        print(json.dumps({"error": "usage: audit.py <dns|email|headers|tls> <domain>"}))
        sys.exit(1)

    section, domain = sys.argv[1], sys.argv[2].strip().lower()
    try:
        title, checks = SECTIONS[section](domain)
    except Exception as exc:  # never crash — always emit JSON
        title, checks = section, [check("error", "Audit error", "fail", str(exc))]

    report = {
        "section": section,
        "title": title,
        "domain": domain,
        "score": score(checks),
        "checks": checks,
    }
    print(json.dumps(report))


if __name__ == "__main__":
    main()
