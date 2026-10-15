#!/usr/bin/env python3
"""Subdomain takeover scanner with CNAME resolution and reverse-DNS lookup.

Reads subdomains from stdin (one per line) and writes one JSON object per line
to stdout:

    echo "sub.example.com" | takeover.py

Each record:
    {"subdomain","cname","cname_chain","a_records","reverse_dns",
     "status","service","detail","http_status"}

Status values:
    vulnerable - a fingerprint of a known service is dangling / unclaimed
    dangling   - the CNAME target does not resolve (unknown service)
    edge       - CNAME points at a known service but appears claimed
    safe       - resolves normally, no known-service CNAME
    unknown    - the subdomain itself does not resolve

Requires only dnspython (DNS) and requests (optional HTTP confirmation).
"""
import json
import sys
import warnings
from concurrent.futures import ThreadPoolExecutor

import dns.exception
import dns.resolver
import dns.reversename

warnings.filterwarnings("ignore")

try:
    import requests
    import urllib3

    urllib3.disable_warnings()
except Exception:  # pragma: no cover
    requests = None

# Docker's embedded DNS proxy can be unreliable for full chains; query public
# resolvers directly and fall back to the system resolver.
PUBLIC_RESOLVER = dns.resolver.Resolver(configure=False)
PUBLIC_RESOLVER.nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
PUBLIC_RESOLVER.timeout = 4
PUBLIC_RESOLVER.lifetime = 8

HTTP_TIMEOUT = 6
HTTP_UA = "Mozilla/5.0 (compatible; Vexora-Takeover/1.0)"
MAX_WORKERS = 50


# ---------------------------------------------------------------------------
# Fingerprint database of commonly hijackable services.
#   cnames       - suffixes the CNAME chain ends with
#   fingerprints - strings found in the "unclaimed" response body
#   status_codes - HTTP status codes that indicate an unclaimed service
# ---------------------------------------------------------------------------
FINGERPRINTS = [
    {"service": "Amazon S3", "cnames": ["s3.amazonaws.com", "s3-website", "s3-external-1.amazonaws.com"],
     "fingerprints": ["NoSuchBucket", "The specified bucket does not exist"], "status_codes": [404]},
    {"service": "Amazon CloudFront", "cnames": ["cloudfront.net"],
     "fingerprints": ["Bad request.", "ERROR: The request could not be satisfied", "CloudFront attempted to"],
     "status_codes": [403, 404]},
    {"service": "GitHub Pages", "cnames": ["github.io", "githubusercontent.com"],
     "fingerprints": ["There isn't a GitHub Pages site here", "For root URLs"], "status_codes": [404]},
    {"service": "Heroku", "cnames": ["herokuapp.com", "herokudns.com", "herokussl.com"],
     "fingerprints": ["No such app", "herokucdn.com/error-pages/no-such-app.html"], "status_codes": [404]},
    {"service": "Netlify", "cnames": ["netlify.app", "netlify.com"],
     "fingerprints": ["Not Found - Request ID", "Page not found"], "status_codes": [404]},
    {"service": "Microsoft Azure", "cnames": ["azurewebsites.net", "cloudapp.azure.com", "cloudapp.net",
                                              "trafficmanager.net", "blob.core.windows.net", "azure-api.net"],
     "fingerprints": ["Error 404 - Web app not found", "The resource you are looking for has been removed",
                      "does not exist"], "status_codes": [404]},
    {"service": "Shopify", "cnames": ["myshopify.com", "shopify.com"],
     "fingerprints": ["Sorry, this shop is currently unavailable", "Only one step left"], "status_codes": [404]},
    {"service": "Fastly", "cnames": ["fastly.net", "fastlylb.net"],
     "fingerprints": ["Fastly error: unknown domain", "Please check that this domain has been added to a service"],
     "status_codes": [404]},
    {"service": "Pantheon", "cnames": ["pantheonsite.io", "pantheon.io"],
     "fingerprints": ["The gods are wise, but do not know of the site which you seek",
                      "404 error unknown site"], "status_codes": [404]},
    {"service": "Tumblr", "cnames": ["domains.tumblr.com", "tumblr.com"],
     "fingerprints": ["There's nothing here", "Whatever you were looking for doesn't currently exist"],
     "status_codes": [404]},
    {"service": "WordPress", "cnames": ["wordpress.com"],
     "fingerprints": ["Do you want to register", "doesn\u2019t exist"], "status_codes": [404]},
    {"service": "Zendesk", "cnames": ["zendesk.com"],
     "fingerprints": ["Help Center Closed", "This help center no longer exists"], "status_codes": [404]},
    {"service": "Bitbucket", "cnames": ["bitbucket.io"],
     "fingerprints": ["Repository not found"], "status_codes": [404]},
    {"service": "Cargo", "cnames": ["cargocollective.com"],
     "fingerprints": ["404 Not Found"], "status_codes": [404]},
    {"service": "Surge.sh", "cnames": ["surge.sh"],
     "fingerprints": ["project not found", "404 Not Found"], "status_codes": [404]},
    {"service": "Ghost", "cnames": ["ghost.io"],
     "fingerprints": ["Domain error", "The owner of this domain has not yet registered"], "status_codes": [404]},
    {"service": "Read the Docs", "cnames": ["readthedocs.io", "readthedocs.org"],
     "fingerprints": ["404 Not Found", "unknown to Read the Docs"], "status_codes": [404]},
    {"service": "Webflow", "cnames": ["webflow.io", "proxy-ssl.webflow.com"],
     "fingerprints": ["The page you are looking for doesn't exist", "This site is not published"],
     "status_codes": [404]},
    {"service": "Strikingly", "cnames": ["strikinglydns.com", "strikingly.com"],
     "fingerprints": ["But if you're looking for", "page has been removed"], "status_codes": [404]},
    {"service": "Unbounce", "cnames": ["unbouncepages.com"],
     "fingerprints": ["The requested URL was not found", "page not found"], "status_codes": [404]},
    {"service": "Tilda", "cnames": ["tildacdn.com", "tilda.ws"],
     "fingerprints": ["Please go to the site settings and put the domain name"],
     "status_codes": [404]},
    {"service": "SendGrid", "cnames": ["sendgrid.net"],
     "fingerprints": ["The page you are looking for doesn't exist"], "status_codes": [404]},
    {"service": "Intercom", "cnames": ["custom.intercom.help", "intercom.help"],
     "fingerprints": ["This page is reserved for artistic purposes", "This page is not available"],
     "status_codes": [404]},
    {"service": "Vercel", "cnames": ["vercel.app", "vercel-dns.com", "now.sh"],
     "fingerprints": ["The deployment could not be found", "This project is not found"], "status_codes": [404]},
    {"service": "Fly.io", "cnames": ["fly.dev"],
     "fingerprints": ["404 Not Found", "could not find application"], "status_codes": [404]},
    {"service": "Ngrok", "cnames": ["ngrok.io", "ngrok-free.app"],
     "fingerprints": ["Tunnel not found", "not found"], "status_codes": [404]},
    {"service": "Bitly", "cnames": ["bitly.com", "cname.bitly.com"],
     "fingerprints": ["bitly.com", "http://bitly.com"], "status_codes": [404]},
    {"service": "AWS Elastic Beanstalk", "cnames": ["elasticbeanstalk.com"],
     "fingerprints": ["404 Not Found"], "status_codes": [404]},
    {"service": "Kinsta", "cnames": ["kinsta.cloud"],
     "fingerprints": ["No Site For Domain"], "status_codes": [404]},
    {"service": "Helpscout", "cnames": ["helpscoutdocs.com"],
     "fingerprints": ["No settings were found for this company:"], "status_codes": [404]},
    {"service": "Freshdesk", "cnames": ["freshdesk.com"],
     "fingerprints": ["We couldn't find this page"], "status_codes": [404]},
    {"service": "UserVoice", "cnames": ["uservoice.com"],
     "fingerprints": ["This UserVoice subdomain is currently available!"], "status_codes": [404]},
    {"service": "Aftership", "cnames": ["aftership.com"],
     "fingerprints": ["Oops.", "This page is no longer available"], "status_codes": [404]},
    {"service": "Canny", "cnames": ["canny.io"],
     "fingerprints": ["Company Not Found"], "status_codes": [404]},
    {"service": "Campaign Monitor", "cnames": ["createsend.com"],
     "fingerprints": ["Double check the URL", "Trying to access"], "status_codes": [404]},
    {"service": "Desk", "cnames": ["desk.com"],
     "fingerprints": ["Sorry, We Couldn't Find That Page"], "status_codes": [404]},
    {"service": "Pingdom", "cnames": ["pingdom.com"],
     "fingerprints": ["Sorry, couldn't find the status page"], "status_codes": [404]},
    {"service": "Smartling", "cnames": ["smartling.com"],
     "fingerprints": ["Domain is not configured"], "status_codes": [404]},
    {"service": "Squarespace", "cnames": ["squarespace.com"],
     "fingerprints": ["No Such Account", "This site is not available"], "status_codes": [404]},
    {"service": "Teamwork", "cnames": ["teamwork.com"],
     "fingerprints": ["Oops - We didn't find your site."], "status_codes": [404]},
    {"service": "HatenaBlog", "cnames": ["hatenablog.com"],
     "fingerprints": ["404 Blog Not Found"], "status_codes": [404]},
]


def safe_resolve(name, rtype):
    for resolver in (PUBLIC_RESOLVER, dns.resolver):
        try:
            ans = resolver.resolve(name, rtype, lifetime=8, raise_on_no_answer=False)
            if ans.rrset is not None:
                return ans
        except Exception:
            continue
    return None


def resolve_status(name, rtype):
    """Return (records, nxdomain) — nxdomain True only for a definitive NXDOMAIN."""
    for resolver in (PUBLIC_RESOLVER, dns.resolver):
        try:
            ans = resolver.resolve(name, rtype, lifetime=8, raise_on_no_answer=False)
            if ans.rrset is not None:
                return [str(r) for r in ans], False
            return [], False
        except dns.resolver.NXDOMAIN:
            return [], True
        except Exception:
            continue
    return [], False


def cname_chain(name, max_hops=10):
    chain = []
    current = name
    for _ in range(max_hops):
        ans = safe_resolve(current, "CNAME")
        if not ans:
            break
        target = str(ans[0].target).rstrip(".").lower()
        if not target or target in chain:
            break
        chain.append(target)
        current = target
    return chain


def host_ips(name):
    ips = []
    for rtype in ("A", "AAAA"):
        records, _ = resolve_status(name, rtype)
        for rec in records:
            if rec not in ips:
                ips.append(rec)
    return ips


def reverse_dns(ip):
    names = []
    try:
        rev = dns.reversename.from_address(ip)
        ans = safe_resolve(str(rev), "PTR")
        if ans:
            for r in ans:
                names.append(str(r).rstrip(".").lower())
    except Exception:
        pass
    return names


def match_cname_service(chain):
    for fp in FINGERPRINTS:
        for target in chain:
            for suffix in fp["cnames"]:
                if target == suffix or target.endswith("." + suffix) or suffix in target:
                    return fp
    return None


def http_body(host):
    """Fetch the host over https then http; return (body, status_code)."""
    if requests is None:
        return None, None
    for scheme in ("https", "http"):
        try:
            resp = requests.get(
                f"{scheme}://{host}",
                timeout=HTTP_TIMEOUT,
                verify=False,
                allow_redirects=True,
                headers={"User-Agent": HTTP_UA},
            )
            return resp.text or "", resp.status_code
        except Exception:
            continue
    return None, None


def body_matches(fp, body):
    if not body:
        return False
    lowered = body.lower()
    return any(sig.lower() in lowered for sig in fp["fingerprints"])


def scan(host):
    result = {
        "subdomain": host,
        "cname": None,
        "cname_chain": [],
        "a_records": [],
        "reverse_dns": [],
        "status": "unknown",
        "service": None,
        "detail": "",
        "http_status": None,
    }

    ips = host_ips(host)
    chain = cname_chain(host)
    result["cname_chain"] = chain
    result["cname"] = chain[-1] if chain else None
    result["a_records"] = ips

    ptr = []
    for ip in ips[:4]:
        for name in reverse_dns(ip):
            if name not in ptr:
                ptr.append(name)
    result["reverse_dns"] = ptr

    if not chain and not ips:
        result["status"] = "unknown"
        result["detail"] = "no DNS records (NXDOMAIN or empty)"
        return result

    service = match_cname_service(chain)

    # Only spend an HTTP request when there is something to inspect.
    body, code = (None, None)
    if chain:
        body, code = http_body(chain[-1] if chain else host)
        result["http_status"] = code

    # Known service fingerprints found in the response body.
    if service and body_matches(service, body):
        result["status"] = "vulnerable"
        result["service"] = service["service"]
        result["detail"] = "fingerprint of an unclaimed " + service["service"] + " site"
        return result

    # If the CNAME chain matched a known service, verify whether its final hop
    # still resolves. An NXDOMAIN target is a dangling record.
    if service:
        target = chain[-1]
        _, nx = resolve_status(target, "A")
        if nx:
            result["status"] = "vulnerable"
            result["service"] = service["service"]
            result["detail"] = f"CNAME target {target} does not resolve (NXDOMAIN)"
            return result
        result["status"] = "edge"
        result["service"] = service["service"]
        result["detail"] = f"points at {service['service']} ({target}) but appears claimed"
        return result

    # Unrecognised CNAME that does not resolve at all.
    if chain:
        target = chain[-1]
        _, nx = resolve_status(target, "A")
        if nx:
            result["status"] = "dangling"
            result["detail"] = f"CNAME target {target} does not resolve (unknown service)"
            return result

    result["status"] = "safe"
    result["detail"] = "resolves normally with no known-vulnerable CNAME"
    return result


def main():
    stdin = sys.stdin.read() if not sys.stdin.isatty() else ""
    hosts = []
    seen = set()
    for line in stdin.splitlines():
        host = line.strip().lower()
        if not host or host in seen:
            continue
        seen.add(host)
        hosts.append(host)

    if not hosts:
        return

    workers = min(MAX_WORKERS, max(1, len(hosts)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for record in pool.map(scan, hosts):
            print(json.dumps(record), flush=True)


if __name__ == "__main__":
    main()
