"""Patch Sublist3r for Python 3.11 + changed upstream sites.

The stock tool crashes with an uncaught IndexError when an engine's response no
longer matches (e.g. DNSdumpster's CSRF token, Virustotal/Google blocking).
Because each engine runs in its own multiprocessing.Process, the exception
surfaces as an ugly traceback on stderr. We:
  1. guard get_csrftoken against a missing token / empty response;
  2. skip DNSdumpster's POST when no token was obtained;
  3. wrap the per-engine run() so any failure is swallowed instead of crashing.
"""
import sys

PATH = "/opt/sublist3r/sublist3r.py"

with open(PATH, encoding="utf-8") as fh:
    src = fh.read()

replacements = [
    (
        """    def get_csrftoken(self, resp):
        csrf_regex = re.compile('<input type="hidden" name="csrfmiddlewaretoken" value="(.*?)">', re.S)
        token = csrf_regex.findall(resp)[0]
        return token.strip()""",
        """    def get_csrftoken(self, resp):
        if not resp:
            return None
        csrf_regex = re.compile('<input type="hidden" name="csrfmiddlewaretoken" value="(.*?)">', re.S)
        tokens = csrf_regex.findall(resp)
        if not tokens:
            return None
        return tokens[0].strip()""",
    ),
    (
        """        resp = self.req('GET', self.base_url)
        token = self.get_csrftoken(resp)
        params = {'csrfmiddlewaretoken': token, 'targetip': self.domain}""",
        """        resp = self.req('GET', self.base_url)
        token = self.get_csrftoken(resp)
        if token is None:
            return self.live_subdomains
        params = {'csrfmiddlewaretoken': token, 'targetip': self.domain}""",
    ),
    (
        """    def run(self):
        domain_list = self.enumerate()
        for domain in domain_list:
            self.q.append(domain)""",
        """    def run(self):
        try:
            domain_list = self.enumerate()
        except Exception as exc:
            self.print_("%s[!] %s lookup failed: %s%s" % (R, self.engine_name, exc, W))
            domain_list = []
        for domain in domain_list:
            self.q.append(domain)""",
    ),
]

for old, new in replacements:
    if old not in src:
        sys.exit("sublist3r patch target not found:\n" + old)
    src = src.replace(old, new, 1)

with open(PATH, "w", encoding="utf-8") as fh:
    fh.write(src)

print("sublist3r patched")
