from __future__ import annotations
import argparse
import re
import sys
import time
import uuid
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

import requests
from bs4 import BeautifulSoup

requests.packages.urllib3.disable_warnings()  # lab/test targets often use self-signed certs

TIMEOUT = 8
HEADERS = {"User-Agent": "webscan.py/1.0 (authorized black-box scan)"}

SQL_ERROR_SIGNATURES = [
    "sql syntax", "mysql_fetch", "you have an error in your sql",
    "unclosed quotation mark", "quoted string not properly terminated",
    "sqlite3.operationalerror", "pg_query", "ora-01756", "odbc sql server driver",
    "syntax error at or near", "warning: mysqli",
]

SENSITIVE_PATHS = [
    ".git/config", ".git/HEAD", ".env", ".env.local", ".DS_Store",
    "wp-config.php.bak", "config.php.bak", "backup.zip", "backup.sql",
    ".svn/entries", "web.config", "docker-compose.yml", ".htpasswd",
    "id_rsa", ".aws/credentials",
]

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
]

REDIRECT_PARAM_NAMES = {"redirect", "redirect_uri", "url", "next", "return", "returnurl", "dest", "continue"}


@dataclass
class Finding:
    check: str
    severity: str          # "high" | "medium" | "low" | "info"
    location: str
    detail: str
    evidence: str = ""


@dataclass
class InjectionPoint:
    url: str
    method: str
    field: str
    fixed_fields: dict = field(default_factory=dict)


# ---------------------------------------------------------------- crawler --

def crawl(start_url: str, session: requests.Session, max_pages: int = 15) -> tuple[list[InjectionPoint], list[str]]:
    """Same-origin crawl. Collects form fields + query-string params as injection points."""
    seen_pages: set[str] = set()
    to_visit = [start_url]
    points: list[InjectionPoint] = []
    origin = urlparse(start_url).netloc

    while to_visit and len(seen_pages) < max_pages:
        url = to_visit.pop(0)
        if url in seen_pages:
            continue
        seen_pages.add(url)
        try:
            resp = session.get(url, headers=HEADERS, timeout=TIMEOUT, verify=False)
        except requests.RequestException:
            continue

        # query-string params on this page's own URL
        parsed = urlparse(url)
        for pname in parse_qs(parsed.query):
            points.append(InjectionPoint(url=url, method="GET", field=pname))

        if "text/html" not in resp.headers.get("Content-Type", ""):
            continue

        soup = BeautifulSoup(resp.text, "html.parser")

        for form in soup.find_all("form"):
            action = urljoin(url, form.get("action") or url)
            method = (form.get("method") or "GET").upper()
            fixed = {}
            for inp in form.find_all(["input", "textarea"]):
                name = inp.get("name")
                if not name:
                    continue
                itype = (inp.get("type") or "text").lower()
                if itype in ("submit", "button"):
                    fixed[name] = inp.get("value", name)
                else:
                    points.append(InjectionPoint(url=action, method=method, field=name))
            for p in points:
                if p.url == action and p.method == method:
                    p.fixed_fields.update(fixed)

        for a in soup.find_all("a", href=True):
            link = urljoin(url, a["href"])
            if urlparse(link).netloc == origin and link not in seen_pages:
                to_visit.append(link)

    return points, list(seen_pages)


def _send(session, url, method, field, value, fixed_fields):
    fixed_fields = fixed_fields or {}
    if method == "GET":
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        qs.update({k: [v] for k, v in fixed_fields.items()})
        qs[field] = [value]
        new_qs = urlencode({k: v[0] for k, v in qs.items()})
        target = urlunparse(parsed._replace(query=new_qs))
        return session.get(target, headers=HEADERS, timeout=TIMEOUT, verify=False)
    else:
        data = dict(fixed_fields)
        data[field] = value
        return session.post(url, data=data, headers=HEADERS, timeout=TIMEOUT, verify=False)


# ---------------------------------------------------------------- checks --

def check_sqli(session, point: InjectionPoint) -> list[Finding]:
    findings = []
    baseline = _send(session, point.url, point.method, point.field, "1", point.fixed_fields)
    if baseline is None:
        return findings

    # error-based
    error_payloads = ["'", "\"", "1'\"", "1) OR ('1'='1"]
    for payload in error_payloads:
        resp = _send(session, point.url, point.method, point.field, payload, point.fixed_fields)
        if resp is None:
            continue
        body = resp.text.lower()
        for sig in SQL_ERROR_SIGNATURES:
            if sig in body:
                findings.append(Finding(
                    check="SQL Injection (error-based)", severity="high",
                    location=f"{point.method} {point.url} [{point.field}]",
                    detail=f"Injecting `{payload}` triggered a database error string in the response.",
                    evidence=sig,
                ))
                return findings  # one confirmation is enough for this point

    # boolean-based
    true_resp = _send(session, point.url, point.method, point.field, "1 OR 1=1", point.fixed_fields)
    false_resp = _send(session, point.url, point.method, point.field, "1 AND 1=2", point.fixed_fields)
    if true_resp is not None and false_resp is not None and baseline is not None:
        len_true, len_false, len_base = len(true_resp.text), len(false_resp.text), len(baseline.text)
        # TRUE should resemble baseline; FALSE should differ meaningfully from both
        if abs(len_true - len_base) < 5 and abs(len_false - len_true) > 30:
            findings.append(Finding(
                check="SQL Injection (boolean-based)", severity="high",
                location=f"{point.method} {point.url} [{point.field}]",
                detail="TRUE and FALSE conditional payloads produced significantly different "
                       "response sizes, consistent with an unsanitized query condition.",
                evidence=f"len(baseline)={len_base}, len(TRUE)={len_true}, len(FALSE)={len_false}",
            ))
    return findings


def check_xss(session, point: InjectionPoint) -> list[Finding]:
    marker = f"xss{uuid.uuid4().hex[:8]}"
    payload = f"<script>/*{marker}*/</script>"
    resp = _send(session, point.url, point.method, point.field, payload, point.fixed_fields)
    if resp is None:
        return []
    if payload in resp.text:
        return [Finding(
            check="Reflected XSS", severity="high",
            location=f"{point.method} {point.url} [{point.field}]",
            detail="Injected script marker was reflected unescaped in the HTML response body.",
            evidence=marker,
        )]
    return []


def check_open_redirect(session, point: InjectionPoint) -> list[Finding]:
    if point.field.lower() not in REDIRECT_PARAM_NAMES:
        return []
    external = "https://example.org/webscan-redirect-check"
    resp = _send(session, point.url, point.method, point.field, external, point.fixed_fields)
    if resp is None:
        return []
    location = resp.headers.get("Location", "")
    final_url = resp.url
    if external in location or external in final_url:
        return [Finding(
            check="Open Redirect", severity="medium",
            location=f"{point.method} {point.url} [{point.field}]",
            detail="Setting this parameter to an external URL caused the app to redirect there.",
            evidence=external,
        )]
    return []


def check_security_headers(session, base_url: str) -> list[Finding]:
    findings = []
    try:
        resp = session.get(base_url, headers=HEADERS, timeout=TIMEOUT, verify=False)
    except requests.RequestException:
        return findings
    for h in SECURITY_HEADERS:
        if h not in resp.headers:
            findings.append(Finding(
                check="Missing Security Header", severity="low",
                location=base_url,
                detail=f"Response does not set the '{h}' header.",
            ))
    return findings


def check_exposed_paths(session, base_url: str) -> list[Finding]:
    findings = []
    parsed = urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}/"
    for path in SENSITIVE_PATHS:
        target = urljoin(root, path)
        try:
            resp = session.get(target, headers=HEADERS, timeout=TIMEOUT, verify=False)
        except requests.RequestException:
            continue
        if resp.status_code == 200 and len(resp.content) > 0:
            findings.append(Finding(
                check="Exposed Sensitive File", severity="medium",
                location=target,
                detail=f"Path returned HTTP 200 ({len(resp.content)} bytes) — should not be publicly reachable.",
            ))
        time.sleep(0.1)
    return findings


# ---------------------------------------------------------------- report --

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def print_report(findings: list[Finding], target: str, pages_crawled: int, points_tested: int):
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
    print("\n" + "=" * 70)
    print(f"  webscan.py — report for {target}")
    print(f"  pages crawled: {pages_crawled}   injection points tested: {points_tested}")
    print("=" * 70)
    if not findings:
        print("\nNo issues detected by the checks run.")
        return
    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[f.severity] += 1
    print(f"\n{counts['high']} high  ·  {counts['medium']} medium  ·  {counts['low']} low\n")
    for f in findings:
        tag = f.severity.upper()
        print(f"[{tag}] {f.check}")
        print(f"    location: {f.location}")
        print(f"    detail:   {f.detail}")
        if f.evidence:
            print(f"    evidence: {f.evidence}")
        print()


# ---------------------------------------------------------------- main --

def main():
    parser = argparse.ArgumentParser(description="Black-box web vulnerability scanner")
    parser.add_argument("--url", required=True, help="Target URL to scan")
    parser.add_argument("--max-pages", type=int, default=15, help="Max pages to crawl (default 15)")
    parser.add_argument("--i-have-authorization", action="store_true",
                         help="Required flag confirming you own/are authorized to test this target")
    args = parser.parse_args()

    if not args.i_have_authorization:
        print("Refusing to scan: pass --i-have-authorization to confirm you own this target\n"
              "or have explicit written permission to test it. Unauthorized scanning is illegal.")
        sys.exit(1)

    session = requests.Session()
    print(f"[*] Crawling {args.url} (max {args.max_pages} pages)...")
    points, pages = crawl(args.url, session, args.max_pages)
    print(f"[*] Crawled {len(pages)} page(s), found {len(points)} injection point(s).")

    findings: list[Finding] = []
    findings += check_security_headers(session, args.url)
    findings += check_exposed_paths(session, args.url)

    for i, point in enumerate(points, 1):
        print(f"[*] ({i}/{len(points)}) testing {point.method} {point.url} field='{point.field}'")
        findings += check_sqli(session, point)
        findings += check_xss(session, point)
        findings += check_open_redirect(session, point)

    print_report(findings, args.url, len(pages), len(points))


if __name__ == "__main__":
    main()
