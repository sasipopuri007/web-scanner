import requests
from urllib.parse import urlparse


def check_headers(response):
    findings = []

    headers = {
        key.lower(): value
        for key, value in response.headers.items()
    }

    required_headers = {
        "content-security-policy": "Content-Security-Policy",
        "x-content-type-options": "X-Content-Type-Options",
        "x-frame-options": "X-Frame-Options",
        "referrer-policy": "Referrer-Policy",
    }

    for header_key, display_name in required_headers.items():

        if header_key not in headers:

            findings.append({
                "type": "MISSING_SECURITY_HEADER",
                "severity": "LOW",
                "title": f"Missing {display_name}",
                "url": response.url,
                "description": (
                    f"The response does not contain "
                    f"the {display_name} security header."
                )
            })

    return findings


def check_server_header(response):
    findings = []

    server = response.headers.get("Server")

    if server:

        findings.append({
            "type": "SERVER_HEADER_EXPOSED",
            "severity": "INFO",
            "title": "Server information exposed",
            "url": response.url,
            "description": (
                f"The server response exposes "
                f"server information: {server}"
            )
        })

    powered_by = response.headers.get("X-Powered-By")

    if powered_by:

        findings.append({
            "type": "POWERED_BY_EXPOSED",
            "severity": "LOW",
            "title": "Technology information exposed",
            "url": response.url,
            "description": (
                f"X-Powered-By exposes technology "
                f"information: {powered_by}"
            )
        })

    return findings


def check_cookies(response):
    findings = []

    for cookie in response.cookies:

        if response.url.startswith("https://"):

            if not cookie.secure:

                findings.append({
                    "type": "COOKIE_NOT_SECURE",
                    "severity": "MEDIUM",
                    "title": "Cookie missing Secure attribute",
                    "url": response.url,
                    "description": (
                        f"Cookie '{cookie.name}' does not "
                        f"use the Secure attribute."
                    )
                })

        cookie_header = str(cookie)

        if "HttpOnly" not in cookie_header:

            findings.append({
                "type": "COOKIE_NOT_HTTPONLY",
                "severity": "LOW",
                "title": "Cookie missing HttpOnly attribute",
                "url": response.url,
                "description": (
                    f"Cookie '{cookie.name}' may be accessible "
                    f"from client-side scripts."
                )
            })

    return findings


def check_https(url):
    findings = []

    parsed = urlparse(url)

    if parsed.scheme == "http":

        findings.append({
            "type": "HTTP_NOT_HTTPS",
            "severity": "MEDIUM",
            "title": "Site is using HTTP",
            "url": url,
            "description": (
                "The target is using HTTP instead of HTTPS."
            )
        })

    return findings


def check_content_type(response):
    findings = []

    content_type = response.headers.get(
        "Content-Type",
        ""
    ).lower()

    if "text/html" in content_type:

        if "charset=" not in content_type:

            findings.append({
                "type": "MISSING_CHARSET",
                "severity": "INFO",
                "title": "Content-Type does not specify charset",
                "url": response.url,
                "description": (
                    "The HTML response does not explicitly "
                    "specify a character encoding."
                )
            })

    return findings


def scan_page(response):
    findings = []

    findings.extend(
        check_headers(response)
    )

    findings.extend(
        check_server_header(response)
    )

    findings.extend(
        check_cookies(response)
    )

    findings.extend(
        check_https(response.url)
    )

    findings.extend(
        check_content_type(response)
    )

    return findings
