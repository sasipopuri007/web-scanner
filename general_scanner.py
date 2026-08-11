import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from collections import deque

from checks.passive import scan_page


class WebScanner:

    def __init__(self, target, max_pages=20, timeout=10):

        self.target = target.rstrip("/")
        self.max_pages = max_pages
        self.timeout = timeout

        self.session = requests.Session()

        self.session.headers.update({
            "User-Agent": "Authorized-Web-Security-Scanner/1.0"
        })

        parsed = urlparse(self.target)

        self.allowed_host = parsed.netloc

        self.visited = set()
        self.findings = []
        self.forms = []
        self.parameters = []

    def same_host(self, url):

        try:
            return urlparse(url).netloc == self.allowed_host
        except Exception:
            return False

    def normalize(self, url):

        parsed = urlparse(url)

        clean = parsed._replace(
            fragment=""
        )

        return clean.geturl()

    def extract_links(self, html, base_url):

        soup = BeautifulSoup(
            html,
            "html.parser"
        )

        links = set()

        for tag in soup.find_all(
            "a",
            href=True
        ):

            url = urljoin(
                base_url,
                tag["href"]
            )

            url = self.normalize(url)

            if self.same_host(url):
                links.add(url)

        return links

    def discover_forms(self, html, page_url):

        soup = BeautifulSoup(
            html,
            "html.parser"
        )

        discovered = []

        for form in soup.find_all("form"):

            action = form.get("action") or page_url

            action = urljoin(
                page_url,
                action
            )

            if not self.same_host(action):
                continue

            method = form.get(
                "method",
                "GET"
            ).upper()

            fields = []

            for element in form.find_all(
                ["input", "textarea", "select"]
            ):

                name = element.get("name")

                if not name:
                    continue

                field_type = element.get(
                    "type",
                    element.name
                )

                fields.append({
                    "name": name,
                    "type": field_type
                })

            if fields:

                form_data = {
                    "url": action,
                    "method": method,
                    "fields": fields
                }

                discovered.append(
                    form_data
                )

        return discovered

    def discover_parameters(self, url):

        parsed = urlparse(url)

        query = parse_qs(
            parsed.query,
            keep_blank_values=True
        )

        parameters = []

        for name in query:

            parameters.append({
                "name": name,
                "url": url
            })

        return parameters

    def scan(self):

        queue = deque([
            self.target
        ])

        while (
            queue
            and len(self.visited) < self.max_pages
        ):

            url = queue.popleft()

            if url in self.visited:
                continue

            self.visited.add(url)

            print(
                f"[{len(self.visited)}/{self.max_pages}] "
                f"Scanning {url}"
            )

            try:

                response = self.session.get(
                    url,
                    timeout=self.timeout,
                    allow_redirects=True
                )

            except requests.RequestException as error:

                print(
                    f"    Connection error: {error}"
                )

                continue

            page_findings = scan_page(
                response
            )

            self.findings.extend(
                page_findings
            )

            if "text/html" not in response.headers.get(
                "Content-Type",
                ""
            ).lower():

                continue

            forms = self.discover_forms(
                response.text,
                response.url
            )

            for form in forms:

                if form not in self.forms:

                    self.forms.append(form)

                    print(
                        f"    FORM "
                        f"{form['method']} "
                        f"{form['url']}"
                    )

                    for field in form["fields"]:

                        print(
                            f"        FIELD: "
                            f"{field['name']} "
                            f"({field['type']})"
                        )

            parameters = self.discover_parameters(
                response.url
            )

            for parameter in parameters:

                if parameter not in self.parameters:

                    self.parameters.append(
                        parameter
                    )

                    print(
                        f"    PARAMETER: "
                        f"{parameter['name']}"
                    )

            links = self.extract_links(
                response.text,
                response.url
            )

            for link in links:

                if link not in self.visited:

                    queue.append(link)

        return {
            "target": self.target,
            "pages_scanned": len(self.visited),
            "forms": self.forms,
            "parameters": self.parameters,
            "findings": self.findings
        }
