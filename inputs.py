from bs4 import BeautifulSoup
from urllib.parse import urljoin


def discover_inputs(html, page_url):
    inputs = []

    soup = BeautifulSoup(html, "html.parser")

    for form in soup.find_all("form"):

        action = form.get("action") or page_url
        action = urljoin(page_url, action)

        method = (
            form.get("method", "GET")
            .upper()
        )

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

            inputs.append({
                "type": "FORM",
                "url": action,
                "method": method,
                "fields": fields
            })

    return inputs
