from urllib.parse import urlparse, parse_qs


def discover_url_parameters(url):

    parsed = urlparse(url)

    parameters = []

    query = parse_qs(
        parsed.query,
        keep_blank_values=True
    )

    for name in query:

        parameters.append({
            "name": name,
            "url": url
        })

    return parameters
