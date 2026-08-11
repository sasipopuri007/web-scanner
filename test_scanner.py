from general_scanner import WebScanner


TARGET = "http://localhost:8080/"


scanner = WebScanner(
    target=TARGET,
    max_pages=10,
    timeout=10
)

result = scanner.scan()


print()
print("=" * 60)
print("SCAN COMPLETE")
print("=" * 60)

print(
    f"Target: {result['target']}"
)

print(
    f"Pages scanned: "
    f"{result['pages_scanned']}"
)

print(
    f"Forms discovered: "
    f"{len(result['forms'])}"
)

print(
    f"URL parameters: "
    f"{len(result['parameters'])}"
)

print(
    f"Findings: "
    f"{len(result['findings'])}"
)

print()
print("=" * 60)
print("FORMS")
print("=" * 60)

for form in result["forms"]:

    print(
        f"{form['method']} "
        f"{form['url']}"
    )

    for field in form["fields"]:

        print(
            f"  - {field['name']} "
            f"({field['type']})"
        )


print()
print("=" * 60)
print("URL PARAMETERS")
print("=" * 60)

for parameter in result["parameters"]:

    print(
        f"{parameter['name']} "
        f"-> {parameter['url']}"
    )


print()
print("=" * 60)
print("SECURITY FINDINGS")
print("=" * 60)

for finding in result["findings"]:

    print(
        f"[{finding['severity']}] "
        f"{finding['title']}"
    )

    print(
        f"URL: {finding['url']}"
    )

    print(
        f"Type: {finding['type']}"
    )

    print(
        f"Description: "
        f"{finding['description']}"
    )

    print()
