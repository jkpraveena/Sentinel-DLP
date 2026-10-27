"""Command-line demo client. It sends synthetic payloads to the local API."""
import argparse
import json
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:8000"


def post_json(path, data):
    req = urllib.request.Request(
        BASE + path,
        data=json.dumps(data).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return response.status, response.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def main():
    parser = argparse.ArgumentParser(description="Run Sentinel DLP demo cases")
    parser.add_argument("--ai", action="store_true", help="Ask local Ollama to classify ambiguous values")
    args = parser.parse_args()

    cases = [
        ("NORMAL", "Hello professor, this is my DLP assignment."),
        ("LABELLED ID", "Customer identity number: 123456789012"),
        ("AMBIGUOUS", "Sample batch reference: 123456789012"),
        ("SYNTHETIC CARD", "Test payment card: 4111 1111 1111 1111"),
    ]
    for title, payload in cases:
        status, body = post_json("/api/inspect", {"payload": payload, "use_ai": args.ai})
        print(f"\n{'=' * 16} {title} (HTTP {status}) {'=' * 16}")
        print(json.dumps(json.loads(body), indent=2))


if __name__ == "__main__":
    main()
