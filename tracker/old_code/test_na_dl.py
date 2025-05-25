#!/usr/bin/env python3
import sys
import requests
import json

API_URL = "https://www.tenable.com/downloads/api/v2/pages/nessus-agents"
HEADERS = {
    "Accept": "application/json",
    "User-Agent": "TenableAgentFullExtractor/1.0"
}
TIMEOUT = 30  # seconds

def main():
    try:
        resp = requests.get(API_URL, headers=HEADERS, timeout=TIMEOUT)
        resp.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"ERROR fetching {API_URL}: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        data = resp.json()
    except ValueError as e:
        print(f"ERROR parsing JSON: {e}", file=sys.stderr)
        sys.exit(1)

    # Drill into releases.latest
    releases = data.get("releases", {})
    latest   = releases.get("latest", {})
    if not latest:
        print("No 'releases.latest' found in JSON", file=sys.stderr)
        sys.exit(1)

    # For each category under 'latest' (e.g. "Plugins Archive", "Nessus Agents - 10.8.4", etc.)
    for category, files in latest.items():
        print(f"\n=== Category: {category} ===")
        if not isinstance(files, list) or not files:
            print("  (no files here)")
            continue

        for idx, f in enumerate(files, start=1):
            print(f"\n  File #{idx}:")
            print(f"    file:                 {f.get('file')}")
            print(f"    filename:             {f.get('file')}")
            print(f"    file_url:             {f.get('file_url')}")
            print(f"    version:              {f.get('version')}")
            print(f"    os:                   {f.get('os')}")
            print(f"    size:                 {f.get('size')}")
            print(f"    release_date:         {f.get('release_date')}")
            print(f"    product_release_date: {f.get('product_release_date')}")
            print(f"    md5:                  {f.get('md5')}")
            print(f"    sha256:               {f.get('sha256')}")
            print(f"    requires_auth:        {f.get('requires_auth')}")

    print("\nDone.")

if __name__ == "__main__":
    main()
