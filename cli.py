"""
IOC Collector CLI
------------------
Usage:
    python3 cli.py --url https://example.com/threat-report
    python3 cli.py --file report.txt
    python3 cli.py --text "hxxp://evil[.]com and 1.2.3[.]4"

Output: prints found IOCs, saves to iocs.db, and exports iocs.json / iocs.csv
"""

import argparse
import sys
from extractor import IOCExtractor, IOCStore


def fetch_url(url: str) -> str:
    """
    Fetch a URL and extract the main article/body text, discarding nav,
    sidebar, footer, and ad-widget content (e.g. 'related articles' boxes
    that link to unrelated ad-network domains). Uses trafilatura, which is
    purpose-built for isolating real article content from page chrome —
    a naive HTML-tag-stripper leaves sidebar/ad links in as visible text,
    which shows up as false-positive domain IOCs.
    """
    import trafilatura
    downloaded = trafilatura.fetch_url(url)
    if downloaded is None:
        # fall back to a basic urllib fetch if trafilatura's fetcher fails
        # (e.g. site blocks its default user agent)
        import urllib.request
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (IOC-Collector)"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            downloaded = resp.read().decode("utf-8", errors="ignore")

    text = trafilatura.extract(downloaded, include_links=True, include_tables=True)
    if not text:
        # trafilatura couldn't isolate an article body (e.g. non-article page) —
        # fall back to crude tag stripping so we still return *something*
        import re
        text = re.sub(r"<script.*?</script>", " ", downloaded, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r"<style.*?</style>", " ", text, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r"<[^>]+>", " ", text)
    return text


def main():
    parser = argparse.ArgumentParser(description="Extract IOCs from a URL, file, or raw text.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--url", help="Fetch and scan a webpage")
    group.add_argument("--file", help="Scan a local text file")
    group.add_argument("--text", help="Scan a raw text string")
    parser.add_argument("--db", default="iocs.db", help="SQLite DB path (default: iocs.db)")
    parser.add_argument("--json", default="iocs.json", help="JSON export path")
    parser.add_argument("--csv", default="iocs.csv", help="CSV export path")
    parser.add_argument(
        "--include-noise", action="store_true",
        help="Don't filter out common infra/CDN/social domains (google.com, facebook.com, etc.)"
    )
    args = parser.parse_args()

    if args.url:
        print(f"[*] Fetching {args.url} ...")
        text = fetch_url(args.url)
        source = args.url
    elif args.file:
        with open(args.file, "r", errors="ignore") as f:
            text = f.read()
        source = args.file
    else:
        text = args.text
        source = "manual_input"

    extractor = IOCExtractor()
    if args.include_noise:
        extractor.noise_domains = set()
    results = extractor.extract(text, source=source)

    if not results:
        print("[!] No IOCs found.")
        sys.exit(0)

    print(f"[+] Found {len(results)} IOC(s):\n")
    by_type = {}
    for r in results:
        by_type.setdefault(r.ioc_type, []).append(r.value)

    for ioc_type, values in by_type.items():
        print(f"  {ioc_type} ({len(values)}):")
        for v in values:
            print(f"    - {v}")

    store = IOCStore(args.db)
    n_new = store.save(results)
    n_json = store.export_json(args.json)
    n_csv = store.export_csv(args.csv)
    store.close()

    print(f"\n[+] {n_new} new IOC(s) saved to {args.db}")
    print(f"[+] Exported {n_json} total IOC(s) to {args.json} and {args.csv}")


if __name__ == "__main__":
    main()
