"""
Batch Onion Scanner
---------------------
Loops through a config-driven seed list (seeds.json) and scans each onion
source for IOCs, with rate limiting between requests.

Rate limiting matters for two reasons:
  1. Onion services are often low-resourced/volunteer-run; hammering them
     with rapid requests is inconsiderate and can get you blocked.
  2. It reduces the chance of tripping abuse detection on services that
     rate-limit or ban aggressive scrapers.

Usage:
    python3 batch_scan.py --seeds seeds.json
    python3 batch_scan.py --seeds seeds.json --delay 10 --jitter 5

Author: Malik Taha
"""

import argparse
import json
import random
import sys
import time
from datetime import datetime, timezone

from extractor import IOCExtractor, IOCStore
from cli import fetch_onion
from tor_connector import rotate_identity


def load_seeds(path: str) -> list:
    with open(path, "r") as f:
        config = json.load(f)
    return config.get("sources", [])


def batch_scan(
    seeds: list,
    db_path: str = "iocs.db",
    delay: float = 8.0,
    jitter: float = 4.0,
    log_path: str = "scan_log.jsonl",
    rotate_every: int = 0,
):
    """
    Scan each seed source in turn, with a randomized delay between requests
    (delay +/- jitter seconds) so request timing isn't perfectly predictable
    and load is spread out. Failures on one source don't stop the batch —
    they're logged and scanning continues.

    rotate_every: if > 0, request a fresh Tor circuit (new exit node) every
    N sources. Set to 1 to rotate before every single request (max privacy/
    anti-blocking, but slower). 0 disables rotation.
    """
    extractor = IOCExtractor()
    store = IOCStore(db_path)
    results_summary = []

    for i, source in enumerate(seeds):
        name = source.get("name", "unnamed")
        url = source.get("url")
        if not url:
            print(f"[!] Skipping '{name}': no url specified")
            continue

        if rotate_every and i % rotate_every == 0:
            print(f"[*] Rotating Tor circuit before source {i + 1}...")
            rotate_identity()

        print(f"\n[{i + 1}/{len(seeds)}] Scanning '{name}' ({url}) ...")
        entry = {
            "name": name,
            "url": url,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": None,
            "ioc_count": 0,
            "error": None,
        }

        try:
            text = fetch_onion(url)
            found = extractor.extract(text, source=url)
            n_new = store.save(found)
            entry["status"] = "success"
            entry["ioc_count"] = len(found)
            print(f"    [+] Found {len(found)} IOC(s), {n_new} new")
        except SystemExit:
            # fetch_onion calls sys.exit on unrecoverable Tor errors — catch
            # it here so one dead source doesn't kill the whole batch
            entry["status"] = "failed"
            entry["error"] = "Tor fetch failed (see console output above)"
            print(f"    [!] Failed to fetch '{name}', continuing with next source")
        except Exception as e:
            entry["status"] = "failed"
            entry["error"] = str(e)
            print(f"    [!] Error scanning '{name}': {e}")

        results_summary.append(entry)

        # append to a persistent log so you have an audit trail of scan runs
        with open(log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")

        # rate limit before the next request (skip after the last one)
        if i < len(seeds) - 1:
            wait = max(0, delay + random.uniform(-jitter, jitter))
            print(f"    [*] Waiting {wait:.1f}s before next source...")
            time.sleep(wait)

    store.export_json("iocs.json")
    store.export_csv("iocs.csv")
    store.close()

    succeeded = sum(1 for r in results_summary if r["status"] == "success")
    failed = sum(1 for r in results_summary if r["status"] == "failed")
    total_iocs = sum(r["ioc_count"] for r in results_summary)

    print(f"\n{'=' * 50}")
    print(f"Batch scan complete: {succeeded} succeeded, {failed} failed")
    print(f"Total IOCs found this run: {total_iocs}")
    print(f"Log appended to: {log_path}")
    print(f"{'=' * 50}")

    return results_summary


def main():
    parser = argparse.ArgumentParser(description="Batch-scan onion sources from a seed list for IOCs.")
    parser.add_argument("--seeds", default="seeds.json", help="Path to seed list JSON (default: seeds.json)")
    parser.add_argument("--db", default="iocs.db", help="SQLite DB path (default: iocs.db)")
    parser.add_argument("--delay", type=float, default=8.0, help="Base delay in seconds between requests (default: 8)")
    parser.add_argument("--jitter", type=float, default=4.0, help="Random +/- jitter added to delay (default: 4)")
    parser.add_argument("--log", default="scan_log.jsonl", help="Path to append scan log entries (default: scan_log.jsonl)")
    parser.add_argument(
        "--rotate-every", type=int, default=0,
        help="Request a fresh Tor circuit every N sources (0 = disabled, 1 = rotate before every request). Requires ControlPort enabled in torrc."
    )
    args = parser.parse_args()

    try:
        seeds = load_seeds(args.seeds)
    except FileNotFoundError:
        print(f"[!] Seed file not found: {args.seeds}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"[!] Invalid JSON in {args.seeds}: {e}")
        sys.exit(1)

    if not seeds:
        print(f"[!] No sources found in {args.seeds}. Add entries to the 'sources' list.")
        sys.exit(1)

    print(f"[*] Loaded {len(seeds)} source(s) from {args.seeds}")
    batch_scan(seeds, db_path=args.db, delay=args.delay, jitter=args.jitter, log_path=args.log, rotate_every=args.rotate_every)


if __name__ == "__main__":
    main()
