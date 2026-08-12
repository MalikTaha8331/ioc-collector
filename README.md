# IOC Collector

A modular tool to extract, deduplicate, and store Indicators of Compromise
(IPs, domains, URLs, hashes, CVEs, emails, crypto wallet addresses) from
threat intel reports, blog posts, and (phase 2) dark web sources via Tor.

## Phase 1 (current): Clearnet extraction engine

- Handles **defanged IOCs** (`hxxp://`, `1.2.3[.]4`, `evil[.]com`, `user[at]mail.com`)
- Extracts: IPv4, domains, URLs (+ auto hostname), MD5/SHA1/SHA256, CVEs, emails, BTC/XMR wallets
- **Noise filtering**: TLD validation (rejects file extensions/config paths
  masquerading as domains, e.g. `httpd.conf`, `RTCore64.sys`), an SLD
  blocklist for OS/technical terms mistaken for domains, a curated noise-domain
  list (CDNs, social media, common .gov citation domains), and automatic
  exclusion of the source page's own domain
- Uses `trafilatura` for proper article-content extraction, so sidebar/nav/ad
  content doesn't leak false-positive IOCs into results
- Dedup + SQLite storage, JSON/CSV export

### Usage

```bash
pip install -r requirements.txt

# Scan a live URL
python3 cli.py --url https://example.com/threat-report

# Scan a local file
python3 cli.py --file report.txt

# Scan raw text
python3 cli.py --text "hxxp://evil[.]com beacon, hash 44d88612fea8a8f36de82e1278abb02f"

# Disable noise filtering (see everything the regex catches, unfiltered)
python3 cli.py --url https://example.com --include-noise
```

Outputs: `iocs.db` (SQLite), `iocs.json`, `iocs.csv`

### Validation

Tested against CISA Advisory [AA23-347A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a)
(Russian SVR/APT29 exploitation of JetBrains TeamCity, CVE-2023-42793) — a
real, currently-active nation-state threat advisory. The extractor correctly
identified all 28 malware hashes, 3 C2 IPs, 2 disguised C2 domains, and the
CVE, while filtering out unrelated citation/reference links and config-file
false positives.

## Phase 2 (current): Tor / dark web collection

- `stem` + Tor SOCKS5 proxy (`tor_connector.py`) for onion source fetching, with retries
- Same trafilatura + noise-filtering extraction pipeline as Phase 1, applied to onion pages
- **Batch scanning** (`batch_scan.py`) — config-driven seed list (`seeds.json`), rate limiting
  with randomized jitter between requests, and failure resilience (one dead source doesn't
  stop the batch)
- **Circuit rotation** — optional fresh Tor identity (new exit node) every N requests via
  the control port's NEWNYM signal, to avoid per-IP rate limiting/blocking on onion services
- Persistent scan audit log (`scan_log.jsonl`)
- Passive OSINT only — no interaction with marketplaces or illegal content

### Tor setup

1. Install the standalone Tor service (Expert Bundle from torproject.org — not Tor Browser)
2. Add to `torrc`:
   ```
   ControlPort 9051
   CookieAuthentication 1
   ```
3. Run `tor.exe` and wait for `Bootstrapped 100% (done)`
4. `pip install -r requirements.txt`
5. Verify connectivity: `python tor_connector.py`

### Usage

```bash
# Single onion source
python cli.py --onion http://exampleonionaddress.onion/

# Batch scan from seed list
copy seeds.example.json seeds.json   # then edit seeds.json with real sources
python batch_scan.py --seeds seeds.json

# With circuit rotation every request
python batch_scan.py --seeds seeds.json --rotate-every 1

# Custom rate limiting
python batch_scan.py --seeds seeds.json --delay 15 --jitter 5
```

**On sourcing seed targets:** populate `seeds.json` with sources from your own legitimate
research — e.g. known ransomware leak-site addresses from public trackers like
[ransomware.live](https://www.ransomware.live), which publishes known group infrastructure
for exactly this kind of defensive monitoring use case.

## Web UI (local demo)

A local-only Flask interface for pasting text or a URL and viewing extracted
IOCs in a browser, with JSON/CSV export. Same extraction engine and noise
filtering as the CLI.

```bash
pip install -r requirements.txt
python3 app.py
```

Open `http://127.0.0.1:5000`.

**This is a local demo tool, not meant for public deployment.** It
intentionally does not expose onion/Tor fetching over the web — dark web
collection and batch scanning stay CLI-only (`cli.py --onion`,
`batch_scan.py`). Running an open web-facing fetcher that can reach onion
services is a meaningfully different risk than a local single-user CLI tool,
so that capability is deliberately kept off any interface meant to be shared
or exposed.

## Project structure

```
ioc_collector/
├── extractor.py         # core regex + refang + noise-filtering + storage engine
├── cli.py                # command-line interface (clearnet + single onion fetch)
├── tor_connector.py      # Tor SOCKS5 connectivity + circuit rotation
├── batch_scan.py         # batch onion scanning with rate limiting
├── app.py                # local Flask web UI
├── templates/index.html
├── static/style.css
├── seeds.example.json    # template for seeds.json (your real source list, gitignored)
├── examples/
│   └── sample_report.txt
├── requirements.txt
└── README.md
```

