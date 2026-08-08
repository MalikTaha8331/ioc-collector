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

## Phase 2 (planned): Tor / dark web collection

- `stem` + Tor SOCKS5 proxy for onion source fetching
- Config-driven seed list of known onion paste/forum sources
- Rate limiting + circuit rotation
- Passive OSINT only — no interaction with marketplaces or illegal content

## Project structure

```
ioc_collector/
├── extractor.py       # core regex + refang + noise-filtering + storage engine
├── cli.py              # command-line interface
├── examples/
│   └── sample_report.txt
├── requirements.txt
└── README.md
```

