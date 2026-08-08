"""
IOC Extraction Engine
----------------------
Extracts Indicators of Compromise (IPs, domains, hashes, CVEs, emails,
crypto wallet addresses) from raw text. Handles "defanged" IOCs commonly
used in threat intel writeups (e.g. hxxp://, 1.2.3[.]4, evil[.]com).

Author: Malik Taha
"""

import re
import json
import sqlite3
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Set


# ---------------------------------------------------------------------------
# Refanging: threat intel writeups deliberately "defang" IOCs so they aren't
# clickable/executable by accident. We need to reverse that before matching.
# ---------------------------------------------------------------------------

def refang(text: str) -> str:
    """Convert defanged IOCs back to their normal form for extraction."""
    out = text

    # Strip markdown-style link syntax "[visible text](url)" down to plain
    # "visible text url" — trafilatura (and other extractors) emit markdown
    # links, and the literal brackets/parens otherwise pollute domain matches
    # (e.g. "[www.jetbrains.com](https://www.jetbrains.com)" showing up as
    # a single garbled "domain").
    out = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"\1 \2", out)

    # Common defang patterns, order matters
    out = re.sub(r"hxxp(s)?://", lambda m: f"http{m.group(1) or ''}://", out, flags=re.IGNORECASE)
    out = re.sub(r"hxxp(s)?\[://\]", lambda m: f"http{m.group(1) or ''}://", out, flags=re.IGNORECASE)
    out = out.replace("[.]", ".").replace("(.)", ".").replace("[dot]", ".").replace("(dot)", ".")
    out = out.replace("[:]", ":").replace("[at]", "@").replace("(at)", "@")
    out = re.sub(r"\[\.\]", ".", out)
    return out


# ---------------------------------------------------------------------------
# Regex patterns for each IOC type
# ---------------------------------------------------------------------------

PATTERNS = {
    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    ),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"(?:[a-zA-Z]{2,24})\b"
    ),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "email": re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"),
    "btc_wallet": re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b"),
    "xmr_wallet": re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b"),
    "url": re.compile(r"\bhttps?://[^\s\"'<>\)\]]+"),
}

# Domains that are extremely common false positives from the generic domain
# regex (file extensions, doc references, etc.) — filtered out post-match.
DOMAIN_FALSE_POSITIVE_SUFFIXES = {
    ".png", ".jpg", ".jpeg", ".gif", ".exe", ".dll", ".py", ".js",
    ".txt", ".pdf", ".zip", ".rar", ".doc", ".docx", ".xls", ".xlsx",
    ".php", ".asp", ".aspx", ".html", ".htm", ".json", ".xml", ".css",
}

# Common infra/CDN/social/analytics domains that show up on nearly every
# webpage's footer, nav, share buttons, or tracking scripts. These are
# almost never genuine IOCs and just add noise — filtered out by default.
NOISE_DOMAINS = {
    "google.com", "www.google.com", "googleapis.com", "gstatic.com",
    "googletagmanager.com", "google-analytics.com", "googlesyndication.com",
    "facebook.com", "www.facebook.com", "fb.com", "instagram.com",
    "twitter.com", "x.com", "linkedin.com", "www.linkedin.com",
    "youtube.com", "www.youtube.com", "youtu.be",
    "cloudflare.com", "cloudflareinsights.com", "jsdelivr.net",
    "cdnjs.cloudflare.com", "bootstrapcdn.com", "fontawesome.com",
    "fonts.googleapis.com", "fonts.gstatic.com",
    "w3.org", "schema.org", "creativecommons.org",
    "microsoft.com", "www.microsoft.com", "live.com", "office.com",
    "apple.com", "www.apple.com",
    "usa.gov", "wikipedia.org", "en.wikipedia.org",
    "addthis.com", "sharethis.com", "hotjar.com", "doubleclick.net",
    # common .gov/vendor domains that show up as citations/links in
    # advisories and threat intel writeups, not as actual IOCs
    "cisa.gov", "dhs.gov", "us-cert.gov", "us-cert.cisa.gov", "ic3.gov",
    "nist.gov", "nvd.nist.gov", "mitre.org", "attack.mitre.org",
    "fbi.gov", "nsa.gov", "cert.pl", "ncsc.gov.uk",
}

# Second-level-domain fragments that are common technical/OS terms, not
# real domain names. These slip past TLD validation when they happen to be
# followed by a real-but-obscure ccTLD (e.g. "sam.sa" -> "sa" is a genuine
# Saudi Arabia ccTLD, but "sam" here is really "SAM" the Windows registry
# hive, mangled into domain-shaped text by source formatting).
SLD_FALSE_POSITIVES = {
    "sam", "sy", "se", "sys", "reg", "tmp", "bin", "src", "lib", "etc",
    "var", "usr", "opt", "log", "conf", "cfg", "dev", "proc", "root",
}

# Valid TLDs (gTLDs + ccTLDs). The generic domain regex only accepts a match
# whose final label is in this set — this is what stops file extensions,
# config keys, and code identifiers (.log, .conf, .sys, .server, .audit)
# from being mistaken for real domains.
VALID_TLDS = {
    # generic
    "com", "net", "org", "edu", "gov", "mil", "int", "info", "biz", "name",
    "pro", "museum", "coop", "aero", "jobs", "mobi", "travel", "tel", "asia",
    "cat", "xxx", "post",
    # popular new gTLDs commonly seen in IOCs/infra
    "io", "ai", "dev", "app", "tech", "cloud", "online", "site", "xyz",
    "club", "shop", "store", "blog", "news", "live", "world", "email",
    "top", "vip", "icu", "work", "click", "link", "download", "win",
    "bid", "loan", "men", "party", "review", "science", "stream", "trade",
    "date", "faith", "gq", "cf", "ml", "ga", "tk", "wang", "xin",
    # commonly used short ccTLDs (used as branding domains: bit.ly-style)
    "cc", "tv", "co", "me", "to", "sh", "gg", "gl", "ly",
    # ISO 3166 ccTLDs (all countries)
    "ac", "ad", "ae", "af", "ag", "ai", "al", "am", "ao", "aq", "ar", "as",
    "at", "au", "aw", "ax", "az", "ba", "bb", "bd", "be", "bf", "bg", "bh",
    "bi", "bj", "bm", "bn", "bo", "br", "bs", "bt", "bv", "bw", "by", "bz",
    "ca", "cd", "cf", "cg", "ch", "ci", "ck", "cl", "cm", "cn", "co", "cr",
    "cu", "cv", "cw", "cx", "cy", "cz", "de", "dj", "dk", "dm", "do", "dz",
    "ec", "ee", "eg", "eh", "er", "es", "et", "eu", "fi", "fj", "fk", "fm",
    "fo", "fr", "ga", "gd", "ge", "gf", "gh", "gi", "gl", "gm", "gn", "gp",
    "gq", "gr", "gs", "gt", "gu", "gw", "gy", "hk", "hm", "hn", "hr", "ht",
    "hu", "id", "ie", "il", "im", "in", "io", "iq", "ir", "is", "it", "je",
    "jm", "jo", "jp", "ke", "kg", "kh", "ki", "km", "kn", "kp", "kr", "kw",
    "ky", "kz", "la", "lb", "lc", "li", "lk", "lr", "ls", "lt", "lu", "lv",
    "ly", "ma", "mc", "md", "me", "mg", "mh", "mk", "ml", "mm", "mn", "mo",
    "mp", "mq", "mr", "ms", "mt", "mu", "mv", "mw", "mx", "my", "mz", "na",
    "nc", "ne", "nf", "ng", "ni", "nl", "no", "np", "nr", "nu", "nz", "om",
    "pa", "pe", "pf", "pg", "ph", "pk", "pl", "pm", "pn", "pr", "ps", "pt",
    "pw", "py", "qa", "re", "ro", "rs", "ru", "rw", "sa", "sb", "sc", "sd",
    "se", "sg", "sh", "si", "sj", "sk", "sl", "sm", "sn", "so", "sr", "ss",
    "st", "su", "sv", "sx", "sy", "sz", "tc", "td", "tf", "tg", "th", "tj",
    "tk", "tl", "tm", "tn", "to", "tr", "tt", "tv", "tw", "tz", "ua", "ug",
    "uk", "us", "uy", "uz", "va", "vc", "ve", "vg", "vi", "vn", "vu", "wf",
    "ws", "ye", "yt", "za", "zm", "zw",
}


@dataclass
class IOCResult:
    ioc_type: str
    value: str
    source: str
    collected_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict:
        return asdict(self)


class IOCExtractor:
    def __init__(self, extra_noise_domains: Set[str] = None):
        self._seen: Set[str] = set()
        # allow callers to extend the noise list (e.g. their own site domains)
        self.noise_domains = set(NOISE_DOMAINS)
        if extra_noise_domains:
            self.noise_domains |= {d.lower() for d in extra_noise_domains}

    def _is_noise_domain(self, domain: str) -> bool:
        domain = domain.lower()
        if domain in self.noise_domains:
            return True
        # catch subdomains of noise domains, e.g. "mail.google.com" -> "google.com"
        parts = domain.split(".")
        for i in range(1, len(parts) - 1):
            if ".".join(parts[i:]) in self.noise_domains:
                return True
        return False

    def extract(self, text: str, source: str = "unknown") -> List[IOCResult]:
        """Run all patterns against refanged text and return deduped IOCs.

        If `source` is a URL, its own hostname is automatically excluded from
        results (a page's own domain isn't an IOC).
        """
        clean_text = refang(text)
        results: List[IOCResult] = []

        # If source is a URL, pull its hostname so we can exclude self-references
        from urllib.parse import urlparse
        source_host = urlparse(source).hostname
        source_host = source_host.lower() if source_host else None

        # URLs first, so we can pull hostnames from them cleanly
        urls = PATTERNS["url"].findall(clean_text)
        for url in urls:
            host = urlparse(url).hostname
            host_lower = host.lower() if host else None

            # skip URLs pointing back at the source page's own domain
            if host_lower and source_host and host_lower == source_host:
                continue
            if host_lower and self._is_noise_domain(host_lower):
                continue

            key = f"url:{url}"
            if key not in self._seen:
                self._seen.add(key)
                results.append(IOCResult("url", url, source))

            # also register the hostname as a domain/ip IOC
            if host:
                if PATTERNS["ipv4"].fullmatch(host):
                    host_type = "ipv4"
                else:
                    host_type = "domain"
                    tld = host.rsplit(".", 1)[-1].lower()
                    if tld not in VALID_TLDS:
                        host = None  # skip registering a bogus-TLD hostname
                if host:
                    host_key = f"{host_type}:{host.lower()}"
                    if host_key not in self._seen:
                        self._seen.add(host_key)
                        results.append(IOCResult(host_type, host, source))

        # Collect email local-parts so we don't misfire the domain regex on them
        # (e.g. "first.last.name@domain.com" -> "first.last.name" looks domain-shaped)
        email_local_parts = {e.split("@")[0].lower() for e in PATTERNS["email"].findall(clean_text)}

        for ioc_type, pattern in PATTERNS.items():
            if ioc_type == "url":
                continue
            for match in pattern.findall(clean_text):
                value = match if isinstance(match, str) else match[0]

                if ioc_type == "domain":
                    if any(value.lower().endswith(suf) for suf in DOMAIN_FALSE_POSITIVE_SUFFIXES):
                        continue
                    # skip if it's actually an IP (domain regex can false-match)
                    if PATTERNS["ipv4"].fullmatch(value):
                        continue
                    # skip if it's actually the local-part of an email address
                    if value.lower() in email_local_parts:
                        continue
                    # skip the source page's own domain
                    if source_host and value.lower() == source_host:
                        continue
                    # skip known infra/CDN/social noise domains
                    if self._is_noise_domain(value):
                        continue
                    # skip if the last label isn't a real TLD (kills config
                    # paths, file extensions, class names like ".sys", ".log",
                    # ".conf", "MSSQLSERVER", "ACTIVITIES.AUDIT", etc.)
                    tld = value.rsplit(".", 1)[-1].lower()
                    if tld not in VALID_TLDS:
                        continue
                    # skip if the SLD is a known OS/tech term mistakenly
                    # paired with an obscure-but-real ccTLD (e.g. "sam.sa")
                    sld = value.split(".")[0].lower()
                    if sld in SLD_FALSE_POSITIVES:
                        continue

                if ioc_type == "email":
                    email_domain = value.split("@")[-1].lower()
                    if self._is_noise_domain(email_domain):
                        continue

                key = f"{ioc_type}:{value.lower()}"
                if key in self._seen:
                    continue
                self._seen.add(key)
                results.append(IOCResult(ioc_type, value, source))

        return results

    def reset_dedup(self):
        """Call between unrelated documents if you want per-doc dedup instead of global."""
        self._seen.clear()


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------

class IOCStore:
    def __init__(self, db_path: str = "iocs.db"):
        self.conn = sqlite3.connect(db_path)
        self._init_schema()

    def _init_schema(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ioc_type TEXT NOT NULL,
                value TEXT NOT NULL,
                source TEXT NOT NULL,
                collected_at TEXT NOT NULL,
                UNIQUE(ioc_type, value, source)
            )
        """)
        self.conn.commit()

    def save(self, iocs: List[IOCResult]) -> int:
        """Insert IOCs, ignoring duplicates. Returns count of new rows inserted."""
        cur = self.conn.cursor()
        inserted = 0
        for ioc in iocs:
            try:
                cur.execute(
                    "INSERT INTO iocs (ioc_type, value, source, collected_at) VALUES (?, ?, ?, ?)",
                    (ioc.ioc_type, ioc.value, ioc.source, ioc.collected_at),
                )
                inserted += 1
            except sqlite3.IntegrityError:
                pass  # duplicate, skip
        self.conn.commit()
        return inserted

    def export_json(self, path: str):
        cur = self.conn.execute("SELECT ioc_type, value, source, collected_at FROM iocs")
        rows = [
            {"ioc_type": r[0], "value": r[1], "source": r[2], "collected_at": r[3]}
            for r in cur.fetchall()
        ]
        with open(path, "w") as f:
            json.dump(rows, f, indent=2)
        return len(rows)

    def export_csv(self, path: str):
        import csv
        cur = self.conn.execute("SELECT ioc_type, value, source, collected_at FROM iocs")
        rows = cur.fetchall()
        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["ioc_type", "value", "source", "collected_at"])
            writer.writerows(rows)
        return len(rows)

    def close(self):
        self.conn.close()


if __name__ == "__main__":
    # Quick smoke test with a sample defanged threat intel snippet
    sample_text = """
    The malware beacons out to hxxp://185[.]220[.]101[.]45/gate.php
    and drops a payload with hash 44d88612fea8a8f36de82e1278abb02f
    (MD5). Full SHA256: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0a
    It also contacts evil-c2[.]example[.]com and references CVE-2023-12345.
    Attacker contact: badactor[at]protonmail[.]com
    BTC wallet observed: bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh
    """
    extractor = IOCExtractor()
    found = extractor.extract(sample_text, source="test_sample")
    for f in found:
        print(f.to_dict())

    store = IOCStore("/home/claude/ioc_collector/iocs.db")
    n = store.save(found)
    print(f"\nSaved {n} new IOCs to database.")
    store.close()
