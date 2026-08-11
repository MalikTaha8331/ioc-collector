"""
Tor Connectivity Module
-------------------------
Handles fetching pages over the Tor network via a local Tor SOCKS5 proxy.

Requires a running Tor instance (standalone `tor` service, NOT Tor Browser)
listening on 127.0.0.1:9050 (the default). See README for setup instructions.

Author: Malik Taha
"""

import time
import requests


TOR_SOCKS_PROXY = "socks5h://127.0.0.1:9050"  # socks5h = DNS resolved via Tor too (important for .onion)
TOR_CONTROL_PORT = 9051  # requires ControlPort + CookieAuthentication enabled in torrc — see README

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gecko/20100101 Firefox/128.0",
}


class TorConnectionError(Exception):
    """Raised when we can't reach the Tor SOCKS proxy at all."""
    pass


def get_tor_session() -> requests.Session:
    """Return a requests.Session configured to route through the local Tor proxy."""
    session = requests.Session()
    session.proxies = {
        "http": TOR_SOCKS_PROXY,
        "https": TOR_SOCKS_PROXY,
    }
    session.headers.update(DEFAULT_HEADERS)
    return session


def check_tor_connectivity(timeout: int = 15) -> bool:
    """
    Verify Tor is running and we can actually reach the Tor network.
    Uses the Tor Project's own check endpoint, which confirms whether
    the requesting IP is a Tor exit node.
    """
    session = get_tor_session()
    try:
        resp = session.get("https://check.torproject.org/api/ip", timeout=timeout)
        data = resp.json()
        return data.get("IsTor", False)
    except requests.exceptions.RequestException as e:
        raise TorConnectionError(
            f"Could not reach Tor SOCKS proxy at {TOR_SOCKS_PROXY}. "
            f"Is the standalone Tor service running? Original error: {e}"
        )


def fetch_onion(url: str, retries: int = 3, delay: float = 2.0, timeout: int = 30) -> str:
    """
    Fetch a .onion URL through Tor, with retries (onion services are
    frequently slow or temporarily unreachable, so this is expected to be
    much less reliable than clearnet fetching).

    Returns the raw response text. Raises TorConnectionError if all
    retries are exhausted.
    """
    session = get_tor_session()
    last_error = None

    for attempt in range(1, retries + 1):
        try:
            resp = session.get(url, timeout=timeout)
            resp.raise_for_status()
            return resp.text
        except requests.exceptions.RequestException as e:
            last_error = e
            if attempt < retries:
                time.sleep(delay)

    raise TorConnectionError(
        f"Failed to fetch {url} after {retries} attempts. Last error: {last_error}"
    )


def rotate_identity(control_port: int = TOR_CONTROL_PORT, wait_for_new_circuit: bool = True) -> bool:
    """
    Request a fresh Tor circuit (new exit node / new identity) via the
    control port's NEWNYM signal. Useful between batch requests to avoid
    per-IP rate limiting or blocking on onion services that track exit
    node IPs.

    Requires Tor's control port to be enabled with cookie authentication
    (ControlPort 9051 + CookieAuthentication 1 in torrc — see README).

    Returns True on success, False if the control port isn't reachable
    (in which case scanning can continue without rotation — it's a nice-to-
    have, not a hard requirement).
    """
    try:
        from stem import Signal
        from stem.control import Controller
    except ImportError:
        print("[!] 'stem' package not installed — skipping circuit rotation. Run: pip install stem")
        return False

    try:
        with Controller.from_port(port=control_port) as controller:
            controller.authenticate()  # uses cookie auth automatically if enabled
            if wait_for_new_circuit and not controller.is_newnym_available():
                # Tor rate-limits how often NEWNYM can be requested (roughly
                # every 10s) — if we're not allowed yet, wait for it rather
                # than silently no-op.
                wait_time = controller.get_newnym_wait()
                if wait_time > 0:
                    time.sleep(wait_time)
            controller.signal(Signal.NEWNYM)
            return True
    except Exception as e:
        print(f"[!] Could not rotate Tor identity via control port {control_port}: {e}")
        print("    (Is ControlPort 9051 + CookieAuthentication 1 set in torrc? See README.)")
        return False


if __name__ == "__main__":
    print("[*] Checking Tor connectivity...")
    try:
        is_tor = check_tor_connectivity()
        if is_tor:
            print("[+] Successfully connected through Tor.")
        else:
            print("[!] Connected, but check.torproject.org says this is NOT a Tor exit IP.")
    except TorConnectionError as e:
        print(f"[!] {e}")
        raise SystemExit(1)

    # Well-known, safe public onion services to prove end-to-end .onion fetching works
    test_sites = {
        "ProPublica (news, SecureDrop)": "http://p53lf57qovyuvwsc6xnrppyply3vtqm7l6pcobkmyqsiofyeznfu5uqd.onion/",
        "DuckDuckGo (search)": "http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/",
    }

    for name, onion_url in test_sites.items():
        print(f"\n[*] Fetching {name} ...")
        try:
            html = fetch_onion(onion_url)
            print(f"[+] Success — received {len(html)} bytes")
        except TorConnectionError as e:
            print(f"[!] Failed: {e}")
