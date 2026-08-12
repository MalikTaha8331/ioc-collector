"""
IOC Collector — Local Web UI
------------------------------
A local-only Flask interface for the IOC extraction engine: paste text or a
URL, see extracted IOCs rendered as a case-file ledger, export to CSV/JSON.

This is a LOCAL DEMO TOOL, not meant for public deployment. It intentionally
does not expose onion/Tor fetching over the web interface — batch scanning
and dark web collection remain CLI-only (cli.py --onion, batch_scan.py),
since running an open web-facing fetcher (especially one that can reach
onion services) on public infrastructure is a real operational/legal risk
that a local single-user CLI tool doesn't carry. Run this with:

    python3 app.py

Then open http://127.0.0.1:5000 in your browser.

Author: Malik Taha
"""

from flask import Flask, render_template, request, send_file
import io
import json
import csv as csv_module

from extractor import IOCExtractor
from cli import fetch_url

app = Flask(__name__)

# Holds the most recent scan result in memory so /export/<fmt> can serve it.
# Fine for a local single-user tool; would need real session/DB handling
# for anything multi-user.
_last_scan = {"iocs": [], "source": None}


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html", iocs=None, source=None, error=None)


@app.route("/scan", methods=["POST"])
def scan():
    mode = request.form.get("mode", "text")
    raw_input = request.form.get("input", "").strip()

    if not raw_input:
        return render_template("index.html", iocs=None, source=None,
                                error="Enter some text or a URL first.")

    try:
        if mode == "url":
            if not raw_input.startswith(("http://", "https://")):
                raw_input = "https://" + raw_input
            text = fetch_url(raw_input)
            source = raw_input
        else:
            text = raw_input
            source = "pasted_text"
    except Exception as e:
        return render_template("index.html", iocs=None, source=None,
                                error=f"Couldn't fetch that URL: {e}")

    extractor = IOCExtractor()
    results = extractor.extract(text, source=source)

    # group by type for display
    grouped = {}
    for r in results:
        grouped.setdefault(r.ioc_type, []).append(r.value)

    _last_scan["iocs"] = [r.to_dict() for r in results]
    _last_scan["source"] = source

    return render_template("index.html", iocs=grouped, source=source,
                            total=len(results), error=None)


@app.route("/export/<fmt>")
def export(fmt):
    if not _last_scan["iocs"]:
        return "No scan results to export yet.", 400

    if fmt == "json":
        buf = io.BytesIO(json.dumps(_last_scan["iocs"], indent=2).encode())
        return send_file(buf, mimetype="application/json",
                          as_attachment=True, download_name="iocs.json")

    if fmt == "csv":
        buf = io.StringIO()
        writer = csv_module.DictWriter(buf, fieldnames=["ioc_type", "value", "source", "collected_at"])
        writer.writeheader()
        writer.writerows(_last_scan["iocs"])
        byte_buf = io.BytesIO(buf.getvalue().encode())
        return send_file(byte_buf, mimetype="text/csv",
                          as_attachment=True, download_name="iocs.csv")

    return "Unknown format. Use /export/json or /export/csv.", 400


if __name__ == "__main__":
    print("[*] IOC Collector web UI starting at http://127.0.0.1:5000")
    print("[*] Local use only — do not expose this to the public internet.")
    app.run(debug=True, host="127.0.0.1", port=5000)
