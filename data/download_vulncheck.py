"""VulnCheck KEV Community -- reconstructed as a CISA-free exploitation list.

Source: https://api.vulncheck.com/v3/backup/vulncheck-kev
Needs a FREE community token: register at console.vulncheck.com, generate a
token, then   export VULNCHECK_API_TOKEN=<token>   and run this script.

UNTESTED: written against VulnCheck's published schema, but no token was
available when it was written, so it has never run end to end.  Check the first
run's printed counts against the dashboard before using the output.

VulnCheck KEV is a SUPERSET of CISA KEV as shipped ("encompasses all
vulnerabilities listed in the CISA KEV catalog, plus approximately 80% more"),
so using it raw as a second list makes capture-recapture collapse: the overlap
equals CISA KEV by construction.  The list is therefore rebuilt from its
per-report provenance (the research brief's L2'):

  1. ignore cisa_date_added entirely
  2. drop every vulncheck_reported_exploitation[] report hosted on cisa.gov
  3. keep a CVE only if a report survives, or VulnCheck's own honeypot
     canaries saw it (reported_exploited_by_vulncheck_canaries)
  4. its date is the earliest surviving report

When no token is set, load() returns None and the capture-recapture analysis
runs on the lists that need no account.

Run: python data/download_vulncheck.py
"""

import io
import json
import os
import zipfile
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd
import requests

ROOT = Path(__file__).resolve().parent.parent
CACHE = ROOT / "cache" / "vulncheck_kev.json"
URL = "https://api.vulncheck.com/v3/backup/vulncheck-kev"


def _download(token):
    r = requests.get(URL, headers={"Authorization": f"Bearer {token}",
                                   "Accept": "application/json"}, timeout=120)
    r.raise_for_status()
    link = r.json()["data"][0]["url"]          # short-lived signed link
    z = requests.get(link, timeout=600)
    z.raise_for_status()
    with zipfile.ZipFile(io.BytesIO(z.content)) as zf:
        name = next(n for n in zf.namelist() if n.endswith(".json"))
        records = json.loads(zf.read(name))
    CACHE.parent.mkdir(parents=True, exist_ok=True)
    CACHE.write_text(json.dumps(records))
    print(f"VulnCheck: downloaded {len(records):,} KEV records")
    return records


def load():
    """CISA-free VulnCheck list: cve, date, via_canary.  None without a token."""
    if CACHE.exists():
        records = json.loads(CACHE.read_text())
    else:
        token = os.environ.get("VULNCHECK_API_TOKEN")
        if not token:
            print("VulnCheck: no VULNCHECK_API_TOKEN set -- skipped "
                  "(free token at console.vulncheck.com)")
            return None
        records = _download(token)

    rows, dropped_cisa_only = [], 0
    for rec in records:
        reports = [r for r in rec.get("vulncheck_reported_exploitation") or []
                   if "cisa.gov" not in urlparse(r.get("url", "")).netloc]
        canary = bool(rec.get("reported_exploited_by_vulncheck_canaries"))
        if not reports and not canary:
            dropped_cisa_only += 1
            continue
        dates = [r.get("date_added") for r in reports if r.get("date_added")]
        first = min(dates) if dates else rec.get("date_added")
        for cve in rec.get("cve") or []:
            rows.append({"cve": cve, "date": first, "via_canary": canary})
    df = pd.DataFrame(rows).drop_duplicates("cve")
    df["date"] = pd.to_datetime(df["date"], utc=True,
                                errors="coerce").dt.tz_localize(None)
    print(f"VulnCheck: {len(records):,} records -> {len(df):,} CVEs in the "
          f"CISA-free list ({dropped_cisa_only:,} had only CISA-sourced evidence)")
    return df


if __name__ == "__main__":
    out = load()
    if out is not None:
        print(out.head())
