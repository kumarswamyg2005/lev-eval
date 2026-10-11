"""VulnCheck KEV Community -- reconstructed as a CISA-free exploitation list.

Source: https://api.vulncheck.com/v3/backup/vulncheck-kev
Needs a FREE community token: register at console.vulncheck.com, generate a
token, then   export VULNCHECK_API_TOKEN=<token>   and run this script.

Tested 2026-09-28 against a live community token; schema matched.

VulnCheck KEV is a SUPERSET of CISA KEV as shipped ("encompasses all
vulnerabilities listed in the CISA KEV catalog, plus approximately 80% more"),
so using it raw as a second list makes capture-recapture collapse: the overlap
equals CISA KEV by construction.  The list is therefore rebuilt from its
per-report provenance (the research brief's L2'):

  1. ignore cisa_date_added entirely
  2. drop every vulncheck_reported_exploitation[] report hosted on cisa.gov
  3. ALSO drop every report hosted on shadowserver.org.  VulnCheck's largest
     single source is dashboard.shadowserver.org (401,967 reports), which is
     the same honeypot feed as the SENSOR list: all 969 CIRCL sensor CVEs
     appear in VulnCheck's Shadowserver subset (checked 2026-09-28).  Kept, it
     would make this list a superset of SENSOR -- the CISA trap again.
  4. keep a CVE only if a report survives, or VulnCheck's own honeypot
     canaries saw it (reported_exploited_by_vulncheck_canaries)
  5. its date is the earliest surviving report

First run (2026-09-28): 5,371 records -> 4,815 CVEs.  For 78% of CISA-listed
CVEs the earliest surviving report predates CISA's listing (median 28 days
earlier), so the remaining evidence is not an echo of CISA.

The raw download stays in cache/ (gitignored): VulnCheck's terms do not say
whether it may be redistributed.

When no token is set, load() returns None and the capture-recapture analysis
runs on the lists that need no account.

Run: python data/download_vulncheck.py
"""

import hashlib
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
# Pin from DATA_SNAPSHOT.md.  VulnCheck serves only the current feed, so anyone
# re-downloading with their own token can never match it.  ponytail: a warning,
# not an assert, or the four-list results could not be run by anyone else.
SHA256 = "7163d33d4c4698591535af62b6b08b6784e9df0d2614f9fe9fdb33578402f811"
URL = "https://api.vulncheck.com/v3/backup/vulncheck-kev"
# report hosts that are sensor networks rather than write-ups
SENSOR_HOSTS = ("api.vulncheck.com", "crowdsec", "dshield", "greynoise")


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
        got = hashlib.sha256(CACHE.read_bytes()).hexdigest()
        if got != SHA256:
            print(f"VulnCheck: WARNING {CACHE.name} SHA-256 {got} is not the "
                  f"pinned snapshot {SHA256}; four-list numbers will differ "
                  "from DATA_SNAPSHOT.md and the paper")
        records = json.loads(CACHE.read_text())
    else:
        token = os.environ.get("VULNCHECK_API_TOKEN")
        if not token:
            print("VulnCheck: no VULNCHECK_API_TOKEN set -- skipped "
                  "(free token at console.vulncheck.com)")
            return None
        records = _download(token)

    def independent(url):
        host = urlparse(url or "").netloc.lower()
        return "cisa.gov" not in host and "shadowserver" not in host

    rows, dropped_cisa_only = [], 0
    for rec in records:
        reports = [r for r in rec.get("vulncheck_reported_exploitation") or []
                   if independent(r.get("url"))]
        canary = bool(rec.get("reported_exploited_by_vulncheck_canaries"))
        if not reports and not canary:
            dropped_cisa_only += 1
            continue
        dates = [r.get("date_added") for r in reports if r.get("date_added")]
        first = min(dates) if dates else rec.get("date_added")
        # STRICT: sensor-observed, or reported by at least two independent
        # hosts.  65% of VulnCheck-only CVEs rest on one text report (checked
        # 2026-09-28), so this is the precision check on VulnCheck's weakest
        # entries.
        hosts = {urlparse(r.get("url", "")).netloc.lower() for r in reports}
        sensor = canary or any(k in h for h in hosts for k in SENSOR_HOSTS)
        strict = sensor or len(hosts) >= 2
        for cve in rec.get("cve") or []:
            rows.append({"cve": cve, "date": first, "via_canary": canary,
                         "strict": strict})
    df = pd.DataFrame(rows).drop_duplicates("cve")
    df["date"] = pd.to_datetime(df["date"], utc=True,
                                errors="coerce").dt.tz_localize(None)
    print(f"VulnCheck: {int(df['strict'].sum()):,} of them STRICT "
          "(sensor-observed or >= 2 independent sources)")
    print(f"VulnCheck: {len(records):,} records -> {len(df):,} CVEs in the "
          f"CISA-free list ({dropped_cisa_only:,} had only CISA or Shadowserver evidence)")
    return df


if __name__ == "__main__":
    out = load()
    if out is not None:
        print(out.head())
