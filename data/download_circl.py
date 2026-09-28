"""CIRCL Vulnerability-Lookup "exploited" sightings -- a second exploitation list.

Source: https://vulnerability.circl.lu/api/sighting/?type=exploited  (no auth)

Why this source.  Every sighting carries its own `source` field, so each
report can be traced to where it came from.  That per-report provenance is what
lets an exploitation list be made independent of CISA KEV by construction --
drop the CISA-derived reports -- rather than by assertion.  VulnCheck KEV has
the same property but needs an account token; this does not.

The feed is LIVE and changes daily, so it is snapshotted: raw pages are cached
under cache/circl/, and the classified per-CVE table is committed to
data/vendor/circl_exploited.csv with its hash recorded in DATA_SNAPSHOT.md.
Re-running reads the committed snapshot; pass --refresh to re-pull deliberately.

Run: python data/download_circl.py
"""

import argparse
import json
import re
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd
import requests

ROOT = Path(__file__).resolve().parent.parent
CACHE = ROOT / "cache" / "circl"
VENDOR = ROOT / "data" / "vendor" / "circl_exploited.csv"
URL = "https://vulnerability.circl.lu/api/sighting/"
PER_PAGE = 1000
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)


def fetch_pages(refresh=False):
    """All type=exploited sightings, one cached JSON file per page."""
    CACHE.mkdir(parents=True, exist_ok=True)
    first = requests.get(URL, params={"type": "exploited", "page": 1,
                                      "per_page": PER_PAGE}, timeout=120).json()
    total = first["metadata"]["count"]
    pages = -(-total // PER_PAGE)
    print(f"CIRCL: {total:,} exploited sightings across {pages} pages")
    rows = []
    with requests.Session() as s:
        for p in range(1, pages + 1):
            path = CACHE / f"exploited_p{p:03d}.json"
            if path.exists() and not refresh:
                data = json.loads(path.read_text())
            else:
                for attempt in range(4):
                    r = s.get(URL, params={"type": "exploited", "page": p,
                                           "per_page": PER_PAGE}, timeout=120)
                    if r.status_code == 200:
                        break
                    time.sleep(3 * (attempt + 1))
                r.raise_for_status()
                data = r.json()["data"]
                path.write_text(json.dumps(data))
                time.sleep(0.5)                 # be polite to a free service
            rows += data
            if p % 10 == 0 or p == pages:
                print(f"  page {p}/{pages}")
    return pd.DataFrame(rows)


def classify(source):
    """Map a sighting's `source` to a provenance class.

    ASSUMPTION (not in CSWP 41): the classes below are assigned from the
    source string alone.  The estimand is exploitation IN THE WILD, so:
      cisa        -- derived from CISA KEV; must be excluded for independence
      kev_catalog -- CIRCL's own aggregated KEV catalogue entries.  Checked by
                     hand: entries carry CISA KEV's exact field format
                     ("<name> | Affected: <vendor> / <product>"), so they are
                     at least partly CISA-derived.  EXCLUDED from any list
                     claimed independent of CISA -- this is the silent
                     contamination that would make capture-recapture collapse.
      exploit_db  -- PoC publication, i.e. exploit AVAILABILITY; wrong estimand
      sensor     -- honeypot / scan telemetry (Shadowserver and similar)
      report     -- vendor/CERT advisories, security blogs, news
      social     -- Telegram, X/Twitter, Mastodon, forums
      other      -- anything not matched; reported, not silently dropped
    """
    s = source.strip().lower() if isinstance(source, str) else ""
    host = urlparse(s).netloc if "://" in s else ""
    text = host or s
    if "cisa.gov" in text or "known_exploited" in text or text.startswith("cisa"):
        return "cisa"
    if "known-exploited-vulnerabilities-catalog" in s:
        return "kev_catalog"
    if "exploit-db" in text or "exploitdb" in text:
        return "exploit_db"
    if "shadowserver" in text or "honeypot" in text or "greynoise" in text:
        return "sensor"
    if any(h in text for h in ("t.me", "telegram", "twitter.com", "x.com",
                               "mastodon", "infosec.exchange", "bsky",
                               "reddit.com")):
        return "social"
    if host:
        return "report"
    return "other"


def build(refresh=False):
    raw = fetch_pages(refresh)
    raw["cve"] = raw["vulnerability"].astype(str).str.upper().str.strip()
    raw = raw[raw["cve"].str.match(CVE_RE)]
    raw["date"] = pd.to_datetime(raw["creation_timestamp"], utc=True,
                                 errors="coerce").dt.tz_localize(None)
    raw["cls"] = raw["source"].map(classify)
    return raw[["cve", "date", "cls", "source"]]


def load(refresh=False):
    """Per-sighting table: cve, date, cls, source (from the committed snapshot)."""
    if VENDOR.exists() and not refresh:
        df = pd.read_csv(VENDOR, parse_dates=["date"])
        print(f"CIRCL: {len(df):,} exploited sightings from committed snapshot")
        return df
    df = build(refresh)
    VENDOR.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(VENDOR, index=False)
    print(f"CIRCL: wrote {len(df):,} sightings to {VENDOR.relative_to(ROOT)}"
          " -- update DATA_SNAPSHOT.md hash")
    return df


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--refresh", action="store_true")
    df = load(refresh=ap.parse_args().refresh)
    print("\nsightings by provenance class:")
    print(df["cls"].value_counts().to_string())
    print("\ndistinct CVEs by class:")
    print(df.groupby("cls")["cve"].nunique().to_string())
    print(f"\ndistinct CVEs overall: {df['cve'].nunique():,}")
