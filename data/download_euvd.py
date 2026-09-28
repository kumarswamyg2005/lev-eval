"""ENISA EUVD known-exploited dump -- source of the EU KEV list.

Source: https://euvdservices.enisa.europa.eu/api/kev/dump  (no auth)

The dump is a CONSOLIDATION of CISA KEV and ENISA's own EU KEV, but each entry
names its sources ("cisa_kev", "eukev_kev").  Only entries carrying
"eukev_kev" form the EU list; the CISA half is ignored.  Checked 2026-09-28:
66 EU KEV entries, 55 of which CISA also lists, so this is a small and heavily
overlapping list -- useful as a third list, weak on its own.

The feed is live, so the dump is committed to data/vendor/euvd_kev.json (~250
KB) and read from there; --refresh re-pulls it deliberately.

Run: python data/download_euvd.py
"""

import argparse
import json
from pathlib import Path

import pandas as pd
import requests

ROOT = Path(__file__).resolve().parent.parent
VENDOR = ROOT / "data" / "vendor" / "euvd_kev.json"
URL = "https://euvdservices.enisa.europa.eu/api/kev/dump"


def load(refresh=False):
    """EU KEV list: cve, date (dateAdded), also_cisa."""
    if refresh or not VENDOR.exists():
        r = requests.get(URL, timeout=120)
        r.raise_for_status()
        VENDOR.parent.mkdir(parents=True, exist_ok=True)
        VENDOR.write_bytes(r.content)
        print(f"EUVD: downloaded {len(r.content) / 1e3:.0f} KB "
              "-- update DATA_SNAPSHOT.md hash")
    rows = json.loads(VENDOR.read_text())
    eu = [{"cve": x["cveId"], "date": x.get("dateAdded"),
           "also_cisa": "cisa_kev" in x.get("sources", [])}
          for x in rows if "eukev_kev" in x.get("sources", [])]
    df = pd.DataFrame(eu)
    df["date"] = pd.to_datetime(df["date"], errors="coerce")
    print(f"EUVD: {len(rows):,} consolidated entries, {len(df)} on EU KEV "
          f"({int(df['also_cisa'].sum())} also on CISA KEV)")
    return df


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--refresh", action="store_true")
    print(load(refresh=ap.parse_args().refresh).head())
