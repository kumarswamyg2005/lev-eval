"""CISA's Known Exploited Vulnerabilities catalog.

The catalog is live and changes several times a week, so the snapshot used for
every published result (catalogVersion 2026.08.25, 1,676 entries) is committed
to data/vendor/ and read from there.  KEV is a US-government work and public
domain, so redistributing it is fine.  Pass --refresh to fetch the live feed
deliberately; that overwrites the vendored copy and invalidates the pinned hash
in DATA_SNAPSHOT.md.

Run: python data/download_kev.py [--refresh]
"""

import argparse
import hashlib
from pathlib import Path

import pandas as pd
import requests

ROOT = Path(__file__).resolve().parent.parent
VENDOR = ROOT / "data" / "vendor" / "known_exploited_vulnerabilities.json"
SHA256 = "4ddd617740b42cec165f6ce7a3dabe52b3935ebc51617e415968538677e3bb79"
URL = ("https://www.cisa.gov/sites/default/files/feeds/"
       "known_exploited_vulnerabilities.json")


def download(refresh=False):
    if refresh or not VENDOR.exists():
        VENDOR.parent.mkdir(parents=True, exist_ok=True)
        r = requests.get(URL, timeout=60)
        r.raise_for_status()
        VENDOR.write_bytes(r.content)
        print(f"KEV: downloaded {len(r.content)/1e6:.1f} MB "
              "-- update DATA_SNAPSHOT.md hash")
        return VENDOR
    got = hashlib.sha256(VENDOR.read_bytes()).hexdigest()
    assert got == SHA256, (f"{VENDOR.name}: SHA-256 {got} does not match the "
                           f"pin {SHA256} in DATA_SNAPSHOT.md")
    return VENDOR


def load(refresh=False):
    """DataFrame with columns cve, kev_date (dateAdded)."""
    df = pd.read_json(download(refresh))
    df = pd.json_normalize(df["vulnerabilities"])[["cveID", "dateAdded"]]
    df.columns = ["cve", "kev_date"]
    df["kev_date"] = pd.to_datetime(df["kev_date"])
    print(f"KEV: {len(df):,} entries, {df.kev_date.min().date()} to "
          f"{df.kev_date.max().date()}")
    return df


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--refresh", action="store_true",
                    help="fetch the live feed and overwrite the pinned copy")
    print(load(refresh=ap.parse_args().refresh).head())
