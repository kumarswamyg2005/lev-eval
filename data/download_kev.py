"""Download and cache CISA's Known Exploited Vulnerabilities catalog."""

from pathlib import Path

import pandas as pd
import requests

ROOT = Path(__file__).resolve().parent.parent
CACHE = ROOT / "cache" / "known_exploited_vulnerabilities.json"
URL = ("https://www.cisa.gov/sites/default/files/feeds/"
       "known_exploited_vulnerabilities.json")


def download(refresh=False):
    if refresh or not CACHE.exists():
        CACHE.parent.mkdir(parents=True, exist_ok=True)
        r = requests.get(URL, timeout=60)
        r.raise_for_status()
        CACHE.write_bytes(r.content)
        print(f"KEV: downloaded {len(r.content)/1e6:.1f} MB")
    return CACHE


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
    print(load().head())
