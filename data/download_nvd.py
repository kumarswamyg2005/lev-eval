"""CVE metadata (CVSS, CWE, vendor/product) for analysis/top_bucket.py.

Source: the CVE Program's cvelistV5 bulk release, NOT the NVD API.  The API
serves ~10 MB per 2000-record page at roughly 75 KB/s, which works out to
~2.7 hours for the corpus we need; the bulk zip is one 586 MB request.  This
is the upstream record NVD itself enriches, so CVSS/CWE/affected-product come
from the same CNA data, though NVD's CPE-derived vendor strings are normalized
and these are not (see the assumption note in `_affected`).

Run: python data/download_nvd.py
"""

import argparse
import hashlib
import io
import json
import re
import sys
import zipfile
from pathlib import Path

import pandas as pd
import requests

ROOT = Path(__file__).resolve().parent.parent
CACHE = ROOT / "cache"
ZIP = CACHE / "cvelist_all.zip"
INNER = CACHE / "cvelist_cves.zip"   # the release asset is a zip containing a zip
# Pinned release, not releases/latest: the CVE list changes hourly, so "latest"
# silently moves the data under a published result.  Recorded in DATA_SNAPSHOT.md.
TAG = "cve_2026-08-25_1700Z"
ASSET = "2026-08-25_all_CVEs_at_midnight.zip.zip"
URL = (f"https://github.com/CVEProject/cvelistV5/releases/download/{TAG}/{ASSET}")
SHA256 = "87ca8c2c259aeed76d8400b7455a2a34a6f0543562f269fd4826a24fa351e823"

MIN_YEAR = 2022      # cohort CVE IDs are 2022 or later; skip the rest


def _verify(path):
    with open(path, "rb") as fh:
        got = hashlib.file_digest(fh, "sha256").hexdigest()
    assert got == SHA256, (f"{path.name}: SHA-256 {got} does not match the pin "
                           f"{SHA256} (release {TAG}) in DATA_SNAPSHOT.md")


def download(refresh=False):
    """The pinned release asset.  refresh=True re-downloads the SAME tag."""
    if ZIP.exists() and not refresh:
        _verify(ZIP)
        return ZIP
    CACHE.mkdir(parents=True, exist_ok=True)
    print(f"cvelist: downloading {ASSET} (~586 MB, release {TAG})")
    with requests.get(URL, stream=True, timeout=1800) as r:
        r.raise_for_status()
        done = 0
        with open(ZIP, "wb") as fh:
            for chunk in r.iter_content(1 << 22):
                fh.write(chunk)
                done += len(chunk)
                print(f"  {done / 1e6:,.0f} MB", end="\r", flush=True)
    print()
    _verify(ZIP)
    return ZIP


def _cvss(containers):
    """CVSS v3.1 base score, falling back to v3.0, from CNA then ADP."""
    blocks = [containers.get("cna", {})] + list(containers.get("adp", []))
    for block in blocks:
        for metric in block.get("metrics", []):
            for key in ("cvssV3_1", "cvssV3_0"):
                if key in metric:
                    d = metric[key]
                    return d.get("baseScore"), d.get("baseSeverity")
    return None, None


def _cwe(containers):
    blocks = [containers.get("cna", {})] + list(containers.get("adp", []))
    for block in blocks:
        for pt in block.get("problemTypes", []):
            for d in pt.get("descriptions", []):
                if d.get("cweId"):
                    return d["cweId"]
    return None


def _affected(containers):
    """First (vendor, product) listed.

    ASSUMPTION (not in CSWP 41): a CVE affecting several products is attributed
    to the first one the CNA lists, and vendor strings are free text here --
    "Microsoft", "microsoft" and "Microsoft Corporation" are distinct values.
    Vendor counts below are therefore a lower bound per vendor.
    """
    for a in containers.get("cna", {}).get("affected", []):
        v, p = a.get("vendor"), a.get("product")
        if v and v != "n/a":
            return v.strip().lower(), (p or "").strip().lower() or None
    return None, None


def load(refresh=False):
    """DataFrame: cve, published, cvss3, severity, vendor, product, cwe, state."""
    cache = CACHE / f"cvelist_{MIN_YEAR}plus.pkl"
    if cache.exists() and not refresh:
        print(f"cvelist: loading cached {cache.name}")
        return pd.read_pickle(cache)

    outer = download(refresh)
    # The release asset ("..._at_midnight.zip.zip") wraps a single cves.zip.
    if not INNER.exists() or refresh:
        with zipfile.ZipFile(outer) as z:
            inner_name = next(n for n in z.namelist() if n.endswith(".zip"))
            print(f"cvelist: unwrapping {inner_name}")
            with z.open(inner_name) as src, open(INNER, "wb") as dst:
                while chunk := src.read(1 << 22):
                    dst.write(chunk)

    rows = []
    with zipfile.ZipFile(INNER) as z:
        def year_of(name):
            m = re.search(r"CVE-(\d{4})-", name)
            return int(m.group(1)) if m else 0
        names = [n for n in z.namelist()
                 if n.endswith(".json") and year_of(n) >= MIN_YEAR]
        print(f"cvelist: parsing {len(names):,} records from {MIN_YEAR} onward")
        for i, name in enumerate(names, 1):
            if i % 25000 == 0:
                print(f"  {i:,}/{len(names):,}")
            try:
                rec = json.loads(z.read(name))
            except (json.JSONDecodeError, KeyError):
                continue
            meta, containers = rec.get("cveMetadata", {}), rec.get("containers", {})
            if not meta.get("cveId"):
                continue
            score, severity = _cvss(containers)
            vendor, product = _affected(containers)
            rows.append({"cve": meta["cveId"],
                         "published": meta.get("datePublished"),
                         "cvss3": score, "severity": severity,
                         "vendor": vendor, "product": product,
                         "cwe": _cwe(containers), "state": meta.get("state")})

    df = pd.DataFrame(rows)
    df["published"] = pd.to_datetime(df["published"], format="mixed", utc=True,
                                     errors="coerce")
    df.to_pickle(cache)
    print(f"cvelist: {len(df):,} CVEs, {df['cvss3'].notna().mean():.1%} with "
          f"CVSS v3, {df['vendor'].notna().mean():.1%} with a vendor, "
          f"{df['cwe'].notna().mean():.1%} with a CWE")
    return df


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--refresh", action="store_true")
    args = ap.parse_args()
    print(load(refresh=args.refresh).head())
