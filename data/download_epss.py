"""Download and cache monthly EPSS score snapshots.

Source: https://epss.empiricalsecurity.com/epss_scores-YYYY-MM-DD.csv.gz
Each file: one '#' comment line, then header `cve,epss,percentile`.

Phase 1 samples the 1st of each month instead of every day (~66 files instead
of ~1900).  ASSUMPTION (not in CSWP 41): NIST computes LEV over *daily* EPSS
files; monthly sampling is a coarse approximation.  See models/lev.py for how
the sampling interacts with the 30-day windows.

Range note: the spec asked for 2023-03-07 onward, but analysis/validate.py has
to reproduce NIST Table 5 rows for CVEs published since 2021-04-14, which needs
EPSS files back to the start of the public archive.  Default start is therefore
2021-04-14; pass --since 2023-03-07 for the v3-only subset.
"""

import argparse
import datetime as dt
import gzip
import hashlib
import sys
from pathlib import Path

import pandas as pd
import requests

ROOT = Path(__file__).resolve().parent.parent
CACHE = ROOT / "cache" / "epss"
URL = "https://epss.empiricalsecurity.com/epss_scores-{}.csv.gz"

# SHA-256 of every EPSS file the published results read: the monthly samples
# plus the daily files fetched by analysis/sampling_error.py (156 window starts),
# analysis/epss_drift.py (retraining-boundary search) and
# analysis/version_normalize.py (reference days).  `make verify-data` checks the
# cache against it; `--manifest` pre-fetches every listed day so that
# `make reproduce` never touches the network.
MANIFEST = ROOT / "data" / "epss_manifest.sha256"


def manifest():
    """{filename: sha256} from data/epss_manifest.sha256."""
    if not MANIFEST.exists():
        return {}
    return {name: h for h, name in
            (line.split() for line in MANIFEST.read_text().splitlines() if line)}

EPSS_START = dt.date(2021, 4, 14)   # first public EPSS file / EPSS v1
EPSS_V3 = dt.date(2023, 3, 7)       # EPSS v3 release

# Pinned end of the archive used for every published result.  Without this the
# default `until` is today, so `make reproduce` silently ingests new snapshots
# as time passes and stops matching DATA_SNAPSHOT.md.  Raise it deliberately
# when refreshing the dataset, and update DATA_SNAPSHOT.md in the same commit.
ARCHIVE_END = dt.date(2026, 8, 1)

# NIST Table 5 cut-off dates: sampled explicitly so validate.py can slice on a
# date that actually exists in the data.
ANCHORS = [EPSS_START, dt.date(2022, 2, 4), EPSS_V3]


def sample_dates(since=EPSS_START, until=None):
    """1st of each month in [since, until], plus the Table 5 anchor dates."""
    until = until or ARCHIVE_END
    firsts = pd.date_range(since, until, freq="MS").date
    days = {d for d in firsts} | {a for a in ANCHORS if since <= a <= until}
    return sorted(days)


# The archive is fronted by S3, which answers 403 (not 404) for keys that do
# not exist, so both codes mean "no file for that day" -- e.g. 2024-12-01.
MISSING = (403, 404)
SLIP = 3  # days to slide forward when a sampled date is missing
# Days the archive is known not to have (checked 2026-08-25).  Without this,
# every load() re-asks the server about them, so `make reproduce` was not
# offline.  ponytail: hand-kept list; add a day here if a new gap shows up.
KNOWN_MISSING = {dt.date(2024, 12, 1)}


def fetch(day, session=None):
    """Download one day's file into cache/epss/. Returns path, or None if absent."""
    CACHE.mkdir(parents=True, exist_ok=True)
    path = CACHE / f"epss_scores-{day}.csv.gz"
    if path.exists() and path.stat().st_size > 0:
        return path
    if day in KNOWN_MISSING:
        return None
    r = (session or requests).get(URL.format(day), timeout=60)
    if r.status_code in MISSING:
        return None
    r.raise_for_status()
    pinned = manifest().get(path.name)
    got = hashlib.sha256(r.content).hexdigest()
    assert pinned in (None, got), (f"{path.name}: SHA-256 {got} does not match "
                                   f"{pinned} in {MANIFEST.name} -- upstream file changed")
    path.write_bytes(r.content)
    print(f"  {day}: downloaded {len(r.content)/1e6:.1f} MB")
    return path


def fetch_days(days):
    """Fetch an explicit list of days (no slip: the list names real files)."""
    with requests.Session() as s:
        for day in days:
            if fetch(day, s) is None:
                print(f"  {day}: not in the archive")


def manifest_days():
    """Dates of every file in the manifest."""
    return sorted(dt.date.fromisoformat(n[len("epss_scores-"):-len(".csv.gz")])
                  for n in manifest())


def download_all(since=EPSS_START, until=None):
    """Fetch each sampled day, sliding forward up to SLIP days if it is missing.

    ASSUMPTION (not in CSWP 41): substituting the next available day for a
    missing one is what NIST's own implementation does for gaps in the EPSS
    archive; here it also keeps the monthly cadence from losing whole months.
    """
    days = sample_dates(since, until)
    print(f"EPSS: {len(days)} snapshots from {days[0]} to {days[-1]}")
    got = []
    with requests.Session() as s:
        for day in days:
            for slip in range(SLIP + 1):
                d = day + dt.timedelta(days=slip)
                path = fetch(d, s)
                if path:
                    if slip:
                        print(f"  {day}: missing, using {d} instead")
                    got.append((d, path))
                    break
            else:
                print(f"  {day}: missing, no file within {SLIP} days -- skipped")
    return got


def load(since=EPSS_START, until=None):
    """Tidy EPSS scores indexed by (cve, date), column `epss`.

    Parsed frames are pickled so re-runs are ~instant.  Percentile is dropped;
    LEV only uses the raw probability.
    """
    got = download_all(since, until)
    cache = ROOT / "cache" / f"epss_tidy_{got[0][0]}_{got[-1][0]}_{len(got)}.pkl"
    if cache.exists():
        print(f"EPSS: loading cached frame {cache.name}")
        return pd.read_pickle(cache)

    frames = []
    for i, (day, path) in enumerate(got, 1):
        # EPSS v1 files (April 2021) have no '#' metadata line and no
        # percentile column; everything from v2 onwards does.
        with gzip.open(path, "rt") as fh:
            has_header_comment = fh.readline().startswith("#")
        df = pd.read_csv(path, skiprows=1 if has_header_comment else 0,
                         usecols=["cve", "epss"],
                         dtype={"cve": "string", "epss": "float32"})
        df["date"] = pd.Timestamp(day)
        frames.append(df)
        print(f"  parsed {day} ({i}/{len(got)}, {len(df):,} CVEs)")

    tidy = pd.concat(frames, ignore_index=True)
    tidy["cve"] = tidy["cve"].astype("category")
    tidy = tidy.set_index(["cve", "date"]).sort_index()
    tidy.to_pickle(cache)
    print(f"EPSS: {len(tidy):,} rows, {tidy.index.levels[0].size:,} unique CVEs")
    return tidy


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--since", default=str(EPSS_START))
    ap.add_argument("--manifest", action="store_true",
                    help="also pre-fetch every daily file in epss_manifest.sha256")
    args = ap.parse_args()
    if args.manifest:
        days = manifest_days()
        print(f"EPSS: pre-fetching {len(days)} files listed in {MANIFEST.name}")
        fetch_days(days)
    df = load(since=dt.date.fromisoformat(args.since))
    print(df.head())
    print(df.tail())
