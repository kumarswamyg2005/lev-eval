"""Task 4 -- reproduce NIST CSWP 41 Table 5 as a correctness check.

Table 5 reports the average LEV probability over all CVEs published since a
given date.  If our numbers are in the same neighbourhood, the LEV
implementation is behaving; if not, nothing downstream is worth interpreting.

Run: python analysis/validate.py
"""

import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from data import download_epss
from models import lev as levmod

# CSWP 41 Table 5.  The "all" row is computed over every CVE with EPSS data
# and no version restriction, so it deliberately mixes EPSS v1/v2/v3 -- which
# makes it the row most exposed to the version-mixing effect measured in
# analysis/version_normalize.py.
NIST = {"2023-03-07": 0.015, "2022-02-04": 0.047, "2021-04-14": 0.087,
        "all": 0.146}

TOLERANCE = 0.30  # flag anything off by more than 30% relative

# CSWP 41 is dated May 2025 and its Table 5 was computed against EPSS data
# ending around this date.  Our snapshots run to today, and LEV grows
# monotonically with the length of the window, so comparing at today's date
# would overstate every row.  ASSUMPTION: dn = 2025-03-01 approximates the
# paper's analysis date; the exact one is not stated in the paper.
PAPER_DN = pd.Timestamp("2025-03-01")


def build(since=None):
    tidy = download_epss.load(since=since) if since else download_epss.load()
    print("building wide EPSS matrix...")
    wide, first_idx = levmod.to_wide(tidy)
    print(f"  {wide.shape[0]:,} CVEs x {wide.shape[1]} snapshots")
    return wide, first_idx


def table(wide, first_idx, dn):
    """Average LEV per Table 5 cut-off, at analysis date dn."""
    dates = wide.columns
    first_date = pd.Series(dates.to_numpy()[first_idx.to_numpy()],
                           index=wide.index)

    print(f"\ncomputing LEV (dn = {dn.date()})...")
    scores = levmod.lev(wide, first_idx, dn=dn)
    scores2 = levmod.lev2(wide, first_idx, dn=dn)

    # PROXY (not in CSWP 41): we have no CVE publication dates, so a CVE's
    # first EPSS appearance stands in for its publication date.  EPSS scores
    # new CVEs within days of publication, so this is usually close.  Two
    # corrections are needed:
    #  1. the ~65k CVEs already in the very first snapshot pre-date the archive
    #     and their publication dates are unknowable from EPSS alone -- dropped.
    #  2. EPSS periodically *backfills* coverage: on 2022-02-04 (v2) the corpus
    #     jumped from 81k to 168k CVEs, most of them old.  Without this filter
    #     those old CVEs get counted as "published 2022-02-04", which inflated
    #     the two older rows of Table 5 by 3-4x.  A CVE is treated as a genuine
    #     new publication only if EPSS first scored it within one calendar year
    #     of its CVE-ID year.  THREAT TO VALIDITY: this drops the small number
    #     of CVEs legitimately published >1 year after their ID was reserved.
    id_year = pd.Series(wide.index.astype(str).str.slice(4, 8).astype(int),
                        index=wide.index)
    not_backfill = (first_date.dt.year - id_year) <= 1
    born = (first_date > dates[0]) & not_backfill
    live = first_date <= dn                # not yet published as of dn

    rows = []
    for since, expected in NIST.items():
        # "all" drops the publication cut-off AND keeps the pre-archive corpus
        # (CVEs already present in the first snapshot), since the row is not
        # about publication date at all.  The backfill correction still
        # applies: it is data hygiene (EPSS retroactively scoring old CVEs),
        # not an EPSS-version restriction, so applying it to three rows and not
        # the fourth would make them incomparable.  Without it the row reads
        # 0.2549 (+75%); with it, 0.1299 (-11%).
        m = (not_backfill & live if since == "all"
             else born & live & (first_date >= pd.Timestamp(since)))
        got, got2 = scores[m].mean(), scores2[m].mean()
        rel = (got - expected) / expected
        rows.append({"since": since, "n_cves": int(m.sum()),
                     "nist_table5": expected, "ours_lev": round(got, 4),
                     "ours_lev2": round(got2, 4),
                     "rel_err": f"{rel:+.0%}",
                     "ok": "PASS" if abs(rel) <= TOLERANCE else "FLAG"})
    return pd.DataFrame(rows)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dn", default=None,
                    help="analysis date; default: paper-era and latest")
    args = ap.parse_args()

    wide, first_idx = build()
    dns = ([pd.Timestamp(args.dn)] if args.dn
           else [PAPER_DN, wide.columns[-1]])

    ok = True
    for dn in dns:
        t = table(wide, first_idx, dn)
        print(f"\n=== NIST CSWP 41 Table 5 vs ours (dn = {dn.date()}) ===")
        print(t.to_string(index=False))
        if dn == dns[0]:   # only the paper-era date is the actual check
            ok = (t["ok"] == "PASS").all()

    print("\nThe dn = today table is context, not a check: LEV grows with the "
          "length of the observation window, so it is expected to run high.")
    print("sum(LEV)/count is an approximation here: Phase 1 samples EPSS "
          "monthly, not daily, and uses first-EPSS-date as a publication-date "
          "proxy.  See the docstrings for both assumptions.")
    print("\nRESULT:", "PASS" if ok else
          f"FLAGGED -- one or more rows off by >{TOLERANCE:.0%} relative")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
