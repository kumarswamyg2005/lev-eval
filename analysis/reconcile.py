"""Task A -- reconcile the Task 4 (validate.py) and Task 5 (calibration.py)
populations, which report mean LEV 0.016 and 0.081 on nominally similar sets.

Loads the CVE universe once, then reports N / sum / mean / min / max LEV under
each script's exact filter predicates, walks the difference one filter change
at a time, and checks the four candidate causes explicitly.

Run: python analysis/reconcile.py
"""

import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from data import download_epss
from models import lev as levmod
from analysis import calibration, validate

pd.set_option("display.width", 200)

TASK4_DN = validate.PAPER_DN                 # 2025-03-01
EPSS_V3 = calibration.EPSS_V3                # 2023-03-07
CENSOR = calibration.CENSOR_DAYS             # 183

# The two scripts' filter chains, written out so the difference is inspectable
# rather than buried in two functions.
TASK4_PREDICATES = [
    "first_epss_date > earliest_snapshot            (undatable pre-archive CVEs)",
    "first_epss_date.year - cve_id_year <= 1        (EPSS coverage backfills)",
    "first_epss_date >= 2023-03-07                  (Table 5 'published since')",
    "first_epss_date <= dn                          (not yet published at dn)",
    "dn = 2025-03-01                                (paper-era analysis date)",
]
TASK5_PREDICATES = [
    "first_epss_date >= 2023-03-07                  (EPSS v3 era)",
    "first_epss_date.year - cve_id_year <= 1        (EPSS coverage backfills)",
    "first_epss_date <= dn - 183 days               (right-censoring control)",
    "dn = 2026-08-01                                (latest snapshot)",
]


def describe(name, scores):
    return {
        "population": name,
        "N": len(scores),
        "sum_LEV": round(float(scores.sum()), 1),
        "mean_LEV": round(float(scores.mean()), 5),
        "min_LEV": round(float(scores.min()), 6),
        "max_LEV": round(float(scores.max()), 6),
    }


def main():
    tidy = download_epss.load()
    print("\nbuilding wide EPSS matrix...")
    wide, first_idx = levmod.to_wide(tidy)
    dates = wide.columns
    latest = dates[-1]
    print(f"  {wide.shape[0]:,} CVEs x {wide.shape[1]} snapshots, latest {latest.date()}")

    first_date = pd.Series(dates.to_numpy()[first_idx.to_numpy()], index=wide.index)
    id_year = pd.Series(wide.index.astype(str).str.slice(4, 8).astype(int),
                        index=wide.index)
    not_backfill = (first_date.dt.year - id_year) <= 1

    # ---------------------------------------------------------------- cause 3
    print("\n--- candidate cause: duplicate CVE rows across monthly files ---")
    dup_pairs = int(tidy.index.duplicated().sum())
    print(f"  duplicated (cve, date) rows in tidy frame : {dup_pairs:,}")
    print(f"  wide index unique                         : {wide.index.is_unique}")
    print("  VERDICT: not the cause -- unstack() collapses to one row per CVE."
          if dup_pairs == 0 and wide.index.is_unique else "  VERDICT: REAL PROBLEM")

    # ---------------------------------------------------------------- stage Ns
    print("\n--- filter-stage row counts ---")
    stages = [
        ("all CVEs with any EPSS data", pd.Series(True, index=wide.index)),
        ("+ first EPSS date >= 2023-03-07", first_date >= EPSS_V3),
        ("+ not an EPSS coverage backfill", (first_date >= EPSS_V3) & not_backfill),
    ]
    for dn in (TASK4_DN, latest):
        stages.append((f"+ age >= 6 months at dn={dn.date()}",
                       (first_date >= EPSS_V3) & not_backfill
                       & (first_date <= dn - pd.Timedelta(days=CENSOR))))
    prev = None
    for label, m in stages:
        n = int(m.sum())
        delta = "" if prev is None else f"   ({n - prev:+,})"
        print(f"  {label:<48s} N = {n:>7,}{delta}")
        prev = n

    # ------------------------------------------------------ the two populations
    print("\n--- LEV under each script's own predicates ---")
    for name, preds in [("Task 4 (validate.py)", TASK4_PREDICATES),
                        ("Task 5 (calibration.py)", TASK5_PREDICATES)]:
        print(f"\n  {name} predicates:")
        for p in preds:
            print(f"    - {p}")

    t4_mask = (first_date > dates[0]) & not_backfill & (first_date >= EPSS_V3) \
        & (first_date <= TASK4_DN)
    t5_mask = calibration.cohort(wide, first_idx, latest)

    print("\ncomputing LEV for both populations...")
    t4 = levmod.lev(wide[t4_mask], first_idx[t4_mask], dn=TASK4_DN)
    t5 = levmod.lev(wide[t5_mask], first_idx[t5_mask], dn=latest)
    summary = pd.DataFrame([describe("Task 4 (dn=2025-03-01)", t4),
                            describe("Task 5 (dn=2026-08-01)", t5)])
    print("\n" + summary.to_string(index=False))

    # ------------------------------------------------------------- the bridge
    # Walk one change at a time. LEV is a product over 30-day windows from a
    # CVE's first EPSS date to dn, so it grows monotonically with dn -- moving
    # the analysis date 17 months later is not a neutral bookkeeping change.
    print("\n--- bridging the gap, one filter change at a time ---")
    bridge_defs = [
        ("A. Task 4 config: dn=2025-03-01, no age filter", t4_mask, TASK4_DN),
        ("B. A but dn=2026-08-01 (latest snapshot)",
         (first_date > dates[0]) & not_backfill & (first_date >= EPSS_V3)
         & (first_date <= latest), latest),
        ("C. B + age >= 6 months == Task 5 population", t5_mask, latest),
    ]
    rows, prev_mean = [], None
    for label, m, dn in bridge_defs:
        s = levmod.lev(wide[m], first_idx[m], dn=dn)
        mean = float(s.mean())
        rows.append({"step": label, "N": len(s), "mean_LEV": round(mean, 5),
                     "x_prev": "-" if prev_mean is None else f"{mean/prev_mean:.2f}x"})
        prev_mean = mean
    bridge = pd.DataFrame(rows)
    print(bridge.to_string(index=False))
    total = bridge["mean_LEV"].iloc[-1] / bridge["mean_LEV"].iloc[0]
    print(f"\n  total: {total:.2f}x  (dn shift x age filter)")

    # ------------------------------------------- cause 1: near-zero LEV mass
    print("\n--- candidate cause: near-zero-LEV CVEs present in one set only ---")
    for name, s in [("Task 4", t4), ("Task 5", t5)]:
        print(f"  {name}: LEV < 0.001 -> {float((s < 0.001).mean()):.1%} of rows, "
              f"LEV < 0.01 -> {float((s < 0.01).mean()):.1%}")

    # ------------------------------------------- cause 2 / 4: date field, set
    print("\n--- candidate cause: different date field / disjoint CVE sets ---")
    print("  both scripts use first EPSS appearance as the publication proxy; "
          "neither reads a CVE publish date")
    only4 = int((t4_mask & ~t5_mask).sum())
    only5 = int((t5_mask & ~t4_mask).sum())
    both = int((t4_mask & t5_mask).sum())
    print(f"  in Task 4 only: {only4:,}   in Task 5 only: {only5:,}   in both: {both:,}")
    shared = wide.index[t4_mask & t5_mask]
    print(f"  mean LEV on the {len(shared):,} SHARED CVEs: "
          f"{float(t4[shared].mean()):.5f} at dn=2025-03-01 vs "
          f"{float(t5[shared].mean()):.5f} at dn=2026-08-01 "
          f"({float(t5[shared].mean() / t4[shared].mean()):.2f}x)")

    # ----------------------------------------------------------- Table 5 redo
    print("\n--- CSWP 41 Table 5 recomputed on the Task 5 filtered set ---")
    rows = []
    for since, expected in validate.NIST.items():
        for dn in (TASK4_DN, latest):
            # "all" is a population, not a publication cut-off: no date
            # threshold and the pre-archive corpus is kept (see validate.py).
            m = not_backfill & (first_date <= dn - pd.Timedelta(days=CENSOR))
            if since != "all":
                m &= (first_date >= pd.Timestamp(since)) & (first_date > dates[0])
            s = levmod.lev(wide[m], first_idx[m], dn=dn)
            rows.append({"since": since, "dn": str(dn.date()), "N": len(s),
                         "nist_table5": expected, "ours": round(float(s.mean()), 4),
                         "rel_err": f"{(s.mean() - expected) / expected:+.0%}"})
    print(pd.DataFrame(rows).to_string(index=False))
    print("  (Task 5's age filter applied; Table 5 itself has no such filter,")
    print("   so these are diagnostics, not the Task 4 check.)")

    # -------------------------------------------------------------- deciles
    print("\n--- LEV distribution (deciles) ---")
    q = np.arange(0, 1.01, 0.1)
    dec = pd.DataFrame({"quantile": [f"{x:.0%}" for x in q],
                        "Task 4": t4.quantile(q).to_numpy(),
                        "Task 5": t5.quantile(q).to_numpy()})
    print(dec.to_string(index=False, float_format=lambda v: f"{v:.6f}"))

    print(f"""
=== RESOLUTION ===
The populations are not the same analysis. The gap is {total:.1f}x and decomposes
cleanly into two known, intended differences:

  {bridge['x_prev'].iloc[1]:>5s}  moving dn from 2025-03-01 to 2026-08-01
  {bridge['x_prev'].iloc[2]:>5s}  the 6-month right-censoring filter

LEV(v, d0, dn) is a product over 30-day windows from d0 to dn, so it is
monotonically increasing in dn by construction. Adding 17 months of windows to
every CVE cannot leave the mean unchanged. On the {len(shared):,} CVEs present in BOTH
populations the mean rises {float(t5[shared].mean() / t4[shared].mean()):.2f}x from the dn shift alone, with the
population held fixed -- so this is the dn, not the filters.

The 1.4x estimate for the censoring filter was right; the missing factor was dn.
None of the four suspected causes is responsible: no duplicate rows, one shared
date field, and the two sets overlap on {both:,} CVEs rather than being disjoint.

CORRECT POPULATION FOR CALIBRATION: Task 5's (dn = latest snapshot).
KEV membership is observed through the present, so LEV must be computed to the
same date. Using dn=2025-03-01 while checking KEV through 2026-08 would score
predictions against 17 months of outcomes the prediction could not see.
dn=2025-03-01 is correct only for reproducing the paper's Table 5, whose value
depends on NIST's own analysis date.

Neither number is wrong. mean LEV 0.016 answers "what did LEV say in March
2025"; 0.081 answers "what does LEV say today about CVEs old enough to judge".
Calibration needs the second.""")
    return 0


if __name__ == "__main__":
    sys.exit(main())
