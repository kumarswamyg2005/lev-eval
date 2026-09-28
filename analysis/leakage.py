"""Is the LEV-vs-KEV comparison circular, and by how much?

EPSS v3 uses "CVE is listed on CISA KEV" as an INPUT FEATURE (Jacobs et al.,
arXiv:2302.14172, "Public vulnerability lists (3 features)": CISA KEV, Google
Project Zero, Trend Micro ZDI).  LEV is computed entirely from EPSS scores, so
once a CVE is listed its later scores -- and therefore its LEV -- may be raised
by the very outcome LEV is then judged against.

CORRECTION (2026-09-28).  An earlier version of this script compared
over-confidence on "all CVEs" against a "leak-free" cohort built by dropping
every CVE on KEV before the model was trained.  All 307 dropped CVEs were KEV
members and every non-member was kept, so the observed rate fell by
construction: that is selection on the outcome, and the resulting 11.9x ->
32.7x comparison is invalid.  It is replaced by two designs that cannot select
on the outcome:

  1. THE JUMP AT LISTING.  For each KEV CVE, EPSS at the last monthly snapshot
     before its dateAdded against the first snapshot on or after it, compared
     with non-KEV CVEs that had the same starting EPSS decile over the same two
     snapshots.  Pairs straddling an EPSS model retraining are excluded, since
     a retraining moves every score at once (analysis/epss_drift.py).
  2. PRE-LISTING LEV.  Each KEV member's LEV computed only from EPSS scores
     dated before it was listed, which the listing cannot have influenced.  If
     most top-bucket KEV members were already high before listing, the leak did
     not create the ranking result.

Run: python analysis/leakage.py
"""

import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from data import download_epss, download_kev
from models import lev as levmod
from analysis import calibration, version_normalize

DN = version_normalize.DN
# EPSS model deployments, measured in analysis/epss_drift.py
RETRAININGS = [pd.Timestamp(d) for d in
               ("2022-02-04", "2023-03-07", "2025-03-17", "2026-06-15")]


def jump_at_listing(wide, first_idx, kev_dates):
    """Log-ratio of EPSS across each KEV CVE's listing date, net of controls."""
    dates = wide.columns
    vals = wide.to_numpy()
    idx_of = {c: i for i, c in enumerate(wide.index)}
    rows = []
    for cve, d in kev_dates.items():
        i = idx_of.get(cve)
        if i is None:
            continue
        b = dates.searchsorted(d, "left") - 1           # last snapshot before
        a = b + 1                                       # first on/after
        if b < 0 or a >= len(dates) or first_idx.iloc[i] > b:
            continue
        if any(dates[b] < r <= dates[a] for r in RETRAININGS):
            continue                                    # retraining in between
        rows.append((cve, b, a, vals[i, b], vals[i, a]))
    kev = pd.DataFrame(rows, columns=["cve", "b", "a", "e_b", "e_a"])
    kev = kev[(kev.e_b > 0) & (kev.e_a > 0)]
    kev_set = set(kev_dates.index)

    effects = []
    for (b, a), g in kev.groupby(["b", "a"]):
        present = (first_idx.to_numpy() <= b) & (vals[:, b] > 0) & (vals[:, a] > 0)
        ctrl = present & ~wide.index.isin(kev_set)
        eb, ea = vals[ctrl, b], vals[ctrl, a]
        edges = np.quantile(vals[present, b], np.linspace(0, 1, 11))
        cbin = np.clip(np.searchsorted(edges, eb, "right") - 1, 0, 9)
        clr = np.log(ea / eb)
        cmed = pd.Series(clr).groupby(cbin).median()
        kbin = np.clip(np.searchsorted(edges, g.e_b.to_numpy(), "right") - 1, 0, 9)
        klr = np.log(g.e_a.to_numpy() / g.e_b.to_numpy())
        effects += list(klr - cmed.reindex(kbin).to_numpy())
    eff = np.array([e for e in effects if np.isfinite(e)])
    return kev, eff


def main():
    tidy = download_epss.load()
    kev = download_kev.load()
    print("\nbuilding matrices...")
    wide, first_idx = levmod.to_wide(tidy)
    norm_wide = version_normalize.normalize(wide)
    kev_dates = kev.drop_duplicates("cve").set_index("cve")["kev_date"]
    kev_dates = kev_dates[kev_dates <= DN]

    # ---------------------------------------------------- 1. jump at listing
    print(f"\n{'=' * 84}\n1. THE JUMP AT LISTING -- EPSS across each CVE's KEV dateAdded\n{'=' * 84}")
    pairs, eff = jump_at_listing(wide, first_idx, kev_dates)
    raw = np.log(pairs.e_a / pairs.e_b)
    print(f"  KEV CVEs with a clean before/after snapshot pair: {len(pairs):,}")
    print(f"  (pairs straddling an EPSS retraining excluded)")
    print(f"  raw EPSS change across listing, median   : x{np.exp(np.median(raw)):.2f}")
    print(f"  NET of matched non-KEV controls, median  : x{np.exp(np.median(eff)):.2f}")
    print(f"  net change quartiles                     : "
          f"x{np.exp(np.quantile(eff, .25)):.2f} .. x{np.exp(np.quantile(eff, .75)):.2f}")
    print(f"  share of KEV CVEs whose EPSS rose more than controls: {(eff > 0).mean():.0%}")

    # --------------------------------------------------- 2. pre-listing LEV
    print(f"\n{'=' * 84}\n2. PRE-LISTING LEV -- scores the listing could not have touched\n{'=' * 84}")
    m = calibration.cohort(wide, first_idx, DN)
    at_dn = levmod.lev(norm_wide[m], first_idx[m], dn=DN)
    members = at_dn.index[at_dn.index.isin(kev_dates.index)]
    pre = {}
    for d, cves in kev_dates.reindex(members).groupby(kev_dates.reindex(members)).groups.items():
        sel = wide.index.isin(cves)
        fi = first_idx[sel]
        d0 = wide.columns[fi.to_numpy()]
        ok = d0 < d                              # scored before being listed
        if ok.any():
            s = levmod.lev(norm_wide[sel][ok], fi[ok], dn=d)
            pre.update(s.to_dict())
    pre = pd.Series(pre).reindex(members)
    has = pre.notna()
    age_m = ((kev_dates.reindex(members) - pd.Series(
        wide.columns[first_idx[members].to_numpy()], index=members)).dt.days / 30.4)
    print(f"  KEV members in the calibration cohort : {len(members)}")
    print(f"  listed in the same month they were first scored (no pre-listing "
          f"history): {int((~has).sum())} ({(~has).mean():.0%})")
    print(f"  with a pre-listing EPSS history       : {int(has.sum())}; "
          f"median {age_m[has].median():.1f} months from first score to listing")
    print(f"\n  what LEV said BEFORE CISA listed them (n={int(has.sum())}):")
    for thr in (0.9, 0.5, 0.1):
        print(f"    LEV >= {thr:<4}: {int((pre[has] >= thr).sum()):>4} "
              f"({(pre[has] >= thr).mean():.0%})")
    print(f"    median     : {pre[has].median():.4f}   (at dn: "
          f"{at_dn[members[has]].median():.3f})")
    top_now = (at_dn[members] >= 0.9) & has
    print(f"\n  of the {int(top_now.sum())} with history now in the top bucket, "
          f"{int((pre[top_now] >= 0.9).sum())} ({(pre[top_now] >= 0.9).mean():.0%}) "
          f"were already >= 0.9 before listing")
    print("\n  READING: pre-listing LEV covers fewer 30-day windows, so it is lower")
    print("  partly through elapsed time alone.  What it does show without that")
    print("  confound is what a defender relying on LEV would have seen before CISA")
    print("  acted -- LEV's value as a LEADING indicator of KEV listing, which is")
    print("  the use CSWP 41 proposes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
