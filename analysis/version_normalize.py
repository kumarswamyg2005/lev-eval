"""Task C'' -- how much of current LEV is EPSS version shift, not exploitation?

EPSS v4 (model_version v2025.03.14) deployed 2025-03-17 and roughly tripled
cohort mean scores overnight; the 2026-06-15 model moved them partly back.
LEV multiplies scores across those boundaries as if they were one measurement
series, so a corpus-wide rescaling enters LEV as accumulated evidence.

Three variants of the same cohort at the same dn:
  LEV_raw     -- as computed elsewhere in this repo (mixed versions)
  LEV_v3only  -- windows truncated at the v4 boundary (DIAGNOSTIC ONLY: this
                 changes dn, so it is not a fair comparison to the other two)
  LEV_norm    -- percentile-preserving: every post-boundary score is replaced
                 by the v3-reference score at the same percentile

Run: python analysis/version_normalize.py
"""

import gzip
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from data import download_epss, download_kev
from models import lev as levmod
from analysis import calibration, dn_sweep, validate

ROOT = Path(__file__).resolve().parent.parent
CACHE = ROOT / "cache" / "version_normalize.pkl"

# Last v3 snapshot before EPSS v4 went live (v4 first appears 2025-03-17; the
# v2025.03.14 version string is a BUILD date -- see analysis/epss_drift.py).
REF_DATE = pd.Timestamp("2025-03-16")
BOUNDARY = pd.Timestamp("2025-03-17")
# Sensitivity check: a second v3-era reference, 6 weeks earlier.
REF_ALT = pd.Timestamp("2025-02-01")
DN = pd.Timestamp("2026-08-01")


def read_scores(day, with_percentile=True):
    """cve-indexed frame of epss (+percentile) for one EPSS file."""
    path = download_epss.fetch(day.date() if hasattr(day, "date") else day)
    if path is None:
        raise FileNotFoundError(day)
    with gzip.open(path, "rt") as fh:
        commented = fh.readline().startswith("#")
    cols = ["cve", "epss"] + (["percentile"] if with_percentile else [])
    df = pd.read_csv(path, skiprows=1 if commented else 0, usecols=cols,
                     dtype={"cve": "string", "epss": "float32",
                            "percentile": "float32"})
    return df.set_index("cve")


def percentile_map(ref_day):
    """Quantile function of the reference snapshot: percentile -> v3 EPSS score.

    ASSUMPTION (not in CSWP 41): a CVE's RANK within the corpus is comparable
    across model versions, so mapping a post-v4 percentile back to the v3 score
    at that percentile removes the corpus-level rescaling.  This removes shift,
    NOT per-CVE model improvement -- v4 added features (malware telemetry,
    endpoint detection), so some rank changes are genuine signal that this
    procedure will strip along with the artifact.
    """
    ref = read_scores(ref_day).dropna().sort_values("percentile")
    return ref["percentile"].to_numpy(), ref["epss"].to_numpy()


def normalize(wide, ref_day=REF_DATE, boundary=BOUNDARY):
    """Copy of `wide` with every post-boundary column mapped to the v3 scale."""
    ref_pct, ref_eps = percentile_map(ref_day)
    out = wide.copy()
    post = [d for d in wide.columns if d >= boundary]
    print(f"  normalizing {len(post)} post-boundary snapshots to "
          f"{pd.Timestamp(ref_day).date()} scale")
    for d in post:
        pct = read_scores(d)["percentile"].reindex(wide.index)
        mapped = pd.Series(np.interp(pct.to_numpy(), ref_pct, ref_eps),
                           index=wide.index)
        # CVEs absent from that day's file keep their forward-filled raw score;
        # they are a fraction of a percent (see analysis/epss_drift.py step 5).
        out[d] = mapped.where(pct.notna(), out[d]).astype("float32")
    return out


def crossings(raw, norm, thr):
    """How many CVEs cross `thr` in each direction under normalization."""
    down = int(((raw >= thr) & (norm < thr)).sum())
    up = int(((raw < thr) & (norm >= thr)).sum())
    return down, up


def main():
    tidy = download_epss.load()
    kev = download_kev.load()
    print("\nbuilding wide EPSS matrix...")
    wide, first_idx = levmod.to_wide(tidy)
    dates = wide.columns

    print("\nbuilding version-normalized matrix...")
    norm_wide = normalize(wide)

    m = calibration.cohort(wide, first_idx, DN)
    idx = wide.index[m]
    print(f"\ncohort: {len(idx):,} CVEs (same as calibration.py), dn={DN.date()}")

    # ---------------------------------------------------------- 1. variants
    print("\ncomputing LEV variants...")
    lev_raw = levmod.lev(wide[m], first_idx[m], dn=DN)
    lev_norm = levmod.lev(norm_wide[m], first_idx[m], dn=DN)

    # v3-only: drop every column past the boundary, then stop at REF_DATE.
    pre_cols = [d for d in dates if d < BOUNDARY]
    pre_wide = wide.loc[idx, pre_cols]
    first_pre = first_idx[m].clip(upper=len(pre_cols) - 1)
    born_pre = pd.Series(dates.to_numpy()[first_idx[m].to_numpy()],
                         index=idx) < BOUNDARY
    lev_v3 = levmod.lev(pre_wide, first_pre, dn=REF_DATE)
    lev_v3[~born_pre] = 0.0        # these CVEs did not exist in the v3 regime

    summary = pd.DataFrame([
        {"variant": "LEV_raw", "N": len(lev_raw), "mean": lev_raw.mean(),
         "sum": lev_raw.sum(), "frac>0.5": (lev_raw > .5).mean(),
         "frac>0.9": (lev_raw > .9).mean()},
        {"variant": "LEV_norm", "N": len(lev_norm), "mean": lev_norm.mean(),
         "sum": lev_norm.sum(), "frac>0.5": (lev_norm > .5).mean(),
         "frac>0.9": (lev_norm > .9).mean()},
        {"variant": "LEV_v3only*", "N": len(lev_v3), "mean": lev_v3.mean(),
         "sum": lev_v3.sum(), "frac>0.5": (lev_v3 > .5).mean(),
         "frac>0.9": (lev_v3 > .9).mean()},
    ])
    print("\n=== 1-2. LEV variants, same cohort, same dn ===")
    print(summary.to_string(index=False, float_format=lambda v: f"{v:.5f}"))
    print(f"  * LEV_v3only stops at {REF_DATE.date()}: fewer windows AND a "
          f"different dn.\n    DIAGNOSTIC ONLY -- not comparable to the other "
          f"two rows.\n    {int((~born_pre).sum()):,} cohort CVEs were born after "
          f"the boundary and score 0;\n    mean over the "
          f"{int(born_pre.sum()):,} born before it: {lev_v3[born_pre].mean():.5f}")

    ratio = float(lev_norm.mean() / lev_raw.mean())
    mass = 1 - float(lev_norm.sum() / lev_raw.sum())
    print(f"\n  LEV_norm / LEV_raw (mean)          : {ratio:.4f}")
    print(f"  LEV mass attributable to version shift: {mass:.1%}")

    print("\n  per-CVE change (LEV_norm - LEV_raw):")
    d = (lev_norm - lev_raw)
    print(f"    decreased {int((d < -1e-9).sum()):,}   unchanged "
          f"{int((d.abs() <= 1e-9).sum()):,}   increased {int((d > 1e-9).sum()):,}")
    print(f"    deciles: " + ", ".join(
        f"{q:.0%}={d.quantile(q):+.4f}" for q in np.arange(0, 1.01, 0.25)))
    for thr in (0.5, 0.9):
        down, up = crossings(lev_raw, lev_norm, thr)
        print(f"    crossing {thr}: {down:,} fall below, {up:,} rise above")
    top = lev_raw >= 0.9
    print(f"\n  of the {int(top.sum()):,} CVEs at LEV_raw >= 0.9, "
          f"{int((lev_norm[top] < 0.9).sum()):,} fall below 0.9 under "
          f"normalization ({(lev_norm[top] < 0.9).mean():.1%})")

    # sensitivity to the reference snapshot choice
    alt = levmod.lev(normalize(wide, REF_ALT)[m], first_idx[m], dn=DN)
    print(f"\n  reference-date sensitivity: mean LEV_norm = {lev_norm.mean():.5f} "
          f"({REF_DATE.date()}) vs {alt.mean():.5f} ({REF_ALT.date()}), "
          f"{abs(alt.mean() / lev_norm.mean() - 1):.1%} apart")

    # -------------------------------------------------- 3. calibration redo
    in_kev = set(kev.loc[kev["kev_date"] <= DN, "cve"])
    y = lev_raw.index.isin(in_kev).astype(float)
    print("\n=== 3. calibration under each variant ===")
    tables = {}
    for label, p in [("LEV_raw", lev_raw), ("LEV_norm", lev_norm)]:
        tab, brier, ece = calibration.evaluate(p.to_numpy(), y)
        tables[label] = (tab, brier, ece, float(p.mean()))
        print(f"\n--- {label} ---")
        print(tab[["bucket", "n", "predicted", "observed", "n_in_kev",
                   "obs_pred_ratio"]].to_string(
            index=False, na_rep="-", float_format=lambda v: f"{v:.4f}"))
        print(f"  Brier {brier:.5f}   ECE {ece:.5f}   "
              f"mean pred {p.mean():.5f} / obs {y.mean():.5f} "
              f"= {p.mean() / y.mean():.1f}x")

    r_over = tables["LEV_raw"][3] / y.mean()
    n_over = tables["LEV_norm"][3] / y.mean()
    shrink = 1 - n_over / r_over
    print(f"\n  over-confidence {r_over:.1f}x (raw) -> {n_over:.1f}x (normalized), "
          f"a {shrink:.0%} reduction")
    print(f"  Brier {tables['LEV_raw'][1]:.5f} -> {tables['LEV_norm'][1]:.5f}   "
          f"ECE {tables['LEV_raw'][2]:.5f} -> {tables['LEV_norm'][2]:.5f}")
    if shrink >= 0.5:
        print("\n  VERDICT: the calibration gap and the version-mixing finding are")
        print("  LARGELY THE SAME FINDING -- normalization removes most of the")
        print("  over-confidence, so one mechanism explains both symptoms.")
    elif shrink >= 0.2:
        print("\n  VERDICT: PARTIALLY shared. Version mixing explains a material")
        print("  share of the over-confidence but a large gap remains, so the two")
        print("  findings overlap without being the same.")
    else:
        print("\n  VERDICT: INDEPENDENT. Normalization barely moves the")
        print("  over-confidence, so the calibration gap and the version-mixing")
        print("  finding are separate results and both stand on their own.")

    # ---------------------------------------------------- 4. dn sweep redo
    print("\n=== 4. dn sweep under each variant ===")
    fd = pd.Series(dates.to_numpy()[first_idx.to_numpy()], index=wide.index)
    iy = pd.Series(wide.index.astype(str).str.slice(4, 8).astype(int),
                   index=wide.index)
    lo, hi = dn_sweep.COHORTS["v3 (first EPSS 2023-03-07..2023-09-30)"]
    sm = ((fd.dt.year - iy) <= 1) & fd.between(pd.Timestamp(lo), pd.Timestamp(hi))
    dns = [d for d in dates if d >= dn_sweep.SWEEP_START]
    kev_dates = kev.drop_duplicates("cve").set_index("cve")["kev_date"]
    for label, w in [("raw", wide), ("normalized", norm_wide)]:
        print(f"\n--- sweep, {label} ---")
        sw = dn_sweep.sweep(w, first_idx, sm, kev_dates, dns)
        t = np.arange(1, len(sw) + 1, dtype=float)
        fits = dn_sweep.fit_all(t, sw["mean_lev"].to_numpy())
        rank = sorted(fits.items(), key=lambda kv: kv[1]["aic"])
        for k, v in rank:
            print(f"    {k:<11s} AIC={v['aic']:>9.2f}  R2={v['r2']:.4f}")
        margin = rank[1][1]["aic"] - rank[0][1]["aic"]
        print(f"    BEST: {rank[0][0]} (dAIC {margin:.2f}), "
              f"mean LEV {sw['mean_lev'].iloc[0]:.5f} -> {sw['mean_lev'].iloc[-1]:.5f}")

    # ----------------------------------------------------- 5. Table 5 redo
    print("\n=== 5. CSWP 41 Table 5 under each variant and dn ===")
    nbf = (fd.dt.year - iy) <= 1
    born = (fd > dates[0]) & nbf
    rows = []
    for since, expected in validate.NIST.items():
        for dn in (validate.PAPER_DN, DN):
            mm = (nbf & (fd <= dn) if since == "all"
                  else born & (fd <= dn) & (fd >= pd.Timestamp(since)))
            r = {"since": since, "dn": str(dn.date()), "N": int(mm.sum()),
                 "nist": expected}
            for label, w in [("raw", wide), ("norm", norm_wide)]:
                v = float(levmod.lev(w[mm], first_idx[mm], dn=dn).mean())
                r[label] = round(v, 4)
                r[f"{label}_err"] = f"{(v - expected) / expected:+.0%}"
            rows.append(r)
    t5 = pd.DataFrame(rows)
    print(t5.to_string(index=False))
    print(f"  At dn={validate.PAPER_DN.date()} raw and norm are identical by "
          f"construction:\n  no window extends past the v4 boundary.")

    # ---- Addition 2: Table 5 convergence as independent corroboration -----
    # The normalization uses only EPSS percentiles.  It never sees NIST's
    # published values, so movement toward them is independent evidence that
    # it is removing an artifact rather than fitting a target.
    late = t5[t5["dn"] == str(DN.date())].copy()
    late["raw_dev"] = (late["raw"] - late["nist"]).abs() / late["nist"]
    late["norm_dev"] = (late["norm"] - late["nist"]).abs() / late["nist"]
    late["improvement"] = late["raw_dev"] - late["norm_dev"]
    print(f"\n=== 5b. Table 5 convergence under normalization (dn={DN.date()}) ===")
    print(late[["since", "N", "nist", "raw", "norm", "raw_dev", "norm_dev",
                "improvement"]].to_string(
        index=False, float_format=lambda v: f"{v:.4f}"))
    mad_raw, mad_norm = late["raw_dev"].mean(), late["norm_dev"].mean()
    print(f"\n  mean absolute deviation from NIST Table 5:")
    print(f"    raw        : {mad_raw:.1%}")
    print(f"    normalized : {mad_norm:.1%}")
    print(f"    improvement: {mad_raw - mad_norm:.1%} "
          f"({1 - mad_norm / mad_raw:.0%} of the deviation removed)")
    print(f"  rows that moved toward NIST: "
          f"{int((late['improvement'] > 0).sum())} of {len(late)}")
    print("  The normalization is derived from EPSS percentiles alone and never")
    print("  sees these published values, so this is independent corroboration.")
    print("  It also partially bounds the threat that percentile mapping strips")
    print("  genuine v4 signal: if it did so heavily, deviations would grow.")

    pd.to_pickle({"raw": lev_raw, "norm": lev_norm, "v3only": lev_v3}, CACHE)
    print(f"\nwrote {CACHE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
