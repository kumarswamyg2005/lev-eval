"""Quantify the monthly-sampling approximation in Phase 1's LEV.

Phase 1 reads EPSS on the 1st of each month, but LEV windows are exactly 30
days.  A 30-day stride against ~30.44-day spacing drifts ~0.44 days per
window, so by the 30th window the pipeline is reading a score up to two weeks
from the date the equation asks for.  This measures that error directly:
LEV over the true daily window starts, against LEV as the pipeline computes it,
on the same CVEs at the same dn.

Only the daily files actually needed are fetched -- the union of window-start
dates for a handful of d0 cohorts, ~145 files rather than the ~1,950 in the
full archive.

Run: python analysis/sampling_error.py
"""

import datetime as dt
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from data import download_epss
from models import lev as levmod
from analysis import calibration, version_normalize

ROOT = Path(__file__).resolve().parent.parent
FIGURE = ROOT / "figures" / "sampling_error.png"
CACHE = ROOT / "cache" / "sampling_error.pkl"

DN = version_normalize.DN
WINDOW = levmod.WINDOW

# d0 cohorts spanning the usable age range.  Every sampled CVE's window starts
# are d0 + 30k, so the number of distinct daily files scales with the number of
# cohorts, not with the number of CVEs -- 6 cohorts keep the fetch to ~145
# files while giving 6 age strata for the age breakdown.
D0_GROUPS = [pd.Timestamp(d) for d in
             ("2023-04-01", "2023-10-01", "2024-04-01",
              "2024-10-01", "2025-04-01", "2025-10-01")]
PER_CELL = 9          # CVEs per (d0 cohort, LEV decile) cell -> ~540 target
SLIP = 3              # days to slide forward when a daily file is missing


def sample(wide, first_idx, lev_norm, d0):
    """~PER_CELL CVEs per (cohort, LEV_norm decile), so the sparse top
    buckets are represented rather than swamped by the [0, 0.1) mass."""
    dec = np.clip(np.digitize(lev_norm.to_numpy(), calibration.BINS) - 1, 0, 9)
    frame = pd.DataFrame({"lev_norm": lev_norm, "d0": d0, "decile": dec})
    frame = frame[frame["d0"].isin(D0_GROUPS)]
    rng = np.random.default_rng(0)      # fixed seed: the sample is part of the result
    picks = []
    for (_, _), g in frame.groupby(["d0", "decile"], observed=True):
        take = min(PER_CELL, len(g))
        picks.append(g.sample(take, random_state=rng.integers(1 << 31)))
    out = pd.concat(picks)
    print(f"sampled {len(out):,} CVEs across {out['d0'].nunique()} cohorts "
          f"x {out['decile'].nunique()} deciles")
    print(out.groupby(["d0", "decile"]).size().unstack(fill_value=0).to_string())
    return out


def window_starts(d0, dn=DN, window=WINDOW):
    """Exact window start dates and their weights, per CSWP 41 Sec. 4.1."""
    starts = pd.date_range(d0, dn, freq=f"{window}D")
    weights = np.minimum(window, (dn - starts).days) / window
    keep = weights > 0
    return starts[keep], weights[keep].to_numpy(float)


def fetch_daily(dates):
    """cve-indexed EPSS score per requested date, from the daily archive.

    Missing days slide forward up to SLIP days, the same substitution the
    monthly pipeline and NIST's implementation use.
    """
    out, missing = {}, []
    for i, d in enumerate(dates, 1):
        path = None
        for slip in range(SLIP + 1):
            day = (d + pd.Timedelta(days=slip)).date()
            path = download_epss.fetch(day)
            if path is not None:
                if slip:
                    missing.append((d.date(), day))
                break
        if path is None:
            missing.append((d.date(), None))
            continue
        df = pd.read_csv(path, skiprows=1, usecols=["cve", "epss"],
                         dtype={"cve": "string", "epss": "float32"})
        out[d] = df.set_index("cve")["epss"]
        if i % 20 == 0 or i == len(dates):
            print(f"  daily {i}/{len(dates)}")
    if missing:
        print(f"  {len(missing)} dates substituted or unavailable: "
              f"{missing[:5]}{' ...' if len(missing) > 5 else ''}")
    return out


def main():
    tidy = download_epss.load()
    print("\nbuilding matrices...")
    wide, first_idx = levmod.to_wide(tidy)
    norm_wide = version_normalize.normalize(wide)
    m = calibration.cohort(wide, first_idx, DN)
    lev_norm = levmod.lev(norm_wide[m], first_idx[m], dn=DN)
    dates = wide.columns
    d0 = pd.Series(dates.to_numpy()[first_idx[m].to_numpy()], index=lev_norm.index)

    picked = sample(wide, first_idx, lev_norm, d0)
    idx = picked.index

    # union of window starts across the sampled cohorts
    needed = sorted({s for g in D0_GROUPS for s in window_starts(g)[0]})
    print(f"\nfetching {len(needed)} daily EPSS files "
          f"({needed[0].date()} .. {needed[-1].date()})")
    daily = fetch_daily(needed)

    # ---- LEV over the TRUE window starts
    print("\ncomputing LEV_daily...")
    lev_daily = {}
    for g in D0_GROUPS:
        starts, weights = window_starts(g)
        rows = picked.index[picked["d0"] == g]
        cols = [daily[s].reindex(rows) for s in starts if s in daily]
        w = np.array([w for s, w in zip(starts, weights) if s in daily])
        mat = pd.concat(cols, axis=1).ffill(axis=1).fillna(0.0).to_numpy(float)
        lev_daily.update(dict(zip(rows, 1.0 - np.prod(1.0 - mat * w, axis=1))))
    lev_daily = pd.Series(lev_daily).reindex(idx)

    # ---- LEV as the pipeline computes it (monthly, next-available-date)
    lev_monthly = levmod.lev(wide.loc[idx], first_idx[idx], dn=DN)

    res = pd.DataFrame({"monthly": lev_monthly, "daily": lev_daily,
                        "d0": picked["d0"], "decile": picked["decile"]})
    res["diff"] = res["monthly"] - res["daily"]
    res["abs_diff"] = res["diff"].abs()
    res["age_days"] = (DN - res["d0"]).dt.days
    res.to_pickle(CACHE)

    n = len(res)
    print(f"\n{'=' * 78}\nMONTHLY vs DAILY LEV, {n:,} CVEs, dn={DN.date()}\n{'=' * 78}")
    print(f"  mean |difference|   : {res['abs_diff'].mean():.5f}")
    print(f"  median |difference| : {res['abs_diff'].median():.5f}")
    print(f"  90th pct |diff|     : {res['abs_diff'].quantile(0.9):.5f}")
    print(f"  max |difference|    : {res['abs_diff'].max():.5f}")
    print(f"\n  mean LEV_monthly    : {res['monthly'].mean():.5f}")
    print(f"  mean LEV_daily      : {res['daily'].mean():.5f}")
    print(f"  mean signed diff    : {res['diff'].mean():+.5f} "
          f"({res['diff'].mean() / res['daily'].mean():+.1%} of mean LEV_daily)")
    over = int((res["diff"] > 1e-9).sum())
    under = int((res["diff"] < -1e-9).sum())
    print(f"  monthly OVER-estimates : {over:,} ({over / n:.1%})")
    print(f"  monthly UNDER-estimates: {under:,} ({under / n:.1%})")
    print(f"  SIGNED? {'yes -- systematic bias' if abs(over - under) / n > 0.2 else 'no clear direction'}")

    print("\n  distribution of signed difference:")
    for q in (0.01, 0.10, 0.25, 0.50, 0.75, 0.90, 0.99):
        print(f"    {q:>5.0%}: {res['diff'].quantile(q):+.5f}")

    print("\n  threshold crossings between the two:")
    for thr in (0.5, 0.9):
        a = int(((res["monthly"] >= thr) & (res["daily"] < thr)).sum())
        b = int(((res["monthly"] < thr) & (res["daily"] >= thr)).sum())
        n_at = int((res["daily"] >= thr).sum())
        print(f"    {thr}: {a} cross down, {b} cross up, {a + b} total "
              f"({(a + b) / n:.2%} of sample; {n_at} CVEs sit above it)")

    print("\n  by CVE age (drift accumulates with window count):")
    by_age = res.groupby("d0").agg(
        n=("diff", "size"), age_days=("age_days", "first"),
        windows=("age_days", lambda s: int(s.iloc[0] // WINDOW)),
        mean_abs=("abs_diff", "mean"), mean_signed=("diff", "mean"),
        max_abs=("abs_diff", "max"), mean_daily=("daily", "mean"))
    print(by_age.to_string(float_format=lambda v: f"{v:.5f}"))

    print("\n  by LEV decile:")
    by_dec = res.groupby("decile").agg(
        n=("diff", "size"), mean_abs=("abs_diff", "mean"),
        mean_signed=("diff", "mean"), mean_daily=("daily", "mean"))
    by_dec["rel_err"] = by_dec["mean_abs"] / by_dec["mean_daily"]
    print(by_dec.to_string(float_format=lambda v: f"{v:.5f}"))

    # ---- reweight to the real population -------------------------------
    # Stratifying by decile deliberately oversamples high-LEV CVEs (sample
    # mean LEV ~0.58 against a cohort mean of ~0.06), so the raw sample mean
    # is measured against the wrong denominator.  Reweighting each decile's
    # error by its true share of the cohort gives the figure that actually
    # propagates into the reported results.
    counts = pd.Series(np.bincount(
        np.clip(np.digitize(lev_norm.to_numpy(), calibration.BINS) - 1, 0, 9),
        minlength=10), name="cohort_n")
    per_dec = res.groupby("decile")["abs_diff"].mean().reindex(range(10))
    w = counts / counts.sum()
    pop_abs = float((per_dec.fillna(0) * w).sum())
    pop_mean_lev = float(lev_norm.mean())
    print("\n  reweighted to the full cohort (decile shares, not sample shares):")
    print(f"    cohort size                : {int(counts.sum()):,}")
    print(f"    population-weighted |diff| : {pop_abs:.5f}")
    print(f"    cohort mean LEV_norm       : {pop_mean_lev:.5f}")
    print(f"    relative error             : {pop_abs / pop_mean_lev:.1%}")

    # ---------------------------------------------------------------- verdict
    rel = pop_abs / pop_mean_lev
    print(f"\n{'=' * 78}\nVERDICT\n{'=' * 78}")
    print(f"  population-weighted mean |diff| is {rel:.1%} of cohort mean LEV.")
    print(f"  (unweighted, on the decile-stratified sample: "
          f"{res['abs_diff'].mean() / res['daily'].mean():.1%})")
    print("  Effects this must not swamp: 26.9% of LEV mass attributed to EPSS")
    print("  version shift, and the 3.4-4.1x over-confidence bound.")
    if rel < 0.10:
        print(f"\n  BOUNDED AND NEGLIGIBLE. At {rel:.1%} the sampling error is well")
        print("  below the 26.9% version-mass effect and nowhere near the")
        print("  multiplicative bounds. Monthly sampling is a documented,")
        print("  quantified approximation; the daily archive is not required")
        print("  for the Phase 1 conclusions.")
    elif rel < 0.27:
        print(f"\n  BOUNDED BUT NOT NEGLIGIBLE. At {rel:.1%} it is smaller than the")
        print("  26.9% version effect but the same order. Report it alongside")
        print("  every point estimate; recompute on daily data before any claim")
        print("  that turns on a difference of that size.")
    else:
        print(f"\n  REQUIRES FULL DAILY RECOMPUTATION. At {rel:.1%} the sampling")
        print("  error is comparable to the effects being reported and cannot")
        print("  be treated as a bounded nuisance.")
    print("\n  SCOPE: the sample covers d0 from 2023-04 to 2025-10, i.e. the")
    print("  calibration cohort. It does NOT cover the pre-v3 CVEs behind the")
    print("  older Table 5 rows, which carry more windows and would drift more.")

    # ---------------------------------------------------------------- figure
    fig, (ax, ax2) = plt.subplots(1, 2, figsize=(11, 4.5))
    ax.scatter(res["daily"], res["monthly"], s=6, alpha=.35, color="#c1440e")
    ax.plot([0, 1], [0, 1], "--", color="gray", lw=1)
    ax.set_xlabel("LEV (true daily window starts)")
    ax.set_ylabel("LEV (monthly sampling)")
    ax.set_title(f"n={n:,}, mean |diff| = {res['abs_diff'].mean():.4f}")
    ax.grid(alpha=.3)
    ax2.boxplot([g["diff"].to_numpy() for _, g in res.groupby("d0")],
                tick_labels=[str(d.date())[:7] for d in sorted(res["d0"].unique())])
    ax2.axhline(0, color="gray", ls="--", lw=1)
    ax2.set_xlabel("d0 cohort (older = more windows)")
    ax2.set_ylabel("monthly - daily")
    ax2.set_title("signed error by cohort age")
    ax2.grid(alpha=.3)
    plt.setp(ax2.get_xticklabels(), rotation=45, ha="right")
    FIGURE.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(FIGURE, dpi=150, bbox_inches="tight")
    print(f"\nwrote {FIGURE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
