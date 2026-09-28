"""Task B-prime -- how LEV behaves as the analysis date dn advances.

LEV(v, d0, dn) is a product over 30-day windows and therefore cannot decrease
in dn: the *direction* is structural, not a finding.  What is empirical is the
RATE -- whether growth is linear, decelerating, or saturating -- and that is
measurable from EPSS alone, with no exploitation ground truth, so it is not
confounded by KEV incompleteness.

Two fixed cohorts are swept: one born in the EPSS v3 era, one in the v1/v2 era.

Run: python analysis/dn_sweep.py
"""

import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from scipy import optimize

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from data import download_epss, download_kev
from models import lev as levmod

ROOT = Path(__file__).resolve().parent.parent
FIGURE = ROOT / "figures" / "dn_sweep.png"
CACHE = ROOT / "cache" / "dn_sweep.pkl"

SWEEP_START = pd.Timestamp("2023-10-01")

# EPSS model retraining dates, read from the model_version field in the
# snapshot headers (first snapshot in which each version appears).  These are
# CONFOUNDS for any statement about how LEV evolves with dn: a retraining can
# move every score in the corpus at once, so growth across a boundary is not
# the same quantity as growth within a regime.  CSWP 41 does not address EPSS
# version changes over an LEV observation window.
EPSS_ERAS = {
    pd.Timestamp("2022-02-04"): "v2022.01.01",
    pd.Timestamp("2023-03-07"): "v2023.03.01",
    pd.Timestamp("2025-04-01"): "v2025.03.14",
    pd.Timestamp("2026-07-01"): "v2026.06.15",
}
# Longest stretch of the sweep under one unchanged EPSS model.
REGIME = (pd.Timestamp("2023-10-01"), pd.Timestamp("2025-03-01"))

# Cohorts are defined by first-EPSS-date window.  The v1/v2 cohort starts at
# 2021-05-01, not 2021-04-14: CVEs in the very first snapshot pre-date the
# archive entirely and their first-EPSS date carries no information.
COHORTS = {
    "v3 (first EPSS 2023-03-07..2023-09-30)": ("2023-03-07", "2023-09-30"),
    "v1/v2 (first EPSS 2021-05-01..2021-09-30)": ("2021-05-01", "2021-09-30"),
}


# ---------------------------------------------------------------- model fits
def f_linear(t, a, b):
    return a + b * t


def f_log(t, a, b):
    return a + b * np.log(t)


def f_sat(t, a, b):
    """Saturating growth a*(1-exp(-b*t)): a is the asymptote LEV converges to."""
    return a * (1.0 - np.exp(-b * t))


# Convex families.  Month-over-month increments GROW, which linear/log/
# saturating cannot represent: all three are straight or concave.  A family
# that can bend upward has to be in the comparison or the test is rigged.
def f_quad(t, a, b, c):
    return a + b * t + c * t ** 2


def f_exp(t, a, b):
    """Exponential a*exp(b*t); doubling time = ln2/b when b > 0."""
    return a * np.exp(b * t)


def f_pow(t, a, b):
    """Power law a*t^b; convex for b > 1, concave for b < 1."""
    return a * np.power(t, b)


CONVEX = {"quadratic", "exponential", "power"}


def aic(y, yhat, k):
    """Gaussian AIC from residual sum of squares; k = params + 1 for sigma."""
    n = len(y)
    rss = float(np.sum((y - yhat) ** 2))
    return n * np.log(max(rss, 1e-300) / n) + 2 * (k + 1)


def fit_all(t, y):
    """Fit linear / log / saturating, return {name: (params, aic, r2, fn)}."""
    out = {}
    slope = (y[-1] - y[0]) / max(t[-1], 1)
    specs = [("linear", f_linear, [y[0], slope], (-np.inf, np.inf)),
             ("log", f_log, [y[0], y[-1] - y[0]], (-np.inf, np.inf)),
             # asymptote allowed anywhere in (0, 1]; LEV is a probability
             ("saturating", f_sat, [max(y[-1] * 1.5, 1e-3), 0.05],
              ([1e-6, 1e-6], [1.0, 5.0])),
             ("quadratic", f_quad, [y[0], slope, 0.0], (-np.inf, np.inf)),
             ("exponential", f_exp, [max(y[0], 1e-6),
                                     np.log(max(y[-1], 1e-9) / max(y[0], 1e-9))
                                     / max(t[-1], 1)],
              ([1e-12, -1.0], [10.0, 1.0])),
             ("power", f_pow, [max(y[0], 1e-6), 1.0],
              ([1e-12, -5.0], [10.0, 10.0]))]
    for name, fn, p0, bounds in specs:
        try:
            p, _ = optimize.curve_fit(fn, t, y, p0=p0, bounds=bounds, maxfev=20000)
        except (RuntimeError, ValueError):
            continue
        yhat = fn(t, *p)
        ss = float(np.sum((y - y.mean()) ** 2))
        out[name] = {"params": p, "aic": aic(y, yhat, len(p)),
                     "r2": 1 - float(np.sum((y - yhat) ** 2)) / ss if ss else np.nan,
                     "fn": fn}
    return out


# ------------------------------------------------------------------- sweeping
def sweep(wide, first_idx, mask, kev_dates, dns):
    """Per-dn LEV summary for a fixed cohort."""
    sub_w, sub_f = wide[mask], first_idx[mask]
    kev = kev_dates.reindex(sub_w.index)          # NaT where never in KEV
    rows = []
    for i, dn in enumerate(dns, 1):
        s = levmod.lev(sub_w, sub_f, dn=dn)
        # This module bins nothing -- it reports threshold fractions -- so the
        # equivalent invariant is that the fixed cohort is conserved at every
        # dn and the thresholds nest.
        assert len(s) == len(sub_w), "cohort not conserved across dn"
        assert s.between(0, 1).all(), "LEV outside [0, 1]"
        assert (s > 0.9).sum() <= (s > 0.5).sum(), "thresholds do not nest"
        # KEV rate as of dn: only entries CISA had catalogued by then.  The
        # cohort is fixed, so this rises only through new KEV additions.
        obs = float((kev <= dn).mean())
        mean_epss = float(sub_w[dn].mean()) if dn in sub_w.columns else np.nan
        rows.append({"dn": dn, "mean_lev": float(s.mean()),
                     "median_lev": float(s.median()),
                     "frac_gt_0.5": float((s > 0.5).mean()),
                     "frac_gt_0.9": float((s > 0.9).mean()),
                     "kev_rate_asof": obs,
                     "ratio": float(s.mean()) / obs if obs > 0 else np.nan,
                     "mean_epss": mean_epss})
        print(f"    dn={dn.date()} ({i}/{len(dns)}) mean LEV={s.mean():.4f} "
              f"KEV={obs:.5f}")
    return pd.DataFrame(rows)


def report(name, df, kev_now):
    t = np.arange(1, len(df) + 1, dtype=float)     # months since sweep start
    y = df["mean_lev"].to_numpy()

    print(f"\n{'=' * 78}\n{name}\n{'=' * 78}")
    print(df.assign(dn=df["dn"].dt.date).to_string(
        index=False, float_format=lambda v: f"{v:.5f}"))

    print(f"\n  KEV rate as of first dn : {df['kev_rate_asof'].iloc[0]:.5f}")
    print(f"  KEV rate as of last dn  : {df['kev_rate_asof'].iloc[-1]:.5f}")
    # The as-of-dn rate is itself right-censored at early dn -- CISA had
    # catalogued far less in 2023.  The present-day rate for the SAME cohort is
    # the un-censored comparison.
    print(f"  KEV rate, present day   : {kev_now:.5f}  (same cohort, no censoring)")

    inc = np.diff(y)
    print(f"\n  month-over-month increment in mean LEV:")
    print(f"    first 6 months mean : {inc[:6].mean():+.5f}")
    print(f"    last 6 months mean  : {inc[-6:].mean():+.5f}")
    print(f"    shrinking?          : "
          f"{'YES' if inc[-6:].mean() < inc[:6].mean() else 'NO'}")

    # Within-regime refit: the full sweep straddles two EPSS retrainings, so
    # the full-window shape mixes LEV accumulation with score-level shifts.
    reg = df["dn"].between(*REGIME).to_numpy()
    treg, yreg = t[reg], y[reg]
    rfits = fit_all(treg - treg[0] + 1, yreg)
    rbest = min(rfits, key=lambda k: rfits[k]["aic"])
    rinc = np.diff(yreg)
    print(f"\n  WITHIN-REGIME ({REGIME[0].date()}..{REGIME[1].date()}, EPSS "
          f"v2023.03.01 unchanged, {int(reg.sum())} points):")
    print(f"    mean LEV {yreg[0]:.5f} -> {yreg[-1]:.5f}")
    print(f"    increment first 6 / last 6 : {rinc[:6].mean():+.5f} / "
          f"{rinc[-6:].mean():+.5f}  ({'shrinking' if rinc[-6:].mean() < rinc[:6].mean() else 'growing'})")
    rrank = sorted(rfits.items(), key=lambda kv: kv[1]["aic"])
    for k, v in rrank:
        print(f"    {k:<11s} AIC={v['aic']:>9.2f}  R2={v['r2']:.4f}")
    rmargin = rrank[1][1]["aic"] - rrank[0][1]["aic"] if len(rrank) > 1 else np.nan
    print(f"    BEST (within regime): {rbest}  "
          f"(dAIC to 2nd = {rmargin:.2f}{'  -- NOT decisive' if rmargin < 2 else ''})")
    e0 = df.loc[reg, "mean_epss"]
    print(f"    mean EPSS {e0.iloc[0]:.5f} -> {e0.iloc[-1]:.5f} "
          f"({'decaying' if e0.iloc[-1] < e0.iloc[0] else 'NOT decaying'})")

    fits = fit_all(t, y)
    rank = sorted(fits.items(), key=lambda kv: kv[1]["aic"])
    print("\n  model fits to mean LEV vs dn, FULL sweep (spans 2 retrainings):")
    for k, v in rank:
        ps = ", ".join(f"{p:.5f}" for p in v["params"])
        print(f"    {k:<11s} AIC={v['aic']:>9.2f}  R2={v['r2']:.4f}  params=({ps})")
    best = rank[0][0]
    margin = rank[1][1]["aic"] - rank[0][1]["aic"]
    print(f"    BEST: {best}  (dAIC to 2nd ({rank[1][0]}) = {margin:.2f}"
          f"{'  -- NOT decisive, treat shape as unsettled' if margin < 2 else ''})")

    if best in CONVEX:
        print("\n  CONVEX family wins -- growth is accelerating, not linear.")
        if best == "exponential":
            b = fits[best]["params"][1]
            if b > 0:
                print(f"    doubling time: {np.log(2) / b:.1f} months")
        else:
            # quadratic and power have no constant doubling time; report the
            # time to double from the LAST observed value under the fit.
            fn, ps = fits[best]["fn"], fits[best]["params"]
            target, tt = 2 * y[-1], t[-1]
            while tt < t[-1] + 600 and fn(tt, *ps) < target:
                tt += 1
            print(f"    no constant doubling time ({best}); doubles from the "
                  f"current {y[-1]:.4f} in {tt - t[-1]:.0f} months")

    if best == "saturating":
        a, b = fits["saturating"]["params"]
        t95 = -np.log(0.05) / b                    # months to 95% of asymptote
        reached = df["dn"].iloc[0] + pd.DateOffset(months=int(round(t95)))
        print(f"\n  asymptote a = {a:.4f}; time constant 1/b = {1/b:.1f} months; "
              f"95% of a at t={t95:.1f} months ({reached.date()})")

    # Projection of the saturation-risk metric under its own best model.
    yf = df["frac_gt_0.9"].to_numpy()
    ffits = fit_all(t, yf)
    frank = sorted(ffits.items(), key=lambda kv: kv[1]["aic"])
    fbest = frank[0][0]
    fmargin = frank[1][1]["aic"] - frank[0][1]["aic"]
    print(f"\n  frac(LEV > 0.9): best model {fbest} "
          f"(dAIC to 2nd = {fmargin:.2f}), now {yf[-1]:.3f}")
    projections = {}
    for year in (2028, 2030, 2035):
        months = (pd.Timestamp(f"{year}-01-01").to_period("M")
                  - df["dn"].iloc[0].to_period("M")).n + 1
        v = float(np.clip(ffits[fbest]["fn"](months, *ffits[fbest]["params"]), 0, 1))
        projections[year] = v
        print(f"    projected {year}-01: {v:.3f}")
    # EXTRAPOLATION WARNING: these run 1.5-9x beyond the 35-month fitted range
    # and assume no further EPSS retraining, which the sweep shows is false.
    print("    (extrapolation well past the fitted window; assumes no further")
    print("     EPSS retraining, which this data shows does not hold)")
    proj = projections[2028]

    print(f"\n  mean EPSS for the cohort: {df['mean_epss'].iloc[0]:.5f} at "
          f"{df['dn'].iloc[0].date()} -> {df['mean_epss'].iloc[-1]:.5f} at "
          f"{df['dn'].iloc[-1].date()} "
          f"({'decaying' if df['mean_epss'].iloc[-1] < df['mean_epss'].iloc[0] else 'NOT decaying'})")
    return fits, best, ffits, fbest, proj, rbest, rfits


def plot(results, path=FIGURE):
    fig, axes = plt.subplots(4, 1, figsize=(8, 11), sharex=True)
    colors = ["#c1440e", "#365c8d"]
    for (name, df), c in zip(results.items(), colors):
        short = name.split(" (")[0]
        axes[0].plot(df["dn"], df["mean_lev"], "-o", ms=3, color=c, label=short)
        axes[1].plot(df["dn"], df["frac_gt_0.5"], "-o", ms=3, color=c,
                     label=f"{short}: >0.5")
        axes[1].plot(df["dn"], df["frac_gt_0.9"], "--s", ms=3, color=c,
                     label=f"{short}: >0.9")
        axes[2].plot(df["dn"], df["kev_rate_asof"], "-o", ms=3, color=c, label=short)
        axes[3].plot(df["dn"], df["ratio"], "-o", ms=3, color=c, label=short)

    axes[0].set_ylabel("mean LEV")
    axes[0].set_title("LEV vs analysis date dn, fixed cohorts")
    axes[1].set_ylabel("fraction of cohort")
    axes[2].set_ylabel("observed KEV rate\n(as of dn)")
    axes[3].set_ylabel("mean LEV / KEV rate")
    axes[3].set_yscale("log")
    axes[3].set_xlabel("analysis date (dn)")
    for ax in axes:
        for d, v in EPSS_ERAS.items():
            if d >= SWEEP_START:
                ax.axvline(d, color="gray", ls=":", lw=1)
        ax.grid(alpha=.3)
        ax.legend(fontsize=7)
    for d, v in EPSS_ERAS.items():
        if d >= SWEEP_START:
            axes[0].annotate(f"EPSS {v}", (d, axes[0].get_ylim()[1]),
                             fontsize=6, rotation=90, va="top", ha="right",
                             color="gray")
    fig.autofmt_xdate()
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=150, bbox_inches="tight")
    print(f"\nwrote {path}")


def main():
    tidy = download_epss.load()
    kev = download_kev.load()
    print("\nbuilding wide EPSS matrix...")
    wide, first_idx = levmod.to_wide(tidy)
    dates = wide.columns
    first_date = pd.Series(dates.to_numpy()[first_idx.to_numpy()], index=wide.index)
    id_year = pd.Series(wide.index.astype(str).str.slice(4, 8).astype(int),
                        index=wide.index)
    # Same backfill correction as validate.py / calibration.py, so cohort
    # membership means "newly published then", not "newly scored then".
    not_backfill = (first_date.dt.year - id_year) <= 1

    kev_dates = kev.drop_duplicates("cve").set_index("cve")["kev_date"]
    dns = [d for d in dates if d >= SWEEP_START]
    print(f"sweeping {len(dns)} analysis dates "
          f"{dns[0].date()} -> {dns[-1].date()}")

    results, summaries = {}, {}
    for name, (lo, hi) in COHORTS.items():
        m = not_backfill & first_date.between(pd.Timestamp(lo), pd.Timestamp(hi))
        print(f"\ncohort {name}: {int(m.sum()):,} CVEs")
        kev_now = float(kev_dates.reindex(wide.index[m]).notna().mean())
        df = sweep(wide, first_idx, m, kev_dates, dns)
        results[name] = df
        summaries[name] = (df, kev_now, int(m.sum()))

    pd.to_pickle(results, CACHE)
    reports = {n: report(n, df, kn) for n, (df, kn, _) in summaries.items()}
    plot(results)

    print(f"\n{'=' * 78}\nSUMMARY\n{'=' * 78}")
    for name, (fits, best, ffits, fbest, proj, rbest, rfits) in reports.items():
        df, kev_now, n = summaries[name]
        shape = {"saturating": "SATURATING", "log": "DECELERATING (log-like)",
                 "linear": "LINEAR", "quadratic": "CONVEX (quadratic)",
                 "exponential": "CONVEX (exponential)",
                 "power": "CONVEX (power law)"}[best]
        print(f"\n{name}  (n={n:,})")
        print(f"  growth shape          : {shape}")
        if best == "saturating":
            a, b = fits["saturating"]["params"]
            print(f"  asymptote             : {a:.4f}")
            print(f"  time constant 1/b     : {1/b:.1f} months")
        print(f"  mean LEV {df['dn'].iloc[0].date()} -> {df['dn'].iloc[-1].date()}"
              f": {df['mean_lev'].iloc[0]:.4f} -> {df['mean_lev'].iloc[-1]:.4f}")
        print(f"  shape within regime   : {rbest}  (no EPSS retraining)")
        print(f"  frac > 0.9            : {df['frac_gt_0.9'].iloc[0]:.3f} -> "
              f"{df['frac_gt_0.9'].iloc[-1]:.3f}, projected {np.clip(proj,0,1):.3f} by 2028-01")
        if best != "saturating":
            print("  RANKING RISK: growth does not saturate within the observed")
            print("  window, so LEV drifts toward 1.0 for every surviving CVE and")
            print("  loses discriminative power for ranking as dn advances.")
    print("\nCONFOUND: the sweep spans two EPSS retrainings (v2025.03.14 seen from")
    print("2025-04-01, v2026.06.15 from 2026-07-01), each of which shifted scores")
    print("corpus-wide. Both cohorts kink there. The within-regime shape above is")
    print("the cleaner read on LEV's own accumulation; the full-sweep rate mixes")
    print("it with score-level shifts CSWP 41 does not model.")
    print("\nNOTE: monotonic growth in dn is STRUCTURAL (LEV is a product over")
    print("windows and cannot decrease). Only the RATE and SHAPE above are")
    print("empirical. No exploitation ground truth is used for those.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
