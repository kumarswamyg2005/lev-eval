"""Task B-prime -- how LEV behaves as the analysis date dn advances.

LEV(v, d0, dn) is a product over 30-day windows and therefore cannot decrease
in dn: the *direction* is structural, not a finding.  What is empirical is the
RATE -- whether growth is linear, decelerating, or saturating -- and that is
measurable from EPSS alone, with no exploitation ground truth, so it is not
confounded by KEV incompleteness.

Two fixed cohorts are swept: one born in the EPSS v3 era, one in the v1/v2 era.

Run: python analysis/dn_sweep.py
"""

import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from scipy import optimize, stats

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from data import download_epss, download_kev
from models import lev as levmod

ROOT = Path(__file__).resolve().parent.parent
FIGURE = ROOT / "figures" / "dn_sweep.png"
FIG_APPX = ROOT / "figures" / "dn_sweep_appendix.png"
CACHE = ROOT / "cache" / "dn_sweep.pkl"
RESULTS = ROOT / "results" / "dn_sweep.json"

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
# Actual deployment days (first daily file carrying the new model; see
# analysis/epss_drift.py), used for figure annotation only.
RELEASES = {pd.Timestamp("2025-03-17"): "EPSS v4",
            pd.Timestamp("2026-06-15"): "EPSS v5"}
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


def f_sat3(t, a, b, c):
    """Saturating growth with an intercept: a + b*(1-exp(-c*t)), asymptote a+b.

    The two-parameter f_sat is pinned to 0 at t=0, but the cohorts already
    carry LEV at the first sweep date, so f_sat could only lose.  This is the
    fair concave competitor."""
    return a + b * (1.0 - np.exp(-c * t))


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


def fit_all(t, y, only=None):
    """Fit every growth family, return {name: {params, aic, r2, fn}}.
    `only` restricts to the named families (used by the bootstrap)."""
    out = {}
    slope = (y[-1] - y[0]) / max(t[-1], 1)
    specs = [("linear", f_linear, [y[0], slope], (-np.inf, np.inf)),
             ("log", f_log, [y[0], y[-1] - y[0]], (-np.inf, np.inf)),
             # asymptote allowed anywhere in (0, 1]; LEV is a probability
             ("saturating", f_sat, [max(y[-1] * 1.5, 1e-3), 0.05],
              ([1e-6, 1e-6], [1.0, 5.0])),
             ("saturating3", f_sat3,
              [y[0], max(2 * (y[-1] - y[0]), 1e-4), 0.05],
              ([-1.0, 1e-8, 1e-6], [1.0, 1.0, 5.0])),
             ("quadratic", f_quad, [y[0], slope, 0.0], (-np.inf, np.inf)),
             ("exponential", f_exp, [max(y[0], 1e-6),
                                     np.log(max(y[-1], 1e-9) / max(y[0], 1e-9))
                                     / max(t[-1], 1)],
              ([1e-12, -1.0], [10.0, 1.0])),
             ("power", f_pow, [max(y[0], 1e-6), 1.0],
              ([1e-12, -5.0], [10.0, 10.0]))]
    for name, fn, p0, bounds in specs:
        if only is not None and name not in only:
            continue
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


# ------------------------------------------------ autocorrelation-robust tests
# The ~35 monthly means are a cumulative series: residuals from any smooth fit
# are strongly autocorrelated (lag-1 ~0.7), so Gaussian AIC treats far fewer
# effective observations as independent ones.  Two corrections:
#   * HAC (Newey-West) standard error on the quadratic term -- curvature test;
#   * moving-block residual bootstrap: simulate each concave/linear null with
#     its own block-resampled residuals and ask how often it produces a
#     quadratic AIC advantage as large as the observed one.
BOOT = 499
BLOCK = 4                       # ~ n^(1/3) for n = 35
RNG_SEED = 20261011


def lag1(e):
    e = np.asarray(e) - np.mean(e)
    return float(np.sum(e[1:] * e[:-1]) / np.sum(e * e))


def hac_quadratic(t, y, lags=(3, 6)):
    """OLS quadratic; z of the t^2 coefficient with Newey-West SEs."""
    X = np.column_stack([np.ones_like(t), t, t ** 2])
    beta, *_ = np.linalg.lstsq(X, y, rcond=None)
    e = y - X @ beta
    XtXi = np.linalg.inv(X.T @ X)
    out = {"c": float(beta[2]), "lag1_resid": lag1(e)}
    for L in lags:
        Xe = X * e[:, None]
        S = Xe.T @ Xe
        for l in range(1, L + 1):
            G = Xe[l:].T @ Xe[:-l]
            S += (1 - l / (L + 1)) * (G + G.T)
        se = float(np.sqrt((XtXi @ S @ XtXi)[2, 2]))
        out[f"z_hac{L}"] = float(beta[2] / se)
        out[f"p_hac{L}"] = float(2 * stats.norm.sf(abs(beta[2] / se)))
    return out


def _mbb(e, rng, block=BLOCK):
    """Moving-block resample of residual vector e (same length)."""
    n = len(e)
    starts = rng.integers(0, n - block + 1, size=int(np.ceil(n / block)))
    return np.concatenate([e[s:s + block] for s in starts])[:n]


def robust_compare(t, y, nulls=("linear", "saturating3", "log"), boot=BOOT,
                   seed=RNG_SEED):
    """Block-bootstrap check of the quadratic's AIC advantage.

    p_null[H0] = share of series simulated under H0 (fitted H0 + block-resampled
    H0 residuals) whose quadratic-vs-H0 AIC gap >= the observed gap.  support =
    share of series simulated under the quadratic fit in which each family
    has the lowest AIC (how stable the 'winner' is under dependent noise)."""
    rng = np.random.default_rng(seed)
    fits = fit_all(t, y)
    out = {"aic": {k: v["aic"] for k, v in fits.items()},
           "lag1_resid": {k: lag1(y - v["fn"](t, *v["params"]))
                          for k, v in fits.items()},
           "hac": hac_quadratic(t, y), "p_null": {}, "dAIC_obs": {}}
    q = fits["quadratic"]
    for h in nulls:
        if h not in fits:
            continue
        f = fits[h]
        yhat = f["fn"](t, *f["params"])
        e = y - yhat
        e = e - e.mean()
        obs = f["aic"] - q["aic"]
        hits = 0
        for _ in range(boot):
            fb = fit_all(t, yhat + _mbb(e, rng), only=(h, "quadratic"))
            if h in fb and "quadratic" in fb:
                hits += (fb[h]["aic"] - fb["quadratic"]["aic"]) >= obs
        out["dAIC_obs"][h] = float(obs)
        out["p_null"][h] = (hits + 1) / (boot + 1)
    yq = q["fn"](t, *q["params"])
    eq = (y - yq) - (y - yq).mean()
    wins = {}
    for _ in range(boot):
        fb = fit_all(t, yq + _mbb(eq, rng))
        b = min(fb, key=lambda k: fb[k]["aic"])
        wins[b] = wins.get(b, 0) + 1
    out["support"] = {k: v / boot for k, v in sorted(wins.items())}
    return out


def print_robust(r, indent="    "):
    h = r["hac"]
    print(f"{indent}residual lag-1 autocorrelation: " + ", ".join(
        f"{k} {v:+.2f}" for k, v in r["lag1_resid"].items()))
    print(f"{indent}quadratic t^2 coef {h['c']:+.2e}: HAC z = {h['z_hac3']:.2f} "
          f"(p={h['p_hac3']:.3g}, 3 lags), {h['z_hac6']:.2f} "
          f"(p={h['p_hac6']:.3g}, 6 lags)")
    for k, p in r["p_null"].items():
        print(f"{indent}block bootstrap, null={k:<11s}: dAIC obs "
              f"{r['dAIC_obs'][k]:6.2f}, p = {p:.3f}")
    print(f"{indent}bootstrap support for best family (under quadratic fit): "
          + ", ".join(f"{k} {v:.0%}" for k, v in r["support"].items()))


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
    print("    autocorrelation-robust comparison (within regime):")
    robust_reg = robust_compare(treg - treg[0] + 1, yreg)
    print_robust(robust_reg, indent="      ")
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
    print("    autocorrelation-robust comparison (full sweep):")
    robust_full = robust_compare(t, y)
    print_robust(robust_full)

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
    return (fits, best, ffits, fbest, proj, rbest, rfits,
            {"full": robust_full, "regime": robust_reg})


def never_listed(wide, mask, dns, kev_dates):
    """Cohort mean / median EPSS at each dn for CVEs never on CISA KEV, and
    never on any exploitation list.  This is the white paper's premise ('EPSS
    decays for old CVEs') tested where KEV feedback cannot drive the score."""
    idx = wide.index[mask]
    groups = {"all": idx, "never_kev": idx[~idx.isin(kev_dates.index)]}
    try:   # read-only use of the Phase 2 list loader; skipped if unavailable
        from analysis import capture_recapture
        lists = capture_recapture.exploitation_lists(dn=pd.Timestamp("2100-01-01"))
        listed = set().union(*[set(v.index) for v in lists.values()])
        groups["never_any_list"] = idx[~idx.isin(listed)]
        groups_note = "lists: " + ", ".join(lists)
    except Exception as exc:                       # noqa: BLE001
        groups_note = f"any-list group skipped ({type(exc).__name__}: {exc})"
    out = {}
    for g, ix in groups.items():
        sub = wide.loc[ix, dns]
        out[g] = pd.DataFrame({"n": len(ix), "mean_epss": sub.mean(),
                               "median_epss": sub.median()})
    return out, groups_note


def regime_change(series, lo, hi):
    """Start, end and OLS slope/month of a series restricted to [lo, hi]."""
    s = series[(series.index >= lo) & (series.index <= hi)]
    sl = stats.linregress(np.arange(len(s)), s.to_numpy())
    return {"from": str(s.index[0].date()), "to": str(s.index[-1].date()),
            "start": float(s.iloc[0]), "end": float(s.iloc[-1]),
            "slope_per_month": float(sl.slope), "slope_p": float(sl.pvalue)}


V4_REGIME = (pd.Timestamp("2025-04-01"), pd.Timestamp("2026-06-01"))


def _releases(ax, label=False):
    for d, v in RELEASES.items():
        ax.axvline(d, color="gray", ls=":", lw=1)
        if label:
            ax.annotate(v, (d, 1), xycoords=("data", "axes fraction"),
                        xytext=(-3, -3), textcoords="offset points",
                        fontsize=8, va="top", ha="right", color="gray")


def plot(results, path=FIGURE):
    """Main figure: one panel, mean LEV for the two fixed cohorts."""
    import matplotlib.dates as mdates
    fig, ax = plt.subplots(figsize=(6.5, 3.6))
    for (name, df), c in zip(results.items(), ["#c1440e", "#365c8d"]):
        ax.plot(df["dn"], df["mean_lev"], "-o", ms=3, color=c,
                label=name.replace("first EPSS", "first scored"))
    _releases(ax, label=True)
    ax.set_ylabel("cohort mean LEV")
    ax.set_xlabel("analysis date")
    ax.set_ylim(bottom=0)
    ax.grid(alpha=.3)
    ax.legend(fontsize=8, loc="center left")
    ax.xaxis.set_major_locator(mdates.MonthLocator(bymonth=(1, 7)))
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%b %Y"))
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=150, bbox_inches="tight")
    fig.savefig(path.with_suffix(".pdf"), bbox_inches="tight")
    print(f"\nwrote {path} and .pdf")


def plot_appendix(results, nl, path=FIG_APPX):
    """Appendix: threshold shares, KEV rate, LEV/KEV ratio, never-listed EPSS."""
    import matplotlib.dates as mdates
    from matplotlib.ticker import FuncFormatter, LogLocator, NullFormatter
    fig, axes = plt.subplots(4, 1, figsize=(6.5, 10), sharex=True)
    colors = ["#c1440e", "#365c8d"]
    for (name, df), c in zip(results.items(), colors):
        short = name.split(" (")[0] + " cohort"
        axes[0].plot(df["dn"], df["frac_gt_0.5"], "-o", ms=3, color=c,
                     label=f"{short}: LEV > 0.5")
        axes[0].plot(df["dn"], df["frac_gt_0.9"], "--s", ms=3, color=c,
                     label=f"{short}: LEV > 0.9")
        axes[1].plot(df["dn"], df["kev_rate_asof"], "-o", ms=3, color=c, label=short)
        axes[2].plot(df["dn"], df["ratio"], "-o", ms=3, color=c, label=short)
        g = nl[name]
        axes[3].plot(g["all"].index, g["all"]["mean_epss"], "-", color=c,
                     lw=1, alpha=.5, label=f"{short}: all")
        axes[3].plot(g["never_kev"].index, g["never_kev"]["mean_epss"], "-o",
                     ms=3, color=c, label=f"{short}: never on KEV")
        if "never_any_list" in g:
            axes[3].plot(g["never_any_list"].index,
                         g["never_any_list"]["mean_epss"], "--", color=c,
                         lw=1, label=f"{short}: never on any list")
    axes[0].set_ylabel("share of cohort")
    axes[1].set_ylabel("KEV rate\n(as of analysis date)")
    axes[2].set_ylabel("mean LEV / KEV rate")
    axes[2].set_yscale("log")
    axes[2].yaxis.set_major_locator(LogLocator(base=10, subs=(1, 2, 5)))
    axes[2].yaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:g}"))
    axes[2].yaxis.set_minor_formatter(NullFormatter())
    axes[3].set_ylabel("cohort mean EPSS")
    axes[3].set_xlabel("analysis date")
    for i, ax in enumerate(axes):
        _releases(ax, label=(i == 0))
        ax.grid(alpha=.3)
        ax.legend(fontsize=7)
    axes[-1].xaxis.set_major_locator(mdates.MonthLocator(bymonth=(1, 7)))
    axes[-1].xaxis.set_major_formatter(mdates.DateFormatter("%b %Y"))
    fig.savefig(path, dpi=150, bbox_inches="tight")
    fig.savefig(path.with_suffix(".pdf"), bbox_inches="tight")
    print(f"wrote {path} and .pdf")


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

    results, summaries, masks = {}, {}, {}
    for name, (lo, hi) in COHORTS.items():
        m = not_backfill & first_date.between(pd.Timestamp(lo), pd.Timestamp(hi))
        print(f"\ncohort {name}: {int(m.sum()):,} CVEs")
        kev_now = float(kev_dates.reindex(wide.index[m]).notna().mean())
        df = sweep(wide, first_idx, m, kev_dates, dns)
        results[name] = df
        summaries[name] = (df, kev_now, int(m.sum()))
        masks[name] = m

    pd.to_pickle(results, CACHE)
    reports = {n: report(n, df, kn) for n, (df, kn, _) in summaries.items()}

    # ---- the cleaner test of the decay premise: never-listed CVEs ---------
    print(f"\n{'=' * 78}\nEPSS TRAJECTORY OF NEVER-LISTED CVEs (decay premise)\n{'=' * 78}")
    nl, nl_out = {}, {}
    for name, m in masks.items():
        groups, note = never_listed(wide, m, dns, kev_dates)
        nl[name] = groups
        print(f"\n{name}   ({note})")
        nl_out[name] = {}
        for g, df in groups.items():
            rec = {"n": int(df["n"].iloc[0])}
            for stat in ("mean_epss", "median_epss"):
                rec[stat] = {
                    "first": float(df[stat].iloc[0]), "last": float(df[stat].iloc[-1]),
                    "v3_regime": regime_change(df[stat], *REGIME),
                    "v4_regime": regime_change(df[stat], *V4_REGIME)}
            nl_out[name][g] = rec
            mm = rec["mean_epss"]
            print(f"  {g:<15s} n={rec['n']:>6,}  mean EPSS {mm['first']:.5f} -> "
                  f"{mm['last']:.5f}   within v3 {mm['v3_regime']['start']:.5f} -> "
                  f"{mm['v3_regime']['end']:.5f} ({mm['v3_regime']['slope_per_month']:+.2e}/mo, "
                  f"p={mm['v3_regime']['slope_p']:.2g})   within v4 "
                  f"{mm['v4_regime']['start']:.5f} -> {mm['v4_regime']['end']:.5f} "
                  f"({mm['v4_regime']['slope_per_month']:+.2e}/mo)")
            md = rec["median_epss"]
            print(f"  {'':<15s}           median {md['first']:.5f} -> {md['last']:.5f}"
                  f"   within v3 {md['v3_regime']['start']:.5f} -> {md['v3_regime']['end']:.5f}"
                  f"   within v4 {md['v4_regime']['start']:.5f} -> {md['v4_regime']['end']:.5f}")

    plot(results)
    plot_appendix(results, nl)

    def fitsum(f):
        return {k: {"aic": v["aic"], "r2": v["r2"],
                    "params": [float(x) for x in v["params"]]} for k, v in f.items()}
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(json.dumps({
        name: {"n": summaries[name][2],
               "series": summaries[name][0].assign(
                   dn=summaries[name][0]["dn"].astype(str)).to_dict("records"),
               "fits_full": fitsum(r[0]), "fits_regime": fitsum(r[6]),
               "robust": r[7], "never_listed": nl_out[name]}
        for name, r in reports.items()},
        indent=1, default=lambda o: o.item() if hasattr(o, "item") else str(o)))
    print(f"wrote {RESULTS}")

    print(f"\n{'=' * 78}\nSUMMARY\n{'=' * 78}")
    for name, (fits, best, ffits, fbest, proj, rbest, rfits, _) in reports.items():
        df, kev_now, n = summaries[name]
        shape = {"saturating": "SATURATING", "saturating3": "SATURATING (intercept)",
                 "log": "DECELERATING (log-like)",
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
