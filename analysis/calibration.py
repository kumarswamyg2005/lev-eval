"""Task 5 -- is LEV calibrated against observed CISA KEV appearance?

Bins CVEs by their LEV score and compares the mean predicted probability in
each bin against the fraction that actually appear in KEV, plus overall Brier
score and Expected Calibration Error.

Run: python analysis/calibration.py
"""

import argparse
import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from scipy import stats

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from data import download_epss, download_kev
from models import lev as levmod

ROOT = Path(__file__).resolve().parent.parent
FIGURE = ROOT / "figures" / "reliability.png"
RESULTS = ROOT / "results" / "calibration.json"

EPSS_V3 = pd.Timestamp("2023-03-07")
CENSOR_DAYS = 183          # "at least 6 months old"
BINS = np.linspace(0, 1, 11)


def cohort(wide, first_idx, dn, censor_days=CENSOR_DAYS):
    """CVEs in the EPSS v3 era, old enough not to be right-censored.

    Returns a boolean mask over wide.index.
    """
    dates = wide.columns
    first_date = pd.Series(dates.to_numpy()[first_idx.to_numpy()],
                           index=wide.index)

    # Same backfill correction as validate.py: EPSS expands coverage
    # retroactively, so a CVE whose first score arrives long after its CVE-ID
    # year is an old CVE being backfilled, not a new publication.  Including
    # them would mix pre-v3 vulnerabilities into a v3-era cohort.
    id_year = pd.Series(wide.index.astype(str).str.slice(4, 8).astype(int),
                        index=wide.index)
    new = first_date.dt.year - id_year <= 1

    # Right-censoring control: KEV entries lag exploitation, so a CVE first
    # scored last month has had no chance to appear.  ASSUMPTION (not in
    # CSWP 41): 6 months is enough lag.  It is a floor, not a guarantee --
    # KEV additions trail real-world exploitation by an unbounded amount.
    mature = first_date <= dn - pd.Timedelta(days=censor_days)
    return (first_date >= EPSS_V3) & new & mature


def poisson_ci(k, alpha=0.05):
    """Exact (Garwood) interval on a Poisson count k."""
    return (stats.chi2.ppf(alpha / 2, 2 * k) / 2 if k else 0.0,
            stats.chi2.ppf(1 - alpha / 2, 2 * k + 2) / 2)


def wilson_ci(k, n, alpha=0.05):
    """Wilson score interval for a binomial proportion k/n.

    Chosen over bootstrap and the normal approximation because several buckets
    hold 7-24 KEV hits: the normal interval undercovers badly and can run
    negative at these counts, and a bootstrap of a near-zero proportion just
    resamples the same handful of successes.  Wilson stays inside [0, 1] and
    keeps nominal coverage down to single-digit counts.
    """
    if n == 0:
        return (np.nan, np.nan)
    z = stats.norm.ppf(1 - alpha / 2)
    p = k / n
    denom = 1 + z ** 2 / n
    centre = (p + z ** 2 / (2 * n)) / denom
    half = z / denom * np.sqrt(p * (1 - p) / n + z ** 2 / (4 * n ** 2))
    return (max(0.0, centre - half), min(1.0, centre + half))


def reliability(pred, observed, bins=BINS):
    """Per-bucket mean predicted probability vs observed KEV fraction."""
    idx = np.clip(np.digitize(pred, bins) - 1, 0, len(bins) - 2)
    rows = []
    for b in range(len(bins) - 1):
        m = idx == b
        n, k = int(m.sum()), int(observed[m].sum())
        lo, hi = wilson_ci(k, n)
        obs = observed[m].mean() if m.any() else np.nan
        p = pred[m].mean() if m.any() else np.nan
        rows.append({
            "bucket": f"[{bins[b]:.1f}, {bins[b+1]:.1f})",
            "n": n,
            "predicted": p,
            "observed": obs,
            "obs_lo": lo,
            "obs_hi": hi,
            "n_in_kev": k,
            "obs_pred_ratio": obs / p if p else np.nan,
        })
    table = pd.DataFrame(rows)
    # Every prediction must land in exactly one bucket.  np.digitize with the
    # top edge clipped in does this; pd.cut(right=False) would silently drop
    # LEV == 1.0, which is 0.3-0.5% of the cohort and ~30% of the KEV hits.
    assert int(table["n"].sum()) == len(pred), (
        f"binning lost rows: {int(table['n'].sum())} != {len(pred)}")
    assert int(table["n_in_kev"].sum()) == int(np.asarray(observed).sum()), (
        "binning lost KEV entries")
    return table


def significance(table):
    """Adjacent-bucket comparisons: Fisher exact (exact at these counts) with
    Holm correction, plus whether the Wilson intervals overlap.

    CI overlap is the conservative read -- non-overlapping intervals imply a
    significant difference, but overlapping ones do not imply the opposite --
    so both are printed.
    """
    rows = []
    occ = table[table["n"] > 0].reset_index(drop=True)
    for i in range(len(occ) - 1):
        a, b = occ.iloc[i], occ.iloc[i + 1]
        _, p = stats.fisher_exact([[a["n_in_kev"], a["n"] - a["n_in_kev"]],
                                   [b["n_in_kev"], b["n"] - b["n_in_kev"]]])
        rows.append({"pair": f"{a['bucket']} vs {b['bucket']}",
                     "obs_a": a["observed"], "obs_b": b["observed"],
                     "p_fisher": p,
                     "ci_overlap": not (a["obs_hi"] < b["obs_lo"]
                                        or b["obs_hi"] < a["obs_lo"])})
    out = pd.DataFrame(rows)
    # Holm-Bonferroni across the 9 adjacent comparisons
    order = np.argsort(out["p_fisher"].to_numpy())
    m = len(out)
    adj = np.empty(m)
    running = 0.0
    for rank, idx in enumerate(order):
        running = max(running, (m - rank) * out["p_fisher"].iloc[idx])
        adj[idx] = min(1.0, running)
    out["p_holm"] = adj
    out["signif"] = np.where(out["p_holm"] < 0.05, "YES", "no")
    return out


def trend_test(table, scores="index"):
    """Cochran-Armitage test for a linear trend in KEV rate across buckets.

    The adjacent-pair Fisher tests above can only say whether two NEIGHBOURING
    buckets differ; failing to reject is not evidence of a flat stretch.  The
    trend test asks the ranking question directly: does the KEV rate rise with
    the bucket over the rows given?  scores = "index" (0, 1, ...) or "predicted"
    (bucket mean LEV).  Returns {z, p (two-sided), p_one (increasing)}.
    """
    t = table[table["n"] > 0]
    n, k = t["n"].to_numpy(float), t["n_in_kev"].to_numpy(float)
    s = (np.arange(len(t), dtype=float) if scores == "index"
         else t["predicted"].to_numpy(float))
    N, K = n.sum(), k.sum()
    pbar = K / N
    T = float(np.sum(s * (k - n * pbar)))
    var = pbar * (1 - pbar) * (np.sum(n * s ** 2) - np.sum(n * s) ** 2 / N)
    z = T / np.sqrt(var)
    return {"buckets": list(t["bucket"]), "scores": scores, "z": float(z),
            "p": float(2 * stats.norm.sf(abs(z))), "p_one": float(stats.norm.sf(z))}


def ratio_row(pred, y):
    """n, mean LEV, KEV rate and ratio with an exact Poisson interval on k."""
    pred, y = np.asarray(pred, float), np.asarray(y, float)
    k = int(y.sum())
    lo, hi = poisson_ci(k)
    return {"n": len(pred), "mean_lev": float(pred.mean()), "n_kev": k,
            "kev_rate": float(y.mean()),
            "ratio": float(pred.sum() / k) if k else np.nan,
            "ratio_lo": float(pred.sum() / hi),
            "ratio_hi": float(pred.sum() / lo) if lo else np.inf}


AGE_BANDS = [(6, 12), (12, 24), (24, 999)]     # months since first EPSS score


def age_bands(pred, y, age_months):
    """Calibration by CVE age at dn: the pooled 17.3x mixes 6- to 41-month-old
    CVEs, and LEV accumulates windows with age."""
    out = []
    for lo, hi in AGE_BANDS:
        m = (age_months >= lo) & (age_months < hi)
        r = ratio_row(pred[m], y[m])
        r["band"] = f"{lo}-{hi if hi < 999 else ''} months"
        r["top_bucket_rate"] = (float(y[m & (pred >= 0.9)].mean())
                                if (m & (pred >= 0.9)).any() else np.nan)
        out.append(r)
    return out


def dip_check(table, lo="[0.5, 0.6)"):
    """Is the [0.5, 0.6) dip signal or noise? Compare it to both neighbours."""
    occ = table[table["n"] > 0].reset_index(drop=True)
    i = occ.index[occ["bucket"] == lo]
    if len(i) == 0:
        return
    i = int(i[0])
    row = occ.iloc[i]
    print(f"\n--- is the {lo} dip real? ---")
    print(f"  {lo}: {row['n_in_kev']} of {row['n']:,} in KEV = "
          f"{row['observed']:.4f}  95% Wilson [{row['obs_lo']:.4f}, {row['obs_hi']:.4f}]")
    verdicts = []
    for j in (i - 1, i + 1):
        if not 0 <= j < len(occ):
            continue
        nb = occ.iloc[j]
        _, p = stats.fisher_exact([[row["n_in_kev"], row["n"] - row["n_in_kev"]],
                                   [nb["n_in_kev"], nb["n"] - nb["n_in_kev"]]])
        overlap = not (row["obs_hi"] < nb["obs_lo"] or nb["obs_hi"] < row["obs_lo"])
        verdicts.append(overlap and p >= 0.05)
        print(f"  vs {nb['bucket']}: {nb['observed']:.4f} "
              f"[{nb['obs_lo']:.4f}, {nb['obs_hi']:.4f}]  "
              f"Fisher p={p:.3f}  CI overlap={overlap}")
    if all(verdicts):
        print(f"  VERDICT: the {lo} dip is NOISE, not signal. Its Wilson "
              f"interval overlaps both\n           neighbours and neither "
              f"Fisher test rejects at 0.05. With "
              f"{int(row['n_in_kev'])} KEV hits\n           in "
              f"{int(row['n']):,} CVEs the bucket cannot resolve a difference "
              f"of this size.")
    else:
        print("  VERDICT: the dip separates from at least one neighbour.")


def evaluate(pred, obs):
    """(bucket table, Brier, ECE) for aligned prediction/outcome arrays."""
    p, y = np.asarray(pred, float), np.asarray(obs, float)
    table = reliability(p, y)
    brier = float(np.mean((p - y) ** 2))
    ece = float(np.sum(table["n"] / len(p)
                       * (table["predicted"] - table["observed"]).abs().fillna(0)))
    return table, brier, ece


def plot(table, brier, ece, n, path=FIGURE):
    """Reliability diagram on log-log axes.

    Observed rates run 0.0003-0.13 against predictions of 0.01-0.99; on linear
    axes every point sat in the bottom 15%.  Log axes keep the diagonal and
    show the factor gap directly (one decade = 10x).  Brier/ECE go in the
    caption, not a title.
    """
    from matplotlib.ticker import FuncFormatter, NullFormatter
    ok = table["n"] > 0
    fig, (ax, axh) = plt.subplots(
        2, 1, figsize=(5.5, 6), sharex=True,
        gridspec_kw={"height_ratios": [3, 1], "hspace": 0.08})

    lim = (1e-4, 1.0)
    ax.plot(lim, lim, "--", color="gray", lw=1, label="perfect calibration")
    for f in (10, 100):
        ax.plot(lim, np.array(lim) / f, ":", color="gray", lw=.8)
        ax.annotate(f"{f}x over", (0.6, 0.6 / f), fontsize=7, color="gray",
                    ha="right", va="bottom")
    t = table[ok]
    lo = np.maximum(t["obs_lo"], lim[0])     # Wilson lower bound can be 0
    ax.errorbar(t["predicted"], t["observed"],
                yerr=[t["observed"] - lo, t["obs_hi"] - t["observed"]],
                fmt="o-", color="#c1440e", ecolor="#c1440e", capsize=3,
                lw=1.5, ms=5, label="LEV vs KEV (95% Wilson)")
    ax.set_xscale("log"); ax.set_yscale("log")
    ax.set_ylabel("observed fraction in CISA KEV")
    ax.set_xlim(5e-3, 1.2); ax.set_ylim(*lim)
    ax.grid(alpha=.3, which="major"); ax.legend(loc="upper left", fontsize=8)

    axh.bar(t["predicted"], t["n"], width=t["predicted"] * 0.12,
            color="#365c8d")
    axh.set_yscale("log")
    axh.set_ylabel("CVEs")
    axh.set_xlabel("mean predicted LEV in bucket")
    axh.grid(alpha=.3, which="major")
    plain = FuncFormatter(lambda v, _: f"{v:g}")
    for a in (ax, axh):
        a.xaxis.set_major_formatter(plain)
        a.xaxis.set_minor_formatter(NullFormatter())
    ax.yaxis.set_major_formatter(plain)

    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=150, bbox_inches="tight")
    fig.savefig(path.with_suffix(".pdf"), bbox_inches="tight")
    print(f"\nwrote {path} and .pdf")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dn", default=None, help="analysis date; default latest")
    args = ap.parse_args()

    tidy = download_epss.load()
    kev = download_kev.load()

    print("building wide EPSS matrix...")
    wide, first_idx = levmod.to_wide(tidy)
    dn = pd.Timestamp(args.dn) if args.dn else wide.columns[-1]
    print(f"  {wide.shape[0]:,} CVEs x {wide.shape[1]} snapshots, dn = {dn.date()}")

    m = cohort(wide, first_idx, dn)
    print(f"cohort: {int(m.sum()):,} CVEs (EPSS v3 era, >= {CENSOR_DAYS}d old)")

    print("computing LEV...")
    pred = levmod.lev(wide[m], first_idx[m], dn=dn)
    # OBSERVED: ever added to KEV on or before dn.  THREAT TO VALIDITY: KEV is
    # a lower bound on real exploitation -- CISA only lists what it confirms
    # and prioritises -- so "observed" understates the truth by an unknown
    # factor and every calibration number below is pessimistic by that factor.
    in_kev = set(kev.loc[kev["kev_date"] <= dn, "cve"])
    obs = pd.Series(pred.index.isin(in_kev).astype(float), index=pred.index)

    p, y = pred.to_numpy(), obs.to_numpy()
    table, brier, ece = evaluate(p, y)

    print(f"\n=== LEV reliability, {len(p):,} CVEs, {int(y.sum())} in KEV "
          f"(base rate {y.mean():.5f}) ===")
    print(table.to_string(index=False, na_rep="-",
                          float_format=lambda v: f"{v:.4f}"))
    print("\n--- adjacent-bucket differences (Fisher exact, Holm-corrected) ---")
    sig = significance(table)
    print(sig.to_string(index=False, float_format=lambda v: f"{v:.4f}"))
    n_sig = int((sig["signif"] == "YES").sum())
    print(f"  {n_sig} of {len(sig)} adjacent pairs significant after Holm "
          f"correction: "
          + ", ".join(sig.loc[sig['signif'] == 'YES', 'pair']) if n_sig else
          "  no adjacent pair is significant after Holm correction")

    dip_check(table)

    print(f"\nBrier score               : {brier:.5f}")
    print(f"Expected Calibration Error: {ece:.5f}")
    print(f"mean predicted / observed : {p.mean():.5f} / {y.mean():.5f} "
          f"(ratio {p.mean()/max(y.mean(), 1e-12):.1f}x)")
    lo, hi = poisson_ci(int(y.sum()))
    print(f"  95% interval on the ratio (Poisson error on the {int(y.sum())} KEV CVEs): "
          f"{p.sum() / hi:.1f}x - {p.sum() / lo:.1f}x")

    # ---- trend test: does LEV rank inside the middle range? -------------
    print("\n--- Cochran-Armitage trend test (KEV rate rising with bucket) ---")
    trends = {}
    for label, rows in [("all", slice(None)), ("middle [0.1,0.9)", slice(1, 9))]:
        for sc in ("index", "predicted"):
            r = trend_test(table.iloc[rows], sc)
            trends[f"{label}, scores={sc}"] = r
            print(f"  {label:<17s} scores={sc:<9s}: z = {r['z']:6.2f}  "
                  f"p = {r['p']:.2e}  ({len(r['buckets'])} buckets)")
    print("  The adjacent-pair tests above do not show a flat middle: failing to")
    print("  separate neighbours is not evidence of no ranking.")

    # ---- calibration by CVE age at dn ------------------------------------
    first_date = pd.Series(wide.columns.to_numpy()[first_idx[m].to_numpy()],
                           index=pred.index)
    age = ((dn - first_date).dt.days / 30.44).to_numpy()
    bands = age_bands(p, y, age)
    print(f"\n--- calibration by CVE age at dn ({dn.date()}) ---")
    for r in bands:
        print(f"  {r['band']:<13s} n={r['n']:>6,}  mean LEV {r['mean_lev']:.4f}  "
              f"KEV {r['n_kev']:>3} ({r['kev_rate']:.5f})  ratio {r['ratio']:.1f}x "
              f"[{r['ratio_lo']:.1f}, {r['ratio_hi']:.1f}]  "
              f"KEV rate at LEV>=0.9: {r['top_bucket_rate']:.3f}")

    # ---- maturity-window sensitivity --------------------------------------
    print("\n--- maturity window (minimum age at dn) sensitivity ---")
    maturity = []
    for months, days in ((3, 91), (6, CENSOR_DAYS), (12, 365)):
        mm = cohort(wide, first_idx, dn, censor_days=days)
        pp = pred if days == CENSOR_DAYS else levmod.lev(
            wide[mm], first_idx[mm], dn=dn)
        yy = pp.index.isin(in_kev).astype(float)
        r = ratio_row(pp.to_numpy(), yy)
        top = pp.to_numpy() >= 0.9
        r.update({"months": months, "top_bucket_n": int(top.sum()),
                  "top_bucket_rate": float(yy[top].mean()),
                  "top_bucket_mean_lev": float(pp[top].mean())})
        maturity.append(r)
        print(f"  >= {months:>2} months: n={r['n']:>7,}  ratio {r['ratio']:.1f}x "
              f"[{r['ratio_lo']:.1f}, {r['ratio_hi']:.1f}]  top bucket "
              f"{r['top_bucket_rate']:.3f} of {r['top_bucket_n']:,}")

    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(json.dumps({
        "dn": str(dn.date()), "headline": ratio_row(p, y),
        "brier": brier, "ece": ece,
        "buckets": table.to_dict("records"),
        "adjacent_fisher_holm": sig.to_dict("records"),
        "trend_tests": trends, "age_bands": bands, "maturity": maturity,
    }, indent=1, default=lambda o: o.item() if hasattr(o, "item") else str(o)))
    print(f"\nwrote {RESULTS}")

    plot(table, brier, ece, len(p))
    return 0


if __name__ == "__main__":
    sys.exit(main())
