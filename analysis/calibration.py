"""Task 5 -- is LEV calibrated against observed CISA KEV appearance?

Bins CVEs by their LEV score and compares the mean predicted probability in
each bin against the fraction that actually appear in KEV, plus overall Brier
score and Expected Calibration Error.

Run: python analysis/calibration.py
"""

import argparse
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

EPSS_V3 = pd.Timestamp("2023-03-07")
CENSOR_DAYS = 183          # "at least 6 months old"
BINS = np.linspace(0, 1, 11)


def cohort(wide, first_idx, dn):
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
    mature = first_date <= dn - pd.Timedelta(days=CENSOR_DAYS)
    return (first_date >= EPSS_V3) & new & mature


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
    ok = table["n"] > 0
    fig, (ax, axh) = plt.subplots(
        2, 1, figsize=(6.5, 7.5), sharex=True,
        gridspec_kw={"height_ratios": [3, 1], "hspace": 0.08})

    ax.plot([0, 1], [0, 1], "--", color="gray", lw=1, label="perfect calibration")
    t = table[ok]
    ax.errorbar(t["predicted"], t["observed"],
                yerr=[t["observed"] - t["obs_lo"], t["obs_hi"] - t["observed"]],
                fmt="o-", color="#c1440e", ecolor="#c1440e", capsize=3,
                lw=1.5, ms=5, label="LEV (95% Wilson)")
    ax.set_ylabel("observed fraction in CISA KEV")
    ax.set_title(f"LEV reliability diagram (n={n:,} CVEs)\n"
                 f"Brier = {brier:.4f}   ECE = {ece:.4f}")
    ax.set_xlim(0, 1); ax.set_ylim(0, 1)
    ax.grid(alpha=.3); ax.legend(loc="upper left")

    centres = (BINS[:-1] + BINS[1:]) / 2
    axh.bar(centres, table["n"], width=.09, color="#365c8d")
    axh.set_yscale("log")
    axh.set_ylabel("CVEs (log)")
    axh.set_xlabel("predicted LEV probability")
    axh.grid(alpha=.3)

    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=150, bbox_inches="tight")
    print(f"\nwrote {path}")


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

    plot(table, brier, ece, len(p))
    return 0


if __name__ == "__main__":
    sys.exit(main())
