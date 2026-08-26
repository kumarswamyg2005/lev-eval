"""Task C -- is the observed/predicted ratio constant across the middle range?

A flat ratio is the signature of a constant-coverage detection process ("KEV
observes a fixed fraction of exploited CVEs") rather than a bucket-dependent
LEV error.  This fits that constant, tests where it breaks, and -- the decisive
part -- checks whether it drifts with the analysis date.

CAVEAT, stated here and in every printed block: c is derived from LEV itself.
This does NOT independently validate LEV.  It establishes only that whatever
relationship holds in the middle range is approximately multiplicative and
bucket-independent.

Run: python analysis/plateau.py
"""

import sys
from pathlib import Path

import numpy as np
import pandas as pd
from scipy import stats

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from data import download_epss, download_kev
from models import lev as levmod
from analysis import calibration, version_normalize

DN_MAIN = pd.Timestamp("2026-08-01")
# Six half-yearly dates rather than the three specified: three points leave
# df=1 for the trend test, which has almost no power to distinguish drift from
# noise.  The three requested dates are included in this set.
DN_SWEEP = [pd.Timestamp(d) for d in
            ("2024-02-01", "2024-08-01", "2025-02-01", "2025-08-01",
             "2026-02-01", "2026-08-01")]
MIDDLE = slice(1, 9)          # buckets [0.1,0.2) .. [0.8,0.9)


def wls_through_origin(x, y, w):
    """Fit y = c*x by weighted least squares. Returns c, (lo, hi), R2, se."""
    x, y, w = map(np.asarray, (x, y, w))
    c = float(np.sum(w * x * y) / np.sum(w * x ** 2))
    resid = y - c * x
    k = len(x)
    # residual variance with 1 fitted parameter
    sigma2 = float(np.sum(w * resid ** 2) / (k - 1))
    se = float(np.sqrt(sigma2 / np.sum(w * x ** 2)))
    h = stats.t.ppf(0.975, k - 1) * se
    ybar = float(np.sum(w * y) / np.sum(w))
    ss_tot = float(np.sum(w * (y - ybar) ** 2))
    r2 = 1 - float(np.sum(w * resid ** 2)) / ss_tot if ss_tot else np.nan
    return c, (c - h, c + h), r2, se


def departure(row, c):
    """Does one bucket depart from the fitted line? Exact binomial test.

    ASSUMPTION: c is treated as known when computing the expected rate, so the
    p-value ignores uncertainty in c and is anti-conservative.  With 8 buckets
    and thousands of CVEs behind c that uncertainty is small, but it is not 0.
    """
    n, k = int(row["n"]), int(row["n_in_kev"])
    expected_p = float(np.clip(c * row["predicted"], 1e-12, 1 - 1e-12))
    p = stats.binomtest(k, n, expected_p).pvalue
    return {"bucket": row["bucket"], "n": n, "observed": row["observed"],
            "expected": expected_p, "factor": row["observed"] / expected_p,
            "p": p}


def fit_at(wide, norm_wide, first_idx, kev_dates, dn, variant="norm"):
    """(bucket table, predictions, observations) for one dn and variant."""
    m = calibration.cohort(wide, first_idx, dn)
    src = norm_wide if variant == "norm" else wide
    pred = levmod.lev(src[m], first_idx[m], dn=dn)
    # KEV membership restricted to what CISA had catalogued by dn, so the
    # outcome is not read from the future relative to the prediction.
    obs = (kev_dates.reindex(pred.index) <= dn).astype(float)
    table = calibration.reliability(pred.to_numpy(), obs.to_numpy())
    # calibration.reliability() asserts this internally; repeated here so the
    # invariant is visible at the site that consumes the bucket counts.
    assert int(table["n"].sum()) == len(pred), "binning lost rows"
    assert int(table["n_in_kev"].sum()) == int(obs.sum()), "binning lost KEV"
    return table, pred, obs


def main():
    tidy = download_epss.load()
    kev = download_kev.load()
    print("\nbuilding matrices...")
    wide, first_idx = levmod.to_wide(tidy)
    norm_wide = version_normalize.normalize(wide)
    kev_dates = kev.drop_duplicates("cve").set_index("cve")["kev_date"]

    # ---------------------------------------------- 5. THE DECISIVE TEST
    print(f"\n{'=' * 78}\n5. DOES c DRIFT WITH dn?  (LEV_norm)\n{'=' * 78}")
    rows = []
    for dn in DN_SWEEP:
        table, pred, obs = fit_at(wide, norm_wide, first_idx, kev_dates, dn)
        mid = table.iloc[MIDDLE]
        mid = mid[mid["n"] > 0]
        c, ci, r2, se = wls_through_origin(mid["predicted"], mid["observed"],
                                           mid["n"])
        rows.append({"dn": str(dn.date()), "N": int(table["n"].sum()),
                     "in_kev": int(table["n_in_kev"].sum()),
                     "c": c, "ci_lo": ci[0], "ci_hi": ci[1], "r2": r2, "se": se})
        print(f"  {dn.date()}: N={int(table['n'].sum()):>7,} kev={int(table['n_in_kev'].sum()):>4} "
              f"c = {c:.5f}  95% CI [{ci[0]:.5f}, {ci[1]:.5f}]  R2 = {r2:+.4f}"
              f"{'   <- fit fails, c unreliable' if r2 < 0 else ''}")
    drift = pd.DataFrame(rows)

    def trend(sub):
        """Weighted regression of c on time, weights 1/se^2."""
        t = np.array([(pd.Timestamp(d) - DN_SWEEP[0]).days / 365.25
                      for d in sub["dn"]])
        w = 1 / sub["se"].to_numpy() ** 2
        xm, ym = np.average(t, weights=w), np.average(sub["c"], weights=w)
        sl = float(np.sum(w * (t - xm) * (sub["c"] - ym))
                   / np.sum(w * (t - xm) ** 2))
        resid = sub["c"] - (ym + sl * (t - xm))
        df = len(t) - 2
        if df < 1:
            return sl, np.nan, np.nan, df
        se = float(np.sqrt(np.sum(w * resid ** 2) / df
                           / np.sum(w * (t - xm) ** 2)))
        return sl, se, 2 * stats.t.sf(abs(sl / se), df), df

    # The early dates have too few KEV hits for the plateau model to fit at all
    # (negative weighted R2 = worse than a flat line).  c is not estimable
    # there, so the trend is judged on the dates where the model does fit and
    # the all-dates fit is reported alongside it.
    good = drift[drift["r2"] > 0]
    slope, se_slope, p_slope, df = trend(good)
    sl_all, se_all, p_all, df_all = trend(drift)
    overlap = float(good["ci_lo"].max()) <= float(good["ci_hi"].min())

    print(f"\n  trend in c, usable fits only ({len(good)} dates): "
          f"{slope:+.5f}/yr (se {se_slope:.5f}, p = {p_slope:.4f}, df = {df})")
    print(f"  trend in c, all {len(drift)} dates:          "
          f"{sl_all:+.5f}/yr (se {se_all:.5f}, p = {p_all:.4f}, df = {df_all})")
    print(f"  CIs overlap across usable fits: {overlap}")
    print(f"  c range (usable fits): {good['c'].min():.5f} to "
          f"{good['c'].max():.5f} ({good['c'].max() / good['c'].min():.2f}x)")

    monotone = bool((np.diff(good["c"].to_numpy()) < 0).all()
                    or (np.diff(good["c"].to_numpy()) > 0).all())
    print(f"  monotone across usable fits: {monotone}   "
          f"({len(good)}/{len(drift)} dates had R2 > 0)")

    # Verdict weighs three things, not one p-value: monotonicity, whether the
    # endpoint CIs are disjoint, and both trend tests.  With 4-6 points a
    # marginal p alone should not decide this either way.
    drifts = monotone and not overlap and (p_all < 0.05 or p_slope < 0.05)
    if drifts:
        print("\n  INTERPRETATION: c DRIFTS with dn -- it falls "
              f"{good['c'].max() / good['c'].min():.1f}x from "
              f"{good['c'].max():.3f} to {good['c'].min():.3f}.")
        print("  KEV coverage should not track the analysis date, so a falling c")
        print("  points at LEV error rather than ground-truth incompleteness:")
        print("  the residual over-confidence is largely a METRIC problem, and it")
        print("  GROWS with the observation window -- exactly what the convex dn")
        print("  sweep (analysis/dn_sweep.py) implies it should do.")
        print(f"  Strength of evidence: monotone across all {len(good)} usable")
        print(f"  fits, endpoint CIs disjoint, p = {p_all:.4f} (all dates) and")
        print(f"  p = {p_slope:.4f} (usable fits only). The restricted test is")
        print("  marginal on 4 points; the direction is consistent in both.")
    elif overlap and p_slope >= 0.05:
        print("\n  INTERPRETATION: c is STABLE across dn. This is consistent with")
        print("  constant-coverage KEV incompleteness -- KEV observing a roughly")
        print("  fixed fraction of exploited CVEs regardless of when you look --")
        print("  which would make the residual over-confidence largely a")
        print("  GROUND-TRUTH problem rather than a LEV error.")
    else:
        print("\n  INTERPRETATION: INCONCLUSIVE. The point estimates move")
        print(f"  {'monotonically' if monotone else 'non-monotonically'} "
              f"({drift['c'].max() / drift['c'].min():.1f}x across the range) but the trend")
        print(f"  is not significant (p = {p_slope:.3f}). Neither the")
        print("  constant-coverage nor the LEV-error reading is established by")
        print("  this test alone. Report the direction, not a conclusion.")
    print("\n  This test CONSTRAINS the interpretation; it does not prove it.")
    print("  c is LEV-derived, so a LEV error that happens to be stable in dn")
    print("  would produce the same signature.")

    # ------------------------------------------------- 1. plateau fit
    print(f"\n{'=' * 78}\n1-3. PLATEAU FIT at dn={DN_MAIN.date()}\n{'=' * 78}")
    fits = {}
    for variant in ("raw", "norm"):
        table, pred, obs = fit_at(wide, norm_wide, first_idx, kev_dates,
                                  DN_MAIN, variant)
        mid = table.iloc[MIDDLE]
        mid = mid[mid["n"] > 0]
        c, ci, r2, se = wls_through_origin(mid["predicted"], mid["observed"],
                                           mid["n"])
        fits[variant] = (table, pred, obs, c, ci, r2)
        print(f"\n--- LEV_{variant} ---")
        print(f"  c = {c:.5f}   95% CI [{ci[0]:.5f}, {ci[1]:.5f}]   "
              f"R2 = {r2:.4f}   (buckets [0.1,0.9), weights = bucket n)")
        for b in (0, 9):
            d = departure(table.iloc[b], c)
            share = table.iloc[b]["n"] / table["n"].sum()
            print(f"  {d['bucket']}: observed {d['observed']:.5f} vs fitted "
                  f"{d['expected']:.5f}  = {d['factor']:.2f}x  p = {d['p']:.3g}"
                  f"   [{share:.0%} of all CVEs]")

    # ------------------------------------------- 4. KEV completeness
    print(f"\n{'=' * 78}\n4. KEV COMPLETENESS IMPLIED BY c\n{'=' * 78}")
    for variant in ("raw", "norm"):
        table, pred, obs, c, ci, r2 = fits[variant]
        n_kev = int(table["n_in_kev"].sum())
        implied = n_kev / c
        lev_sum = float(pred.sum())
        print(f"\n--- LEV_{variant} ---")
        print(f"  CVEs in KEV                    : {n_kev:,}")
        print(f"  implied truly exploited (k/c)  : {implied:,.0f}")
        print(f"  sum(LEV) over same population  : {lev_sum:,.0f}")
        print(f"  ratio sum(LEV) / implied       : {lev_sum / implied:.2f}x")
        print(f"  implied KEV completeness       : {c:.1%} of exploited CVEs")

    print(f"\n{'=' * 78}\nCAVEAT\n{'=' * 78}")
    print("c is derived from LEV itself. This does NOT independently validate")
    print("LEV. It establishes only that the middle-range relationship between")
    print("predicted and observed is approximately multiplicative and")
    print("bucket-independent. The implied-completeness figures inherit that")
    print("limit entirely: they are what KEV completeness WOULD be if LEV were")
    print("correct in the middle range, not a measurement of it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
