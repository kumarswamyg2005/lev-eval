"""Task F -- vendor-ceiling lower bound on KEV incompleteness.

Task D found KEV membership varying ~14x by vendor among CVEs LEV_norm scores
identically.  At equal LEV, exploitation propensity is asserted equal, so that
spread is observation probability, not exploitation probability.  The
best-observed vendor stratum therefore bounds how much KEV sees.

Every number here is a LOWER bound on incompleteness: it assumes the best
vendor is FULLY observed, which is certainly false.  True completeness is
lower and true over-confidence lower still.

Run: python analysis/vendor_ceiling.py
"""

import re
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from scipy import optimize, stats

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from data import download_epss, download_exploits, download_kev, download_nvd
from models import lev as levmod
from analysis import calibration, top_bucket, version_normalize

DN = version_normalize.DN
MIN_N = 30            # minimum CVEs for a vendor to form a stratum in a bucket
MIN_VENDORS = 3       # minimum strata before a bucket ceiling is estimated
TOP_DECILE = 0.10

# Corporate suffixes stripped during canonicalization.  Deliberately a short,
# mechanical list -- no hand-curated alias table, so the merge is reproducible
# and auditable (the merges it makes are printed).
SUFFIXES = {"inc", "inc.", "corp", "corp.", "corporation", "ltd", "ltd.",
            "llc", "llc.", "gmbh", "co", "co.", "company", "plc", "sa", "s.a.",
            "ag", "ab", "bv", "b.v.", "nv", "n.v.", "oy", "as", "srl", "spa",
            "pty", "limited", "incorporated", "software", "systems",
            "technologies", "technology", "foundation", "group", "labs",
            "solutions", "the"}


# CNA-supplied placeholders that are not vendors.
NON_VENDORS = {"unknown", "n a", "na", "none", "other", "various", "multiple"}


def canonical(name):
    """lowercase, strip punctuation and corporate suffixes, collapse spaces."""
    if not isinstance(name, str) or not name.strip():
        return None
    s = re.sub(r"[^\w\s.]", " ", name.lower())
    tokens = [t for t in s.split() if t not in SUFFIXES]
    out = " ".join(tokens) or name.strip().lower()
    return None if out in NON_VENDORS else out


def strata(df, vendor_col="vendor"):
    """Per (bucket, vendor) KEV rate with Wilson intervals."""
    rows = []
    for (b, v), g in df.groupby(["bucket", vendor_col], observed=True):
        n, k = len(g), int(g["in_kev"].sum())
        if n < MIN_N:
            continue
        lo, hi = calibration.wilson_ci(k, n)
        rows.append({"bucket": b, "vendor": v, "n": n, "k": k,
                     "rate": k / n, "lo": lo, "hi": hi})
    return pd.DataFrame(rows)


def ceiling_envelope(sub):
    """Asymptote of KEV rate vs vendor CVE count (prominence proxy).

    rate(n) = a * (1 - exp(-b*n)); `a` is the rate a fully-observed vendor
    would show.  Weighted by sqrt(n) so large strata dominate without swamping.
    """
    if len(sub) < MIN_VENDORS:
        return np.nan
    x = sub["n"].to_numpy(float)
    y = sub["rate"].to_numpy(float)
    try:
        p, _ = optimize.curve_fit(
            lambda t, a, b: a * (1 - np.exp(-b * t)), x, y,
            p0=[max(y.max(), 1e-3), 0.01], sigma=1 / np.sqrt(x),
            bounds=([1e-9, 1e-6], [1.0, 10.0]), maxfev=20000)
        a = float(p[0])
        # a pinned at the upper bound means the saturating curve never turned
        # over within the observed range: the asymptote is not identified by
        # these points and the "ceiling" is an artifact of the bound.
        return np.nan if a >= 0.99 else a
    except (RuntimeError, ValueError):
        return np.nan


def ceiling_top_decile(sub):
    """Weighted mean rate of the top decile of vendors by KEV rate."""
    if len(sub) < MIN_VENDORS:
        return np.nan
    k = max(1, int(np.ceil(len(sub) * TOP_DECILE)))
    top = sub.nlargest(k, "rate")
    return float(np.average(top["rate"], weights=top["n"]))


def main():
    tidy = download_epss.load()
    kev = download_kev.load()
    expl = download_exploits.load()
    meta = download_nvd.load().set_index("cve")

    print("\nbuilding matrices...")
    wide, first_idx = levmod.to_wide(tidy)
    norm_wide = version_normalize.normalize(wide)
    m = calibration.cohort(wide, first_idx, DN)
    pred = levmod.lev(norm_wide[m], first_idx[m], dn=DN)
    kev_dates = kev.drop_duplicates("cve").set_index("cve")["kev_date"]

    df = pd.DataFrame({"lev": pred})
    df["in_kev"] = (kev_dates.reindex(pred.index) <= DN).fillna(False)
    # full-cohort ratios for the progression printed below (computed, not typed in)
    raw_over = float(levmod.lev(wide[m], first_idx[m], dn=DN).mean() / df["in_kev"].mean())
    norm_over = float(df["lev"].mean() / df["in_kev"].mean())
    edges = calibration.BINS
    # Same binning as calibration.reliability(): digitize with the top edge
    # clipped INTO the last bucket.  pd.cut(right=False) would drop LEV == 1.0
    # entirely -- 132 of the 441 KEV CVEs here sit exactly at 1.0.
    bi = np.clip(np.digitize(df["lev"].to_numpy(), edges) - 1, 0, len(edges) - 2)
    labels = [f"[{edges[i]:.1f}, {edges[i+1]:.1f})" for i in range(len(edges) - 1)]
    df["bucket"] = pd.Categorical([labels[i] for i in bi], categories=labels,
                                  ordered=True)
    raw_vendor = meta["vendor"].reindex(pred.index)
    df["vendor_raw"] = raw_vendor
    df["vendor"] = raw_vendor.map(canonical)

    # ---------------------------------------------- 6. canonicalization report
    print("\n=== 6. vendor canonicalization ===")
    merged = (df.dropna(subset=["vendor"]).groupby("vendor")["vendor_raw"]
              .nunique().sort_values(ascending=False))
    multi = merged[merged > 1]
    print(f"  raw distinct vendor strings   : {raw_vendor.nunique():,}")
    print(f"  canonical distinct vendors    : {df['vendor'].nunique():,}")
    print(f"  canonical names absorbing >1 raw string: {len(multi):,}")
    for v in multi.head(8).index:
        raws = sorted(df.loc[df["vendor"] == v, "vendor_raw"].dropna().unique())
        print(f"    {v!r} <- {raws[:4]}{' ...' if len(raws) > 4 else ''}")

    df = df.dropna(subset=["vendor"])
    print(f"  CVEs with a usable vendor     : {len(df):,} of {len(pred):,} "
          f"({len(df) / len(pred):.0%})")

    # ------------------------------------------------------ 1. strata
    can_strata = strata(df, "vendor")
    raw_strata = strata(df, "vendor_raw")
    for label, st in [("raw", raw_strata), ("canonical", can_strata)]:
        print(f"\n=== 1. vendor strata ({label} names, n >= {MIN_N}) ===")
        print(f"  {len(st)} strata across {st['bucket'].nunique()} buckets")
    top_b = max(can_strata["bucket"].unique())
    show = can_strata[can_strata["bucket"] == top_b]
    print(f"\n  top bucket {top_b}, per-vendor KEV rate (Wilson 95%):")
    print(show.sort_values("rate", ascending=False).to_string(
        index=False, float_format=lambda v: f"{v:.4f}"))

    # ---------------------------------------------- 2-3. ceilings + completeness
    results = {}
    for label, st in [("canonical", can_strata), ("raw", raw_strata)]:
        rows = []
        for b, sub in st.groupby("bucket", observed=True):
            if len(sub) < MIN_VENDORS:
                continue
            env, dec = ceiling_envelope(sub), ceiling_top_decile(sub)
            pool = df[df["bucket"] == b]
            n, k = len(pool), int(pool["in_kev"].sum())
            obs = k / n if n else np.nan
            lo, hi = calibration.wilson_ci(k, n)
            ntop = max(1, int(np.ceil(len(sub) * TOP_DECILE)))
            cs = sub.nlargest(ntop, "rate")
            c_lo, c_hi = float(cs["lo"].min()), float(cs["hi"].max())
            for method, ceil in (("envelope", env), ("top_decile", dec)):
                if not np.isfinite(ceil) or ceil <= 0:
                    continue
                comp = min(obs / ceil, 1.0)
                # CI propagated from the observed-rate Wilson interval against
                # the ceiling's own Wilson interval (widest defensible span).
                rows.append({
                    "bucket": b, "method": method, "n": n, "k": k,
                    "obs_rate": obs, "ceiling": ceil, "completeness": comp,
                    "comp_lo": min(lo / c_hi, 1.0) if c_hi else np.nan,
                    # c_lo = 0 happens when every top-decile vendor has 0 hits;
                    # the upper bound on completeness is then uninformative.
                    "comp_hi": min(hi / c_lo, 1.0) if c_lo > 0 else 1.0,
                    "implied_true": k / comp if comp else np.nan,
                    "mean_lev": float(pool["lev"].mean())})
        results[label] = pd.DataFrame(rows)

    res = results["canonical"]
    print("\n=== 2-3. ceiling and implied completeness (canonical names) ===")
    print(res.to_string(index=False, na_rep="-",
                        float_format=lambda v: f"{v:.4f}"))

    # ------------------------------------------------------ 4. over-confidence
    print("\n=== 4. over-confidence under the vendor-ceiling bound ===")
    n_all = len(df)
    mean_lev = float(df["lev"].mean())
    obs_all = float(df["in_kev"].mean())
    n_kev = int(df["in_kev"].sum())
    print(f"  population                     : {n_all:,} CVEs with a vendor, "
          f"{n_kev:,} in KEV")
    print(f"  mean LEV_norm                  : {mean_lev:.5f}")
    print(f"  observed KEV rate              : {obs_all:.5f} "
          f"-> over-confidence {mean_lev / obs_all:.1f}x")
    summary = []
    for method in ("envelope", "top_decile"):
        sub = res[res["method"] == method]
        if sub.empty:
            continue
        covered = set(sub["bucket"])
        # buckets with no estimable ceiling contribute their observed count
        rest = sum(int(g["in_kev"].sum())
                   for b, g in df.groupby("bucket", observed=True)
                   if b not in covered)
        # Every KEV entry must land in exactly one bucket, covered or not.
        assert rest + int(sub["k"].sum()) == n_kev, (rest, int(sub["k"].sum()))
        implied_total = float(sub["implied_true"].sum()) + rest
        rate = implied_total / n_all
        over = mean_lev / rate
        t_lo = float((sub["k"] / sub["comp_lo"]).sum()) + rest
        t_hi = float((sub["k"] / sub["comp_hi"]).sum()) + rest
        lo_o, hi_o = mean_lev / (t_lo / n_all), mean_lev / (t_hi / n_all)
        summary.append({"method": method, "implied": implied_total,
                        "rate": rate, "over": over,
                        "lo": min(lo_o, hi_o), "hi": max(lo_o, hi_o)})
        print(f"\n  --- ceiling method: {method} ---")
        print(f"  implied truly exploited        : {implied_total:,.0f} "
              f"(vs {n_kev:,} observed)")
        print(f"  implied true exploitation rate : {rate:.5f}")
        print(f"  OVER-CONFIDENCE                : {over:.1f}x  "
              f"[{min(lo_o, hi_o):.1f}x, {max(lo_o, hi_o):.1f}x]")
    sm = pd.DataFrame(summary)
    if len(sm) > 1:
        print(f"\n  method sensitivity: {sm['over'].min():.1f}x to "
              f"{sm['over'].max():.1f}x "
              f"({sm['over'].max() / sm['over'].min():.2f}x apart)")
    print("\n  progression of the bound:")
    print(f"    {raw_over:.1f}x  raw LEV vs observed KEV")
    print(f"    {norm_over:.1f}x  version-normalized LEV vs observed KEV")
    for r in summary:
        print(f"    {r['over']:.1f}x  version-normalized LEV vs vendor-ceiling "
              f"implied rate ({r['method']})")
    print("  Each is a LOWER bound on incompleteness and therefore an UPPER")
    print("  bound on over-confidence. The vendor ceiling assumes the best-")
    print("  observed vendor is FULLY observed, which is certainly false, so")
    print("  the true figure is below the tightest number here.")

    # ------------------------------------------------------ 6b. sensitivity
    rr = results["raw"]
    if not rr.empty:
        print("\n=== 6b. sensitivity to vendor canonicalization ===")
        for method in ("envelope", "top_decile"):
            a = res[res["method"] == method]["completeness"]
            b = rr[rr["method"] == method]["completeness"]
            if len(a) and len(b):
                print(f"  {method}: mean completeness {a.mean():.4f} "
                      f"(canonical) vs {b.mean():.4f} (raw), "
                      f"{abs(a.mean() / b.mean() - 1):.1%} apart")

    # ------------------------------------------------------ 5. falsification
    print("\n=== 5. falsification: do high-KEV vendors differ on exploitation "
          "signal? ===")
    # The premise is "at EQUAL LEV, exploitation propensity is equal", so the
    # test has to hold LEV constant too.  Comparing vendors pooled across
    # buckets would just re-measure the LEV difference between them.  This runs
    # inside the single bucket where the 14x spread was found.
    st = can_strata[can_strata["bucket"] == top_b]
    med = st["rate"].median()
    hi_v = set(st.loc[st["rate"] > med, "vendor"])
    lo_v = set(st.loc[st["rate"] <= med, "vendor"])
    pop = df[(df["bucket"] == top_b) & df["vendor"].isin(hi_v | lo_v)].copy()
    print(f"  restricted to bucket {top_b} so LEV is held constant")
    pop = pop.join(top_bucket.features(wide, first_idx, pop.index, DN))
    pop["cvss3"] = meta["cvss3"].reindex(pop.index)
    ex = expl.set_index("cve")
    pop["has_exploit"] = (ex["in_exploitdb"].reindex(pop.index).fillna(False)
                          | ex["in_metasploit"].reindex(pop.index).fillna(False))
    grp = pop["vendor"].isin(hi_v)
    print(f"  {int(grp.sum()):,} CVEs from {len(hi_v)} high-KEV-rate vendors vs "
          f"{int((~grp).sum()):,} from {len(lo_v)} low-KEV-rate vendors")
    rows = []
    for col in ("peak_epss", "days_above_0.5", "cvss3"):
        a, b = pop.loc[grp, col].dropna(), pop.loc[~grp, col].dropna()
        if len(a) < 3 or len(b) < 3:
            continue
        u, p = stats.mannwhitneyu(a, b, alternative="two-sided")
        # rank-biserial correlation: effect SIZE, so a large n cannot turn a
        # trivial difference into a "significant" one.
        rows.append({"feature": col, "hi": float(a.median()),
                     "lo": float(b.median()),
                     "effect_r": 2 * u / (len(a) * len(b)) - 1, "p": float(p)})
    a, b = pop.loc[grp, "has_exploit"], pop.loc[~grp, "has_exploit"]
    _, p, _, _ = stats.chi2_contingency(pd.crosstab(pop["has_exploit"], grp))
    rows.append({"feature": "has_public_exploit", "hi": float(a.mean()),
                 "lo": float(b.mean()), "effect_r": float(a.mean() - b.mean()),
                 "p": float(p)})
    fals = pd.DataFrame(rows)
    print(fals.to_string(index=False, float_format=lambda v: f"{v:.4g}"))
    # Direction matters as much as size.  A feature on which high-KEV vendors
    # score HIGHER could explain their KEV rate by real exploitation and would
    # contaminate the ceiling.  One on which they score LOWER cannot explain a
    # higher KEV rate at all, so it reinforces the visibility reading instead.
    contaminating = fals[fals["effect_r"] > 0.2]
    reinforcing = fals[fals["effect_r"] < -0.2]
    print(f"\n  |effect| > 0.2 on {len(contaminating) + len(reinforcing)} of "
          f"{len(fals)} features "
          f"({len(contaminating)} favouring real exploitation difference, "
          f"{len(reinforcing)} against)")
    if len(contaminating):
        print("  VERDICT: BOUND WEAKENS. High-KEV-rate vendors score higher on "
              + ", ".join(contaminating["feature"]) + ",")
        print("  so part of the vendor spread is real exploitation difference")
        print("  rather than visibility. The ceiling is contaminated upward,")
        print("  implied completeness is too low, and true over-confidence lies")
        print(f"  closer to {norm_over:.1f}x than to the vendor-ceiling figure above.")
    elif len(reinforcing):
        print("  VERDICT: BOUND HOLDS, and the visibility reading is REINFORCED.")
        print("  High-KEV-rate vendors score LOWER on "
              + ", ".join(reinforcing["feature"]) + " --")
        print("  less exploitation signal, not more -- yet their KEV rate is far")
        print("  higher. A real-exploitation explanation would require the")
        print("  opposite sign, so the spread is not explained by exploitation")
        print("  propensity. If anything the ceiling is contaminated DOWNWARD,")
        print("  making the bound conservative.")
        print("  CAVEAT: only "
              f"{len(hi_v)} high and {len(lo_v)} low vendors clear n >= {MIN_N}")
        print("  in this bucket, so these comparisons rest on few strata.")
    else:
        print("  VERDICT: high- and low-KEV-rate vendors do NOT differ")
        print("  substantially on exploitation signal. The equal-propensity")
        print("  assumption survives and the ceiling is not visibly contaminated.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
