"""Task D -- what separates the KEV entries from the rest of the top bucket?

2,332 CVEs sit at LEV_norm >= 0.9; 324 are in KEV.  If the 324 differ
systematically from the other 2,008 on attributes that have nothing to do with
exploitation likelihood -- vendor prominence, CVSS, exploit publication -- that
is measurable visibility bias, NIST CSWP 41's error source #4, as opposed to
source #1 (scope).

Continuous features: Mann-Whitney U (no normality assumption, robust to the
heavy tails in EPSS-derived features).  Categorical: chi-square on the top
categories.  Holm-corrected across all features tested.

Run: python analysis/top_bucket.py
"""

import sys
from pathlib import Path

import numpy as np
import pandas as pd
from scipy import stats

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from data import download_epss, download_exploits, download_kev, download_nvd
from models import lev as levmod
from analysis import calibration, version_normalize

DN = version_normalize.DN
TOP = 0.9
N_CATEGORIES = 8      # top-N categories kept for each chi-square


def features(wide, first_idx, idx, dn):
    """Per-CVE features derived from the EPSS history alone."""
    dates = wide.columns
    sub = wide.loc[idx, [d for d in dates if d <= dn]]
    first = pd.Series(dates.to_numpy()[first_idx[idx].to_numpy()], index=idx)

    # Days above EPSS 0.5: each snapshot is credited with the span until the
    # next one.  ASSUMPTION (not in CSWP 41): EPSS is treated as constant
    # between monthly snapshots, the same piecewise-constant assumption lev2()
    # makes.  With monthly sampling this is a coarse measure.
    edges = np.append(sub.columns.to_numpy(), np.datetime64(dn))
    spans = np.diff(edges) / np.timedelta64(1, "D")
    above = (sub.to_numpy() > 0.5) * spans
    return pd.DataFrame({
        "peak_epss": sub.max(axis=1),
        "days_above_0.5": above.sum(axis=1),
        "age_days": (dn - first).dt.days,
    }, index=idx)


def mannwhitney(df, group, col):
    a = df.loc[group, col].dropna()
    b = df.loc[~group, col].dropna()
    if len(a) < 3 or len(b) < 3:
        return None
    u, p = stats.mannwhitneyu(a, b, alternative="two-sided")
    return {"feature": col, "test": "Mann-Whitney", "n_kev": len(a),
            "n_other": len(b), "median_kev": float(a.median()),
            "median_other": float(b.median()), "mean_kev": float(a.mean()),
            "mean_other": float(b.mean()), "p": float(p)}


def chisquare(df, group, col):
    """Chi-square over the top-N categories plus an 'other' bin."""
    s = df[col].fillna("(missing)")
    keep = s.value_counts().head(N_CATEGORIES).index
    binned = s.where(s.isin(keep), "(other)")
    tab = pd.crosstab(binned, group)
    if tab.shape[1] < 2 or tab.shape[0] < 2:
        return None, None
    chi2, p, _, _ = stats.chi2_contingency(tab)
    return {"feature": col, "test": "chi-square", "n_kev": int(group.sum()),
            "n_other": int((~group).sum()), "median_kev": np.nan,
            "median_other": np.nan, "mean_kev": np.nan, "mean_other": np.nan,
            "p": float(p)}, tab


def holm(rows):
    p = np.array([r["p"] for r in rows])
    order = np.argsort(p)
    m, adj, run = len(p), np.empty(len(p)), 0.0
    for rank, i in enumerate(order):
        run = max(run, (m - rank) * p[i])
        adj[i] = min(1.0, run)
    for r, a in zip(rows, adj):
        r["p_holm"] = a
        r["signif"] = "YES" if a < 0.05 else "no"
    return pd.DataFrame(rows)


def main():
    tidy = download_epss.load()
    kev = download_kev.load()
    expl = download_exploits.load()
    nvd = download_nvd.load()

    print("\nbuilding matrices...")
    wide, first_idx = levmod.to_wide(tidy)
    norm_wide = version_normalize.normalize(wide)
    m = calibration.cohort(wide, first_idx, DN)

    lev_raw = levmod.lev(wide[m], first_idx[m], dn=DN)
    lev_norm = levmod.lev(norm_wide[m], first_idx[m], dn=DN)

    top = lev_norm[lev_norm >= TOP].index
    kev_dates = kev.drop_duplicates("cve").set_index("cve")["kev_date"]
    in_kev = (kev_dates.reindex(top) <= DN).fillna(False)
    print(f"\ntop bucket: {len(top):,} CVEs at LEV_norm >= {TOP}, "
          f"{int(in_kev.sum()):,} in KEV, {int((~in_kev).sum()):,} not")

    df = features(wide, first_idx, top, DN)
    meta = nvd.set_index("cve").reindex(top)
    df["cvss3"] = meta["cvss3"]
    df["vendor"] = meta["vendor"]
    df["product"] = meta["product"]
    df["cwe"] = meta["cwe"]
    df["in_exploitdb"] = expl.set_index("cve")["in_exploitdb"].reindex(top).fillna(False)
    df["in_metasploit"] = expl.set_index("cve")["in_metasploit"].reindex(top).fillna(False)
    print(f"  NVD metadata found for {meta['cvss3'].notna().sum():,} of "
          f"{len(top):,} ({meta['cvss3'].notna().mean():.0%} have CVSS v3)")

    rows, tables = [], {}
    for col in ("cvss3", "age_days", "days_above_0.5", "peak_epss"):
        r = mannwhitney(df, in_kev, col)
        if r:
            rows.append(r)
    for col in ("vendor", "cwe"):
        r, tab = chisquare(df, in_kev, col)
        if r:
            rows.append(r)
            tables[col] = tab
    # exploit availability is binary -> chi-square on the 2x2
    for col in ("in_exploitdb", "in_metasploit"):
        r, tab = chisquare(df, in_kev, col)
        if r:
            rows.append(r)
            tables[col] = tab

    res = holm(rows)
    print(f"\n{'=' * 90}\nKEV vs non-KEV within the top bucket "
          f"(Holm-corrected)\n{'=' * 90}")
    print(res.to_string(index=False, na_rep="-",
                        float_format=lambda v: f"{v:.4g}"))

    print("\n--- top vendors in the bucket ---")
    if "vendor" in tables:
        t = tables["vendor"].copy()
        t.columns = ["not_in_kev", "in_kev"]
        t["kev_rate"] = t["in_kev"] / (t["in_kev"] + t["not_in_kev"])
        print(t.sort_values("kev_rate", ascending=False).to_string(
            float_format=lambda v: f"{v:.3f}"))

    # ---------------------------------------------- Addition 3
    print(f"\n{'=' * 90}\nERROR SOURCE #4 (visibility): public exploit but no "
          f"KEV entry\n{'=' * 90}")
    non_kev = df[~in_kev]
    pub = non_kev["in_exploitdb"] | non_kev["in_metasploit"]
    kev_pub = df[in_kev]["in_exploitdb"] | df[in_kev]["in_metasploit"]
    print(f"  non-KEV CVEs in this bucket           : {len(non_kev):,}")
    print(f"    with an Exploit-DB entry            : "
          f"{int(non_kev['in_exploitdb'].sum()):,}")
    print(f"    with a Metasploit module            : "
          f"{int(non_kev['in_metasploit'].sum()):,}")
    print(f"    with either                         : {int(pub.sum()):,} "
          f"({pub.mean():.1%})")
    print(f"  KEV CVEs with either, for comparison  : {int(kev_pub.sum()):,} "
          f"({kev_pub.mean():.1%})")
    print(f"\n  {int(pub.sum()):,} CVEs have a published, working exploit and no KEV")
    print("  entry. These are demonstrated exploit AVAILABILITY without recorded")
    print("  exploitation -- error source #4 (visibility) if they were exploited")
    print("  and CISA did not catalogue it, source #1 (scope) if availability")
    print("  never became use. This separates the two populations; it does not")
    print("  by itself decide which applies to any given CVE.")

    # ------------------------------- CVEs demoted by normalization
    demoted = lev_raw[(lev_raw >= TOP) & (lev_norm < TOP)].index
    d_kev = (kev_dates.reindex(demoted) <= DN).fillna(False)
    base = float(in_kev.mean())
    print(f"\n{'=' * 90}\nCVEs demoted from the top bucket by normalization\n"
          f"{'=' * 90}")
    print(f"  demoted (LEV_raw >= {TOP}, LEV_norm < {TOP}) : {len(demoted):,}")
    print(f"  of those, in KEV                        : {int(d_kev.sum()):,} "
          f"({d_kev.mean():.2%})")
    print(f"  KEV rate of the retained top bucket      : {base:.2%}")
    if len(demoted) and d_kev.mean() < base:
        odds, p = stats.fisher_exact(
            [[int(d_kev.sum()), len(demoted) - int(d_kev.sum())],
             [int(in_kev.sum()), len(top) - int(in_kev.sum())]])
        print(f"  Fisher exact vs retained bucket          : p = {p:.3g}, "
              f"odds ratio {odds:.3f}")
        print(f"\n  The demoted CVEs are {base / max(d_kev.mean(), 1e-9):.1f}x LESS likely to be in KEV")
        print("  than the ones normalization retains, so normalization is")
        print("  preferentially removing FALSE POSITIVES -- a directly citable")
        print("  practical benefit, not just a bias correction.")
    else:
        print("\n  The demoted CVEs are NOT disproportionately non-KEV, so")
        print("  normalization is not selectively removing false positives.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
