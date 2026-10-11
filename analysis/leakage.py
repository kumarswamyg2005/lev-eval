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

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from data import download_epss, download_kev
from models import lev as levmod
from analysis import calibration, version_normalize

DN = version_normalize.DN
RESULTS = Path(__file__).resolve().parent.parent / "results" / "leakage.json"
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


def lev_asof(wide, first_idx, dn, strict=False):
    """LEV at dn reading only snapshots dated <= dn (< dn if strict).

    levmod.lev substitutes the NEXT available snapshot for a window start it
    does not hold, which can read a file dated after dn.  For a pre-listing
    score that file may postdate the listing, so the comparator analysis
    trims the columns first."""
    cols = (wide.columns < dn) if strict else (wide.columns <= dn)
    return levmod.lev(wide.loc[:, cols], first_idx, dn=dn)


def matched_comparator(src, first_idx, members, kev_dates, controls,
                       strict=True, thresholds=(0.1, 0.5, 0.9)):
    """Pre-listing LEV of each KEV member against non-KEV CVEs first scored on
    the same snapshot (same age), evaluated at the member's listing date.

    Returns a per-member frame: pre-listing LEV, matched-control share above
    each threshold, control median, and the member's percentile among its
    controls."""
    fi = first_idx.reindex(members)
    when = kev_dates.reindex(members)
    rows = []
    for (f, d), g in pd.DataFrame({"fi": fi, "d": when}).groupby(["fi", "d"]):
        if src.columns[f] >= d:
            continue                                   # no pre-listing history
        ctrl = controls[first_idx.reindex(controls).to_numpy() == f]
        sel = g.index.append(ctrl)
        s = lev_asof(src.loc[sel], first_idx.reindex(sel), d, strict=strict)
        cs = s.reindex(ctrl).to_numpy()
        for cve in g.index:
            r = {"cve": cve, "pre": float(s[cve]), "n_ctrl": len(cs),
                 "ctrl_median": float(np.median(cs)),
                 "pctile": float((cs < s[cve]).mean() + 0.5 * (cs == s[cve]).mean()),
                 "age_m": (d - src.columns[f]).days / 30.44}
            for t in thresholds:
                r[f"ctrl_ge_{t}"] = float((cs >= t).mean())
            rows.append(r)
    return pd.DataFrame(rows).set_index("cve")


def summarize_comparator(df, thr=0.5):
    """Observed vs age-matched expected share above thr, lift, z."""
    obs = float((df["pre"] >= thr).mean())
    p = df[f"ctrl_ge_{thr}"].to_numpy()
    exp = float(p.mean())
    n = len(df)
    z = (obs * n - p.sum()) / np.sqrt(max(np.sum(p * (1 - p)), 1e-12))
    return {"threshold": thr, "n": n, "observed_share": obs,
            "matched_control_share": exp,
            "lift": obs / exp if exp else np.inf, "z": float(z)}


def fixed_age_lift(src, first_idx, pop, kev_dates, ages=(1, 3, 6, 12), thr=0.5):
    """Leading-indicator test at fixed CVE age: at first score + A months,
    flag LEV >= thr among cohort CVEs not yet KEV-listed; outcome = listed
    after that date and by DN.  Precision vs base rate = lift."""
    out = []
    first_date = pd.Series(src.columns[first_idx.reindex(pop).to_numpy()], index=pop)
    for A in ages:
        lev_a, ev = [], {}
        for f, g in first_date.groupby(first_date):
            e = f + pd.DateOffset(months=A)
            if e > DN:
                continue
            kd = kev_dates.reindex(g.index)
            keep = g.index[~(kd <= e).to_numpy()]      # not yet listed at e
            if len(keep):
                lev_a.append(lev_asof(src.loc[keep], first_idx.reindex(keep), e))
                ev.update(dict.fromkeys(keep, e))
        s = pd.concat(lev_a)
        e = pd.Series(ev).reindex(s.index)
        kd = kev_dates.reindex(s.index)
        y = ((kd > e) & (kd <= DN)).to_numpy()
        flag = (s >= thr).to_numpy()
        base = y.mean()
        prec = y[flag].mean() if flag.any() else np.nan
        out.append({"age_months": A, "n": int(len(s)), "flagged": int(flag.sum()),
                    "later_listed": int(y.sum()), "base_rate": float(base),
                    "precision": float(prec), "lift": float(prec / base) if base else np.nan,
                    "recall": float(flag[y].mean()) if y.any() else np.nan})
    return out


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
            # snapshots dated before the listing only: levmod.lev's
            # next-available rule otherwise reads the first post-listing file
            # for the trailing window (raised the median 0.0050 -> 0.0064)
            s = lev_asof(norm_wide[sel][ok], fi[ok], d, strict=True)
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
    # ------------------------------------- 3. age-matched comparator (fix)
    print(f"\n{'=' * 84}\n3. AGE-MATCHED COMPARATOR -- is 'only 15% >= 0.5' low or high?\n{'=' * 84}")
    cohort_idx = at_dn.index
    controls = cohort_idx[~cohort_idx.isin(kev_dates.index)]     # never on KEV by dn
    print(f"  controls: {len(controls):,} cohort CVEs never on KEV, matched on "
          f"first-score snapshot (= same age) and evaluated on the member's listing date")
    out = {"n_members": len(members), "n_with_history": int(has.sum()),
           "headline_original": {"share_ge_0.5": float((pre[has] >= 0.5).mean()),
                                 "median": float(pre[has].median()),
                                 "median_at_dn": float(at_dn[members[has]].median())}}
    for label, src, strict in [("norm", norm_wide, True),
                               ("raw", wide, True)]:
        cmp_ = matched_comparator(src, first_idx, members, kev_dates, controls,
                                  strict=strict)
        res = {f"ge_{t}": summarize_comparator(cmp_, t) for t in (0.1, 0.5, 0.9)}
        res.update({"median_pre": float(cmp_["pre"].median()),
                    "median_ctrl": float(cmp_["ctrl_median"].median()),
                    "median_pctile_among_controls": float(cmp_["pctile"].median()),
                    "share_above_ctrl_p90": float((cmp_["pctile"] >= 0.9).mean()),
                    "n": len(cmp_)})
        out[label] = res
        print(f"\n  --- {label} (n={len(cmp_)}) ---")
        for t in (0.1, 0.5, 0.9):
            r = res[f"ge_{t}"]
            print(f"    LEV >= {t}: KEV-to-be {r['observed_share']:.1%} vs age-matched "
                  f"non-KEV {r['matched_control_share']:.2%}  lift {r['lift']:.1f}x  "
                  f"z = {r['z']:.1f}")
        print(f"    median pre-listing LEV {res['median_pre']:.4f} vs matched-control "
              f"median {res['median_ctrl']:.5f}; median KEV member sits at the "
              f"{res['median_pctile_among_controls']:.0%} percentile of its controls; "
              f"{res['share_above_ctrl_p90']:.0%} above their 90th percentile")

    # elapsed time: same comparison at dn
    print("\n  --- does elapsed time explain 0.006 (pre) vs 1.0 (at dn)? ---")
    fi_m = first_idx.reindex(members[has])
    ctrl_fi = first_idx.reindex(controls)
    ctrl_dn = at_dn.reindex(controls)
    # weight controls by how many members share their first-score snapshot
    w = fi_m.value_counts()
    meds, ge5 = [], []
    for f, k in w.items():
        c = ctrl_dn[ctrl_fi.to_numpy() == f]
        meds += [float(c.median())] * k
        ge5 += [float((c >= 0.5).mean())] * k
    elapsed = {"kev_median_at_dn": float(at_dn[members[has]].median()),
               "kev_share_ge_0.5_at_dn": float((at_dn[members[has]] >= 0.5).mean()),
               "ctrl_median_at_dn": float(np.median(meds)),
               "ctrl_share_ge_0.5_at_dn": float(np.mean(ge5)),
               "kev_median_pre": out["norm"]["median_pre"],
               "ctrl_median_pre": out["norm"]["median_ctrl"]}
    out["elapsed_time"] = elapsed
    print(f"    KEV members : median {elapsed['kev_median_pre']:.4f} before listing -> "
          f"{elapsed['kev_median_at_dn']:.3f} at dn  "
          f"(share >= 0.5 at dn {elapsed['kev_share_ge_0.5_at_dn']:.0%})")
    print(f"    same-age non-KEV: median {elapsed['ctrl_median_pre']:.5f} at the same "
          f"listing dates -> {elapsed['ctrl_median_at_dn']:.4f} at dn "
          f"(share >= 0.5 at dn {elapsed['ctrl_share_ge_0.5_at_dn']:.1%})")

    # fixed-age leading-indicator test
    print("\n  --- leading-indicator test at fixed age (LEV >= 0.5, norm, no lookahead) ---")
    fa = fixed_age_lift(norm_wide, first_idx, cohort_idx, kev_dates)
    for r in fa:
        print(f"    age {r['age_months']:>2} mo: n={r['n']:>7,} flagged {r['flagged']:>5,} "
              f"later listed {r['later_listed']:>3}  precision {r['precision']:.3f} vs base "
              f"{r['base_rate']:.4f}  lift {r['lift']:.0f}x  recall {r['recall']:.0%}")
    out["fixed_age_leading_indicator"] = fa

    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(json.dumps(out, indent=1, default=lambda o: o.item()
                                  if hasattr(o, "item") else str(o)))
    print(f"\n  wrote {RESULTS}")

    print("\n  READING: pre-listing LEV covers fewer 30-day windows, so it is lower")
    print("  partly through elapsed time alone.  What it does show without that")
    print("  confound is what a defender relying on LEV would have seen before CISA")
    print("  acted -- LEV's value as a LEADING indicator of KEV listing, which is")
    print("  the use CSWP 41 proposes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
