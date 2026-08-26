"""Task C-prime.1 -- is the cohort EPSS rise organic or retraining-driven?

Cohort mean EPSS rose 0.0044 -> 0.0240 (v3 cohort) over the sweep, which is
what makes LEV growth fail to decelerate.  The sweep spans three EPSS model
versions, so the rise could be organic drift within versions, step changes at
retraining boundaries, or both.

Boundary steps are measured from the DAILY files bracketing each retraining,
not from the monthly snapshots: a monthly step would bundle ~30 days of
organic drift into the retraining effect.  Same CVE set, one day apart.

Run: python analysis/epss_drift.py
"""

import datetime as dt
import gzip
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from scipy import stats

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from data import download_epss
from models import lev as levmod
from analysis.dn_sweep import COHORTS, EPSS_ERAS, SWEEP_START

ROOT = Path(__file__).resolve().parent.parent
FIGURE = ROOT / "figures" / "epss_drift.png"

# The model_version string is a BUILD date, not a deployment date: v2025.03.14
# first appears in the 2025-03-17 file, three days later.  Assuming the two
# were the same put the bracket on the wrong side of the step and reported the
# retraining effect as ~0.  So the switchover day is discovered by binary
# search over the daily files instead of being read off the version name.
BOUNDARY_SEARCH = [
    ("v2023.03.01 -> v2025.03.14", dt.date(2025, 3, 1), dt.date(2025, 4, 1)),
    ("v2025.03.14 -> v2026.06.15", dt.date(2026, 6, 1), dt.date(2026, 7, 1)),
]


def read_day(day):
    """(version, Series of epss by cve) for one daily file, or None if absent."""
    path = download_epss.fetch(day)
    if path is None:
        return None
    with gzip.open(path, "rt") as fh:
        head = fh.readline()
    version = (head.split("model_version:")[1].split(",")[0].strip()
               if head.startswith("#") else "v1-none")
    df = pd.read_csv(path, skiprows=1 if head.startswith("#") else 0,
                     usecols=["cve", "epss"],
                     dtype={"cve": "string", "epss": "float32"})
    return version, df.set_index("cve")["epss"]


def find_switch(lo, hi):
    """First day in (lo, hi] whose file carries a different version than lo.

    Binary search: ~5 daily fetches per boundary instead of ~30.
    """
    v_lo = read_day(lo)
    if v_lo is None:
        return None
    v_lo = v_lo[0]
    while (hi - lo).days > 1:
        mid = lo + dt.timedelta(days=(hi - lo).days // 2)
        got = read_day(mid)
        if got is None:                      # missing day: nudge forward
            mid += dt.timedelta(days=1)
            got = read_day(mid)
            if got is None or mid >= hi:
                break
        if got[0] == v_lo:
            lo = mid
        else:
            hi = mid
    return lo, hi


def regimes(dns):
    """Split the sweep dates into unbroken model-version runs."""
    starts = sorted(d for d in EPSS_ERAS if d <= dns[-1])
    out = []
    for i, s in enumerate(starts):
        end = starts[i + 1] if i + 1 < len(starts) else dns[-1] + pd.Timedelta(days=1)
        block = [d for d in dns if s <= d < end]
        if block:
            out.append((EPSS_ERAS[s], block))
    return out


def slope_ci(x, y, alpha=0.05):
    """OLS slope with CI and R2; CI is nan when df < 1."""
    r = stats.linregress(x, y)
    df = len(x) - 2
    if df < 1:
        return r.slope, np.nan, np.nan, np.nan
    h = stats.t.ppf(1 - alpha / 2, df) * r.stderr
    return r.slope, r.slope - h, r.slope + h, r.rvalue ** 2


def main():
    tidy = download_epss.load()
    print("\nbuilding matrices...")
    # Raw (NaN preserved) alongside the ffilled matrix, so the NaN-fill control
    # in step 5 can compare them directly.
    raw = tidy["epss"].unstack("date").sort_index(axis=1)
    wide, first_idx = levmod.to_wide(tidy)
    dates = wide.columns
    dns = [d for d in dates if d >= SWEEP_START]
    first_date = pd.Series(dates.to_numpy()[first_idx.to_numpy()], index=wide.index)
    id_year = pd.Series(wide.index.astype(str).str.slice(4, 8).astype(int),
                        index=wide.index)
    not_backfill = (first_date.dt.year - id_year) <= 1

    print("\nlocating each retraining's actual switchover day (binary search)...")
    brackets = []
    for label, lo, hi in BOUNDARY_SEARCH:
        found = find_switch(lo, hi)
        if found is None:
            print(f"  {label}: daily files unavailable, skipping")
            continue
        d_before, d_after = found
        a, b = read_day(d_before), read_day(d_after)
        print(f"  {label}: switchover {d_before} -> {d_after} "
              f"({a[0]} -> {b[0]})"
              f"{'  [version string implies a different date]' if b[0].lstrip('v').replace('.', '-') != str(d_after) else ''}")
        brackets.append((label, d_before, d_after, a, b))

    series, verdicts = {}, {}
    for name, (lo, hi) in COHORTS.items():
        m = not_backfill & first_date.between(pd.Timestamp(lo), pd.Timestamp(hi))
        idx = wide.index[m]
        ff = wide.loc[idx, dns]
        rw = raw.loc[idx, dns]
        mean_ff = ff.mean()
        series[name] = mean_ff

        print(f"\n{'=' * 78}\n{name}   n={len(idx):,}\n{'=' * 78}")

        # ---- step 5: NaN-fill control -----------------------------------
        present = rw.notna()
        always = present.all(axis=1)
        mean_raw = rw.mean()          # skipna: present CVEs only
        mean_always = ff.loc[always].mean()
        print("--- NaN-fill control (step 5) ---")
        print(f"  present in every snapshot : {int(always.sum()):,} of {len(idx):,} "
              f"({always.mean():.1%})")
        print(f"  CVEs retired by EPSS      : {int((~always).sum()):,} "
              f"(forward-filled by to_wide)")
        print(f"  mean EPSS first->last, forward-filled : "
              f"{mean_ff.iloc[0]:.5f} -> {mean_ff.iloc[-1]:.5f}")
        print(f"  mean EPSS first->last, present-only   : "
              f"{mean_raw.iloc[0]:.5f} -> {mean_raw.iloc[-1]:.5f}")
        print(f"  mean EPSS first->last, always-present : "
              f"{mean_always.iloc[0]:.5f} -> {mean_always.iloc[-1]:.5f}")
        drift_ff = mean_ff.iloc[-1] - mean_ff.iloc[0]
        drift_al = mean_always.iloc[-1] - mean_always.iloc[0]
        print(f"  VERDICT: forward-fill accounts for "
              f"{abs(drift_ff - drift_al) / abs(drift_ff):.1%} of the rise "
              f"-- {'NOT inflating' if abs(drift_ff - drift_al) / abs(drift_ff) < 0.1 else 'MATERIAL, treat with care'}")

        # ---- step 2: within-regime slopes -------------------------------
        print("\n--- within-regime slopes (step 2) ---")
        regs = regimes(dns)
        rows = []
        for version, block in regs:
            y = mean_ff.loc[block].to_numpy()
            x = np.arange(len(block), dtype=float)
            if len(block) < 2:
                continue
            sl, lo_, hi_, r2 = slope_ci(x, y)
            rows.append({"version": version, "n_months": len(block),
                         "from": str(block[0].date()), "to": str(block[-1].date()),
                         "slope/mo": sl, "ci_lo": lo_, "ci_hi": hi_, "r2": r2,
                         "rise": y[-1] - y[0]})
        reg_tab = pd.DataFrame(rows)
        print(reg_tab.to_string(index=False, na_rep="-",
                                float_format=lambda v: f"{v:+.6f}"))

        # ---- step 3/4: boundary steps and decomposition ------------------
        print("\n--- boundary steps (step 3) ---")
        monthly_steps = []
        for i in range(len(regs) - 1):
            last_old = mean_ff.loc[regs[i][1][-1]]
            first_new = mean_ff.loc[regs[i + 1][1][0]]
            monthly_steps.append(first_new - last_old)
        for (label, d_before, d_after, (v0, s0), (v1, s1)), mstep in zip(
                brackets, monthly_steps):
            # Same CVE set, one day apart: this is the retraining alone.
            common = idx.intersection(s0.index).intersection(s1.index)
            b_before = float(s0.reindex(common).mean())
            b_after = float(s1.reindex(common).mean())
            print(f"  {label}")
            print(f"    daily {d_before} -> {d_after}, same {len(common):,} CVEs: "
                  f"{b_before:.5f} -> {b_after:.5f}  "
                  f"(step {b_after - b_before:+.5f}, "
                  f"{b_after / b_before if b_before else np.nan:.2f}x)")
            print(f"    monthly-snapshot step across the same boundary: "
                  f"{mstep:+.5f}")
            share = abs(b_after - b_before) / abs(mstep) if mstep else np.nan
            print(f"    -> of the monthly step, {share:.0%} "
                  f"is the retraining itself, the rest is ~1 month of drift")

        print("\n--- decomposition of total rise (step 4) ---")
        total = mean_ff.iloc[-1] - mean_ff.iloc[0]
        within = float(reg_tab["rise"].sum())
        steps = float(np.sum(monthly_steps))
        print(f"  total rise                        : {total:+.5f}  (100%)")
        print(f"  sum of within-regime drift        : {within:+.5f}  "
              f"({within / total:6.1%})")
        print(f"  sum of retraining boundary steps  : {steps:+.5f}  "
              f"({steps / total:6.1%})")
        assert abs((within + steps) - total) < 1e-9, "decomposition must be exact"

        frac_step = steps / total
        verdict = ("RETRAINING-DOMINATED" if frac_step > 0.6 else
                   "ORGANIC-DOMINATED" if frac_step < 0.4 else "MIXED")
        verdicts[name] = (verdict, within / total, frac_step)
        print(f"\n  VERDICT: {verdict} -- {within / total:.0%} organic "
              f"(within-version drift), {frac_step:.0%} retraining steps")

    # ---- step 1: plot -------------------------------------------------
    fig, ax = plt.subplots(figsize=(8, 4.5))
    for (name, s), c in zip(series.items(), ["#c1440e", "#365c8d"]):
        ax.plot(s.index, s.to_numpy(), "-o", ms=3, color=c,
                label=name.split(" (")[0])
    for d, v in EPSS_ERAS.items():
        if d >= SWEEP_START:
            ax.axvline(d, color="gray", ls=":", lw=1)
            ax.annotate(f"EPSS {v}", (d, ax.get_ylim()[1]), fontsize=7,
                        rotation=90, va="top", ha="right", color="gray")
    ax.set_xlabel("analysis date (dn)")
    ax.set_ylabel("cohort mean EPSS")
    ax.set_title("Cohort mean EPSS vs dn, with model-version boundaries")
    ax.grid(alpha=.3); ax.legend(fontsize=8)
    fig.autofmt_xdate()
    FIGURE.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(FIGURE, dpi=150, bbox_inches="tight")
    print(f"\nwrote {FIGURE}")

    print(f"\n{'=' * 78}\nVERDICT\n{'=' * 78}")
    for name, (v, org, ret) in verdicts.items():
        print(f"{name}\n  {v}: {org:.0%} organic within-version drift, "
              f"{ret:.0%} retraining steps")
    print("\nNOTE: 'organic' here means the score moved without a model change;"
          "\nit does not mean the movement reflects real-world exploitation"
          "\nsignal. CSWP 41 does not model either source.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
