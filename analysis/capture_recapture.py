"""Phase 2 -- how many exploited CVEs did no catalogue record?

Phase 1 could show LEV and CISA KEV disagree, but not how much of the gap is LEV
error versus KEV incompleteness, because KEV was the only ground truth.  This
estimates the exploited population no list saw, using multiple-systems
(capture-recapture) estimation over independent exploitation lists, and then
re-evaluates LEV against that ESTIMATED truth rather than against KEV alone.

Lists (each a set of CVEs recorded as exploited in the wild):
  CISA    -- CISA KEV
  SENSOR  -- Shadowserver honeypot telemetry, via CIRCL (independent mechanism)
  SOCIAL  -- threat-actor / researcher channels, mostly Telegram, via CIRCL
  VULNCHK -- VulnCheck KEV rebuilt without CISA-sourced evidence; included
             automatically once VULNCHECK_API_TOKEN is set
Excluded, with the audit that justifies it, in data/download_circl.py and
data/download_euvd.py: CIRCL's aggregated KEV catalogue (contains all of CISA
KEV), Exploit-DB (availability, not exploitation) and EU KEV (88% of its CISA
overlap carries CISA's own date, so it is derivative).

Method.  Lists are NOT independent -- they read the same advisories and see the
same campaigns -- so naive two-list Lincoln-Petersen is reported only to show
that.  The estimate comes from log-linear models over all hierarchical two-way
interaction structures (Bishop, Fienberg & Holland 1975), selected by AIC, with
a parametric bootstrap CI; the three-way interaction is assumed zero, the
standard identifying assumption.  Chao's (1987) estimator is reported as a
heterogeneity-robust lower bound.  Heterogeneity in capture probability is
handled by stratifying on LEV itself, which is also what turns the estimate
into a calibration curve.

Run: python analysis/capture_recapture.py
"""

import itertools
import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from scipy.special import gammaln

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from data import (download_circl, download_epss, download_kev,
                  download_vulncheck)
from models import lev as levmod
from analysis import calibration, version_normalize

ROOT = Path(__file__).resolve().parent.parent
FIGURE = ROOT / "figures" / "capture_recapture.png"
RESULTS = ROOT / "results" / "capture_recapture.json"

DN = version_normalize.DN                      # 2026-08-01
SENSOR_START = pd.Timestamp("2024-10-24")      # first Shadowserver sighting
CENSOR = pd.Timedelta(days=183)
BOOT = 1000
RNG = np.random.default_rng(20260928)          # fixed: the CI is part of the result

# LEV strata used both to absorb capture heterogeneity and to form the
# calibration curve.  Three, not ten: each stratum needs enough captured units
# for its own log-linear fit.
STRATA = [(0.0, 0.1), (0.1, 0.9), (0.9, 1.0 + 1e-9)]

# Which lists form the PRIMARY analysis.  Telegram/social sightings include
# mass lists of CVEs actors merely CLAIM to use (threat 47, recorded before
# VulnCheck was available), so when a fourth list exists the primary analysis
# uses only lists whose entries each cite evidence.  Every other configuration
# is still run and reported by list_set_grid().
EVIDENCE_LISTS = ["CISA", "SENSOR", "VULNCHK"]
FALLBACK_LISTS = ["CISA", "SENSOR", "SOCIAL"]
LIST_SETS = {
    "CISA+SENSOR+SOCIAL": ["CISA", "SENSOR", "SOCIAL"],
    "CISA+SENSOR+VULNCHK (evidence-citing)": ["CISA", "SENSOR", "VULNCHK"],
    "all four": ["CISA", "SENSOR", "SOCIAL", "VULNCHK"],
    "CISA+SOCIAL+VULNCHK (no SENSOR)": ["CISA", "SOCIAL", "VULNCHK"],
    "CISA+SENSOR+VULNCHK_STRICT (precision check)": ["CISA", "SENSOR", "VULNCHK_STRICT"],
}


# ------------------------------------------------------------------ lists
def exploitation_lists(dn=DN):
    """{name: Series(first-exploited date, index=cve)} for every usable list."""
    kev = download_kev.load()
    circl = download_circl.load()
    first = (lambda d: d[d["date"].notna() & (d["date"] <= dn)]
             .groupby("cve")["date"].min())
    lists = {
        "CISA": kev.drop_duplicates("cve").set_index("cve")["kev_date"],
        "SENSOR": first(circl[circl["cls"] == "sensor"]),
        "SOCIAL": first(circl[circl["cls"] == "social"]),
    }
    vc = download_vulncheck.load()
    if vc is not None:
        lists["VULNCHK"] = first(vc)
        lists["VULNCHK_STRICT"] = first(vc[vc["strict"]])
    return {k: v[v <= dn] for k, v in lists.items()}


def histories(pop, lists):
    """0/1 capture-history matrix, one row per CVE in `pop`."""
    return pd.DataFrame({k: pop.isin(v.index).astype(int)
                         for k, v in lists.items()}, index=pop)


# ------------------------------------------------------------- log-linear
def _design(k, interactions):
    """Rows = the 2^k - 1 observable capture patterns (all-zero excluded)."""
    pats = [p for p in itertools.product([0, 1], repeat=k) if any(p)]
    cols = [np.ones(len(pats))] + [np.array([p[i] for p in pats]) for i in range(k)]
    cols += [np.array([p[i] * p[j] for p in pats]) for i, j in interactions]
    return pats, np.column_stack(cols)


def _fit_poisson(X, y, iters=100):
    """Poisson GLM by IRLS.  Returns beta, fitted mu, log-likelihood."""
    beta = np.zeros(X.shape[1])
    beta[0] = np.log(max(y.mean(), 0.5))
    for _ in range(iters):
        mu = np.exp(np.clip(X @ beta, -30, 30))
        z = X @ beta + (y - mu) / mu
        XtW = X.T * mu
        try:
            new = np.linalg.solve(XtW @ X, XtW @ z)
        except np.linalg.LinAlgError:
            new = np.linalg.lstsq(XtW @ X, XtW @ z, rcond=None)[0]
        if np.max(np.abs(new - beta)) < 1e-10:
            beta = new
            break
        beta = new
    mu = np.exp(np.clip(X @ beta, -30, 30))
    ll = float(np.sum(y * np.log(np.maximum(mu, 1e-300)) - mu - gammaln(y + 1)))
    return beta, mu, ll


def cell_counts(H):
    """Observed count per capture pattern, in _design's row order."""
    k = H.shape[1]
    pats = [p for p in itertools.product([0, 1], repeat=k) if any(p)]
    key = H.astype(str).agg("".join, axis=1).value_counts()
    return np.array([key.get("".join(map(str, p)), 0) for p in pats], float)


def loglinear(H):
    """Fit every hierarchical two-way model; return all fits, AIC-sorted.

    Each result: interactions, n_obs, unseen (fitted all-zero cell), N_hat,
    aic, bic, deviance df.  The saturated two-way model is excluded when it has
    no residual degrees of freedom: it fits the data exactly by construction,
    so AIC cannot compare it fairly and its unseen-cell estimate is unstable.
    """
    k = H.shape[1]
    y = cell_counts(H)
    n_obs = float(y.sum())
    pairs = list(itertools.combinations(range(k), 2))
    out = []
    for r in range(len(pairs) + 1):
        for inter in itertools.combinations(pairs, r):
            _, X = _design(k, inter)
            if X.shape[1] >= len(y):             # no residual df
                continue
            beta, mu, ll = _fit_poisson(X, y)
            unseen = float(np.exp(beta[0]))
            if not np.isfinite(unseen) or unseen > 1e7:
                continue                          # non-identified fit
            p = X.shape[1]
            out.append({"interactions": [f"{H.columns[i]}x{H.columns[j]}"
                                         for i, j in inter],
                        "_inter": inter, "n_obs": n_obs, "unseen": unseen,
                        "N_hat": n_obs + unseen,
                        "aic": 2 * p - 2 * ll,
                        "bic": p * np.log(n_obs) - 2 * ll,
                        "df": len(y) - p})
    return sorted(out, key=lambda m: m["aic"])


def bootstrap_ci(H, inter):
    """Parametric Poisson bootstrap of N_hat for one fixed model."""
    k = H.shape[1]
    y = cell_counts(H)
    _, X = _design(k, inter)
    _, mu, _ = _fit_poisson(X, y)
    draws = []
    for _ in range(BOOT):
        yb = RNG.poisson(mu).astype(float)
        if yb.sum() == 0:
            continue
        b, _, _ = _fit_poisson(X, yb)
        u = np.exp(b[0])
        if np.isfinite(u) and u < 1e7:
            draws.append(yb.sum() + u)
    return tuple(np.percentile(draws, [2.5, 97.5])) if draws else (np.nan, np.nan)


def chao_lower_bound(H):
    """Chao (1987) lower bound with its log-normal 95% CI.

    N = S + f1^2 / (2 f2): a lower bound on population size that stays valid
    under heterogeneous capture probabilities.  Unstable when f2 is small
    relative to f1 -- the CI makes that visible rather than hiding it.
    """
    caps = H.sum(axis=1)
    S = int((caps > 0).sum())
    f1, f2 = int((caps == 1).sum()), int((caps == 2).sum())
    if f2 == 0:
        N = S + f1 * (f1 - 1) / 2
        return N, (np.nan, np.nan), S, f1, f2
    N = S + f1 ** 2 / (2 * f2)
    r = f1 / f2
    var = f2 * (r ** 4 / 4 + r ** 3 + r ** 2 / 2)
    T = N - S
    if T <= 0:
        return N, (N, N), S, f1, f2
    C = np.exp(1.96 * np.sqrt(np.log(1 + var / T ** 2)))
    return N, (S + T / C, S + T * C), S, f1, f2


def chapman(H, a, b):
    """Two-list Chapman estimator -- valid only if the lists are independent."""
    n1, n2 = int(H[a].sum()), int(H[b].sum())
    m = int((H[a] & H[b]).sum())
    return (n1 + 1) * (n2 + 1) / (m + 1) - 1, n1, n2, m


# --------------------------------------------------------------- analysis
def estimate(H, label, n_pop=None, verbose=True):
    """Log-linear estimate with the checks that make it reportable.

    NOT IDENTIFIED is declared, and no point estimate reported, when either
      * models within 2 AIC of the best disagree on N by more than 2x -- the
        data cannot choose the interaction structure, and the unseen cell is
        determined by that choice alone (Burnham & Anderson's delta-AIC < 2
        rule for models with substantial support); or
      * the estimate exceeds the number of CVEs in the population, which is
        infeasible; or
      * the estimate falls below the lower end of Chao's CI.  Chao's estimator
        is a lower bound that stays valid under heterogeneous capture
        probabilities, so a log-linear estimate beneath it means the model's
        homogeneity assumption is violated in that population.
    A model-averaged N (Akaike weights) is reported alongside the selected one.
    """
    fits = loglinear(H)
    chao, chao_ci, S, f1, f2 = chao_lower_bound(H)
    n_pop = n_pop if n_pop is not None else len(H)
    res = {"label": label, "n": int(n_pop), "observed": S,
           "chao": chao, "chao_ci": list(chao_ci), "f1": f1, "f2": f2}
    if not fits:
        res.update({"identified": False, "reason": "no model with residual df"})
        if verbose:
            print(f"\n  {label}: {S} captured -- log-linear not estimable "
                  f"with {H.shape[1]} lists; Chao {chao:.0f}")
        return res
    best = fits[0]
    a = np.array([m["aic"] for m in fits])
    w = np.exp(-(a - a.min()) / 2); w /= w.sum()
    n_avg = float(np.sum(w * np.array([m["N_hat"] for m in fits])))
    close = [m["N_hat"] for m in fits if m["aic"] - best["aic"] < 2]
    spread = max(close) / min(close)
    lo, hi = bootstrap_ci(H, best["_inter"])
    below_chao = np.isfinite(chao_ci[0]) and best["N_hat"] < chao_ci[0]
    identified = spread <= 2 and best["N_hat"] <= n_pop and not below_chao
    if spread > 2:
        reason = f"models within 2 AIC span {min(close):.0f}-{max(close):.0f}"
    elif best["N_hat"] > n_pop:
        reason = f"N_hat {best['N_hat']:.0f} exceeds population {n_pop}"
    elif below_chao:
        reason = (f"N_hat {best['N_hat']:.0f} below Chao lower bound "
                  f"{chao_ci[0]:.0f} -- heterogeneity violates the model")
    else:
        reason = ""
    res.update({"identified": bool(identified), "reason": reason,
                "N_hat": best["N_hat"], "ci": [lo, hi], "N_avg": n_avg,
                "model": best["interactions"], "support_range": [min(close), max(close)],
                "alt": [{"N_hat": m["N_hat"], "aic": m["aic"],
                         "model": m["interactions"]} for m in fits[:4]]})
    if verbose:
        print(f"\n  {label}: {n_pop:,} CVEs, {S} captured by >=1 list  (f1={f1}, f2={f2})")
        for m in fits[:4]:
            inter = ", ".join(m["interactions"]) or "independence"
            print(f"      N_hat={m['N_hat']:>8.0f}  AIC={m['aic']:>8.2f}  "
                  f"df={m['df']}  [{inter}]")
        tag = "IDENTIFIED" if identified else f"NOT IDENTIFIED -- {reason}"
        print(f"    selected N_hat={best['N_hat']:.0f} [{lo:.0f}, {hi:.0f}], "
              f"model-averaged {n_avg:.0f}   -> {tag}")
        print(f"    Chao lower bound {chao:.0f} [{chao_ci[0]:.0f}, {chao_ci[1]:.0f}]")
    return res


def truth_ladder(H, lev, label):
    """Over-confidence against progressively stronger notions of 'truth'.

    Each rung adds one assumption to the rung above it, so a reader can stop
    at whichever assumption they are willing to accept.  Every rung is a LOWER
    bound on the true exploited count (or an estimate of it), so every
    over-confidence figure is an UPPER bound on LEV's error.
    """
    n = len(H)
    mean_lev = float(lev.mean())
    rungs = []
    def add(name, assumption, count, lo=None, hi=None):
        rate = count / n
        rungs.append({"truth": name, "assumption": assumption,
                      "exploited": count, "over": mean_lev / rate if rate else np.inf,
                      "over_lo": mean_lev / (hi / n) if hi else None,
                      "over_hi": mean_lev / (lo / n) if lo else None})
    has = lambda c: c in H.columns
    add("CISA KEV", "KEV is complete", int(H["CISA"].sum()))
    if has("SENSOR"):
        add("CISA or SENSOR", "honeypot sightings are real exploitation",
            int((H["CISA"] | H["SENSOR"]).sum()))
    add("union of all lists", "every listed sighting is real",
        int((H.sum(axis=1) > 0).sum()))
    if has("SENSOR"):
        N, *_ = chapman(H, "CISA", "SENSOR")
        add("Chapman(CISA, SENSOR)", "+ the two lists are independent", N)
    chao, chao_ci, *_ = chao_lower_bound(H)
    add("Chao lower bound", "closed population; robust to heterogeneity",
        chao, *chao_ci)
    e = estimate(H, label, verbose=False)
    if e.get("identified"):
        add("log-linear (AIC-selected)", "+ no three-way interaction",
            e["N_hat"], *e["ci"])
    else:
        rungs.append({"truth": "log-linear (AIC-selected)",
                      "assumption": "NOT IDENTIFIED: " + e.get("reason", ""),
                      "exploited": None, "over": None,
                      "over_lo": None, "over_hi": None})
    print(f"\n  {label}  (N={n:,}, mean LEV {mean_lev:.4f})")
    print(f"    {'truth':<27}{'exploited':>10}{'over-confidence':>22}   assumption")
    for r in rungs:
        if r["exploited"] is None:
            print(f"    {r['truth']:<27}{'-':>10}{'-':>22}   {r['assumption']}")
            continue
        ci = (f" [{r['over_lo']:.2f}, {r['over_hi']:.2f}]"
              if r["over_lo"] is not None and r["over_hi"] is not None else "")
        print(f"    {r['truth']:<27}{r['exploited']:>10,.0f}{r['over']:>9.2f}x{ci:>13}"
              f"   {r['assumption']}")
    return rungs


def list_set_grid(H_all, lev):
    """Over-confidence for every list configuration x LEV stratum.

    Cells show union / Chao / log-linear; 'n.i.' = log-linear not identified.
    This is the table that shows the conclusion does not hinge on one choice.
    """
    rows = []
    strata = [("all LEV", np.ones(len(lev), bool))] + [
        (f"[{lo:.1f}, {min(hi, 1):.1f})", ((lev >= lo) & (lev < hi)).to_numpy())
        for lo, hi in STRATA]
    for name, cols in LIST_SETS.items():
        if not all(c in H_all.columns for c in cols):
            continue
        for sname, m in strata:
            Hs, ls = H_all.loc[m, cols], lev[m]
            n, ml = len(Hs), float(ls.mean())
            union = int((Hs.sum(axis=1) > 0).sum())
            chao, chao_ci, *_ = chao_lower_bound(Hs)
            e = estimate(Hs, sname, verbose=False)
            ll = (f"{ml / (e['N_hat'] / n):.2f}x [{ml / (e['ci'][1] / n):.2f}, "
                  f"{ml / (e['ci'][0] / n):.2f}]") if e.get("identified") else "n.i."
            rows.append({"lists": name, "stratum": sname, "n": n,
                         "union": ml / (union / n), "chao": ml / (chao / n),
                         "loglinear": ll})
    g = pd.DataFrame(rows)
    print(f"\n{'=' * 90}\nLIST-SET SENSITIVITY -- over-confidence (union / Chao / log-linear)\n{'=' * 90}")
    for name, sub in g.groupby("lists", sort=False):
        print(f"\n  {name}")
        for _, r in sub.iterrows():
            print(f"    {r['stratum']:<12} n={r['n']:>6,}  union {r['union']:5.2f}x   "
                  f"Chao {r['chao']:5.2f}x   log-linear {r['loglinear']}")
    return g


def main():
    tidy = download_epss.load()
    print("\nbuilding matrices...")
    wide, first_idx = levmod.to_wide(tidy)
    norm_wide = version_normalize.normalize(wide)
    dates = wide.columns
    fd = pd.Series(dates.to_numpy()[first_idx.to_numpy()], index=wide.index)
    iy = pd.Series(wide.index.astype(str).str.slice(4, 8).astype(int),
                   index=wide.index)
    nbf = (fd.dt.year - iy) <= 1

    lists = exploitation_lists()
    print("\nlists: " + ", ".join(f"{k}={len(v):,}" for k, v in lists.items()))

    # PRIMARY population: CVEs first scored inside the sensor window, so every
    # list could observe every CVE from birth -- the assumption capture-
    # recapture cannot do without.  Six-month maturity as in Phase 1.
    prim = nbf & (fd >= SENSOR_START) & (fd <= DN - CENSOR)
    pop = wide.index[prim]
    H_all = histories(pop, lists)
    lev = levmod.lev(norm_wide[prim], first_idx[prim], dn=DN)
    primary = EVIDENCE_LISTS if "VULNCHK" in H_all.columns else FALLBACK_LISTS
    H = H_all[primary]
    print(f"\nPRIMARY lists: {', '.join(primary)}")

    print(f"\n{'=' * 90}\nPRIMARY -- CVEs first scored {SENSOR_START.date()} .. "
          f"{(DN - CENSOR).date()} (N={len(pop):,})\n{'=' * 90}")
    print("  capture counts: " + "  ".join(f"{c}={int(H[c].sum())}" for c in H))
    print("\n  pairwise Chapman estimates -- these AGREE only if lists are independent:")
    for a, b in itertools.combinations(H.columns, 2):
        N, n1, n2, m = chapman(H, a, b)
        print(f"    {a:>7} x {b:<7} n1={n1:<4} n2={n2:<4} overlap={m:<4} N={N:,.0f}")
    print("  -> they disagree by >2x, so list dependence must be modelled.")

    overall = estimate(H, "ALL LEV, 3-list log-linear")

    # SOCIAL is mostly Telegram, where actors also post mass lists of CVEs they
    # claim to use -- a false-positive risk.  If SOCIAL-only singletons dominate
    # a stratum, Chao's f1 is inflated there and the stratum is untrustworthy.
    print("\n  who are the singletons (captured by exactly one list)?")
    one = H[H.sum(axis=1) == 1]
    for lo_, hi_ in STRATA:
        s = ((lev >= lo_) & (lev < hi_)).reindex(one.index).to_numpy()
        o = one[s]
        if len(o):
            print(f"    LEV [{lo_:.1f}, {min(hi_, 1):.1f}): {len(o):>4} singletons -- "
                  + ", ".join(f"{c}-only {int(o[c].sum())} ({o[c].mean():.0%})"
                              for c in H.columns))

    print(f"\n{'=' * 90}\nTRUTH LADDER -- over-confidence vs increasingly assumption-laden truth\n{'=' * 90}")
    ladder = truth_ladder(H, lev, "ALL LEV")

    strata_ladders, strata_est = {}, {}
    for lo_, hi_ in STRATA:
        s = ((lev >= lo_) & (lev < hi_)).to_numpy()
        name = f"LEV [{lo_:.1f}, {min(hi_, 1):.1f})"
        strata_ladders[name] = truth_ladder(H[s], lev[s], name)
        strata_est[name] = estimate(H[s], name, verbose=False)

    # ------------- every list configuration, including the circularity check
    # (no SENSOR: Shadowserver is an EPSS label source) and the false-claim
    # check (no SOCIAL), in one table.
    grid = list_set_grid(H_all, lev)

    # ------------- sensitivity: full cohort, stratified by birth period
    print(f"\n{'=' * 90}\nSENSITIVITY -- full v3-era cohort, by birth period\n{'=' * 90}")
    full = calibration.cohort(wide, first_idx, DN)
    Hf = histories(wide.index[full], lists)[primary]
    levf = levmod.lev(norm_wide[full], first_idx[full], dn=DN)
    born_in = (fd[full] >= SENSOR_START).to_numpy()
    sens = {"born before sensor window": truth_ladder(Hf[~born_in], levf[~born_in],
                                                      "born BEFORE sensor window"),
            "born inside sensor window": truth_ladder(Hf[born_in], levf[born_in],
                                                      "born INSIDE sensor window")}

    # ------------------------------------------------------------- figure
    fig, ax = plt.subplots(figsize=(7.2, 5.0))
    names = list(strata_ladders)
    xs = [float(lev[((lev >= lo) & (lev < hi)).to_numpy()].mean()) for lo, hi in STRATA]
    def rate(name, truth):
        r = next((x for x in strata_ladders[name] if x["truth"] == truth), None)
        n = strata_est[name]["n"]
        return (r["exploited"] / n) if r and r["exploited"] else np.nan
    ax.plot([1e-3, 1], [1e-3, 1], "--", color="gray", lw=1, label="perfect calibration")
    for truth, style, col in [("CISA KEV", "o-", "#365c8d"),
                              ("union of all lists", "s-", "#6a8fbf"),
                              ("Chao lower bound", "^-", "#8a6212")]:
        ax.plot(xs, [rate(n, truth) for n in names], style, color=col, label=truth)
    ll = [rate(n, "log-linear (AIC-selected)") for n in names]
    ax.plot(xs, ll, "D", color="#c1440e", ms=8,
            label="log-linear estimate (identified strata only)")
    ax.set_xscale("log"); ax.set_yscale("log")
    ax.set_xlim(5e-3, 1.5); ax.set_ylim(3e-4, 1.5)
    # The lowest stratum's upper points are driven by Telegram-only sightings
    # (86% of its singletons) -- say so on the plot, or the Chao point above
    # the diagonal reads as "LEV under-confident at low scores".
    for name, x in zip(names, xs):
        e = strata_est[name]
        if not e.get("identified"):
            y = rate(name, "Chao lower bound")
            ax.annotate("not identified", (x, y), textcoords="offset points",
                        xytext=(8, 6), fontsize=7, color="#8a6212", style="italic")
    ax.set_xlabel("mean LEV in stratum (predicted)")
    ax.set_ylabel("exploitation rate under each notion of truth")
    ax.set_title(f"LEV against progressively broader ground truth ({'+'.join(primary)})\n"
                 f"CVEs first scored {SENSOR_START.date()} .. {(DN - CENSOR).date()}, "
                 f"N={len(pop):,}")
    ax.grid(alpha=.3, which="both"); ax.legend(fontsize=7.5, loc="upper left")
    FIGURE.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(FIGURE, dpi=150, bbox_inches="tight")
    print(f"\nwrote {FIGURE}")

    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(json.dumps({
        "population": {"from": str(SENSOR_START.date()),
                       "to": str((DN - CENSOR).date()), "N": len(pop)},
        "lists": {k: len(v) for k, v in lists.items()},
        "captures": {c: int(H[c].sum()) for c in H},
        "overall_estimate": overall, "ladder": ladder,
        "strata": strata_ladders, "strata_estimates": strata_est,
        "primary_lists": primary, "list_set_grid": grid.to_dict(orient="records"),
        "sensitivity": sens}, indent=2, default=float))
    print(f"wrote {RESULTS}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
