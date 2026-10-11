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
standard identifying assumption.  A model whose MLE does not exist (a fitted
interaction over an empty margin, e.g. CISAxSENSOR when no CVE is on both) is
scored as its extended MLE with honestly counted degrees of freedom (see
loglinear()).  Chao's (1987) estimator, in its small-sample form for t lists,
N = S + ((t-1)/t) f1^2 / (2 f2), is reported as a heterogeneity-robust lower
bound.  Heterogeneity in capture probability is
handled by stratifying on LEV itself, which is also what turns the estimate
into a calibration curve.

LEV variant.  Every LEV here is computed from VERSION-NORMALIZED EPSS
(version_normalize.normalize), the paper's primary choice; strata are formed
on it.  Raw-LEV (un-normalized EPSS) companions of every over-confidence
figure are stored beside it under *_raw_lev keys, for the same CVEs.

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
from scipy.stats import beta

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
# A fitted coefficient this large means IRLS was walking towards the +-30
# clip on the linear predictor in _fit_poisson: the MLE does not exist.
BOUNDARY_BETA = 25.0
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
    aic, bic, residual df, boundary flag.  The saturated two-way model is
    excluded when it has no residual degrees of freedom: it fits the data
    exactly by construction, so AIC cannot compare it fairly and its
    unseen-cell estimate is unstable.

    BOUNDARY FITS.  When a fitted two-way term covers an empty margin (e.g.
    CISAxSENSOR with no CVE on both lists) its MLE is -inf: IRLS walks the
    coefficient to the clip and the cells it covers are fitted as zero.  The
    limit is the EXTENDED MLE (Fienberg & Rinaldo 2012), which is the same
    model fitted to the table with those cells removed and that parameter
    dropped.  We count its degrees of freedom honestly on that reduced table
    -- df = (cells not fitted as zero) - rank(design on those cells) -- and use
    that parameter count in AIC/BIC.  The alternative, dropping boundary models
    outright (Chan, Silverman & Vincent 2021), would let a model that ignores
    the empty cell -- and fits far worse -- win by default; honest df keeps
    the comparison on fit.  A boundary model whose honest df is 0 is saturated
    on the reduced table and is excluded by the rule above, like any other
    saturated model; it is returned with usable=False so estimate() can say
    so.  Boundary = any |beta| >= BOUNDARY_BETA or an empty margin under a
    fitted interaction.
    """
    k = H.shape[1]
    y = cell_counts(H)
    n_obs = float(y.sum())
    pats, _ = _design(k, ())
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
            empty = [f"{H.columns[i]}x{H.columns[j]}" for i, j in inter
                     if y[[p[i] == 1 and p[j] == 1 for p in pats]].sum() == 0]
            boundary = bool(empty) or bool(np.any(np.abs(beta) >= BOUNDARY_BETA))
            live = mu > 1e-6                      # cells not driven to zero
            p = int(np.linalg.matrix_rank(X[live]))
            df = int(live.sum()) - p              # = len(y) - X.shape[1] if not boundary
            out.append({"interactions": [f"{H.columns[i]}x{H.columns[j]}"
                                         for i, j in inter],
                        "_inter": inter, "n_obs": n_obs, "unseen": unseen,
                        "N_hat": n_obs + unseen,
                        "aic": 2 * p - 2 * ll,
                        "bic": p * np.log(n_obs) - 2 * ll,
                        "df": df, "df_nominal": len(y) - X.shape[1],
                        "boundary": boundary, "empty_margins": empty,
                        "usable": df > 0})
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

    N = S + ((t-1)/t) f1^2 / (2 f2) for t lists (sampling occasions): Chao's
    small-sample form, a lower bound on population size that stays valid under
    heterogeneous capture probabilities.  (Until 2026-10 this omitted the
    (t-1)/t factor, which overstates the bound by 50% of its unseen part for
    t = 3.)  The variance uses the same factor K = (t-1)/t,
        var = f2 [K/2 r^2 + K^2 r^3 + K^2/4 r^4],  r = f1/f2,
    so the unseen part T = N - S and its variance scale consistently; the CI
    is Chao's log-normal one.  Unstable when f2 is small relative to f1 -- the
    CI makes that visible rather than hiding it.
    """
    caps = H.sum(axis=1)
    t = H.shape[1]
    K = (t - 1) / t
    S = int((caps > 0).sum())
    f1, f2 = int((caps == 1).sum()), int((caps == 2).sum())
    if f2 == 0:
        N = S + K * f1 * (f1 - 1) / 2
        return N, (np.nan, np.nan), S, f1, f2
    N = S + K * f1 ** 2 / (2 * f2)
    r = f1 / f2
    var = f2 * (K / 2 * r ** 2 + K ** 2 * r ** 3 + K ** 2 / 4 * r ** 4)
    T = N - S
    if T <= 0:
        return N, (N, N), S, f1, f2
    C = np.exp(1.96 * np.sqrt(np.log(1 + var / T ** 2)))
    return N, (S + T / C, S + T * C), S, f1, f2


def stratified_chao_lo(H, lev):
    """Sum over LEV strata of Chao's lower CI end (observed count if f2 = 0).

    A heterogeneity-robust floor for a POOLED estimate: Chao is valid within
    each stratum, and stratifying on LEV absorbs the capture heterogeneity that
    a pooled log-linear model cannot.  A pooled N_hat below it is biased low.
    """
    floor = 0.0
    for lo, hi in STRATA:
        _, ci, S, *_ = chao_lower_bound(H[((lev >= lo) & (lev < hi)).to_numpy()])
        floor += ci[0] if np.isfinite(ci[0]) else S
    return floor


def chapman(H, a, b):
    """Two-list Chapman estimator -- valid only if the lists are independent."""
    n1, n2 = int(H[a].sum()), int(H[b].sum())
    m = int((H[a] & H[b]).sum())
    return (n1 + 1) * (n2 + 1) / (m + 1) - 1, n1, n2, m


# --------------------------------------------------------------- analysis
def estimate(H, label, n_pop=None, verbose=True, floor=None, force=None):
    """Log-linear estimate with the checks that make it reportable.

    The population is IDENTIFIED only if EVERY model within 2 AIC of the best
    (Burnham & Anderson's "substantial support") passes every rule, and they
    agree with each other:
      * they agree on N within 2x -- otherwise the data cannot choose the
        interaction structure and the unseen cell is set by that choice;
      * no N exceeds the number of CVEs in the population (infeasible);
      * no N falls below the lower end of Chao's CI.  Chao's estimator is a
        lower bound that stays valid under heterogeneous capture
        probabilities, so a log-linear estimate beneath it means that model's
        homogeneity assumption is violated in this population;
      * for a pooled population, no N falls below `floor`, the stratified Chao
        bound (stratified_chao_lo) -- the same rule, applied where pooling
        over LEV strata hides heterogeneity from the pooled Chao bound.
    Until 2026-10 only the best model was checked, so two models tied in AIC
    were split by enumeration order.  Boundary fits are scored with honest df
    (loglinear()); those left with none are excluded as saturated and listed
    under "excluded_saturated".
    `force` = (listA, listB) restricts the candidates to models containing
    that interaction (a sensitivity check, not the primary rule).
    A model-averaged N (Akaike weights) is reported alongside the selected one.
    """
    all_fits = loglinear(H)
    if force is not None:
        tag_ = "x".join(force)
        all_fits = [m for m in all_fits if tag_ in m["interactions"]]
    fits = [m for m in all_fits if m["usable"]]
    excluded = [{"N_hat": m["N_hat"], "aic": m["aic"], "model": m["interactions"],
                 "df_nominal": m["df_nominal"], "empty_margins": m["empty_margins"]}
                for m in all_fits if not m["usable"]]
    chao, chao_ci, S, f1, f2 = chao_lower_bound(H)
    n_pop = n_pop if n_pop is not None else len(H)
    res = {"label": label, "n": int(n_pop), "observed": S,
           "chao": chao, "chao_ci": list(chao_ci), "f1": f1, "f2": f2,
           "chao_form": f"S + ((t-1)/t) f1^2/(2 f2), t={H.shape[1]}",
           "excluded_saturated": excluded}
    if force is not None:
        res["forced_interaction"] = "x".join(force)
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
    close = [m for m in fits if m["aic"] - best["aic"] < 2]
    Ns = [m["N_hat"] for m in close]
    spread = max(Ns) / min(Ns)
    lo, hi = bootstrap_ci(H, best["_inter"])
    fails = []
    if spread > 2:
        fails.append(f"models within 2 AIC span {min(Ns):.0f}-{max(Ns):.0f}")
    for m in close:
        name = "+".join(m["interactions"]) or "independence"
        if m["N_hat"] > n_pop:
            fails.append(f"{name}: N_hat {m['N_hat']:.0f} exceeds population {n_pop}")
        if np.isfinite(chao_ci[0]) and m["N_hat"] < chao_ci[0]:
            fails.append(f"{name}: N_hat {m['N_hat']:.0f} below Chao lower bound "
                         f"{chao_ci[0]:.0f} -- heterogeneity violates the model")
        if floor is not None and m["N_hat"] < floor:
            fails.append(f"{name}: N_hat {m['N_hat']:.0f} below stratified Chao bound "
                         f"{floor:.0f} -- pooling across LEV strata biases it low")
    identified = not fails
    reason = "; ".join(fails)
    res.update({"identified": bool(identified), "reason": reason,
                "N_hat": best["N_hat"], "ci": [lo, hi], "N_avg": n_avg,
                "model": best["interactions"], "support_range": [min(Ns), max(Ns)],
                "support": [{"N_hat": m["N_hat"], "aic": m["aic"], "df": m["df"],
                             "boundary": m["boundary"], "model": m["interactions"]}
                            for m in close],
                "alt": [{"N_hat": m["N_hat"], "aic": m["aic"], "df": m["df"],
                         "boundary": m["boundary"], "model": m["interactions"]}
                        for m in fits[:4]]})
    if verbose:
        print(f"\n  {label}: {n_pop:,} CVEs, {S} captured by >=1 list  (f1={f1}, f2={f2})")
        for m in excluded:
            print(f"      N_hat={m['N_hat']:>8.0f}  AIC={m['aic']:>8.2f}  "
                  f"EXCLUDED: boundary fit, honest df 0  [{', '.join(m['model'])}]")
        for m in fits[:4]:
            inter = ", ".join(m["interactions"]) or "independence"
            print(f"      N_hat={m['N_hat']:>8.0f}  AIC={m['aic']:>8.2f}  "
                  f"df={m['df']}{' (boundary)' if m['boundary'] else ''}  [{inter}]")
        tag = "IDENTIFIED" if identified else f"NOT IDENTIFIED -- {reason}"
        print(f"    selected N_hat={best['N_hat']:.0f} [{lo:.0f}, {hi:.0f}], "
              f"model-averaged {n_avg:.0f}   -> {tag}")
        print(f"    Chao lower bound {chao:.0f} [{chao_ci[0]:.0f}, {chao_ci[1]:.0f}]")
    return res


def truth_ladder(H, lev, label, floor=None, lev_raw=None):
    """Over-confidence against progressively stronger notions of 'truth'.

    Each rung adds one assumption to the rung above it, so a reader can stop
    at whichever assumption they are willing to accept.  Every rung is a LOWER
    bound on the true exploited count (or an estimate of it), so every
    over-confidence figure is an UPPER bound on LEV's error.
    `lev` is version-normalized LEV (primary); `lev_raw`, if given, is raw LEV
    for the same CVEs and adds over_raw_lev* companions to every rung.
    H must hold the PRIMARY lists: the union rung is named for them.
    """
    n = len(H)
    mean_lev = float(lev.mean())
    mean_raw = float(lev_raw.mean()) if lev_raw is not None else None
    rungs = []
    def add(name, assumption, count, lo=None, hi=None):
        rate = count / n
        r = {"truth": name, "assumption": assumption,
             "exploited": count, "exploited_lo": lo, "exploited_hi": hi,
             "over": mean_lev / rate if rate else np.inf,
             "over_lo": mean_lev / (hi / n) if hi else None,
             "over_hi": mean_lev / (lo / n) if lo else None}
        if mean_raw is not None:
            r.update({"over_raw_lev": mean_raw / rate if rate else np.inf,
                      "over_raw_lev_lo": mean_raw / (hi / n) if hi else None,
                      "over_raw_lev_hi": mean_raw / (lo / n) if lo else None})
        rungs.append(r)
    has = lambda c: c in H.columns
    counted = lambda k: (k, *calibration.poisson_ci(k))     # Poisson 95% on a count
    add("CISA KEV", "KEV is complete", *counted(int(H["CISA"].sum())))
    if has("SENSOR"):
        add("CISA or SENSOR", "honeypot sightings are real exploitation",
            *counted(int((H["CISA"] | H["SENSOR"]).sum())))
    add("union of primary lists", "every listed report is real",
        *counted(int((H.sum(axis=1) > 0).sum())))
    if has("SENSOR"):
        N, *_ = chapman(H, "CISA", "SENSOR")
        add("Chapman(CISA, SENSOR)", "+ the two lists are independent", N)
    chao, chao_ci, *_ = chao_lower_bound(H)
    add("Chao lower bound", "closed population; robust to heterogeneity",
        chao, *chao_ci)
    e = estimate(H, label, verbose=False, floor=floor)
    if e.get("identified"):
        add("log-linear (AIC-selected)", "+ no three-way interaction",
            e["N_hat"], *e["ci"])
    else:
        rungs.append({"truth": "log-linear (AIC-selected)",
                      "assumption": "NOT IDENTIFIED: " + e.get("reason", ""),
                      "exploited": None, "over": None,
                      "over_lo": None, "over_hi": None})
    print(f"\n  {label}  (N={n:,}, mean LEV {mean_lev:.4f} version-normalized"
          + (f", {mean_raw:.4f} raw)" if mean_raw is not None else ")"))
    print(f"    {'truth':<27}{'exploited':>10}{'over-confidence':>22}"
          f"{'raw-LEV over':>14}   assumption")
    for r in rungs:
        if r["exploited"] is None:
            print(f"    {r['truth']:<27}{'-':>10}{'-':>22}{'-':>14}   {r['assumption']}")
            continue
        ci = (f" [{r['over_lo']:.2f}, {r['over_hi']:.2f}]"
              if r["over_lo"] is not None and r["over_hi"] is not None else "")
        raw = f"{r['over_raw_lev']:.2f}x" if "over_raw_lev" in r else "-"
        print(f"    {r['truth']:<27}{r['exploited']:>10,.0f}{r['over']:>9.2f}x{ci:>13}"
              f"{raw:>14}   {r['assumption']}")
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
            e = estimate(Hs, sname, verbose=False,
                         floor=stratified_chao_lo(Hs, ls) if sname == "all LEV" else None)
            ll = (f"{ml / (e['N_hat'] / n):.2f}x [{ml / (e['ci'][1] / n):.2f}, "
                  f"{ml / (e['ci'][0] / n):.2f}]") if e.get("identified") else "n.i."
            rows.append({"lists": name, "stratum": sname, "n": n,
                         "union": ml / (union / n), "chao": ml / (chao / n),
                         "loglinear": ll, "reason": e.get("reason", "")})
    g = pd.DataFrame(rows)
    print(f"\n{'=' * 90}\nLIST-SET SENSITIVITY -- over-confidence (union / Chao / log-linear)\n{'=' * 90}")
    for name, sub in g.groupby("lists", sort=False):
        print(f"\n  {name}")
        for _, r in sub.iterrows():
            print(f"    {r['stratum']:<12} n={r['n']:>6,}  union {r['union']:5.2f}x   "
                  f"Chao {r['chao']:5.2f}x   log-linear {r['loglinear']}"
                  + (f"\n{'':<17}({r['reason']})" if r["reason"] else ""))
    return g


def _selftest():
    """Boundary detection, honest df and the small-sample Chao form, on a
    hand-built 3-list table with no CVE on both CISA and SENSOR."""
    counts = {(1, 0, 0): 40, (0, 1, 0): 30, (0, 0, 1): 50, (1, 0, 1): 20,
              (0, 1, 1): 15}
    rows = [p for p, c in counts.items() for _ in range(c)]
    H = pd.DataFrame(rows, columns=["CISA", "SENSOR", "VULNCHK"])
    fits = {"+".join(m["interactions"]) or "indep": m for m in loglinear(H)}
    cs = fits["CISAxSENSOR"]
    assert cs["boundary"] and cs["empty_margins"] == ["CISAxSENSOR"], cs
    assert cs["df_nominal"] == 2 and cs["df"] == 1, cs            # 5 live cells, rank 4
    assert not fits["CISAxSENSOR+CISAxVULNCHK"]["usable"]          # saturated on live cells
    assert not fits["CISAxVULNCHK"]["boundary"] and fits["CISAxVULNCHK"]["df"] == 2
    # Chao: S=155, f1=120, f2=35, t=3 -> 155 + (2/3) 120^2 / 70
    N, *_ = chao_lower_bound(H)
    assert abs(N - (155 + (2 / 3) * 120 ** 2 / 70)) < 1e-9, N


def over(lev, count, n):
    """Mean LEV over exploitation rate; inf if nothing was exploited."""
    return float(lev.mean()) / (count / n) if count else np.inf


def main():
    _selftest()
    print("capture-recapture self-test OK")
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
    # PRIMARY LEV is from version-normalized EPSS (the paper's choice); raw LEV
    # from the un-normalized scores is the disclosed companion.  Strata are
    # always formed on the normalized LEV, so raw companions describe the same
    # CVEs.
    lev = levmod.lev(norm_wide[prim], first_idx[prim], dn=DN)
    lev_raw = levmod.lev(wide[prim], first_idx[prim], dn=DN)
    print(f"\nmean LEV: version-normalized {lev.mean():.4f}, raw {lev_raw.mean():.4f}")
    primary = EVIDENCE_LISTS if "VULNCHK" in H_all.columns else FALLBACK_LISTS
    H = H_all[primary]
    print(f"\nPRIMARY lists: {', '.join(primary)}")
    in_stratum = lambda lo_, hi_: ((lev >= lo_) & (lev < hi_)).to_numpy()
    sname = lambda lo_, hi_: f"LEV [{lo_:.1f}, {min(hi_, 1):.1f})"

    print(f"\n{'=' * 90}\nPRIMARY -- CVEs first scored {SENSOR_START.date()} .. "
          f"{(DN - CENSOR).date()} (N={len(pop):,})\n{'=' * 90}")
    print("  capture counts: " + "  ".join(f"{c}={int(H[c].sum())}" for c in H))
    print("\n  pairwise Chapman estimates -- these AGREE only if lists are independent:")
    for a, b in itertools.combinations(H.columns, 2):
        N, n1, n2, m = chapman(H, a, b)
        print(f"    {a:>7} x {b:<7} n1={n1:<4} n2={n2:<4} overlap={m:<4} N={N:,.0f}")
    print("  -> they disagree by >2x, so list dependence must be modelled.")

    overall = estimate(H, "ALL LEV, 3-list log-linear", floor=stratified_chao_lo(H, lev))

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
    ladder = truth_ladder(H, lev, "ALL LEV", floor=stratified_chao_lo(H, lev),
                          lev_raw=lev_raw)

    # ------------- how much of the KEV gap is catalogue incompleteness?
    # The share depends on the scale it is measured on, so report three:
    #   ratio  1 - b/a           (= 1 - KEV count / union count; LEV cancels)
    #   log    ln(a/b) / ln(a)   (share of the log over-confidence)
    #   excess (a-b) / (a-1)     (share of the over-confidence above 1x)
    # where a = over-confidence vs KEV, b = vs the union.  It treats every
    # listed CVE as truly exploited; the strict-VulnCheck row relaxes that.
    def decomposition(Hd):
        k, u = int(Hd["CISA"].sum()), int((Hd.sum(axis=1) > 0).sum())
        lo, hi = beta.ppf(0.025, k, u - k + 1), beta.ppf(0.975, k + 1, u - k)   # Clopper-Pearson
        out = {"lists": list(Hd.columns), "kev": k, "union": u,
               "share_ratio_scale": 1 - k / u,
               "share_ratio_scale_ci": [1 - hi, 1 - lo]}
        for tag, L in [("", lev), ("_raw_lev", lev_raw)]:
            a, b = over(L, k, len(Hd)), over(L, u, len(Hd))
            out.update({f"over_kev{tag}": a, f"over_union{tag}": b,
                        f"share_log_scale{tag}": np.log(a / b) / np.log(a),
                        f"share_excess_scale{tag}": (a - b) / (a - 1)})
        return out
    gap = {"lev_variant": "version-normalized (raw companions: *_raw_lev)",
           "primary": decomposition(H)}
    if "VULNCHK_STRICT" in H_all.columns:
        gap["strict_vulncheck"] = decomposition(
            H_all[[c if c != "VULNCHK" else "VULNCHK_STRICT" for c in primary]])
    print("\n  share of the KEV gap that counting attributes to catalogue incompleteness:")
    for key, d in gap.items():
        if key == "lev_variant":
            continue
        print(f"    {key:<17} KEV {d['kev']} / union {d['union']}:  ratio scale "
              f"{d['share_ratio_scale']:.1%} [{d['share_ratio_scale_ci'][0]:.1%}, "
              f"{d['share_ratio_scale_ci'][1]:.1%}]   log {d['share_log_scale']:.1%} "
              f"(raw LEV {d['share_log_scale_raw_lev']:.1%})   excess "
              f"{d['share_excess_scale']:.1%} (raw LEV {d['share_excess_scale_raw_lev']:.1%})")
    chao_all = next(r for r in ladder if r["truth"] == "Chao lower bound")["exploited"]
    print(f"    KEV share of the Chao bound: {int(H['CISA'].sum()) / chao_all:.1%}")
    gap["kev_share_of_chao"] = int(H["CISA"].sum()) / chao_all

    strata_ladders, strata_est = {}, {}
    for lo_, hi_ in STRATA:
        s = in_stratum(lo_, hi_)
        name = sname(lo_, hi_)
        strata_ladders[name] = truth_ladder(H[s], lev[s], name, lev_raw=lev_raw[s])
        e = estimate(H[s], name, verbose=False)
        e.update({"mean_lev": float(lev[s].mean()),
                  "mean_lev_raw_lev": float(lev_raw[s].mean())})
        if not e["identified"]:
            # No point estimate: report what the data DO support, the range
            # between the Chao bound (tighter) and the union (pure counting).
            # Both are lower bounds on the exploited count, so both
            # over-confidence figures are upper bounds on LEV's error.
            n, u = int(s.sum()), int((H[s].sum(axis=1) > 0).sum())
            e["range_if_not_identified"] = {
                "exploited": [u, e["chao"]],
                "over": [over(lev[s], e["chao"], n), over(lev[s], u, n)],
                "over_raw_lev": [over(lev_raw[s], e["chao"], n), over(lev_raw[s], u, n)]}
        strata_est[name] = e
    for name, e in strata_est.items():
        print(f"\n  {name}: " + ("IDENTIFIED, N_hat {:.0f} [{:.0f}, {:.0f}]".format(
            e["N_hat"], *e["ci"]) if e["identified"] else
            "NOT IDENTIFIED -- {}\n      over-confidence between {:.2f}x (Chao) and "
            "{:.2f}x (union); raw LEV {:.2f}x-{:.2f}x".format(
                e["reason"], *e["range_if_not_identified"]["over"],
                *e["range_if_not_identified"]["over_raw_lev"])))

    # ------------- every list configuration, including the circularity check
    # (no SENSOR: Shadowserver is an EPSS label source) and the false-claim
    # check (no SOCIAL), in one table.
    grid = list_set_grid(H_all, lev)

    # ------------- sensitivity checks on the primary lists
    print(f"\n{'=' * 90}\nSENSITIVITY -- list dependence and the SENSOR list\n{'=' * 90}")
    pieces = [("all LEV", np.ones(len(lev), bool))] + [
        (sname(lo_, hi_), in_stratum(lo_, hi_)) for lo_, hi_ in STRATA]
    extra = {}
    if "VULNCHK" in primary:
        # (a) VulnCheck is rebuilt WITHOUT its Shadowserver-hosted reports
        # (data/download_vulncheck.py), so a CVE Shadowserver saw is less
        # likely to stay on VULNCHK: negative SENSORxVULNCHK dependence by
        # construction.  Force that interaction in and see what moves.
        forced = {}
        print("\n  (a) SENSORxVULNCHK forced into every candidate model:")
        for name, m in pieces:
            e = estimate(H[m], name, verbose=False, force=("SENSOR", "VULNCHK"),
                         floor=stratified_chao_lo(H[m], lev[m]) if name == "all LEV" else None)
            n = int(m.sum())
            if "N_hat" in e:
                e["over"] = over(lev[m], e["N_hat"], n)
                e["over_raw_lev"] = over(lev_raw[m], e["N_hat"], n)
            forced[name] = e
            print(f"    {name:<16} " + (f"N_hat {e['N_hat']:.0f} [{e['ci'][0]:.0f}, {e['ci'][1]:.0f}] "
                  f"({'+'.join(e['model'])}) -> {e['over']:.2f}x, "
                  + ("identified" if e["identified"] else "NOT identified: " + e["reason"])
                  if "N_hat" in e else "no usable model"))
        extra["forced_SENSORxVULNCHK"] = forced

        # (b) counting without SENSOR: CISA + VULNCHK only (SOCIAL is not an
        # evidence-citing list, so it does not belong in this check).
        nos = {}
        print("\n  (b) counting without SENSOR -- union of CISA + VULNCHK:")
        for name, m in pieces:
            u, n = int((H.loc[m, ["CISA", "VULNCHK"]].sum(axis=1) > 0).sum()), int(m.sum())
            nos[name] = {"union": u, "n": n, "over": over(lev[m], u, n),
                         "over_raw_lev": over(lev_raw[m], u, n)}
            print(f"    {name:<16} union {u:>4}  over-confidence {nos[name]['over']:.2f}x "
                  f"(raw LEV {nos[name]['over_raw_lev']:.2f}x)")
        extra["no_sensor_counting_CISA+VULNCHK"] = nos

        # (c) SENSOR/VULNCHK overlap.  The before-removal count would need the
        # Shadowserver-hosted reports, which download_vulncheck.load() drops
        # before returning, so only the after-removal overlap is reported.
        ov = {name: {"SENSOR": int(H.loc[m, "SENSOR"].sum()),
                     "VULNCHK": int(H.loc[m, "VULNCHK"].sum()),
                     "SENSOR_and_VULNCHK": int((H.loc[m, "SENSOR"] & H.loc[m, "VULNCHK"]).sum())}
              for name, m in pieces}
        ov["all CVEs (any first-score date)"] = {
            "SENSOR": len(lists["SENSOR"]), "VULNCHK": len(lists["VULNCHK"]),
            "SENSOR_and_VULNCHK": len(lists["SENSOR"].index.intersection(lists["VULNCHK"].index))}
        ov["note"] = ("after removing Shadowserver-hosted VulnCheck reports; the "
                      "before-removal overlap is not exposed by data/download_vulncheck.load()")
        print("\n  (c) SENSOR & VULNCHK overlap, after removing Shadowserver-hosted reports "
              "(before-removal not exposed by the loader):")
        for name, d in ov.items():
            if name != "note":
                print(f"    {name:<32} SENSOR {d['SENSOR']:>4}  VULNCHK {d['VULNCHK']:>5}  "
                      f"both {d['SENSOR_and_VULNCHK']:>4}")
        extra["SENSOR_VULNCHK_overlap"] = ov

    # ------------- sensitivity: full cohort, stratified by birth period
    print(f"\n{'=' * 90}\nSENSITIVITY -- full v3-era cohort, by birth period\n{'=' * 90}")
    full = calibration.cohort(wide, first_idx, DN)
    Hf = histories(wide.index[full], lists)[primary]
    levf = levmod.lev(norm_wide[full], first_idx[full], dn=DN)
    born_in = (fd[full] >= SENSOR_START).to_numpy()
    sens = {"born before sensor window": truth_ladder(
                Hf[~born_in], levf[~born_in], "born BEFORE sensor window",
                floor=stratified_chao_lo(Hf[~born_in], levf[~born_in])),
            "born inside sensor window": truth_ladder(
                Hf[born_in], levf[born_in], "born INSIDE sensor window",
                floor=stratified_chao_lo(Hf[born_in], levf[born_in]))}

    # ------------------------------------------------------------- figure
    # No title: the caption lives in the paper.
    fig, ax = plt.subplots(figsize=(7.2, 5.0))
    names = list(strata_ladders)
    xs = [strata_est[n]["mean_lev"] for n in names]
    def rate(name, truth):
        """(rate, lo, hi) for one rung of one stratum; nan where absent."""
        r = next((x for x in strata_ladders[name] if x["truth"] == truth), None)
        n = strata_est[name]["n"]
        if not r or not r["exploited"]:
            return np.nan, np.nan, np.nan
        lo = r["exploited_lo"] if r["exploited_lo"] is not None else np.nan
        hi = r["exploited_hi"] if r["exploited_hi"] is not None else np.nan
        return r["exploited"] / n, lo / n, hi / n
    def plot(truth, style, col, label, **kw):
        y, lo, hi = np.array([rate(n, truth) for n in names]).T
        err = np.array([np.where(np.isfinite(lo), y - lo, 0),
                        np.where(np.isfinite(hi), hi - y, 0)])
        ax.errorbar(xs, y, yerr=np.nan_to_num(err), fmt=style, color=col, label=label,
                    capsize=3, elinewidth=1, **kw)
        return y, hi
    ax.plot([1e-3, 1], [1e-3, 1], "--", color="gray", lw=1, label="perfect calibration")
    plot("CISA KEV", "o-", "#365c8d", "CISA KEV")
    plot("CISA or SENSOR", "v-", "#4f7fae", "CISA or SENSOR")
    plot("union of primary lists", "s-", "#7fa3cc", "union of primary lists")
    chao_y, chao_hi = plot("Chao lower bound", "^-", "#8a6212", "Chao lower bound")
    plot("log-linear (AIC-selected)", "D", "#c1440e",
         "log-linear estimate (identified strata only)", ms=8)
    ax.set_xscale("log"); ax.set_yscale("log")
    ax.set_xlim(5e-3, 1.5); ax.set_ylim(3e-4, 1.5)
    # Mark strata without a log-linear estimate just above the top of the Chao
    # error bar, the highest mark in such a stratum, so the label clears every
    # marker.  The lowest stratum's upper points are driven by single-list
    # VulnCheck captures -- the label stops the Chao point above the diagonal
    # reading as "LEV under-confident at low scores".
    for i, (name, x) in enumerate(zip(names, xs)):
        if not strata_est[name].get("identified"):
            top = chao_hi[i] if np.isfinite(chao_hi[i]) else chao_y[i]
            ax.annotate("log-linear\nnot identified", (x, top), textcoords="offset points",
                        xytext=(0, 5), ha="center", va="bottom", fontsize=7,
                        color="#8a6212", style="italic")
    ax.set_xlabel("mean LEV in stratum (predicted; version-normalized EPSS)")
    ax.set_ylabel("exploitation rate under each notion of truth")
    ax.grid(alpha=.3, which="both"); ax.legend(fontsize=7.5, loc="upper left")
    FIGURE.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(FIGURE, dpi=150, bbox_inches="tight")
    fig.savefig(FIGURE.with_suffix(".pdf"), bbox_inches="tight")
    print(f"\nwrote {FIGURE} and {FIGURE.with_suffix('.pdf').name}")

    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(json.dumps({
        "lev_variant": "version-normalized",
        "lev_variant_note": ("strata and every 'over*' figure use LEV from "
                             "version-normalized EPSS; '*_raw_lev' keys are the same "
                             "figures with LEV from raw EPSS, for the same CVEs"),
        "mean_lev": float(lev.mean()), "mean_lev_raw_lev": float(lev_raw.mean()),
        "identification_rule": ("identified only if every model within 2 AIC of the "
                                "best is feasible, not below Chao's lower CI (or the "
                                "stratified Chao bound when pooled), and they agree "
                                "within 2x; boundary fits scored by extended MLE with "
                                "honest df, excluded if that leaves df 0"),
        "chao_form": "S + ((t-1)/t) f1^2/(2 f2)",
        "population": {"from": str(SENSOR_START.date()),
                       "to": str((DN - CENSOR).date()), "N": len(pop)},
        "lists": {k: len(v) for k, v in lists.items()},
        "captures": {c: int(H[c].sum()) for c in H},
        "overall_estimate": overall, "ladder": ladder, "gap_decomposition": gap,
        "strata": strata_ladders, "strata_estimates": strata_est,
        "primary_lists": primary, "list_set_grid": grid.to_dict(orient="records"),
        "sensitivity_lists": extra, "sensitivity": sens}, indent=2, default=float))
    print(f"wrote {RESULTS}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
