"""Phase 2 -- a learned alternative to LEV's compounding rule.

LEV is a fixed rule for aggregating a CVE's EPSS history: multiply the
30-day survival probabilities.  This script asks whether a model that sees the
SAME information -- the CVE's EPSS history and nothing else -- but LEARNS how
to aggregate it does better.  If it does, LEV's error lies in the rule
(independence across windows, compounding across EPSS retrainings, no decay),
not in the information EPSS carries.  That is the paper's question asked of a
model, so the model answers it rather than replacing it.

The four objections in the report's "Why there is no model" are met by design:
  wrong question  -- inputs are restricted to LEV's own information set, so the
                     comparison isolates the aggregation rule; no CVSS, CWE,
                     vendor or exploit-code features.
  broken labels   -- the primary target is the union of the evidence-citing
                     lists (CISA KEV, Shadowserver honeypots, VulnCheck rebuilt
                     CISA- and Shadowserver-free); KEV is reported second.
  circularity     -- Experiment 2 is FORWARD: features use EPSS dated <= t,
                     the population excludes CVEs already on any list at t, and
                     the label is first listing in (t, t + 6 months].  A
                     listing cannot feed back into scores dated before it.
  copies EPSS     -- the current EPSS score is a baseline, not a hidden input:
                     the model must beat it to claim anything.

Two learned models.  The primary one is L2 logistic regression on the logit
scale, where LEV's compounding is additive -- so it is LEV with learned weights
instead of fixed ones, and its coefficients say how.  A gradient-boosted model
(GBM) is the flexibility check: if it does no better, there is nothing
non-linear left for ~100-700 positives to teach.

Experiment 1 (snapshot correction) extends Section 5.7: same populations, same
three validation schemes, with both models beside isotonic and age-aware
Platt.  Experiment 2 (leading indicator) is new: can LEV, EPSS or
the model flag a CVE before any list records it?  No test row's label window
overlaps any training row's, so there is no temporal snooping (Arp et al.,
USENIX Security 2022, pitfall P3).

Run: python analysis/learned_lev.py
"""

import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.inspection import permutation_importance
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler
from sklearn.metrics import average_precision_score, precision_recall_curve

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from data import download_epss
from models import lev as levmod
from analysis import calibration, capture_recapture as cr, recalibrate as rc
from analysis.leakage import RETRAININGS

ROOT = Path(__file__).resolve().parent.parent
FIGURE = ROOT / "figures" / "learned_lev.png"
RESULTS = ROOT / "results" / "learned_lev.json"
DN = cr.DN                                   # 2026-08-01
DN_TR = DN - pd.Timedelta(days=365)          # Section 5.7's prospective fit date
HORIZON = pd.Timedelta(days=182)             # forward label window
T_TR, T_TE = DN_TR, DN_TR + HORIZON         # 2025-08-01 and 2026-01-30;
# the training labels end on T_TE, where the test features begin
TOP = 0.01                                   # "flag the top 1%" operating point
BOOT = 500
RNG = np.random.default_rng(20261011)

FEATURES = ["lev", "log_age", "epss_last", "epss_max", "epss_mean",
            "epss_first", "epss_trend", "n_retrain"]
# LEV can only raise the predicted probability: keeps the model a correction
# of LEV, not a reversal of it.  ponytail: one constraint; add more if a
# feature's sign turns out to flip between splits.
MONOTONE = [1 if f == "lev" else 0 for f in FEATURES]


def model():
    # heavily regularized: the union target has only ~100-700 positives
    return HistGradientBoostingClassifier(
        learning_rate=0.05, max_iter=200, max_leaf_nodes=8, min_samples_leaf=100,
        l2_regularization=1.0, early_stopping=False, monotonic_cst=MONOTONE,
        random_state=0)


def logistic():
    """The primary learned model: probabilities go to the logit scale first,
    where LEV's compounding is additive, so this is a re-weighted LEV."""
    def tf(X):
        X = X.copy()
        for c in ["lev", "epss_last", "epss_max", "epss_mean", "epss_first"]:
            q = np.clip(X[c].to_numpy(), rc.EPS, 1 - rc.EPS)
            X[c] = np.log(q / (1 - q))
        return X
    return make_pipeline(FunctionTransformer(tf), StandardScaler(),
                         LogisticRegression(C=1.0, max_iter=5000))


# ---------------------------------------------------------------- features
def features(wide, first_idx, mask, t):
    """EPSS-history features at date t, using only snapshots dated <= t."""
    dates = wide.columns
    cols = dates <= t
    v = wide.loc[mask, cols].to_numpy(dtype="float64")
    fi = first_idx[mask].to_numpy()
    j = np.arange(v.shape[1])
    seen = j[None, :] >= fi[:, None]
    n = seen.sum(axis=1)
    first_date = dates.to_numpy()[fi]
    rows = np.arange(len(v))
    X = pd.DataFrame({
        "lev": levmod.lev(wide[mask], first_idx[mask], dn=t).to_numpy(),
        "log_age": np.log1p((t - pd.DatetimeIndex(first_date)).days.to_numpy()),
        "epss_last": v[:, -1],
        "epss_max": v.max(axis=1),
        "epss_mean": (v * seen).sum(axis=1) / np.maximum(n, 1),
        "epss_first": v[rows, np.minimum(fi, v.shape[1] - 1)],
        "epss_trend": v[:, -1] - v[rows, np.maximum(v.shape[1] - 4, fi)],
        "n_retrain": sum(((first_date < r) & (r <= t)).astype(int) for r in RETRAININGS),
    }, index=wide.index[mask])
    return X[FEATURES]


# ----------------------------------------------------------------- metrics
def score(p, y):
    m = rc.metrics(p, y)
    m["ap"] = float(average_precision_score(y, p)) if y.sum() else np.nan
    k = max(1, int(round(TOP * len(p))))
    top = np.argsort(-np.asarray(p), kind="mergesort")[:k]
    m["prec_top1"] = float(y[top].mean())
    m["recall_top1"] = float(y[top].sum() / max(y.sum(), 1))
    return m


def ap_diff_ci(y, pa, pb):
    """95% bootstrap interval on AP(a) - AP(b), resampling test CVEs."""
    d = []
    for _ in range(BOOT):
        i = RNG.integers(0, len(y), len(y))
        if y[i].sum():
            d.append(average_precision_score(y[i], pa[i]) - average_precision_score(y[i], pb[i]))
    return [float(np.percentile(d, 2.5)), float(np.percentile(d, 97.5))]


def compare(Xtr, ytr, Xte, yte):
    """Every method fitted on train, scored on test.
    Returns (scores, preds, fitted logistic, fitted GBM)."""
    iso = rc.fit_isotonic(Xtr["lev"].to_numpy(), ytr)
    age = lambda X: np.expm1(X["log_age"].to_numpy())
    pa = rc.fit_platt_age(Xtr["lev"].to_numpy(), age(Xtr), ytr)
    gbm = model().fit(Xtr, ytr)
    lr = logistic().fit(Xtr, ytr)
    preds = {
        "raw LEV": Xte["lev"].to_numpy(),
        "EPSS now": Xte["epss_last"].to_numpy(),
        "isotonic": rc.predict_isotonic(iso, Xte["lev"].to_numpy()),
        "Platt+age": rc.predict_platt_age(pa, Xte["lev"].to_numpy(), age(Xte)),
        "logistic": lr.predict_proba(Xte)[:, 1],
        "GBM": gbm.predict_proba(Xte)[:, 1],
    }
    return {k: score(p, yte) for k, p in preds.items()}, preds, lr, gbm


def report(title, res):
    print(f"\n  {title}")
    print(f"    {'':<11}{'pred/obs':>9}{'ECE':>9}{'Brier':>9}{'AP':>8}{'P@1%':>8}{'R@1%':>8}")
    for k, m in res.items():
        print(f"    {k:<11}{m['ratio']:>8.2f}x{m['ece']:>9.4f}{m['brier']:>9.5f}"
              f"{m['ap']:>8.3f}{m['prec_top1']:>8.3f}{m['recall_top1']:>8.3f}")


def coefficients(lr):
    """Standardized logistic coefficients: the learned aggregation rule."""
    c = dict(zip(FEATURES, lr[-1].coef_[0].round(3).tolist()))
    print("    logistic coefficients (per SD, logit scale):",
          ", ".join(f"{k} {v:+.2f}" for k, v in c.items()))
    return c


def ap_cis(y, preds, pairs):
    ci = {f"{a} - {b}": ap_diff_ci(y, preds[a], preds[b]) for a, b in pairs}
    print("    AP difference, 95% bootstrap:",
          "; ".join(f"{k} [{lo:+.3f}, {hi:+.3f}]" for k, (lo, hi) in ci.items()))
    return ci


def importance(gbm, X, y):
    r = permutation_importance(gbm, X, y, scoring="average_precision",
                               n_repeats=5, random_state=0)
    imp = dict(zip(FEATURES, r.importances_mean.round(4).tolist()))
    print("    permutation importance (drop in held-out AP):",
          ", ".join(f"{k} {v:+.3f}" for k, v in sorted(imp.items(), key=lambda kv: -kv[1])))
    return imp


# ------------------------------------------------------------- experiments
def snapshot(name, wide, first_idx, m_all, y_of, t_split, m_prev, y_prev):
    """Experiment 1: Section 5.7's three schemes, plus the learned model."""
    X = features(wide, first_idx, m_all, DN)
    y = y_of(X.index)
    fd = wide.columns.to_numpy()[first_idx[m_all].to_numpy()]
    print(f"\n{'=' * 78}\nE1 SNAPSHOT  target {name}: N={len(X):,}, positives={int(y.sum())}"
          f"\n{'=' * 78}")
    out = {"n": len(X), "positives": int(y.sum())}

    folds = RNG.permutation(len(X)) % 5
    cv = {}
    for f in range(5):
        res, *_ = compare(X[folds != f], y[folds != f], X[folds == f], y[folds == f])
        for k, mm in res.items():
            for s, val in mm.items():
                cv.setdefault(k, {}).setdefault(s, []).append(val)
    out["cv"] = {k: {s: float(np.mean(v)) for s, v in d.items()} for k, d in cv.items()}
    report("A. 5-fold CV (in-distribution)", out["cv"])

    tr, te = fd < t_split, fd >= t_split
    out["birth_split"], *_ = compare(X[tr], y[tr], X[te], y[te])
    report(f"B. birth-cohort split at {t_split.date()}: train {tr.sum():,}, test {te.sum():,}",
           out["birth_split"])

    Xp = features(wide, first_idx, m_prev, DN_TR)
    yp = y_prev(Xp.index)
    unseen = ~X.index.isin(Xp.index)
    out["prospective"], preds, lr, gbm = compare(Xp, yp, X[unseen], y[unseen])
    report(f"C. PROSPECTIVE: fit at {DN_TR.date()} on {len(Xp):,} ({int(yp.sum())} pos), "
           f"scored at {DN.date()} on {unseen.sum():,} unseen", out["prospective"])
    out["ap_diff_ci"] = ap_cis(y[unseen], preds, [("logistic", b) for b in
                               ("raw LEV", "EPSS now", "Platt+age")] + [("GBM", "logistic")])
    out["coefficients"] = coefficients(lr)
    out["importance"] = importance(gbm, X[unseen], y[unseen])
    return out


def forward(name, wide, first_idx, eligible, first_listed):
    """Experiment 2: features at t, label = first listed in (t, t + HORIZON]."""
    dates = wide.columns.to_numpy()
    fd = pd.Series(dates[first_idx.to_numpy()], index=wide.index)
    listed = first_listed.reindex(wide.index)

    def at(t):
        # history of at least one month, and not yet on any list at t
        mask = eligible & (fd <= t - pd.Timedelta(days=30)) & ~(listed <= t)
        X = features(wide, first_idx, mask, t)
        lt = listed[mask]
        return X, ((lt > t) & (lt <= t + HORIZON)).to_numpy().astype(float)

    Xtr, ytr = at(T_TR)
    Xte, yte = at(T_TE)
    print(f"\n{'=' * 78}\nE2 FORWARD  target {name}: train t={T_TR.date()} N={len(Xtr):,} "
          f"pos={int(ytr.sum())};  test t={T_TE.date()} N={len(Xte):,} pos={int(yte.sum())}"
          f"\n{'=' * 78}")
    res, preds, lr, gbm = compare(Xtr, ytr, Xte, yte)
    report("all unlisted CVEs at t", res)
    new = (fd[Xte.index] > T_TR).to_numpy()   # CVEs the training set never contained
    res_new = {k: score(p[new], yte[new]) for k, p in preds.items()}
    report(f"subset first scored after {T_TR.date()} ({new.sum():,} CVEs, "
           f"{int(yte[new].sum())} pos)", res_new)
    ci = ap_cis(yte, preds, [(a, b) for a in ("logistic", "GBM")
                             for b in ("raw LEV", "EPSS now")] + [("EPSS now", "raw LEV")])
    coef = coefficients(lr)
    imp = importance(gbm, Xte, yte)
    return {"train": {"t": str(T_TR.date()), "n": len(Xtr), "positives": int(ytr.sum())},
            "test": {"t": str(T_TE.date()), "n": len(Xte), "positives": int(yte.sum())},
            "all": res, "new_cves": res_new, "ap_diff_ci": ci, "coefficients": coef, "importance": imp}, preds, yte


def main():
    tidy = download_epss.load()
    print("building matrices...")
    wide, first_idx = levmod.to_wide(tidy)
    dates = wide.columns
    fd = pd.Series(dates.to_numpy()[first_idx.to_numpy()], index=wide.index)
    iy = pd.Series(wide.index.astype(str).str.slice(4, 8).astype(int), index=wide.index)
    nbf = (fd.dt.year - iy) <= 1
    lists, lists_tr = cr.exploitation_lists(DN), cr.exploitation_lists(DN_TR)
    use = cr.EVIDENCE_LISTS if "VULNCHK" in lists else cr.FALLBACK_LISTS
    print(f"union lists: {', '.join(use)}")
    union = lambda L: lambda idx: (cr.histories(idx, L)[use].sum(axis=1) > 0).to_numpy().astype(float)
    kev = lambda L: lambda idx: idx.isin(L["CISA"].index).astype(float)

    # ---- E1: the two populations of Section 5.7, unchanged
    born_ok = nbf & (fd >= cr.SENSOR_START)
    e1_union = snapshot("UNION", wide, first_idx,
                        born_ok & (fd <= DN - cr.CENSOR), union(lists),
                        pd.Timestamp("2025-06-01"),
                        born_ok & (fd <= DN_TR - cr.CENSOR), union(lists_tr))
    e1_kev = snapshot("CISA KEV", wide, first_idx,
                      calibration.cohort(wide, first_idx, DN), kev(lists),
                      pd.Timestamp("2024-07-01"),
                      calibration.cohort(wide, first_idx, DN_TR), kev(lists_tr))

    # ---- E2: forward, inside the sensor window so every list can see every CVE
    first_union = pd.concat([lists[k] for k in use]).groupby(level=0).min()
    e2_union, preds, yte = forward("UNION", wide, first_idx, born_ok, first_union)
    e2_kev, _, _ = forward("CISA KEV", wide, first_idx, born_ok, lists["CISA"])

    # ---- figure
    fig, axes = plt.subplots(1, 2, figsize=(12, 4.6))
    ax = axes[0]
    methods = ["raw LEV", "isotonic", "Platt+age", "logistic", "GBM"]
    schemes = [("cv", "5-fold CV"), ("birth_split", "birth split"), ("prospective", "prospective")]
    cols = ["#9aa7b8", "#365c8d", "#c1440e"]
    for i, (key, lab) in enumerate(schemes):
        ax.bar(np.arange(len(methods)) + (i - 1) * 0.26, [e1_union[key][m]["ratio"] for m in methods],
               0.26, color=cols[i], label=lab)
    ax.axhline(1, color="black", lw=1)
    ax.set_xticks(range(len(methods))); ax.set_xticklabels(methods, fontsize=8); ax.set_yscale("log")
    ax.set_ylabel("predicted / observed, held-out (1 = calibrated)")
    ax.set_title("E1: correcting LEV (union target)"); ax.grid(alpha=.3, axis="y")
    ax.legend(fontsize=8)
    ax = axes[1]
    for k, c in [("raw LEV", "#9aa7b8"), ("EPSS now", "#2a9d8f"), ("logistic", "#c1440e")]:
        pr, rcl, _ = precision_recall_curve(yte, preds[k])
        # drop sklearn's sentinel point (recall 0, precision 1)
        ax.plot(rcl[:-1], pr[:-1], color=c, lw=2, label=f"{k} (AP {e2_union['all'][k]['ap']:.3f})")
    ax.axhline(yte.mean(), color="gray", ls="--", lw=1, label="base rate")
    ax.set_xlabel("recall"); ax.set_ylabel("precision"); ax.set_yscale("log")
    ax.set_title(f"E2: flagging CVEs before any list (next {HORIZON.days} days)")
    ax.grid(alpha=.3); ax.legend(fontsize=8)
    FIGURE.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(FIGURE, dpi=150, bbox_inches="tight")
    print(f"\nwrote {FIGURE}")

    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(json.dumps({
        "features": FEATURES, "horizon_days": HORIZON.days,
        "E1_snapshot": {"UNION": e1_union, "KEV": e1_kev},
        "E2_forward": {"UNION": e2_union, "KEV": e2_kev}}, indent=2, default=float))
    print(f"wrote {RESULTS}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
