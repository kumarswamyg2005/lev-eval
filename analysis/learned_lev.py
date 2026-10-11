"""Phase 2 -- can a learned aggregation of EPSS history beat LEV?  (Appendix.)

LEV aggregates a CVE's EPSS history with one fixed rule (multiply 30-day
survival probabilities).  Here a model sees the SAME information -- the CVE's
EPSS history, nothing else -- and learns how to aggregate it.  Restricting the
inputs is what makes this a test of LEV's rule rather than a new predictor.

Both experiments are reported as NEGATIVE / circularity results; see
PROJECT-REVIEW.md section 9 for how the first version of this script
over-claimed and why it was rewritten.

E1  SNAPSHOT, PROSPECTIVE (the setup of recalibrate.py / paper Sec. 5.7):
    fit at 2025-08-01 on outcomes known then, score at 2026-08-01 on CVEs the
    fit never saw.  Three targets:
      UNION         any primary list (CISA KEV, SENSOR, VULNCHK)
      KEV           CISA KEV only
      UNION-NO-KEV  SENSOR or VULNCHK, with every CISA-KEV CVE removed from
                    train (KEV as of the fit date) and test (KEV as of the
                    score date).  KEV is an EPSS input, so a listed CVE's later
                    scores already reflect the outcome; dropping KEV members
                    cuts that path.  If a learned gain survives only with KEV
                    in the target, the gain is circular.
E2  FORWARD, ROLLING ORIGINS: features at t, label = first listing in
    (t, t + 182 d], population = CVEs >= 30 days old and on no list at t.
    Three origins.  Second target uses only CISA and SENSOR dates, because
    VulnCheck dates come from a 2026-09-28 snapshot and may be backdated.

Inputs are computed from VERSION-NORMALIZED EPSS (version_normalize.normalize),
as in recalibrate.py and capture_recapture.py, so "LEV" here is the same LEV
as in Sec. 5.6-5.7.  Within one day normalization is monotone, so rankings by
current EPSS are unchanged by it; only calibration differs.

Model choice is fixed by a rule that sees training data only: the training
cohort is split by first-score date (older 2/3 fit, newer 1/3 validate) and the
model with the higher validation AP is "selected".  Both models are always
reported.  (The rule was written after the first version of this script had
been run -- disclosed in the paper.)

Uncertainty: for the logistic model in E1 the bootstrap resamples training AND
test CVEs and refits, so training variance is included; other intervals
resample test CVEs only.  Many intervals, no multiplicity correction: the
results are exploratory.

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
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from data import download_epss
from models import lev as levmod
from analysis import capture_recapture as cr, recalibrate as rc, version_normalize

ROOT = Path(__file__).resolve().parent.parent
FIGURE = ROOT / "figures" / "learned_lev.png"
RESULTS = ROOT / "results" / "learned_lev.json"
DN = cr.DN                                   # 2026-08-01
DN_TR = DN - pd.Timedelta(days=365)          # Sec. 5.7's prospective fit date
HORIZON = pd.Timedelta(days=182)
ORIGINS = [pd.Timestamp(d) for d in ("2025-02-01", "2025-05-02", "2025-08-01")]
TOP = 0.01
BOOT = 500
SEED = 20261011

FEATURES = ["lev", "log_age", "epss_last", "epss_peak", "epss_mean",
            "epss_first", "epss_trend"]
PROBS = ["lev", "epss_last", "epss_peak", "epss_mean", "epss_first"]
METHODS = ["LEV", "EPSS now", "EPSS peak", "isotonic", "Platt+age", "logistic", "GBM"]


# ------------------------------------------------------------------ models
def logistic():
    """L2 logistic regression; probability features on the logit scale."""
    def tf(X):
        X = X.copy()
        for c in PROBS:
            q = np.clip(X[c].to_numpy(), rc.EPS, 1 - rc.EPS)
            X[c] = np.log(q / (1 - q))
        return X
    return make_pipeline(FunctionTransformer(tf), StandardScaler(),
                         LogisticRegression(C=1.0, max_iter=5000))


def gbm():
    # monotone in LEV, heavily regularized: training sets hold 24-288 positives
    return HistGradientBoostingClassifier(
        learning_rate=0.05, max_iter=200, max_leaf_nodes=8, min_samples_leaf=100,
        l2_regularization=1.0, early_stopping=False, random_state=0,
        monotonic_cst=[1 if f == "lev" else 0 for f in FEATURES])


# ---------------------------------------------------------------- features
def features(wide, first_idx, mask, t):
    """EPSS-history features at t from snapshots dated <= t (normalized EPSS)."""
    dates = wide.columns
    v = wide.loc[mask, dates <= t].to_numpy(dtype="float64")
    fi = first_idx[mask].to_numpy()
    seen = np.arange(v.shape[1])[None, :] >= fi[:, None]
    rows = np.arange(len(v))
    first_date = pd.DatetimeIndex(dates.to_numpy()[fi])
    return pd.DataFrame({
        "lev": levmod.lev(wide[mask], first_idx[mask], dn=t).to_numpy(),
        "log_age": np.log1p((t - first_date).days.to_numpy()),
        "epss_last": v[:, -1],
        "epss_peak": v.max(axis=1),
        "epss_mean": (v * seen).sum(axis=1) / np.maximum(seen.sum(axis=1), 1),
        "epss_first": v[rows, np.minimum(fi, v.shape[1] - 1)],
        "epss_trend": v[:, -1] - v[rows, np.maximum(v.shape[1] - 4, fi)],
    }, index=wide.index[mask])[FEATURES]


# ----------------------------------------------------------------- metrics
def score(p, y):
    m = rc.metrics(p, y)
    m["ap"] = float(average_precision_score(y, p)) if y.sum() else np.nan
    k = max(1, int(round(TOP * len(p))))
    # random tie-break: isotonic and LEV have many ties near 1
    order = np.lexsort((np.random.default_rng(0).random(len(p)), -np.asarray(p)))
    m["prec_top1"] = float(y[order[:k]].mean())
    m["recall_top1"] = float(y[order[:k]].sum() / max(y.sum(), 1))
    return m


def ap_diff_ci(y, pa, pb, rng):
    """AP(a) - AP(b), 95% bootstrap over test CVEs (predictions fixed)."""
    d = []
    for _ in range(BOOT):
        i = rng.integers(0, len(y), len(y))
        if y[i].sum():
            d.append(average_precision_score(y[i], pa[i]) - average_precision_score(y[i], pb[i]))
    return [float(np.percentile(d, 2.5)), float(np.percentile(d, 97.5))]


def refit_ci(Xtr, ytr, Xte, yte, baseline, rng, reps=200):
    """AP(logistic) - AP(baseline), resampling train AND test and refitting."""
    d = []
    for _ in range(reps):
        i = rng.integers(0, len(ytr), len(ytr))
        j = rng.integers(0, len(yte), len(yte))
        if ytr[i].sum() < 5 or not yte[j].sum():
            continue
        p = logistic().fit(Xtr.iloc[i], ytr[i]).predict_proba(Xte.iloc[j])[:, 1]
        d.append(average_precision_score(yte[j], p) - average_precision_score(yte[j], baseline[j]))
    return [float(np.percentile(d, 2.5)), float(np.percentile(d, 97.5))]


def select(Xtr, ytr, born):
    """Pre-declared choice: older 2/3 of the training cohort fit, newer 1/3 validate."""
    cut = np.quantile(born.astype("int64"), 2 / 3)
    a, b = born.astype("int64") <= cut, born.astype("int64") > cut
    if ytr[a].sum() < 5 or ytr[b].sum() < 1:
        return "logistic", {}
    ap = {name: float(average_precision_score(ytr[b], f().fit(Xtr[a], ytr[a]).predict_proba(Xtr[b])[:, 1]))
          for name, f in (("logistic", logistic), ("GBM", gbm))}
    return max(ap, key=ap.get), ap


def compare(Xtr, ytr, Xte, yte):
    lev_tr, lev_te = Xtr["lev"].to_numpy(), Xte["lev"].to_numpy()
    age = lambda X: np.expm1(X["log_age"].to_numpy())
    iso = rc.fit_isotonic(lev_tr, ytr)
    pa = rc.fit_platt_age(lev_tr, age(Xtr), ytr)
    preds = {
        "LEV": lev_te,
        "EPSS now": Xte["epss_last"].to_numpy(),
        "EPSS peak": Xte["epss_peak"].to_numpy(),
        "isotonic": rc.predict_isotonic(iso, lev_te),
        "Platt+age": rc.predict_platt_age(pa, lev_te, age(Xte)),
        "logistic": logistic().fit(Xtr, ytr).predict_proba(Xte)[:, 1],
        "GBM": gbm().fit(Xtr, ytr).predict_proba(Xte)[:, 1],
    }
    return {k: score(p, yte) for k, p in preds.items()}, preds


def report(title, res):
    print(f"\n  {title}")
    print(f"    {'':<11}{'pred/obs':>9}{'ECE':>9}{'Brier':>9}{'AP':>8}{'P@1%':>8}{'R@1%':>8}")
    for k, m in res.items():
        print(f"    {k:<11}{m['ratio']:>8.2f}x{m['ece']:>9.4f}{m['brier']:>9.5f}"
              f"{m['ap']:>8.3f}{m['prec_top1']:>8.3f}{m['recall_top1']:>8.3f}")


def show_ci(ci):
    print("    AP difference, 95% bootstrap: " +
          "; ".join(f"{k} [{lo:+.3f}, {hi:+.3f}]" for k, (lo, hi) in ci.items()))


# ------------------------------------------------------------- experiments
def snapshot(name, wide, first_idx, fd, test_mask, y_test, train_mask, y_train):
    rng = np.random.default_rng(SEED)
    Xp, yp = features(wide, first_idx, train_mask, DN_TR), y_train
    X, y = features(wide, first_idx, test_mask, DN), y_test
    unseen = ~X.index.isin(Xp.index)
    X, y = X[unseen], y[unseen]
    chosen, inner = select(Xp, yp, fd[Xp.index].to_numpy())
    print(f"\n{'=' * 78}\nE1 PROSPECTIVE  {name}: fit {DN_TR.date()} on {len(Xp):,} "
          f"({int(yp.sum())} pos) -> score {DN.date()} on {len(X):,} unseen "
          f"({int(y.sum())} pos); pre-declared rule selects {chosen} {inner}\n{'=' * 78}")
    res, preds = compare(Xp, yp, X, y)
    report("held-out", res)
    ci = {f"logistic - {b} (refit)": refit_ci(Xp, yp, X, y, preds[b], rng)
          for b in ("LEV", "EPSS now", "EPSS peak")}
    ci.update({f"GBM - {b}": ap_diff_ci(y, preds["GBM"], preds[b], rng)
               for b in ("LEV", "EPSS now")})
    show_ci(ci)
    coef = dict(zip(FEATURES, logistic().fit(Xp, yp)[-1].coef_[0].round(3).tolist()))
    return {"train": {"n": len(Xp), "positives": int(yp.sum())},
            "test": {"n": len(X), "positives": int(y.sum())},
            "selected_model": chosen, "selection_inner_ap": inner,
            "scores": res, "ap_diff_ci": ci, "logistic_coefficients": coef}


def forward(name, wide, first_idx, fd, eligible, first_listed, t_tr):
    rng = np.random.default_rng(SEED)
    t_te = t_tr + HORIZON
    listed = first_listed.reindex(wide.index)

    def at(t):
        mask = eligible & (fd <= t - pd.Timedelta(days=30)) & ~(listed <= t)
        lt = listed[mask]
        return (features(wide, first_idx, mask, t),
                ((lt > t) & (lt <= t + HORIZON)).to_numpy().astype(float))

    Xtr, ytr = at(t_tr)
    Xte, yte = at(t_te)
    # scope: listings in the test window that this population cannot contain
    win = eligible & (listed > t_te) & (listed <= t_te + HORIZON)
    outside = float((fd[win] > t_te - pd.Timedelta(days=30)).mean()) if win.sum() else np.nan
    chosen, inner = select(Xtr, ytr, fd[Xtr.index].to_numpy())
    print(f"\n{'=' * 78}\nE2 FORWARD  {name}: train t={t_tr.date()} N={len(Xtr):,} pos={int(ytr.sum())}"
          f";  test t={t_te.date()} N={len(Xte):,} pos={int(yte.sum())};  "
          f"{outside:.0%} of window listings fall outside the population; "
          f"rule selects {chosen}\n{'=' * 78}")
    res, preds = compare(Xtr, ytr, Xte, yte)
    report("all unlisted CVEs >= 30 days old at t", res)
    ci = {f"{a} - {b}": ap_diff_ci(yte, preds[a], preds[b], rng)
          for a, b in [("logistic", "EPSS now"), ("logistic", "LEV"),
                       ("GBM", "EPSS now"), ("EPSS now", "LEV")]}
    show_ci(ci)
    return {"train": {"t": str(t_tr.date()), "n": len(Xtr), "positives": int(ytr.sum())},
            "test": {"t": str(t_te.date()), "n": len(Xte), "positives": int(yte.sum()),
                     "base_rate": float(yte.mean())},
            "share_of_window_listings_outside_population": outside,
            "selected_model": chosen, "selection_inner_ap": inner,
            "scores": res, "ap_diff_ci": ci}


def main():
    tidy = download_epss.load()
    print("building matrices...")
    raw, first_idx = levmod.to_wide(tidy)
    wide = version_normalize.normalize(raw)
    dates = wide.columns
    fd = pd.Series(dates.to_numpy()[first_idx.to_numpy()], index=wide.index)
    iy = pd.Series(wide.index.astype(str).str.slice(4, 8).astype(int), index=wide.index)
    born_ok = ((fd.dt.year - iy) <= 1) & (fd >= cr.SENSOR_START)
    lists, lists_tr = cr.exploitation_lists(DN), cr.exploitation_lists(DN_TR)
    use = cr.EVIDENCE_LISTS if "VULNCHK" in lists else cr.FALLBACK_LISTS
    noncisa = [k for k in use if k != "CISA"]
    print(f"primary lists: {', '.join(use)}")
    on = lambda idx, L, ks: (cr.histories(idx, L)[ks].sum(axis=1) > 0).to_numpy().astype(float)

    test_pop = born_ok & (fd <= DN - cr.CENSOR)
    train_pop = born_ok & (fd <= DN_TR - cr.CENSOR)
    kev_te = wide.index.isin(lists["CISA"].index)
    kev_tr = wide.index.isin(lists_tr["CISA"].index)
    idx = lambda m: wide.index[m]
    out = {"lev_variant": "version-normalized", "features": FEATURES,
           "horizon_days": HORIZON.days, "E1": {}, "E2": {}}

    for name, te, tr, ks in [("UNION", test_pop, train_pop, use),
                             ("KEV", test_pop, train_pop, ["CISA"]),
                             ("UNION-NO-KEV", test_pop & ~kev_te, train_pop & ~kev_tr, noncisa)]:
        out["E1"][name] = snapshot(name, wide, first_idx, fd,
                                   te, on(idx(te), lists, ks), tr, on(idx(tr), lists_tr, ks))

    first_of = lambda ks: pd.concat([lists[k] for k in ks]).groupby(level=0).min()
    for name, ks in [("UNION", use), ("CISA+SENSOR dates", ["CISA", "SENSOR"])]:
        out["E2"][name] = [forward(name, wide, first_idx, fd, born_ok, first_of(ks), t)
                           for t in ORIGINS]

    # ---- figure: E1 AP by target (the circularity reversal), E2 AP by origin
    fig, axes = plt.subplots(1, 2, figsize=(12, 4.4))
    ax = axes[0]
    show = ["LEV", "EPSS now", "EPSS peak", "logistic", "GBM"]
    cols = ["#9aa7b8", "#2a9d8f", "#6a8caf", "#c1440e", "#7a5195"]
    targets = list(out["E1"])
    w = 0.16
    for i, (m, c) in enumerate(zip(show, cols)):
        ax.bar(np.arange(len(targets)) + (i - 2) * w,
               [out["E1"][t]["scores"][m]["ap"] for t in targets], w, color=c, label=m)
    ax.set_xticks(range(len(targets)))
    ax.set_xticklabels(["union", "CISA KEV", "union without KEV"])
    ax.set_ylabel("average precision, held-out (prospective)")
    ax.grid(alpha=.3, axis="y"); ax.legend(fontsize=8, ncol=2)
    ax = axes[1]
    e2 = out["E2"]["UNION"]
    x = [r["test"]["t"] for r in e2]
    for m, c in zip(show, cols):
        ax.plot(x, [r["scores"][m]["ap"] for r in e2], "o-", color=c, label=m)
    ax.plot(x, [r["test"]["base_rate"] for r in e2], "--", color="gray", label="base rate")
    ax.set_ylabel("average precision, next 182 days"); ax.set_xlabel("forecast origin")
    ax.set_yscale("log"); ax.grid(alpha=.3); ax.legend(fontsize=8, ncol=2)
    FIGURE.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(FIGURE, dpi=150, bbox_inches="tight")
    fig.savefig(FIGURE.with_suffix(".pdf"), bbox_inches="tight")
    print(f"\nwrote {FIGURE}")
    RESULTS.write_text(json.dumps(out, indent=2, default=float))
    print(f"wrote {RESULTS}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
