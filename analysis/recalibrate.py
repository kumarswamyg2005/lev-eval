"""Phase 2 -- fit a correction curve from LEV to observed exploitation.

This is the one model fitting the study does, and the only kind the data
supports honestly (see "Why there is no model" in the report): a monotone map
from LEV to observed probability, not a new predictor.  It answers a practical
question -- if a defender is handed a LEV score, what probability should they
actually read into it?

Two estimators:
  isotonic -- pool-adjacent-violators; non-parametric, monotone by construction
  Platt    -- logistic regression on logit(LEV); two parameters, smooth

Two targets, because the answer depends on what "exploited" means:
  KEV   -- CISA KEV only, full v3-era calibration cohort (105,250 CVEs)
  UNION -- any of the primary capture-recapture lists (CISA KEV, Shadowserver
           honeypots, VulnCheck rebuilt CISA-free; Telegram/social only if
           VulnCheck is unavailable), on CVEs born inside the sensor window so
           every list could see them (54,612)
Both targets are catalogue appearance, so both corrected probabilities are
LOWER bounds on true exploitation.  analysis/capture_recapture.py is what
estimates the truth; this gives the usable correction.

Validation -- the part that makes it "proper":
  * temporal holdout: fit on older CVEs, evaluate on newer ones.  This is the
    deployment situation (a correction fitted on the past, applied to new
    CVEs) and it exposes drift, which random splits hide.
  * 5-fold cross-validation, reported alongside for comparison.
All metrics are on held-out data only.  The prospective pred/obs ratios
carry a 95% bootstrap interval over test CVEs (maps held fixed).

LEV variant.  The correction is fitted on LEV from VERSION-NORMALIZED EPSS
(the paper's choice), and the uncorrected baseline row is that same LEV,
labelled "LEV (version-normalized)".  A "LEV (raw)" row, LEV from the
un-normalized EPSS for the same CVEs, is reported beside it for disclosure.

Run: python analysis/recalibrate.py
"""

import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from scipy import optimize

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from data import download_epss
from models import lev as levmod
from analysis import calibration, capture_recapture as cr, version_normalize

ROOT = Path(__file__).resolve().parent.parent
FIGURE = ROOT / "figures" / "recalibration.png"
RESULTS = ROOT / "results" / "recalibration.json"
DN = version_normalize.DN
EPS = 1e-6
RNG = np.random.default_rng(20260928)
# separate stream for the curve bootstrap, so adding it leaves the CV folds unchanged
CURVE_RNG, CURVE_BOOT = np.random.default_rng(1), 400
# and another for the prospective pred/obs interval, for the same reason
PROSP_RNG, PROSP_BOOT = np.random.default_rng(2), 1000
BASE, BASE_RAW = "LEV (version-normalized)", "LEV (raw)"


# ------------------------------------------------------------ estimators
def fit_isotonic(x, y):
    """Pool-adjacent-violators.  Returns (knots_x, knots_y) for a step map."""
    order = np.argsort(x, kind="mergesort")
    xs, ys = x[order], y[order].astype(float)
    # collapse ties first so the map is a function of x
    ux, inv = np.unique(xs, return_inverse=True)
    sums = np.bincount(inv, weights=ys)
    cnts = np.bincount(inv).astype(float)
    val, wt, lo = [], [], []
    for i in range(len(ux)):
        val.append(sums[i] / cnts[i]); wt.append(cnts[i]); lo.append(i)
        while len(val) > 1 and val[-2] > val[-1]:
            w = wt[-2] + wt[-1]
            v = (val[-2] * wt[-2] + val[-1] * wt[-1]) / w
            val[-2:] = [v]; wt[-2:] = [w]; lo.pop()
    out = np.empty(len(ux))
    starts = lo + [len(ux)]
    for j in range(len(val)):
        out[starts[j]:starts[j + 1]] = val[j]
    return ux, out


def _selftest():
    """PAV against hand-computed cases; fails loudly if the pooling is wrong."""
    # y = [1,0,1,1] on x = 1..4: first two violate, pool to 0.5
    ux, uy = fit_isotonic(np.array([1., 2, 3, 4]), np.array([1., 0, 1, 1]))
    assert np.allclose(uy, [0.5, 0.5, 1, 1]), uy
    # decreasing data pools to the global mean everywhere
    ux, uy = fit_isotonic(np.array([1., 2, 3]), np.array([1., 1, 0]))
    assert np.allclose(uy, 2 / 3), uy
    # ties in x are averaged before pooling
    ux, uy = fit_isotonic(np.array([1., 1, 2]), np.array([0., 1, 1]))
    assert np.allclose(uy, [0.5, 1]), uy
    # output is monotone and preserves the weighted mean, on random data
    x = RNG.random(500); y = (RNG.random(500) < x).astype(float)
    ux, uy = fit_isotonic(x, y)
    assert np.all(np.diff(uy) >= -1e-12)
    assert abs(predict_isotonic((ux, uy), x).mean() - y.mean()) < 1e-9


def predict_isotonic(model, x):
    ux, uy = model
    return np.interp(x, ux, uy, left=uy[0], right=uy[-1])


def fit_platt(x, y):
    """Logistic regression of y on logit(x): p = sigmoid(a*logit(x) + b)."""
    z = np.log(np.clip(x, EPS, 1 - EPS) / (1 - np.clip(x, EPS, 1 - EPS)))
    def nll(ab):
        t = ab[0] * z + ab[1]
        return np.sum(np.logaddexp(0, t) - y * t)
    res = optimize.minimize(nll, x0=[1.0, 0.0], method="BFGS")
    return tuple(res.x)


def predict_platt(model, x):
    a, b = model
    z = np.log(np.clip(x, EPS, 1 - EPS) / (1 - np.clip(x, EPS, 1 - EPS)))
    return 1 / (1 + np.exp(-(a * z + b)))


def fit_platt_age(x, age, y):
    """Platt with CVE age: p = sigmoid(a*logit(LEV) + c*log(age) + b).

    ASSUMPTION (not in CSWP 41): LEV's meaning depends on how many windows it
    compounded over -- an old CVE reaches a given LEV through many modest EPSS
    scores, a new one through a few high ones.  One extra parameter lets the
    correction condition on that instead of averaging over it.
    """
    z = np.log(np.clip(x, EPS, 1 - EPS) / (1 - np.clip(x, EPS, 1 - EPS)))
    la = np.log(np.maximum(age, 1.0))
    def nll(p):
        t = p[0] * z + p[1] + p[2] * la
        return np.sum(np.logaddexp(0, t) - y * t)
    return tuple(optimize.minimize(nll, x0=[1.0, 0.0, 0.0], method="BFGS").x)


def predict_platt_age(model, x, age):
    a, b, c = model
    z = np.log(np.clip(x, EPS, 1 - EPS) / (1 - np.clip(x, EPS, 1 - EPS)))
    return 1 / (1 + np.exp(-(a * z + b + c * np.log(np.maximum(age, 1.0)))))


# --------------------------------------------------------------- metrics
def metrics(p, y):
    p = np.clip(np.asarray(p, float), 0, 1)
    y = np.asarray(y, float)
    _, brier, ece = calibration.evaluate(p, y)
    pc = np.clip(p, EPS, 1 - EPS)
    logloss = float(-np.mean(y * np.log(pc) + (1 - y) * np.log(1 - pc)))
    return {"brier": brier, "ece": ece, "logloss": logloss,
            "ratio": float(p.mean() / y.mean()) if y.mean() else np.nan}


def evaluate_split(x_tr, y_tr, a_tr, x_te, y_te, a_te, xr_te):
    """Fit the maps on the training split; score them and both uncorrected
    baselines (xr_te = raw LEV of the test CVEs) on the test split."""
    iso, platt = fit_isotonic(x_tr, y_tr), fit_platt(x_tr, y_tr)
    pa = fit_platt_age(x_tr, a_tr, y_tr)
    preds = {BASE: x_te, BASE_RAW: xr_te,
             "isotonic": predict_isotonic(iso, x_te),
             "Platt": predict_platt(platt, x_te),
             "Platt+age": predict_platt_age(pa, x_te, a_te)}
    return {m: metrics(p, y_te) for m, p in preds.items()}, iso, platt, preds


def ratio_ci(preds, y):
    """95% bootstrap interval on pred/obs: resample test CVEs, maps fixed."""
    idx = [PROSP_RNG.integers(0, len(y), len(y)) for _ in range(PROSP_BOOT)]
    return {m: [float(v) for v in np.percentile(
                [p[i].mean() / y[i].mean() for i in idx], [2.5, 97.5])]
            for m, p in preds.items()}


def cross_validate(x, y, age, xr, k=5):
    folds = RNG.permutation(len(x)) % k
    agg = {}
    for f in range(k):
        tr, te = folds != f, folds == f
        res, *_ = evaluate_split(x[tr], y[tr], age[tr], x[te], y[te], age[te], xr[te])
        for m, v in res.items():
            for s, val in v.items():
                agg.setdefault(m, {}).setdefault(s, []).append(val)
    return {m: {s: float(np.mean(v)) for s, v in d.items()} for m, d in agg.items()}


def report(title, res, ci=None):
    print(f"\n  {title}")
    print(f"    {'':<26}{'Brier':>10}{'ECE':>10}{'log-loss':>10}{'pred/obs':>10}")
    for m, v in res.items():
        c = f"  [{ci[m][0]:.2f}, {ci[m][1]:.2f}]" if ci else ""
        print(f"    {m:<26}{v['brier']:>10.5f}{v['ece']:>10.5f}"
              f"{v['logloss']:>10.4f}{v['ratio']:>9.2f}x{c}")


def run(name, x, y, age, born, split, prospective, xr):
    """Three validation schemes, all scored on held-out CVEs only.

    prospective = (x_tr, y_tr, age_tr) fitted at an EARLIER analysis date, on
    CVEs disjoint from the test set; the test set is scored at the final date.
    That is the deployment situation: a correction learned last year, applied
    to CVEs it has never seen.  xr = raw LEV of the same CVEs, for the
    disclosed raw baseline row only.
    """
    print(f"\n{'=' * 82}\nTARGET: {name}   (N={len(x):,}, positives={int(y.sum())}, "
          f"base rate {y.mean():.4f})\n{'=' * 82}")
    cv = cross_validate(x, y, age, xr)
    report("A. 5-fold cross-validation -- in-distribution, the optimistic case", cv)

    tr, te = born < split, born >= split
    birth, *_ = evaluate_split(x[tr], y[tr], age[tr], x[te], y[te], age[te], xr[te])
    report(f"B. birth-cohort split at {split.date()} -- train {int(tr.sum()):,}, "
           f"test {int(te.sum()):,}; ages do not overlap", birth)

    xp, yp, ap, test_mask = prospective
    prosp, _, _, preds = evaluate_split(xp, yp, ap, x[test_mask], y[test_mask],
                                        age[test_mask], xr[test_mask])
    prosp_ci = ratio_ci(preds, y[test_mask])
    report(f"C. PROSPECTIVE -- fitted one year earlier on {len(xp):,} CVEs "
           f"({int(yp.sum())} pos), applied to {int(test_mask.sum()):,} unseen "
           f"({int(y[test_mask].sum())} pos); [95% bootstrap on pred/obs]", prosp, prosp_ci)

    iso_all, platt_all = fit_isotonic(x, y), fit_platt(x, y)
    grid = np.array([0.01, 0.05, 0.1, 0.3, 0.5, 0.7, 0.9, 0.99, 1.0])
    table = pd.DataFrame({"LEV": grid,
                          "isotonic": predict_isotonic(iso_all, grid),
                          "Platt": predict_platt(platt_all, grid)})
    # 95% bootstrap interval on the isotonic curve: resample CVEs, refit, re-read
    bs = np.array([predict_isotonic(fit_isotonic(x[i], y[i]), grid)
                   for i in (CURVE_RNG.integers(0, len(x), len(x)) for _ in range(CURVE_BOOT))])
    table["iso_lo"], table["iso_hi"] = np.percentile(bs, [2.5, 97.5], axis=0)
    print("\n  the correction curve (isotonic, fitted on all data): what a LEV score means")
    print(table.to_string(index=False, float_format=lambda v: f"{v:.4f}"))
    return {"n": len(x), "positives": int(y.sum()), "cv": cv, "birth_split": birth,
            "prospective": prosp, "prospective_ratio_ci": prosp_ci,
            "prospective_test_n": int(test_mask.sum()),
            "prospective_test_positives": int(y[test_mask].sum()),
            "curve": table.to_dict(orient="list")}, iso_all, platt_all


def main():
    _selftest()
    print("isotonic self-test OK")
    tidy = download_epss.load()
    print("\nbuilding matrices...")
    wide, first_idx = levmod.to_wide(tidy)
    norm_wide = version_normalize.normalize(wide)
    dates = wide.columns
    fd = pd.Series(dates.to_numpy()[first_idx.to_numpy()], index=wide.index)
    iy = pd.Series(wide.index.astype(str).str.slice(4, 8).astype(int),
                   index=wide.index)
    nbf = (fd.dt.year - iy) <= 1
    DN_TR = DN - pd.Timedelta(days=365)        # prospective fit date: 2025-08-01
    lists = cr.exploitation_lists(DN)
    lists_tr = cr.exploitation_lists(DN_TR)    # only what was known at DN_TR
    age = lambda idx, dn: (dn - fd[idx]).dt.days.to_numpy().astype(float)

    def lev_at(mask, dn, w=norm_wide):
        return levmod.lev(w[mask], first_idx[mask], dn=dn)

    # ------------------------------------------------ target 1: CISA KEV
    m1 = calibration.cohort(wide, first_idx, DN)
    x1 = lev_at(m1, DN)
    y1 = x1.index.isin(lists["CISA"].index).astype(float)
    tr1 = calibration.cohort(wide, first_idx, DN_TR)
    xp1 = lev_at(tr1, DN_TR)
    yp1 = xp1.index.isin(lists_tr["CISA"].index).astype(float)
    test1 = ~x1.index.isin(xp1.index)          # CVEs the old model never saw
    r1, iso1, pl1 = run("CISA KEV", x1.to_numpy(), y1, age(x1.index, DN),
                        fd[m1].to_numpy(), pd.Timestamp("2024-07-01"),
                        (xp1.to_numpy(), yp1, age(xp1.index, DN_TR), test1),
                        lev_at(m1, DN, wide).to_numpy())

    # ------------------- target 2: union of independent lists, sensor window
    born_ok = nbf & (fd >= cr.SENSOR_START)
    m2 = born_ok & (fd <= DN - cr.CENSOR)
    x2 = lev_at(m2, DN)
    # union over the same lists as the primary capture-recapture analysis
    use = cr.EVIDENCE_LISTS if "VULNCHK" in lists else cr.FALLBACK_LISTS
    print(f"union target lists: {', '.join(use)}")
    y2 = (cr.histories(x2.index, lists)[use].sum(axis=1) > 0).astype(float).to_numpy()
    tr2 = born_ok & (fd <= DN_TR - cr.CENSOR)
    xp2 = lev_at(tr2, DN_TR)
    yp2 = (cr.histories(xp2.index, lists_tr)[use].sum(axis=1) > 0).astype(float).to_numpy()
    test2 = ~x2.index.isin(xp2.index)
    r2, iso2, pl2 = run("UNION of " + " + ".join(use), x2.to_numpy(), y2,
                        age(x2.index, DN), fd[m2].to_numpy(), pd.Timestamp("2025-06-01"),
                        (xp2.to_numpy(), yp2, age(xp2.index, DN_TR), test2),
                        lev_at(m2, DN, wide).to_numpy())

    # ------------------------------------------------------------- figure
    fig, axes = plt.subplots(1, 3, figsize=(15, 4.6),
                             gridspec_kw={"width_ratios": [1, 1, 1]})
    grid = np.linspace(0, 1, 400)
    ax = axes[0]
    ax.plot([0, 1], [0, 1], "--", color="gray", lw=1, label="LEV taken at face value")
    ax.plot(grid, predict_isotonic(iso1, grid), color="#365c8d", lw=2,
            label="corrected to CISA KEV")
    ax.plot(grid, predict_isotonic(iso2, grid), color="#c1440e", lw=2,
            label="corrected to union of primary lists")
    ax.set_xlabel("LEV score (version-normalized EPSS)")
    ax.set_ylabel("probability to read into it")
    ax.set_title("The correction curve (isotonic)"); ax.grid(alpha=.3)
    ax.legend(fontsize=8)

    # Right: does it transfer?  Both targets, every scheme; the prospective
    # bars carry their bootstrap interval.
    methods = [BASE, "isotonic", "Platt", "Platt+age"]
    labels = ["LEV\n(version-normalized)", "isotonic", "Platt", "Platt+age"]
    schemes = [("cv", "5-fold CV"), ("birth_split", "birth split"),
               ("prospective", "prospective")]
    w = 0.26
    cols = ["#9aa7b8", "#365c8d", "#c1440e"]
    for ax, (r, tname) in zip(axes[1:], [(r1, "CISA KEV"),
                                         (r2, "union of primary lists")]):
        for i, (key, lab) in enumerate(schemes):
            vals = np.array([r[key][m]["ratio"] for m in methods])
            err = None
            if key == "prospective":
                ci = np.array([r["prospective_ratio_ci"][m] for m in methods]).T
                err = np.array([vals - ci[0], ci[1] - vals])
            ax.bar(np.arange(4) + (i - 1) * w, vals, w, color=cols[i], label=lab,
                   yerr=err, capsize=2, error_kw={"elinewidth": 1})
        ax.axhline(1, color="black", lw=1)
        ax.set_xticks(range(4)); ax.set_xticklabels(labels, fontsize=8)
        ax.set_yscale("log")
        ax.set_title(f"Does it transfer? Target: {tname}")
        ax.grid(alpha=.3, axis="y"); ax.legend(fontsize=8)
    axes[1].set_ylabel("predicted / observed, held-out (1 = calibrated)")
    axes[2].sharey(axes[1])
    FIGURE.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(FIGURE, dpi=150, bbox_inches="tight")
    print(f"\nwrote {FIGURE}")

    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(json.dumps({"lev_variant": "version-normalized",
                                   "lev_variant_note": (
                                       f"maps are fitted on, and '{BASE}' is, LEV from "
                                       f"version-normalized EPSS; '{BASE_RAW}' is LEV "
                                       "from raw EPSS for the same CVEs"),
                                   "KEV": r1, "UNION": r2,
                                   "prospective_fit_date": str(DN_TR.date())},
                                  indent=2, default=float))
    print(f"wrote {RESULTS}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
