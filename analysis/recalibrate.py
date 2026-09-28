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
  UNION -- CISA KEV, Shadowserver honeypots or Telegram/social, on CVEs born
           inside the sensor window so every list could see them (54,612)
Both targets are catalogue appearance, so both corrected probabilities are
LOWER bounds on true exploitation.  analysis/capture_recapture.py is what
estimates the truth; this gives the usable correction.

Validation -- the part that makes it "proper":
  * temporal holdout: fit on older CVEs, evaluate on newer ones.  This is the
    deployment situation (a correction fitted on the past, applied to new
    CVEs) and it exposes drift, which random splits hide.
  * 5-fold cross-validation, reported alongside for comparison.
All metrics are on held-out data only.

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


def evaluate_split(x_tr, y_tr, a_tr, x_te, y_te, a_te):
    iso, platt = fit_isotonic(x_tr, y_tr), fit_platt(x_tr, y_tr)
    pa = fit_platt_age(x_tr, a_tr, y_tr)
    return {"raw LEV": metrics(x_te, y_te),
            "isotonic": metrics(predict_isotonic(iso, x_te), y_te),
            "Platt": metrics(predict_platt(platt, x_te), y_te),
            "Platt+age": metrics(predict_platt_age(pa, x_te, a_te), y_te)}, iso, platt


def cross_validate(x, y, age, k=5):
    folds = RNG.permutation(len(x)) % k
    agg = {}
    for f in range(k):
        tr, te = folds != f, folds == f
        res, _, _ = evaluate_split(x[tr], y[tr], age[tr], x[te], y[te], age[te])
        for m, v in res.items():
            for s, val in v.items():
                agg.setdefault(m, {}).setdefault(s, []).append(val)
    return {m: {s: float(np.mean(v)) for s, v in d.items()} for m, d in agg.items()}


def report(title, res):
    print(f"\n  {title}")
    print(f"    {'':<10}{'Brier':>10}{'ECE':>10}{'log-loss':>10}{'pred/obs':>10}")
    for m, v in res.items():
        print(f"    {m:<10}{v['brier']:>10.5f}{v['ece']:>10.5f}"
              f"{v['logloss']:>10.4f}{v['ratio']:>9.2f}x")


def run(name, x, y, age, born, split, prospective):
    """Three validation schemes, all scored on held-out CVEs only.

    prospective = (x_tr, y_tr, age_tr) fitted at an EARLIER analysis date, on
    CVEs disjoint from the test set; the test set is scored at the final date.
    That is the deployment situation: a correction learned last year, applied
    to CVEs it has never seen.
    """
    print(f"\n{'=' * 82}\nTARGET: {name}   (N={len(x):,}, positives={int(y.sum())}, "
          f"base rate {y.mean():.4f})\n{'=' * 82}")
    cv = cross_validate(x, y, age)
    report("A. 5-fold cross-validation -- in-distribution, the optimistic case", cv)

    tr, te = born < split, born >= split
    birth, _, _ = evaluate_split(x[tr], y[tr], age[tr], x[te], y[te], age[te])
    report(f"B. birth-cohort split at {split.date()} -- train {int(tr.sum()):,}, "
           f"test {int(te.sum()):,}; ages do not overlap", birth)

    xp, yp, ap, test_mask = prospective
    prosp, _, _ = evaluate_split(xp, yp, ap, x[test_mask], y[test_mask], age[test_mask])
    report(f"C. PROSPECTIVE -- fitted one year earlier on {len(xp):,} CVEs "
           f"({int(yp.sum())} pos), applied to {int(test_mask.sum()):,} unseen", prosp)

    iso_all, platt_all = fit_isotonic(x, y), fit_platt(x, y)
    grid = np.array([0.01, 0.05, 0.1, 0.3, 0.5, 0.7, 0.9, 0.99, 1.0])
    table = pd.DataFrame({"LEV": grid,
                          "isotonic": predict_isotonic(iso_all, grid),
                          "Platt": predict_platt(platt_all, grid)})
    print("\n  the correction curve (isotonic, fitted on all data): what a LEV score means")
    print(table.to_string(index=False, float_format=lambda v: f"{v:.4f}"))
    return {"n": len(x), "positives": int(y.sum()), "cv": cv, "birth_split": birth,
            "prospective": prosp, "curve": table.to_dict(orient="list")}, iso_all, platt_all


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

    def lev_at(mask, dn):
        return levmod.lev(norm_wide[mask], first_idx[mask], dn=dn)

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
                        (xp1.to_numpy(), yp1, age(xp1.index, DN_TR), test1))

    # ------------------- target 2: union of independent lists, sensor window
    born_ok = nbf & (fd >= cr.SENSOR_START)
    m2 = born_ok & (fd <= DN - cr.CENSOR)
    x2 = lev_at(m2, DN)
    y2 = (cr.histories(x2.index, lists).sum(axis=1) > 0).astype(float).to_numpy()
    tr2 = born_ok & (fd <= DN_TR - cr.CENSOR)
    xp2 = lev_at(tr2, DN_TR)
    yp2 = (cr.histories(xp2.index, lists_tr).sum(axis=1) > 0).astype(float).to_numpy()
    test2 = ~x2.index.isin(xp2.index)
    r2, iso2, pl2 = run("UNION of CISA + SENSOR + SOCIAL", x2.to_numpy(), y2,
                        age(x2.index, DN), fd[m2].to_numpy(), pd.Timestamp("2025-06-01"),
                        (xp2.to_numpy(), yp2, age(xp2.index, DN_TR), test2))

    # ------------------------------------------------------------- figure
    fig, axes = plt.subplots(1, 2, figsize=(11.5, 4.6))
    grid = np.linspace(0, 1, 400)
    ax = axes[0]
    ax.plot([0, 1], [0, 1], "--", color="gray", lw=1, label="LEV taken at face value")
    ax.plot(grid, predict_isotonic(iso1, grid), color="#365c8d", lw=2,
            label="corrected to CISA KEV")
    ax.plot(grid, predict_isotonic(iso2, grid), color="#c1440e", lw=2,
            label="corrected to union of lists")
    ax.set_xlabel("LEV score"); ax.set_ylabel("probability to read into it")
    ax.set_title("The correction curve (isotonic)"); ax.grid(alpha=.3)
    ax.legend(fontsize=8)

    ax = axes[1]
    methods = ["raw LEV", "isotonic", "Platt", "Platt+age"]
    schemes = [("cv", "5-fold CV"), ("birth_split", "birth split"),
               ("prospective", "prospective")]
    w = 0.26
    cols = ["#9aa7b8", "#365c8d", "#c1440e"]
    for i, (key, lab) in enumerate(schemes):
        vals = [r1[key][m]["ratio"] for m in methods]
        ax.bar(np.arange(4) + (i - 1) * w, vals, w, color=cols[i], label=lab)
    ax.axhline(1, color="black", lw=1)
    ax.set_xticks(range(4)); ax.set_xticklabels(methods)
    ax.set_yscale("log"); ax.set_ylabel("predicted / observed, held-out (1 = calibrated)")
    ax.set_title("Does the correction transfer? (CISA KEV target)")
    ax.grid(alpha=.3, axis="y"); ax.legend(fontsize=8)
    FIGURE.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(FIGURE, dpi=150, bbox_inches="tight")
    print(f"\nwrote {FIGURE}")

    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(json.dumps({"KEV": r1, "UNION": r2,
                                   "prospective_fit_date": str(DN_TR.date())},
                                  indent=2, default=float))
    print(f"wrote {RESULTS}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
