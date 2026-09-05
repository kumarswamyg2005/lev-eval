"""Is the LEV-vs-KEV comparison circular?

EPSS v3 uses "CVE is listed on CISA KEV" as an INPUT FEATURE (Jacobs et al.,
arXiv:2302.14172, "Public vulnerability lists (3 features)": CISA KEV, Google
Project Zero, Trend Micro ZDI).  LEV is computed entirely from EPSS scores.
So comparing LEV against KEV membership uses an outcome that is also, in part,
a predictor -- KEV-listed CVEs get a boost to the very score LEV compounds.

Direction matters.  The leak inflates LEV for CVEs ALREADY on KEV, which
inflates the apparent RANKING performance (high-LEV buckets contain
mechanically more KEV members).  It works against the over-confidence finding,
since a model told the answer should look better calibrated, not worse.

This isolates the effect by restricting to CVEs whose KEV membership could not
have reached the model that scored them: exclude anything on KEV at the time
the active EPSS model was trained, and stop before the next retraining
re-ingests the catalog.

Run: python analysis/leakage.py
"""

import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from data import download_epss, download_kev
from models import lev as levmod
from analysis import calibration, version_normalize

# EPSS model deployment dates, measured in analysis/epss_drift.py (the version
# STRING is a build date; these are when the scores actually changed).
V4_DEPLOY = pd.Timestamp("2025-03-17")     # v2025.03.14 went live
V5_DEPLOY = pd.Timestamp("2026-06-15")     # v2026.06.15 went live
# Last day of the v2025.03.14 regime: after this, a retraining re-ingests KEV.
DN = V5_DEPLOY - pd.Timedelta(days=1)


def evaluate(pred, obs, label):
    n, k = len(pred), int(obs.sum())
    rate = obs.mean()
    over = pred.mean() / rate if rate else np.nan
    print(f"  {label:<44} n={n:>7,}  kev={k:>4}  "
          f"mean LEV={pred.mean():.5f}  obs={rate:.6f}  over={over:>7.1f}x")
    return over


def main():
    tidy = download_epss.load()
    kev = download_kev.load()
    print("\nbuilding matrices...")
    wide, first_idx = levmod.to_wide(tidy)
    norm_wide = version_normalize.normalize(wide)

    kev_dates = kev.drop_duplicates("cve").set_index("cve")["kev_date"]
    m = calibration.cohort(wide, first_idx, DN)
    pred = levmod.lev(norm_wide[m], first_idx[m], dn=DN)
    kd = kev_dates.reindex(pred.index)

    obs = (kd <= DN).fillna(False)
    # Leaked: on KEV when the active model was trained, so its own KEV
    # membership was an input feature to the score it now gets judged on.
    leaked = (kd <= V4_DEPLOY).fillna(False)

    print(f"\n{'=' * 86}")
    print(f"CIRCULARITY CHECK -- EPSS v2025.03.14 regime, dn={DN.date()}")
    print(f"{'=' * 86}")
    print(f"  EPSS uses 'listed on CISA KEV' as a training feature.")
    print(f"  CVEs on KEV before {V4_DEPLOY.date()} had that feature set when scored.\n")

    evaluate(pred, obs.astype(float), "ALL CVEs (as reported in Phase 1)")
    clean = ~leaked
    evaluate(pred[clean], obs[clean].astype(float),
             "LEAK-FREE (not on KEV at model training)")

    print(f"\n  removed {int(leaked.sum()):,} leaked CVEs "
          f"({int((leaked & obs).sum())} of them KEV members)")
    print(f"  remaining KEV members: {int((obs & clean).sum())} "
          f"-- added to KEV after the model was trained")

    # Ranking: does the monotone bucket relationship survive?
    print(f"\n  reliability, leak-free cohort:")
    tab, brier, ece = calibration.evaluate(pred[clean].to_numpy(),
                                           obs[clean].astype(float).to_numpy())
    print(tab[["bucket", "n", "predicted", "observed", "n_in_kev",
               "obs_pred_ratio"]].to_string(
        index=False, na_rep="-", float_format=lambda v: f"{v:.4f}"))
    print(f"  Brier {brier:.5f}   ECE {ece:.5f}")

    top = tab.iloc[9]["observed"]
    bot = tab.iloc[0]["observed"]
    print(f"\n  top bucket / bottom bucket observed rate: "
          f"{top / bot:.1f}x" if bot else "  bottom bucket empty")
    print("\n  READING: if over-confidence RISES once the leak is removed, the")
    print("  Phase 1 figure was flattered by circularity and the true gap is")
    print("  wider. If discrimination FALLS, the ranking claim was the part")
    print("  inflated by it -- that is the claim to soften, not the gap.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
