"""LEV (Likely Exploited Vulnerabilities) per NIST CSWP 41, Mell & Spring, 2025.

Implements Section 4.1 (LEV, Equation 3) and Section 4.2 (LEV2, Equation 5).

Everything works off a *wide* EPSS matrix: rows = CVE, columns = snapshot date,
values = EPSS score on that date (NaN before the CVE first appears).
"""

import numpy as np
import pandas as pd

WINDOW = 30  # EPSS scores are 30-day exploitation probabilities


def to_wide(tidy):
    """(cve, date)-indexed tidy frame -> cve x date matrix of EPSS scores.

    ASSUMPTION (not in CSWP 41): a CVE that is scored, then missing from a
    later snapshot (EPSS retires scores for rejected/disputed CVEs) keeps its
    last known score, forward-filled.  Dates before a CVE's first appearance
    stay 0, which makes them no-ops in both products below.
    """
    wide = tidy["epss"].unstack("date").sort_index(axis=1)
    first = wide.notna().to_numpy().argmax(axis=1)
    wide = wide.ffill(axis=1).fillna(0.0)
    return wide, pd.Series(first, index=wide.index, name="first_idx")


def _windows(d0, dn, window=WINDOW):
    """Window start dates d0, d0+30, ... < dn, and their weights.

    weight(di, dn) = min(window, dn - di) / window   (CSWP 41 Sec. 4.1):
    1.0 for a full window, the fraction remaining for the trailing partial one.
    """
    starts = pd.date_range(d0, dn, freq=f"{window}D")
    weights = np.minimum(window, (dn - starts).days) / window
    keep = weights > 0
    return starts[keep], weights[keep].to_numpy(dtype="float64")


def lev(wide, first_idx, dn=None, window=WINDOW):
    """LEV(v, d0, dn) = 1 - prod_i (1 - epss(v, di) * weight(di, dn))   [Eq. 3]

    d0 is each CVE's first EPSS date; di = d0 + 30*i; the EPSS score used is
    the one at the *start* of each window.

    ASSUMPTION (not in CSWP 41, but matching NIST's reference implementation):
    when di is not a date we hold, the next available snapshot on or after di
    is substituted.  With Phase-1 monthly sampling this substitution is the
    dominant source of error: a 30-day stride against ~30.4-day spacing drifts,
    so some snapshots are reused for two windows and some are never read.

    Returns a Series of LEV probabilities indexed by CVE.
    """
    dates = wide.columns
    dn = pd.Timestamp(dn or dates[-1])
    vals = wide.to_numpy(dtype="float64")
    out = np.zeros(len(wide))

    # d0 is always one of our snapshot dates, so there are only ~len(dates)
    # distinct window layouts -- group by them and vectorise each group.
    for fi in np.unique(first_idx.to_numpy()):
        rows = np.flatnonzero(first_idx.to_numpy() == fi)
        starts, weights = _windows(dates[fi], dn, window)
        if len(starts) == 0:
            continue
        # "next available date" -> searchsorted left, clipped to the last one
        cols = np.clip(np.searchsorted(dates.to_numpy(), starts.to_numpy(),
                                       "left"), 0, len(dates) - 1)
        p = vals[np.ix_(rows, cols)] * weights
        out[rows] = 1.0 - np.prod(1.0 - p, axis=1)

    return pd.Series(out, index=wide.index, name="lev")


def lev2(wide, first_idx, dn=None, window=WINDOW):
    """LEV2(v, d0, dn) = 1 - prod_d (1 - epss(v, d))^(1/30)   [Eq. 5, Sec. 4.2]

    Section 4.2's refinement: instead of sampling one score per 30-day window,
    every day's EPSS score contributes its equivalent *daily* probability
    1 - (1 - epss)^(1/30), and the daily survival probabilities are multiplied
    across the whole interval.  Strictly greater than or equal to LEV, and the
    paper notes it needs daily EPSS data to be exact.

    `first_idx` is accepted only so lev2 and lev share a call signature; it is
    unused because pre-publication scores are already 0 and log1p(-0) = 0.

    ASSUMPTION (not in CSWP 41): with monthly snapshots we cannot see each day,
    so each snapshot's score is held constant over the span until the next
    snapshot -- exponent span/30 instead of 1/30.  Equivalent to Eq. 5 if EPSS
    were piecewise-constant between snapshots, which it is not.

    Returns a Series indexed by CVE.
    """
    dn = pd.Timestamp(dn or wide.columns[-1])
    wide = wide.loc[:, wide.columns <= dn]     # snapshots after dn are unseen
    edges = np.append(wide.columns.to_numpy(), np.datetime64(dn))
    spans = np.diff(edges) / np.timedelta64(1, "D") / window

    vals = np.clip(wide.to_numpy(dtype="float64"), 0.0, 1.0 - 1e-12)
    # scores before a CVE's first appearance are 0 -> log1p(0) = 0, no-op
    logsurv = np.log1p(-vals) @ spans
    return pd.Series(1.0 - np.exp(logsurv), index=wide.index, name="lev2")


def _demo():
    """Self-check on a hand-computable 3-CVE, 4-snapshot example."""
    dates = pd.to_datetime(["2024-01-01", "2024-02-01", "2024-03-01", "2024-04-01"])
    wide = pd.DataFrame([[0.1, 0.1, 0.1, 0.1],
                         [0.0, 0.0, 0.0, 0.0],
                         [np.nan, np.nan, 0.5, 0.5]],
                        index=["a", "b", "c"], columns=dates)
    first = pd.Series([0, 0, 2], index=wide.index)
    wide = wide.fillna(0.0)

    dn = pd.Timestamp("2024-04-01")
    got = lev(wide, first, dn=dn)

    # 'a': windows at 01-01, 01-31, 03-01, 03-31 -> snapshots 01-01, 02-01,
    # 03-01, 04-01; last window has 1 day left -> weight 1/30.
    want_a = 1 - (0.9 ** 3) * (1 - 0.1 / 30)
    assert abs(got["a"] - want_a) < 1e-12, got["a"]
    assert got["b"] == 0.0                     # zero EPSS -> zero LEV
    # 'c': first date 03-01, windows at 03-01 (full) and 03-31 (1 day)
    want_c = 1 - (1 - 0.5) * (1 - 0.5 / 30)
    assert abs(got["c"] - want_c) < 1e-12, got["c"]

    # LEV2 >= LEV, and monotone in EPSS
    got2 = lev2(wide, first, dn=dn)
    assert got2["b"] == 0.0
    assert (got2 >= got - 1e-9).all(), (got, got2)
    # 'a' held at 0.1 for 91 days: 1 - 0.9^(91/30)
    assert abs(got2["a"] - (1 - 0.9 ** (91 / 30))) < 1e-12, got2["a"]
    print("lev.py self-check OK")


if __name__ == "__main__":
    _demo()
