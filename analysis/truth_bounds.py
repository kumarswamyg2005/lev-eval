"""Per-CVE exploitation truth bounds -- the released dataset.

One row per CVE in the capture-recapture population (Section 4.6), giving the
probability that the CVE was exploited under each rung of the truth ladder:

  p_count   1 if any primary list records it, else 0 (counting: a lower bound)
  p_chao    1 if listed; else the stratum's Chao-unseen share,
            (Chao - S) / (N - S) -- still a lower bound, valid under
            heterogeneous capture
  p_hat     as p_chao but from the log-linear estimate; empty where the
            stratum is not identified (only LEV >= 0.9 is, Table 3)

so any prioritization method can be re-scored against something better than
KEV. Strata, lists and rules are exactly those of capture_recapture.py.

VulnCheck: per-CVE rows reveal VulnCheck membership, whose redistribution
terms are unresolved. Do not publish results/truth_bounds.csv until VulnCheck
agrees; --no-vulncheck builds the CISA/SENSOR/SOCIAL variant, which has no
VulnCheck-derived content.

Run: python analysis/truth_bounds.py [--no-vulncheck]
"""

import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from data import download_epss
from models import lev as levmod
from analysis import capture_recapture as cr, version_normalize

ROOT = Path(__file__).resolve().parent.parent


def main(no_vulncheck=False):
    tidy = download_epss.load()
    wide, first_idx = levmod.to_wide(tidy)
    norm_wide = version_normalize.normalize(wide)
    fd = pd.Series(wide.columns.to_numpy()[first_idx.to_numpy()], index=wide.index)
    iy = pd.Series(wide.index.astype(str).str.slice(4, 8).astype(int), index=wide.index)
    # same population as capture_recapture.main()
    prim = ((fd.dt.year - iy) <= 1) & (fd >= cr.SENSOR_START) & (fd <= cr.DN - cr.CENSOR)
    pop = wide.index[prim]
    lists = cr.exploitation_lists()
    names = cr.FALLBACK_LISTS if no_vulncheck or "VULNCHK" not in lists else cr.EVIDENCE_LISTS
    H = cr.histories(pop, lists)[names]
    lev = levmod.lev(norm_wide[prim], first_idx[prim], dn=cr.DN)
    lev_raw = levmod.lev(wide[prim], first_idx[prim], dn=cr.DN)

    out = pd.DataFrame({"first_epss": fd[prim].dt.date, "lev": lev, "lev_raw": lev_raw},
                       index=pd.Index(pop, name="cve"))
    for c in names:
        out[f"on_{c.lower()}"] = H[c]
    listed = H.sum(axis=1) > 0
    out["p_count"] = listed.astype(float)
    out["p_chao"] = out["p_count"]
    out["p_hat"] = np.where(listed, 1.0, np.nan)
    out["stratum"] = ""
    for lo, hi in cr.STRATA:
        s = ((lev >= lo) & (lev < hi)).to_numpy()
        name = f"[{lo:.1f}, {min(hi, 1):.1f}{')' if hi < 1 else ']'}"
        out.loc[s, "stratum"] = name
        r = cr.estimate(H[s], name, verbose=False)
        n, S = int(s.sum()), r["observed"]
        out.loc[s & ~listed.to_numpy(), "p_chao"] = (r["chao"] - S) / (n - S)
        if r["identified"]:
            out.loc[s & ~listed.to_numpy(), "p_hat"] = (r["N_hat"] - S) / (n - S)
        print(f"  LEV {name}: N={n:,} listed={S} Chao={r['chao']:.0f} "
              f"log-linear={'%.0f' % r['N_hat'] if r['identified'] else 'not identified'}")

    # self-check: the rows reproduce the paper's counts
    assert out["stratum"].ne("").all() and out[["p_count", "p_chao"]].stack().between(0, 1).all()
    if names == cr.EVIDENCE_LISTS:
        assert len(out) == 54_612 and int(out["p_count"].sum()) == 734, "population drifted from Table 2"
    path = ROOT / "results" / f"truth_bounds{'_no_vulncheck' if names != cr.EVIDENCE_LISTS else ''}.csv"
    out.round(6).to_csv(path)
    print(f"wrote {path.relative_to(ROOT)}: {len(out):,} CVEs, lists {', '.join(names)}, "
          f"expected exploited {out['p_chao'].sum():.0f} (Chao), {out['p_count'].sum():.0f} (count)")


if __name__ == "__main__":
    main(no_vulncheck="--no-vulncheck" in sys.argv)
