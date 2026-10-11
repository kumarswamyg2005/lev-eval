# lev-eval — Phase 1

Empirical evaluation of NIST's LEV metric (CSWP 41, Mell & Spring, May 2025):
are LEV probabilities calibrated against observed CISA KEV appearance?

## Setup

Python **3.14.6**. Exact pinned versions in [requirements.lock](requirements.lock);
`requirements.txt` holds the unpinned direct dependencies.

    python -m venv .venv && .venv/bin/pip install -r requirements.lock

## Reproducing

    make fetch       # populate cache/ from the network (once, ~1.5 GB)
    make reproduce   # regenerate every table and figure, offline, in order

Input provenance — hashes, release tags, retrieval dates, record counts — is
pinned in [DATA_SNAPSHOT.md](DATA_SNAPSHOT.md). `cache/` is gitignored.

Every script is standalone and everything downloaded is cached under `cache/`
(gitignored); re-runs never re-download.

    python data/download_epss.py     # ~67 monthly EPSS snapshots, ~130 MB
    python data/download_kev.py      # CISA KEV catalog
    python models/lev.py             # self-check on a hand-computed example
    python analysis/validate.py      # Task 4: reproduce CSWP 41 Table 5
    python analysis/calibration.py   # Task 5: reliability diagram -> figures/
    python analysis/reconcile.py     # Task A: Task 4 vs Task 5 population check
    python analysis/dn_sweep.py      # Task B': LEV vs analysis date -> figures/
    python analysis/epss_drift.py    # Task C'.1: organic vs retraining drift
    python analysis/version_normalize.py  # Task C'': version-normalized LEV
    python analysis/plateau.py       # Task C: plateau fit + c-drift test
    python analysis/top_bucket.py    # Task D: top-bucket stratification
    python analysis/vendor_ceiling.py # Task F: vendor-ceiling bound
    python analysis/leakage.py        # Phase 2: KEV-as-EPSS-feature circularity
    python analysis/capture_recapture.py  # Phase 2: estimated true exploitation
    python analysis/recalibrate.py    # Phase 2: correction curve, held-out
    python analysis/learned_lev.py    # Phase 2: learned aggregation of EPSS history vs LEV
    python analysis/leakage.py       # circularity check: EPSS uses KEV as a feature

## Status

| Task | File | State |
|---|---|---|
| 1 EPSS download | `data/download_epss.py` | done |
| 2 KEV download | `data/download_kev.py` | done |
| 3 LEV / LEV2 | `models/lev.py` | done |
| 4 Table 5 check | `analysis/validate.py` | **PASS** |
| 5 Calibration | `analysis/calibration.py` | done |
| Phase 1 follow-ups (B-F, drift, normalization, sampling) | `analysis/*.py` | done |
| Circularity (KEV as EPSS feature) | `analysis/leakage.py` | done — earlier figure withdrawn, see threat 41 |
| Second exploitation lists | `data/download_circl.py`, `download_euvd.py` | done — audited |
| VulnCheck KEV, rebuilt without CISA and Shadowserver | `data/download_vulncheck.py` | done — tested 2026-09-28 |
| Capture–recapture | `analysis/capture_recapture.py` | done |
| Correction curve, prospective validation | `analysis/recalibrate.py` | done |
| Learned aggregation vs LEV; forward leading-indicator test | `analysis/learned_lev.py` | done |
| Paper draft | `paper/draft.md` -> `paper/draft.pdf` (`bash paper/build.sh`) | **first draft** |

### Task 4 result (dn = 2025-03-01, 67 monthly snapshots)

| Published since | NIST Table 5 | ours (LEV) | ours (LEV2) | rel. err |
|---|---|---|---|---|
| 2023-03-07 | 0.015 | 0.0162 | 0.0159 | +8% |
| 2022-02-04 | 0.047 | 0.0480 | 0.0459 | +2% |
| 2021-04-14 | 0.087 | 0.0839 | 0.0820 | -4% |
| all CVEs (no version restriction) | 0.146 | 0.1299 | 0.1289 | -11% |

*Corrected 2026-09-29: `lev.py` now follows CSWP 41 Table 4 exactly --
`datediff` counts days inclusively, so the last partial window gets one more
day of weight, and LEV2 divides each daily score by 30 as Sec. 4.2 specifies
(it previously used the exact daily rate 1-(1-p)^(1/30)). Mean LEV moved by
+0.03% to +0.23%; the headline became 17.3x (was 17.2x); no conclusion
changed. `sampling_error.py` had its own copy of the window rule and now uses
`lev._windows`.*

All four rows pass. The "all" row keeps the pre-archive corpus (it is not a
publication-date row) but still applies the backfill correction — without it
the row reads 0.2550 (+75%). See threat 7.

### Task 5 result (dn = 2026-08-01, 105,250 CVEs, 495 in KEV, base rate 0.0047)

95% Wilson score intervals (chosen over bootstrap: several buckets hold 7-24
KEV hits, where the normal approximation undercovers and a bootstrap of a
near-zero proportion just resamples the same few successes).

| bucket | n | predicted | observed | 95% Wilson | in KEV | obs/pred |
|---|---|---|---|---|---|---|
| [0.0, 0.1) | 90568 | 0.0265 | 0.0003 | 0.0002-0.0004 | 24 | 0.0100 |
| [0.1, 0.2) | 5823 | 0.1375 | 0.0050 | 0.0035-0.0071 | 29 | 0.0362 |
| [0.2, 0.3) | 2030 | 0.2447 | 0.0089 | 0.0056-0.0140 | 18 | 0.0362 |
| [0.3, 0.4) | 1172 | 0.3469 | 0.0154 | 0.0097-0.0241 | 18 | 0.0443 |
| [0.4, 0.5) | 869 | 0.4501 | 0.0184 | 0.0114-0.0297 | 16 | 0.0409 |
| [0.5, 0.6) | 702 | 0.5488 | 0.0100 | 0.0048-0.0204 | 7 | 0.0182 |
| [0.6, 0.7) | 558 | 0.6497 | 0.0215 | 0.0123-0.0372 | 12 | 0.0331 |
| [0.7, 0.8) | 498 | 0.7484 | 0.0382 | 0.0246-0.0588 | 19 | 0.0510 |
| [0.8, 0.9) | 438 | 0.8494 | 0.0411 | 0.0262-0.0640 | 18 | 0.0484 |
| [0.9, 1.0) | 2592 | 0.9866 | 0.1289 | 0.1165-0.1423 | 334 | 0.1306 |

Brier 0.03735, ECE 0.07652, mean predicted / observed = 17.3x.

**Only 2 of 9 adjacent-bucket differences survive Holm-corrected Fisher exact
tests**: [0.0,0.1) vs [0.1,0.2) and [0.8,0.9) vs [0.9,1.0), both p < 0.0001.
The seven middle buckets are statistically indistinguishable from one another.
The [0.5, 0.6) dip is **noise** — 7 KEV hits in 702 CVEs, Wilson interval
overlapping both neighbours, Fisher p = 0.206 and 0.107. Do not interpret it.
LEV is monotone in the right direction but massively over-confident against
KEV. See threat 9 below before reading that as a miscalibration finding.

![reliability](figures/reliability.png)

### Task C — plateau fit and the c-drift test (`plateau.py`)

WLS `observed = c x predicted` through the origin on buckets [0.1, 0.9),
weights = bucket n.

| variant | c | 95% CI | R2 | [0.0,0.1) departure | [0.9,1.0) departure |
|---|---|---|---|---|---|
| LEV_raw | 0.03960 | 0.0303-0.0489 | 0.844 | 0.25x, p=6.6e-18 (86% of CVEs) | 3.30x, p=3.9e-79 |
| LEV_norm | 0.06005 | 0.0536-0.0665 | 0.964 | 0.45x, p=2.0e-10 (91% of CVEs) | 2.34x, p=8.8e-45 |

Normalization tightens the plateau (R2 0.844 -> 0.964) and halves both
end-bucket departures, but neither end is on the line.

**Implied KEV completeness** (LEV_norm): 495 in KEV / c = 8,243 implied truly
exploited, against sum(LEV_norm) = 6,247 on the same population, a ratio of
0.76x. Implied completeness 6.0% (raw: 4.0%, 12,501 implied, ratio 0.68x).

**c drifts with `dn`** — the decisive test, on LEV_norm with KEV membership
restricted to `dateAdded <= dn`:

| dn | N | in KEV | c | 95% CI | R2 |
|---|---|---|---|---|---|
| 2024-02-01 | 11,335 | 58 | 0.15321 | 0.0063-0.3001 | -1.084 (fit fails) |
| 2024-08-01 | 23,496 | 127 | 0.18232 | 0.0719-0.2928 | -2.284 (fit fails) |
| 2025-02-01 | 45,375 | 198 | 0.19199 | 0.1199-0.2641 | +0.384 |
| 2025-08-01 | 60,934 | 288 | 0.09858 | 0.0672-0.1300 | +0.811 |
| 2026-02-01 | 86,899 | 406 | 0.07981 | 0.0570-0.1027 | +0.825 |
| 2026-08-01 | 105,250 | 495 | 0.06005 | 0.0536-0.0665 | +0.964 |

c falls 3.20x, monotonically across the four dates where the model fits, with
disjoint endpoint CIs. Trend -0.0505/yr, p = 0.0069 (all six dates, df=4) and
-0.0506/yr, p = 0.0805 (usable fits only, df=2). Six dates are swept rather
than the three specified, because three leave df=1.

**Interpretation:** KEV coverage should not track the analysis date, so a
falling c points at LEV error rather than ground-truth incompleteness — the
residual over-confidence is largely a *metric* problem and it grows with the
observation window, consistent with the convex `dn` sweep. See threats 26-27.

### Task D — top-bucket stratification (`top_bucket.py`)

2,339 CVEs at LEV_norm >= 0.9; 325 in KEV, 2,014 not. **Every feature tested
separates the two groups after Holm correction:**

| feature | test | median KEV | median non-KEV | p (Holm) |
|---|---|---|---|---|
| peak EPSS | Mann-Whitney | 0.9194 | 0.7013 | <1e-300 |
| days above EPSS 0.5 | Mann-Whitney | 456 | 183.5 | 8.1e-26 |
| CVE age (days) | Mann-Whitney | 699 | 852 | 5.4e-09 |
| CVSS v3 base | Mann-Whitney | 8.85 | 8.7 | 3.1e-04 |
| vendor | chi-square | - | - | 5.3e-16 |
| CWE | chi-square | - | - | 5.5e-14 |
| Exploit-DB entry | chi-square | - | - | 9.1e-07 |
| Metasploit module | chi-square | - | - | 7.4e-18 |

KEV rate by vendor inside this bucket ranges from **32.7% (Microsoft)** and
24.4% (Ivanti) down to 2.3% (XWiki) and 0% (unknown) — a 14x spread among CVEs
LEV scores identically. CVSS separates significantly but trivially in
magnitude (8.85 vs 8.7), so vendor prominence, not severity, is what tracks KEV
membership here.

**Error source #4 (visibility):** 380 of the 2,014 non-KEV CVEs (18.9%) have a
published Exploit-DB entry or Metasploit module, against 39.7% of the KEV
group. These have demonstrated exploit *availability* and no KEV entry.

**Normalization removes false positives.** Of the 341 CVEs demoted from the
top bucket by normalization, only 15 (4.40%) are in KEV, against 13.89% for
the retained bucket — 3.2x lower, Fisher p = 7.2e-08, odds ratio 0.285.

### Monthly-sampling error, measured (`sampling_error.py`)

481 CVEs, stratified by LEV_norm decile across 6 `d0` cohorts, compared
against LEV computed on true daily window starts (156 targeted daily files).

| statistic | value |
|---|---|
| population-weighted mean \|diff\| | 0.00229 (**3.9%** of cohort mean LEV) |
| unweighted mean \|diff\| on the sample | 0.01229 (2.1% of sample mean LEV) |
| median \|diff\| | 0.00366 |
| 90th percentile \|diff\| | 0.03076 |
| max \|diff\| | 0.43260 |
| mean signed difference | +0.00016 (unsigned: 47.4% over, 38.7% under) |
| crossings of 0.5 / 0.9 | 1.87% / 1.04% of sample |

By cohort age, showing drift accumulating with window count:

| d0 | windows | n | mean \|diff\| | max \|diff\| |
|---|---|---|---|---|
| 2023-04-01 | 40 | 88 | 0.02087 | 0.22772 |
| 2023-10-01 | 34 | 87 | 0.01993 | 0.43260 |
| 2024-04-01 | 28 | 83 | 0.01237 | 0.10685 |
| 2024-10-01 | 22 | 88 | 0.00496 | 0.09178 |
| 2025-04-01 | 16 | 75 | 0.00816 | 0.05897 |
| 2025-10-01 | 10 | 60 | 0.00446 | 0.04394 |

**Verdict: bounded and negligible.** 3.9% sits well below the 26.9%
version-mass effect and is nowhere near the multiplicative bounds. See
threats 1 and 18.

![sampling error](figures/sampling_error.png)

### Task F — vendor-ceiling bound on KEV completeness (`vendor_ceiling.py`)

At equal LEV, exploitation propensity is asserted equal, so the vendor spread
in KEV rate is observation probability. The best-observed stratum bounds it.

| bucket | n | in KEV | observed | ceiling | completeness | implied true |
|---|---|---|---|---|---|---|
| [0.0, 0.1) | 78,180 | 47 | 0.0006 | 0.0025 | 0.243 | 194 |
| [0.1, 0.2) | 2,381 | 21 | 0.0088 | 0.1212 | 0.073 | 289 |
| [0.9, 1.0) | 1,699 | 283 | 0.1666 | 0.3268 | 0.510 | 555 |

(top-decile ceiling; only three buckets have >= 3 vendor strata at n >= 30)

**Over-confidence progression** — each successive figure is a tighter *upper*
bound:

| bound | over-confidence |
|---|---|
| raw LEV vs observed KEV | 17.3x |
| version-normalized LEV vs observed KEV | 12.6x |
| normalized LEV vs vendor-ceiling implied rate (envelope) | **3.3x** |
| normalized LEV vs vendor-ceiling implied rate (top decile) | **4.1x** |

Methods agree to within 1.24x. Implied truly exploited 1,127-1,394 against 441
observed.

> **Superseded values.** An earlier run of this table reported **2.9x
> (envelope) and 5.5x (top decile)**. Those predate the binning fix in
> `vendor_ceiling.py` (README threat 40): `pd.cut(right=False)` had dropped
> every CVE with LEV exactly 1.0 — 132 of 441 KEV entries in this population,
> the most extreme predictions. **The correct values are 3.4x and 4.1x** (3.3x and 4.1x
> after the 2026-09-29 inclusive-day fix to `lev.py`). The
> correction also tightened agreement between the two estimators from 1.9x
> apart to 1.22x apart, which is the better reason to trust them. Do not cite
> 2.9x/5.5x. Tasks B and C were never affected — they bin through
> `calibration.reliability()`, which uses digitize-and-clip and conserves all
> 105,250 CVEs and all 495 KEV entries (verified, and now asserted). Vendor canonicalization (207 canonical names absorbing >1 raw
string, e.g. `tp link` <- 4 variants) moves completeness by **0.0%** — the
merge is immaterial to the estimate.

**Falsification passes, and in the useful direction.** Within the top bucket,
high-KEV-rate vendors score *lower* on every exploitation-signal feature:
days above EPSS 0.5 (121 vs 182, effect -0.213), CVSS (7.8 vs 8.8, -0.220),
peak EPSS (0.720 vs 0.763, -0.177). Public-exploit presence is higher but
small and not significant (18.3% vs 12.6%, p=0.17). A real-exploitation
explanation for the vendor spread would need the *opposite* sign, so the
spread is not explained by exploitation propensity. Only 2 high and 3 low
vendors clear n >= 30 in that bucket. See threats 35-37.

### Task C'' — version-normalized LEV (`version_normalize.py`)

Same cohort (105,250 CVEs), same `dn` = 2026-08-01.

| variant | mean LEV | sum | frac > 0.5 | frac > 0.9 |
|---|---|---|---|---|
| LEV_raw | 0.08122 | 8548.4 | 0.0455 | 0.0246 |
| LEV_norm | 0.05936 | 6247.2 | 0.0341 | 0.0222 |
| LEV_v3only (diagnostic) | 0.01101 | 1158.9 | 0.0045 | 0.0030 |

| metric | LEV_raw | LEV_norm |
|---|---|---|
| mean predicted / observed | 17.3x | **12.6x** |
| Brier | 0.03735 | 0.02885 |
| ECE | 0.07652 | 0.05465 |

**Verdict: partially shared.** Version mixing explains ~27% of the
over-confidence; a 12.6x gap remains. The calibration gap and the
version-mixing finding overlap but are not the same finding — both stand.

**Table 5 convergence at `dn` = 2026-08-01** — independent corroboration, since
the normalization is computed from EPSS percentiles alone and never sees these
published values:

| since | NIST | raw | norm | raw dev | norm dev | improvement |
|---|---|---|---|---|---|---|
| 2023-03-07 | 0.015 | 0.0596 | 0.0435 | 297% | 190% | 107pp |
| 2022-02-04 | 0.047 | 0.0857 | 0.0666 | 82% | 42% | 41pp |
| 2021-04-14 | 0.087 | 0.1097 | 0.0896 | 26% | **3%** | 23pp |
| all CVEs | 0.146 | 0.1421 | 0.1214 | 3% | 17% | **-14pp** |

Mean absolute deviation from NIST: **102.1% raw -> 62.9% normalized**, 38% of
the deviation removed; **3 of 4 rows move toward NIST**. The "all CVEs" row
moves away: once it received the same backfill correction as the other three,
it already sat within 3% raw. At `dn` = 2025-03-01 raw and norm are identical
by construction — no window reaches the v4 boundary.

*Corrected 2026-09-28: this table previously showed the "all CVEs" row before
its backfill fix (0.2627 / 0.2376), giving 120.9% -> 74.1% and 4 of 4 rows. The
three restricted rows are unchanged.*

### Task C'.1 — organic vs retraining EPSS drift (`epss_drift.py`)

| cohort | total rise | within-version drift | retraining steps | verdict |
|---|---|---|---|---|
| v3 | +0.01962 | +0.00706 (36%) | +0.01256 (**64%**) | retraining-dominated |
| v1/v2 | +0.01986 | +0.00586 (30%) | +0.01400 (**70%**) | retraining-dominated |

One-day step at the v4 switchover, same 13,552 CVEs: 0.00862 -> 0.02640
(3.06x). See threat 25 on why the switchover date is not the version string.

![epss drift](figures/epss_drift.png)

### Task B' — LEV vs analysis date (`dn_sweep.py`)

Fixed cohorts, `dn` swept monthly 2023-10-01 to 2026-08-01.

| cohort | n | mean LEV first -> last `dn` | shape (AIC) | within-regime shape | frac > 0.9 now -> 2028-01 |
|---|---|---|---|---|---|
| v3 (first EPSS 2023-03..09) | 13,685 | 0.0083 -> 0.1353 | quadratic (R2 0.980) | quadratic (R2 0.9988) | 0.047 -> 0.096 |
| v1/v2 (first EPSS 2021-05..09) | 7,558 | 0.3083 -> 0.4077 | quadratic (R2 0.993) | quadratic (R2 0.9995) | 0.098 -> 0.170 |

No deceleration in either cohort; month-over-month increments grow. Cohort
mean EPSS rises rather than decays. See threats 12-16.

![dn sweep](figures/dn_sweep.png)

## Phase 2 results

Phase 1 could show LEV and CISA KEV disagree, but not how much of that is LEV
error versus KEV incompleteness, because KEV was the only ground truth. Phase 2
adds independent exploitation lists and estimates the exploitation that **no**
list recorded.

### Independent exploitation lists (`data/download_circl.py`, `data/download_euvd.py`)

Every candidate was audited for overlap with CISA KEV before use. Two sources
that look independent are not:

| source | CVEs | overlap with CISA KEV | verdict |
|---|---|---|---|
| CIRCL aggregated KEV catalogue | 3,149 | **all 1,676** | superset — excluded |
| VulnCheck KEV (as shipped) | ~3.6x CISA | all of it, by its own docs | must be rebuilt CISA-free |
| EU KEV (ENISA) | 66 | 55, 88% carrying CISA's own date | derivative — excluded |
| **Shadowserver honeypots** (via CIRCL) | 969 | 286 (29.5%) | **used: SENSOR** |
| **Telegram / social** (via CIRCL) | 2,396 | 1,128 (47.1%) | **used: SOCIAL** — 58% seen *before* CISA |
| **VulnCheck KEV, rebuilt** | 4,815 | CISA + Shadowserver reports dropped | **used: VULNCHK** — 78% of CISA overlap reported *before* CISA |

VulnCheck needed a second exclusion that only the audit revealed: its largest
source is Shadowserver's dashboard (401,967 reports), and **all 969 SENSOR CVEs
appear in VulnCheck's Shadowserver subset**. Left in, VULNCHK would contain
SENSOR — the CISA trap one list over. What remains is VulnCheck's own
canaries, SANS DShield, CrowdSec, vendor advisories and threat reports.

Using either superset as a "second list" makes capture–recapture return a
confident, meaningless number: the overlap equals CISA KEV by construction.

### Capture–recapture (`capture_recapture.py`)

Population: the 54,612 CVEs first scored 2024-10-24 .. 2026-01-30, so every
list could observe every CVE from birth.

**Primary lists: CISA, SENSOR, VULNCHK** — the three whose entries each cite
evidence. Telegram sightings include mass claims (threat 47, recorded before
VulnCheck was available), so SOCIAL is reported as a sensitivity, not used as
primary. Log-linear models over every hierarchical two-way interaction
structure, AIC selection, bootstrap CI, Chao's lower bound as a consistency
check; an estimate is reported only where identified.

**The truth ladder**, all strata pooled:

| truth | assumption added | exploited | over-confidence |
|---|---|---|---|
| CISA KEV | KEV is complete | 236 | 7.93x [6.98, 9.05] |
| CISA or SENSOR | honeypot sightings are real | 336 | 5.57x [5.01, 6.22] |
| union of primary lists | every listed report is real | 734 | **2.55x** [2.37, 2.75] |
| Chao lower bound | closed population | 1,094 | **1.71x** [1.57, 1.84] |
| log-linear | no three-way interaction | — | not identified |

**By counting alone, about two-thirds (68%) of the gap measured against KEV is
catalogue incompleteness.** KEV recorded at most 32% of what the primary lists
observed (22% under Chao).

**Where true exploitation can be estimated, LEV over-predicts it 2-2.5x:**

| LEV stratum | N | vs KEV | union | Chao | log-linear |
|---|---|---|---|---|---|
| [0.0, 0.1) | 52,012 | 21.2x | 2.36x | 0.83x | not identified |
| [0.1, 0.9) | 1,964 | 9.16x | 3.21x | 2.30x | **2.47x** [1.92, 3.08] |
| [0.9, 1.0] | 636 | 4.54x | 2.26x | 1.96x | **2.04x** [1.81, 2.32] |

At LEV >= 0.9, LEV averages 0.985; an estimated 48% [42%, 55%] were exploited.

**List-set sensitivity** (log-linear over-confidence):

| lists | LEV [0.9, 1.0] | LEV [0.1, 0.9) | all LEV |
|---|---|---|---|
| CISA, SENSOR, VULNCHK (primary) | 2.04x [1.81, 2.32] | 2.47x [1.92, 3.08] | not identified |
| CISA, SENSOR, strict VULNCHK | 2.12x [1.85, 2.42] | not identified | not identified (2.64x below stratified Chao bound) |
| CISA, SENSOR, SOCIAL | 2.07x [1.73, 2.43] | not identified | not claimed (0.99x) |
| all four | 1.54x [0.70, 2.02] | not identified | not claimed (0.35x) |
| CISA, SOCIAL, VULNCHK (no SENSOR) | not identified | not identified | not identified |

The top-stratum ~2x holds in every configuration built from evidence-citing
lists; only adding Telegram to a four-list model moves it (1.54x, interval
including 1). "Strict" VulnCheck keeps a CVE only if a sensor saw it or at
least two independent sources reported it (2,912 CVEs) — the precision check,
since 65% of VulnCheck-only CVEs rest on a single text report. **The middle
stratum's 2.47x does not survive it** (not identified; Chao caps it at 3.21x).

![capture-recapture](figures/capture_recapture.png)

### Correction curve (`recalibrate.py`)

The one model this study fits: a monotone map from LEV to observed
exploitation probability, **scored on held-out CVEs only**. The deciding test is
**prospective** — fitted at 2025-08-01, applied to 44,316 CVEs first scored
later, which it never saw.

| CISA KEV target, prospective | Brier | ECE | pred/obs |
|---|---|---|---|
| raw LEV | 0.0113 | 0.0230 | 6.30x |
| isotonic | 0.0036 | 0.0020 | 0.61x |
| Platt | 0.0037 | 0.0015 | 0.66x |
| Platt + CVE age | 0.0036 | **0.0014** | **0.72x** |

Against the union of primary lists, isotonic **transfers exactly: 1.00x**,
ECE 0.0138 to 0.0046.

Against KEV the correction cuts calibration error 11-17x but drifts, under-
predicting by 28-39% a year later. Much of that is KEV's narrow, lagging
coverage — the broader target shows no drift. What remains is age: an old CVE
reaches LEV 0.5 through many modest EPSS scores, a new one through a few high
ones, and conditioning on age recovers about a quarter of the KEV-target drift.

What a LEV score is worth, fitted on all data:

| LEV | corrected to CISA KEV | corrected to union of primary lists |
|---|---|---|
| 0.10 | 0.8% [0.5, 1.0] | 6.1% [4.6, 7.5] |
| 0.50 | 2.7% [1.9, 4.1] | 15.5% [11.5, 19.0] |
| 0.90 | 6.7% [4.4, 8.4] | 20.2% [16.5, 29.5] |
| 0.99 | 8.2% [6.4, 10.1] | 32.5% [26.9, 37.4] |
| 1.00 | 27.8% [24.3, 30.9] | 76.3% [68.0, 85.9] |

95% bootstrap intervals (400 resamples of CVEs): several points wide, so read
the curve as the scale of LEV's error, not a precise per-score mapping.

Both targets are catalogue appearance, so both are lower bounds on true
exploitation.

![recalibration](figures/recalibration.png)

### Prior work (checked 2026-09-28)

A targeted search found **no empirical evaluation of LEV's calibration** and
**no capture–recapture estimate of exploitation-catalogue completeness**. Closest
work: Empirical Security's descriptive KEV coverage figure (at most ~8.7%, from
proprietary telemetry); the RiskBasedPrioritization independent LEV
implementation, which critiques its assumptions without validating against
exploitation data; and ThreatLens (arXiv 2608.22306), which trains on KEV as
weak supervision — the label bias measured here. References with verification
status: `paper/references.md`. A systematic sweep is still required before
submission (threat 49).

## Threats to validity

Assumptions the implementation makes that CSWP 41 does not specify. Each is
marked with an `ASSUMPTION` / `PROXY` comment at the point it is made.

1. **Monthly, not daily, EPSS sampling — measured at 3.9%**
   (`download_epss.py`, quantified in `sampling_error.py`). NIST computes LEV
   over daily files. A 30-day window stride against ~30.44-day snapshot
   spacing drifts ~0.44 days per window, so by the 30th window the pipeline
   reads a score up to two weeks from the date the equation asks for.
   Measured against true daily window starts on **481 CVEs stratified by
   LEV_norm decile across 6 `d0` cohorts** (156 targeted daily files):
   population-weighted mean |difference| **0.00229, i.e. 3.9% of cohort mean
   LEV** (2.1% unweighted on the decile-stratified sample, whose mean LEV is
   0.577 rather than the cohort's 0.059). The error is **unsigned** — 47.4% of
   CVEs over-estimate, 38.7% under-estimate, mean signed difference +0.00016 —
   so it adds noise, not bias. Threshold crossings: 1.87% of the sample at
   0.5, 1.04% at 0.9. **Verdict: bounded and negligible** against the 26.9%
   version-mass effect and the 3.4-4.1x bound; the daily archive is not needed
   for the Phase 1 conclusions.
2. **Missing snapshot days** (`download_epss.py`). The archive is missing some
   days (e.g. 2024-12-01) and answers 403, not 404, for them. We slide forward
   up to 3 days.
3. **Next-available-date substitution** (`lev.py`). When a window start is not
   a date we hold, the next snapshot on or after it is used — what NIST's own
   implementation does, but far coarser here than with daily data.
4. **Forward-filled retirements** (`lev.py`). A CVE that disappears from a
   later snapshot (EPSS retires rejected/disputed CVEs) keeps its last score.
5. **LEV2 integration** (`lev.py`). Eq. 5 needs a score per day; each snapshot
   is held constant until the next, i.e. EPSS is assumed piecewise-constant
   between snapshots. It is not.
6. **Publication date proxy** (`validate.py`). We have no CVE publication
   dates; a CVE's first EPSS appearance stands in. CVEs present in the first
   snapshot are dropped as undatable.
7. **EPSS coverage backfills** (`validate.py`). EPSS periodically expands
   coverage retroactively — on 2022-02-04 (v2) the corpus jumped from 81k to
   168k CVEs, mostly old ones. Uncorrected this counts old CVEs as newly
   published and inflated the two older Table 5 rows by 3–4x. A CVE counts as
   a genuine new publication only if EPSS first scored it within one calendar
   year of its CVE-ID year. This drops CVEs legitimately published more than a
   year after their ID was reserved.
8. **Analysis date** (`validate.py`). LEV grows monotonically with the
   observation window, so Table 5 is only reproducible at roughly the paper's
   own analysis date. CSWP 41 does not state it; 2025-03-01 is used.
9. **KEV is a lower bound, not ground truth** (`calibration.py`). CISA lists
   only exploitation it confirms *and* prioritises for federal remediation.
   The 17.3x gap is an upper bound on LEV's over-confidence: an unknown share
   of it is KEV's incompleteness, not LEV's error. CSWP 41 says as much — LEV
   is explicitly designed to estimate exploitation that KEV *misses*, so this
   comparison measures the two sources' disagreement, not LEV's error alone.
   Phase 2 needs a second exploitation signal to separate them.
10. **Six months is an arbitrary censoring window** (`calibration.py`). KEV
   additions lag exploitation by an unbounded amount; 334 of the 495 observed
   KEV hits sit in the top bucket, so the top bucket's observed rate is the
   most sensitive number in the table to this choice.
11. **The Task 4 / Task 5 population gap was `dn`, not a filter bug**
   (`reconcile.py`). Mean LEV 0.016 vs 0.081 decomposes as 3.67x from moving
   the analysis date 2025-03-01 -> 2026-08-01 and 1.36x from the 6-month
   censoring filter. On the 68,318 CVEs in *both* populations, with the set
   held fixed, the `dn` shift alone moves the mean 6.62x. **Every calibration
   number in this repo uses the Task 5 population** (`dn` = latest snapshot),
   because KEV membership is observed through the present and LEV must be
   computed to the same date. `dn` = 2025-03-01 is used only to reproduce
   Table 5. Consequence: Table 5 agreement validates the *implementation*, not
   the absolute LEV values used for calibration — recomputed on the Task 5
   filtered set the 2023-03-07 row reads +52% at 2025-03-01 and +441% at
   2026-08-01.
12. **`dn`-dependence is structural; only the rate is empirical**
   (`dn_sweep.py`). LEV is a product over 30-day windows and cannot decrease
   in `dn`, so growth is a property of the equation, not a finding. What is
   measured is the *shape*: on a fixed 13,685-CVE v3 cohort mean LEV runs
   0.0083 -> 0.1353 over 34 months, and AIC selects a quadratic (accelerating)
   fit over power, exponential, linear, saturating and log (R2 = 0.9796). Month-over-month increments grow rather than shrink.
   This uses no exploitation ground truth, so unlike the calibration gap it is
   not confounded by KEV incompleteness.
13. **EPSS retrainings confound the sweep** (`dn_sweep.py`). The sweep spans
   two model changes — v2025.03.14 (first seen 2025-04-01) and v2026.06.15
   (2026-07-01) — each of which shifted scores corpus-wide (2025: corpus mean
   x1.21; 2026: 84% of scores rose but the mean fell to x0.88); both cohorts kink
   at those dates. Refitting within the unbroken v2023.03.01 regime
   (2023-10-01..2025-03-01) still selects quadratic (R2 = 0.9988 v3, 0.9995
   v1/v2; dAIC 13.2 and 4.6 over the runner-up), so the conclusion survives, but the full-sweep *rate* mixes LEV
   accumulation with score-level shifts that CSWP 41 does not model.
14. **NIST's EPSS-decay assumption does not hold in this data**
   (`dn_sweep.py`). LEV growth is expected to stall because EPSS decays toward
   0 for old CVEs. Cohort mean EPSS instead *rises*: 0.0044 -> 0.0240 (v3
   cohort) and 0.0135 -> 0.0334 (v1/v2), and rises even within a single model
   regime. Projected fraction above LEV 0.9 by 2028-01: 9.6% (v3), 17.0%
   (v1/v2). If this continues, LEV loses discriminative power for ranking as
   the corpus saturates near 1.0.
15. **The as-of-`dn` KEV rate is itself right-censored** (`dn_sweep.py`). CISA
   had catalogued fewer entries in 2023, so early-`dn` KEV rates understate
   the cohort. Both are reported: the v3 cohort reads 0.00402 as of
   2023-10-01 and 0.00621 both as of 2026-08-01 and present-day.
16. **Cohort version boundaries** (`dn_sweep.py`). The v3 cohort starts at the
   2023-03-07 EPSS v3 boundary; the v1/v2 cohort spans older models and sits
   at a far higher LEV level throughout (0.31 vs 0.01 at first `dn`). The
   *shape* is the same for both; the level is not comparable across them.
17. **KEV `dateAdded` is not the exploitation date.** CISA records when it
   learned of and prioritised exploitation, often long after the fact. Every
   "observed" timestamp in this repo is that administrative date, so any
   time-resolved comparison against LEV is lagged by an unknown, variable
   amount.
18. **Sampling error grows with CVE age, and the measurement does not cover
   the oldest CVEs** (`sampling_error.py`). Drift accumulates per window, and
   it shows: mean |difference| runs 0.0045 at 10 windows (d0 = 2025-10) to
   0.0209 at 40 windows (d0 = 2023-04), a ~4.7x spread. The sample covers d0
   from 2023-04 to 2025-10 — the calibration cohort — so it does **not** bound
   the error for the pre-v3 CVEs behind the older Table 5 rows, which carry up
   to 65 windows and would drift further. Threat 1's 3.9% applies to the
   calibration results, not to Table 5.
19. **EPSS v4 lands inside the v3 cohort's LEV windows**
   (`version_normalize.py`). CSWP 41 restricts to v3 CVEs to avoid version
   mixing, but EPSS v4 deployed 2025-03-17 — before the paper's publication —
   and LEV windows run past that boundary regardless of how the cohort is
   selected. Percentile-normalizing every post-boundary score back to the
   2025-03-16 v3 scale drops mean LEV from 0.0812 to 0.0594: **26.9% of total
   LEV mass on this cohort is corpus-level version shift, not accumulated
   exploitation signal.** 341 of the 2,592 CVEs at LEV >= 0.9 (13.2%) fall
   below the threshold under normalization.
20. **Version mixing and the calibration gap partly overlap, and both stand**
   (`version_normalize.py`). Over-confidence falls 17.3x -> 12.6x under
   normalization (27% reduction), Brier 0.0373 -> 0.0289, ECE 0.0765 ->
   0.0547. Material, but a 12.6x gap remains: the two are **not** the same
   finding. Report them as overlapping, not as one mechanism.
21. **The convex growth shape survives normalization** (`version_normalize.py`).
   Quadratic still wins on AIC after normalizing (dAIC 2.95 vs 2.02 raw), so
   the acceleration in threat 12 is not purely a retraining artifact — though
   per threat 13 the retraining steps supply most of the *level* change.
22. **Percentile mapping assumes rank preservation across versions**
   (`version_normalize.py`). EPSS v4 added features (malware telemetry,
   endpoint detection), so a CVE's rank can move for legitimate,
   non-artifactual reasons. Normalization removes corpus-level shift, **not**
   per-CVE model improvement, and will strip genuine signal along with the
   artifact. LEV_norm is a lower bound on true LEV, not a corrected value.
23. **Reference-snapshot choice** (`version_normalize.py`). 2025-03-16 as the
   v3 reference is a choice. Re-running against 2025-02-01 gives mean LEV_norm
   0.06002 vs 0.05936 — 1.1% apart, so the result is not sensitive to it.
24. **`LEV_v3only` is not a fair comparison** (`version_normalize.py`). It
   truncates windows at the boundary, changing both the window count and `dn`.
   Reported as a diagnostic only; 36,932 of the 105,250 cohort CVEs were born
   after the boundary and score 0 under it.
25. **Model-version strings are build dates, not deployment dates**
   (`epss_drift.py`). `v2025.03.14` first appears in the 2025-03-17 file.
   Bracketing a retraining by its version name puts the measurement on the
   wrong side of the step — doing so measured the v4 effect as +0.00009
   instead of +0.01778. Switchover days are found by binary search over daily
   files. Anyone reusing this data should not trust the version string as a
   date.
26. **Table 5 convergence is independent corroboration, and partially bounds
   threat 22** (`version_normalize.py`). The percentile normalization is
   derived from EPSS data alone and never sees NIST's published values, yet
   three of four Table 5 rows move toward them and mean absolute deviation
   falls from 102.1% to 62.9%. The fourth ("all CVEs") moves away, from 3% to
   17% — it spans pre-v3 EPSS versions the v3 reference does not describe well.
   This bounds the threat on v3-era rows; it does not eliminate it.
   *(Corrected: previously stated as all four rows, 120.9% -> 74.1%, before
   the "all CVEs" row received its backfill fix.)*
27. **The plateau constant c drifts with `dn`** (`plateau.py`). c falls 3.20x
   (0.192 -> 0.060) across the four analysis dates where the model fits, with
   disjoint endpoint CIs, p = 0.0069 across all six dates. KEV coverage should
   not track the analysis date, so this points at LEV error rather than
   constant-coverage KEV incompleteness: the residual 12.6x over-confidence is
   largely a metric problem that grows with the observation window. **This
   constrains the interpretation, it does not prove it** — c is LEV-derived,
   and a LEV error that happened to be stable in `dn` would look like the
   constant-coverage case.
28. **c is LEV-derived and cannot validate LEV** (`plateau.py`). The plateau
   fit establishes only that the middle-range relationship between predicted
   and observed is approximately multiplicative and bucket-independent. The
   implied-completeness figures (6.0% under LEV_norm) inherit that limit
   entirely: they are what KEV completeness *would* be if LEV were correct in
   the middle range, not a measurement of it.
29. **The two end buckets are not on the plateau line** (`plateau.py`). Under
   LEV_norm the bottom bucket runs 0.45x the fitted rate and the top 2.34x,
   both at p < 1e-10. The bottom bucket holds 91% of all CVEs, so the
   plateau describes a multiplicative relationship over 9% of the corpus.
30. **Visibility bias is measurable inside a single LEV bucket**
   (`top_bucket.py`). Among 2,339 CVEs LEV_norm scores identically (>= 0.9),
   KEV membership ranges from 32.7% (Microsoft) to 2.3% (XWiki), and all eight
   tested features separate KEV from non-KEV after Holm correction. CVSS
   separates significantly but trivially (median 8.9 vs 8.8), so what tracks
   KEV membership is vendor prominence and EPSS persistence, not severity.
   This is CSWP 41 error source #4 (visibility), measured directly.
31. **Exploit availability is not exploitation** (`top_bucket.py`). 380 non-KEV
   CVEs in the top bucket have an Exploit-DB entry or Metasploit module. That
   separates error source #4 (visibility) from #1 (scope) at the population
   level; it does not decide which applies to any individual CVE, and a
   published exploit is evidence of capability, not of use.
32. **Vendor strings are unnormalized free text** (`download_nvd.py`). Metadata
   comes from the CVE Program's cvelistV5 bulk release, not the NVD API (the
   API needs ~2.7 hours for this corpus at ~75 KB/s; the bulk zip is one
   request). CNA-supplied vendor names are not normalized — "Microsoft" and
   "microsoft" are distinct before lowercasing, and multi-product CVEs are
   attributed to the first product listed. Per-vendor counts are lower bounds.
   Coverage: 80.5% CVSS v3, 81.9% vendor, 81.4% CWE.
33. **Growth-shape claims are partly structural, and the empirical part is the
   rate.** LEV cannot decrease in `dn` by construction, so direction is not a
   finding. What is empirical: the shape is convex (quadratic wins on AIC,
   threat 12), it survives normalization (dAIC 2.95, threat 21), and there is
   no deceleration in any regime tested. Report the rate and the absence of
   saturation, never the direction.
34. **Version mixing and calibration error are overlapping, not identical.**
   26.9% of LEV mass on the calibration cohort is version artifact; removing
   it leaves 12.6x over-confidence. Two findings with a shared component —
   never report them as one mechanism.
35. **The vendor-ceiling bound is a lower bound on incompleteness, not a point
   estimate** (`vendor_ceiling.py`). It assumes (a) equal exploitation
   propensity at equal LEV across vendors and (b) that the best-observed
   vendor stratum is *fully* observed. (b) is certainly false — Microsoft CVEs
   are not all catalogued either — so true completeness is lower than the
   0.24-0.51 estimated here and true over-confidence is below the 3.4-4.1x
   figure. Report 3.4-4.1x as the tightest available *upper* bound on LEV
   over-confidence, never as the measured value.
36. **The ceiling rests on very few strata** (`vendor_ceiling.py`). Only three
   of ten LEV buckets have >= 3 vendors with n >= 30, and the top bucket's
   ceiling comes from 2 high-rate vendors. The saturating "envelope" fit is
   additionally non-identified wherever its asymptote pins at the parameter
   bound (that fit is discarded when it does). The 1.24x agreement between the
   two ceiling methods is reassuring but is not independent evidence — both
   read the same handful of strata.
37. **The falsification test has limited power** (`vendor_ceiling.py`). It is
   run inside a single LEV bucket to hold LEV constant, which leaves 235 vs
   159 CVEs from 5 vendor strata. It rules out the *specific* confound tested
   (high-KEV vendors being genuinely more exploited on measurable signal) and
   finds the effects run the other way; it cannot rule out unmeasured
   confounds.
38. **c-drift is partly structural** (`plateau.py`). LEV is monotone in `dn` by
   construction, so a falling c partly restates that LEV grows while KEV
   additions for a fixed cohort do not. It shows LEV outpacing observed KEV
   accumulation; it does **not** decompose that into LEV error versus change
   in KEV coverage. Threat 27's "metric problem" reading is an inference from
   that gap, not a measurement of it.
39. **Task C.5 is underpowered** (`plateau.py`). p = 0.0805 on df=2 for the
   four dates where the plateau model fits. Report the direction, the
   monotonicity, and the disjoint endpoint CIs. Do not claim statistical
   significance, and do not cite the all-dates p = 0.0069 in isolation — it
   includes two dates whose fits have negative R2.
40. **LEV = 1.0 sits outside a right-open top bin.** `pd.cut(right=False)` on
   [0, 0.1, ..., 1.0] silently drops LEV values of exactly 1.0; 132 of 441 KEV
   CVEs in the Task F population sit there. All binning in this repo goes
   through the digitize-and-clip path in `calibration.reliability()`. Anyone
   re-binning these scores should check the top edge first.
41. **The LEV-vs-KEV comparison is partly circular** (`leakage.py`). EPSS v3
   uses *"CVE is listed on CISA KEV"* as an **input feature** (Jacobs et al.,
   arXiv:2302.14172, "Public vulnerability lists (3 features)"), and LEV is
   computed entirely from EPSS, so KEV membership can raise the score it is
   then judged against. Measured two ways that cannot select on the outcome:

   | test | result |
   |---|---|
   | EPSS across the KEV listing date, net of non-KEV controls with the same starting decile, same two snapshots (1,168 CVEs; retraining-straddling pairs excluded) | median x1.00; upper quartile >= x2.85; 45% rise more than controls |
   | LEV before listing, for the 220 cohort KEV members first scored at least a month earlier (median 2.8 months) | 15% at LEV >= 0.5, 27% at >= 0.1; median 0.006, against 1.0 at dn |

   The boost is real for a sizeable minority, not universal. **High LEV among
   KEV members is mostly a consequence of listing rather than a forecast of
   it**, which bears directly on CSWP 41's proposed use of LEV to find
   exploited CVEs missing from KEV. 56% of cohort KEV members were listed in
   the same month EPSS first scored them, so LEV could not have preceded CISA
   for them at all. Pre-listing LEV also covers fewer windows, so part of the
   gap is elapsed time; the leading-indicator reading holds regardless.

   **Withdrawn:** an earlier version reported over-confidence rising from
   11.9x to 32.7x on a "leak-free" cohort and called the Phase 1 figures
   conservative. That cohort was built by deleting the 307 KEV members listed
   before the model's training date while keeping every non-member, so the
   observed rate fell by construction. It selected on the outcome.
42. **The circularity flatters the ranking and top-bucket results**
   (`leakage.py`). Listed CVEs can be lifted into the top LEV bucket by their
   listing, so the top bucket's KEV concentration overstates how well LEV
   ranks *unlisted* exploitation. The capture–recapture top-stratum result
   (2.07x over-prediction) inherits this in the conservative direction: CVEs
   lifted there by listing are true positives, so without the boost the top
   stratum's exploited share would likely be lower and the over-prediction
   larger. The magnitude is not estimated here. *(An earlier version quantified
   this on the withdrawn leak-free cohort; that figure is withdrawn with it.)*
43. **Exploit-DB, Metasploit, Nuclei and Project Zero are also EPSS features**
   (same source). "Published exploit code (3 features): Exploit-DB, Github,
   Metasploit"; "Offensive security tools (4 features): Nuclei, Jaeles,
   Intrigue, Sn1per". Task D uses Exploit-DB and Metasploit presence to
   separate KEV from non-KEV inside a LEV stratum — those are EPSS inputs, so
   they correlate with LEV by construction. Holding the LEV bucket fixed
   controls for this only partially. It also rules out Project Zero as an
   independent validation set, which it would otherwise look like.
44. **`make reproduce` was drifting with the calendar** (`download_epss.py`).
   The EPSS loader defaulted `until` to today, so re-running weeks later
   silently ingested new monthly snapshots and stopped matching
   DATA_SNAPSHOT.md — observed live when a 2026-09-01 file appeared mid-session.
   Now pinned to `ARCHIVE_END = 2026-08-01`; raise it deliberately and update
   DATA_SNAPSHOT.md in the same commit.
45. **Nested sources: three containments, found by audit** (`download_circl.py`,
   `download_vulncheck.py`). CIRCL's aggregated KEV catalogue holds all 1,676
   CISA KEV CVEs; VulnCheck KEV includes CISA KEV by its own documentation; and
   VulnCheck's Shadowserver-sourced reports cover all 969 SENSOR CVEs. Any of
   them used raw makes capture–recapture collapse silently. Each is excluded or
   rebuilt from per-report provenance. A containment the audit missed would bias
   estimates downward; any replication must audit overlap before modelling.
46. **The exploitation lists are dependent, and the model assumes no three-way
   interaction** (`capture_recapture.py`). Pairwise estimates span 530 to
   1,256, so independence is rejected and two-way interactions are fitted. The
   three-way interaction cannot be estimated with three lists and is assumed
   zero — the standard identifying assumption, untestable here. Estimates are
   reported only where identified: models within 2 AIC must agree within 2x,
   the estimate must not exceed the population, and it must not fall below
   Chao's heterogeneity-robust lower bound. Two of three LEV strata fail.
47. **Telegram sightings may include false claims** (`capture_recapture.py`).
   Threat actors post mass lists of CVEs they claim to use; with three lists,
   86% of the lowest stratum's singletons were Telegram-only. Recorded before
   VulnCheck was available, this is why the primary analysis uses the three
   evidence-citing lists and SOCIAL appears only as a sensitivity. Adding it
   to a four-list model is the one configuration that moves the top-stratum
   estimate (2.04x to 1.54x).
48. **Shadowserver is an EPSS label source** (`capture_recapture.py`). EPSS is
   trained to predict roughly what the SENSOR list records, so LEV judged
   against it is judged on home ground. Without SENSOR no log-linear estimate
   is identified, but counting gives 2.10x pooled and 2.25x at the top, in line
   with the primary result.
49. **The prior-work search was targeted, not systematic.** It covered arXiv
   and the web for LEV evaluations and exploitation capture–recapture through
   2026-09-28 and found neither. A systematic sweep of arXiv cs.CR, WEIS,
   eCrime, CCS, S&P, USENIX Security and NDSS from June 2025 is required before
   the novelty claim is submitted; one missed paper costs it.
50. **The correction curve is not stationary** (`recalibrate.py`). Fitted a
   year earlier it under-predicts by 28-39% on new CVEs, because LEV's meaning
   depends on CVE age. A deployed correction must be refitted periodically or
   conditioned on age; the age-conditioned variant recovers only about a
   quarter of the drift.
51. **The capture–recapture population is short-lived** (`capture_recapture.py`).
   SENSOR starts 2024-10-24, so the population is CVEs first scored in a
   15-month window, each observed for 6-21 months. Results describe recently
   published CVEs. The full-cohort sensitivity run (older CVEs, over-confidence
   2.32x log-linear) is biased because the sensor could not see their early
   exploitation.
52. **VulnCheck precision carries the estimates** (`capture_recapture.py`).
   With four lists, 84-99% of single-list captures are VulnCheck-only, and 65%
   of VulnCheck-only CVEs rest on one text report (median one report per CVE).
   The strict configuration (sensor-observed or >= 2 independent sources,
   2,912 CVEs) keeps the top-stratum result (2.12x). Its pooled estimate
   (2.64x, N 709) falls below the sum of per-stratum Chao bounds (721), so it
   is not identified, and the middle stratum's 2.47x does not survive it.
53. **The four-list results need a VulnCheck token to reproduce**
   (`download_vulncheck.py`, `DATA_SNAPSHOT.md`). VulnCheck's terms are silent
   on redistribution, so the snapshot stays in gitignored `cache/` and its hash
   is recorded instead. Without a token the pipeline falls back to CISA +
   SENSOR + SOCIAL and reproduces the three-list results, not the primary ones.
54. **Part of the KEV gap is definitional.** EPSS is trained on IDS and honeypot
   detections, so LEV estimates observed exploitation *activity*; KEV lists
   confirmed, actionable exploitation. Sensor-based lists are closer to LEV's
   own definition, which is part of why LEV looks better against them. The
   choice of ground truth is a choice of definition, and should be stated with
   any LEV calibration figure.
55. **Sparse cells and an imprecise correction curve** (`capture_recapture.py`,
   `recalibrate.py`). In the middle stratum no CVE is on both CISA and
   SENSOR, and the unseen-cell estimate rests on 10 SENSOR-only CVEs. The
   isotonic correction is similarly imprecise at single scores: at LEV 0.9 the
   union-target value is 20.2% with a 95% bootstrap interval of 16.5-29.5%.
   Counted quantities are precise by comparison (17.3x: 15.8-18.9x; union
   2.55x: 2.37-2.75x).
