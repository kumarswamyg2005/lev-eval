# Results and narrative (pre-review)

> Numbers here reflect the pre-review pipeline; the paper (paper/draft.md) and results/*.json are authoritative.
>
> Moved verbatim from the README. "Threat N" refers to [THREATS.md](THREATS.md).

# Status

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

## Task 4 result (dn = 2025-03-01, 67 monthly snapshots)

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

## Task 5 result (dn = 2026-08-01, 105,250 CVEs, 495 in KEV, base rate 0.0047)

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

## Task C — plateau fit and the c-drift test (`plateau.py`)

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

## Task D — top-bucket stratification (`top_bucket.py`)

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

## Monthly-sampling error, measured (`sampling_error.py`)

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

## Task F — vendor-ceiling bound on KEV completeness (`vendor_ceiling.py`)

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

## Task C'' — version-normalized LEV (`version_normalize.py`)

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

## Task C'.1 — organic vs retraining EPSS drift (`epss_drift.py`)

| cohort | total rise | within-version drift | retraining steps | verdict |
|---|---|---|---|---|
| v3 | +0.01962 | +0.00706 (36%) | +0.01256 (**64%**) | retraining-dominated |
| v1/v2 | +0.01986 | +0.00586 (30%) | +0.01400 (**70%**) | retraining-dominated |

One-day step at the v4 switchover, same 13,552 CVEs: 0.00862 -> 0.02640
(3.06x). See threat 25 on why the switchover date is not the version string.

![epss drift](figures/epss_drift.png)

## Task B' — LEV vs analysis date (`dn_sweep.py`)

Fixed cohorts, `dn` swept monthly 2023-10-01 to 2026-08-01.

| cohort | n | mean LEV first -> last `dn` | shape (AIC) | within-regime shape | frac > 0.9 now -> 2028-01 |
|---|---|---|---|---|---|
| v3 (first EPSS 2023-03..09) | 13,685 | 0.0083 -> 0.1353 | quadratic (R2 0.980) | quadratic (R2 0.9988) | 0.047 -> 0.096 |
| v1/v2 (first EPSS 2021-05..09) | 7,558 | 0.3083 -> 0.4077 | quadratic (R2 0.993) | quadratic (R2 0.9995) | 0.098 -> 0.170 |

No deceleration in either cohort; month-over-month increments grow. Cohort
mean EPSS rises rather than decays. See threats 12-16.

![dn sweep](figures/dn_sweep.png)

# Phase 2 results

Phase 1 could show LEV and CISA KEV disagree, but not how much of that is LEV
error versus KEV incompleteness, because KEV was the only ground truth. Phase 2
adds independent exploitation lists and estimates the exploitation that **no**
list recorded.

## Independent exploitation lists (`data/download_circl.py`, `data/download_euvd.py`)

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

## Capture–recapture (`capture_recapture.py`)

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

## Correction curve (`recalibrate.py`)

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

## Prior work (checked 2026-09-28)

A targeted search found **no empirical evaluation of LEV's calibration** and
**no capture–recapture estimate of exploitation-catalogue completeness**. Closest
work: Empirical Security's descriptive KEV coverage figure (at most ~8.7%, from
proprietary telemetry); the RiskBasedPrioritization independent LEV
implementation, which critiques its assumptions without validating against
exploitation data; and ThreatLens (arXiv 2608.22306), which trains on KEV as
weak supervision — the label bias measured here. References with verification
status: `paper/references.md`. A systematic sweep is still required before
submission (threat 49).

