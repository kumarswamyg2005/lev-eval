# Threats to validity

> Moved verbatim from the README. Numbers in the text reflect the pre-review
> pipeline; the paper (paper/draft.md) and results/*.json are authoritative.
> Script names refer to `analysis/`, `data/` and `models/`.

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
   *See also threat 54 (overlapping point).*
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
   *See also threat 33 (overlapping point).*
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
   *See also threat 34 (overlapping point).*
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
   *See also threat 12 (overlapping point).*
34. **Version mixing and calibration error are overlapping, not identical.**
   26.9% of LEV mass on the calibration cohort is version artifact; removing
   it leaves 12.6x over-confidence. Two findings with a shared component —
   never report them as one mechanism.
   *See also threat 20 (overlapping point).*
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
   *See also threat 9 (overlapping point).*
55. **Sparse cells and an imprecise correction curve** (`capture_recapture.py`,
   `recalibrate.py`). In the middle stratum no CVE is on both CISA and
   SENSOR, and the unseen-cell estimate rests on 10 SENSOR-only CVEs. The
   isotonic correction is similarly imprecise at single scores: at LEV 0.9 the
   union-target value is 20.2% with a 95% bootstrap interval of 16.5-29.5%.
   Counted quantities are precise by comparison (17.3x: 15.8-18.9x; union
   2.55x: 2.37-2.75x).
