# Appendix draft: a learned aggregation of EPSS history (negative results)

Status: replaces the 11 October first draft, which over-claimed (see the paper's
Appendix A, "An apparent gain was an artifact"). Every number comes from `python
analysis/learned_lev.py` → `results/learned_lev.json`, `figures/learned_lev.png`.
LEV here is version-normalized, the same LEV as §5.6-5.7.

---

## A. Can a learned aggregation of EPSS history beat LEV?

**Question.** LEV combines a CVE's EPSS history with one fixed rule. Would a
model that sees the same history, and nothing else, combine it better? We
restrict the inputs to EPSS history so that the comparison tests LEV's rule,
not the value of extra data.

**Design.** Seven features, all computed from version-normalized EPSS dated on
or before the analysis date: LEV, log CVE age, and current, peak, mean, first
and three-month-trend EPSS. There are two learners:
- L2 logistic regression, with probability features on the logit scale;
- gradient-boosted trees, monotone in LEV and heavily regularized.

The choice between them is fixed by a rule that sees only training data: fit
on the older two-thirds of the training cohort, validate on the newer third,
keep the higher average precision (AP). We wrote this rule after a first,
unreported run, and we report both models throughout. Baselines are LEV,
current EPSS, peak EPSS, and the isotonic and age-aware Platt maps of §4.7.

*Experiment 1* repeats the prospective test of §4.7. Models are fitted on
2025-08-01 with outcomes known then, and scored on 2026-08-01 on the 44,316
CVEs the fit never saw. There are three targets:
- the union of primary lists;
- CISA KEV;
- the union with every KEV-listed CVE removed from training and test. KEV is
  an EPSS input, so this target cuts the path by which a listing raises later
  scores.

For the logistic model the bootstrap resamples training *and* test CVEs and
refits, so the intervals include training variance.

*Experiment 2* is forward. At origin t we take every CVE that is at least 30
days old and on no list. We compute features at t and label the CVE positive
if it is first listed in the next 182 days. We train one horizon earlier and
use three origins (test origins 2025-08-02, 2025-10-31, 2026-01-30). A second
target uses only CISA and SENSOR dates, because VulnCheck's dates come from a
later snapshot and may be backdated.

**Results.**

*No learned aggregation ranks better than LEV or current EPSS (Table A1).* On
every target the logistic model's AP is within noise of LEV's:
- union: 0.398 against 0.399, difference 95% CI −0.134 to +0.035;
- union without KEV: −0.137 to +0.021;
- CISA KEV: 0.196 against 0.324, difference −0.229 to +0.001. Against current
  EPSS it is significantly worse (−0.354 to −0.124).

The boosted model is significantly worse than LEV on all three targets
(union −0.115 to −0.061). The pre-declared rule picked logistic in five of six
splits. Peak EPSS alone (AP 0.424, union) is as good as anything.

| method | union AP (pred/obs) | KEV AP (pred/obs) | union without KEV AP (pred/obs) |
|---|---|---|---|
| LEV | 0.399 (2.03x) | 0.324 (6.30x) | 0.228 (2.66x) |
| current EPSS | 0.404 (0.65x) | 0.457 (2.02x) | 0.221 (0.72x) |
| peak EPSS | 0.424 (0.97x) | 0.459 (3.03x) | 0.237 (1.17x) |
| isotonic | 0.337 (1.00x) | 0.239 (1.29x) | 0.203 (0.94x) |
| Platt with age | 0.366 (0.88x) | 0.329 (0.61x) | 0.180 (1.20x) |
| logistic | 0.398 (0.99x) | 0.196 (1.52x) | 0.190 (0.74x) |
| boosted trees | 0.309 (1.05x) | 0.127 (2.47x) | 0.089 (0.45x) |

Table A1: Prospective test. Fitted 2025-08-01, scored 2026-08-01 on 44,316
unseen CVEs (union 597 positives, KEV 192, union without KEV 405). Training
positives: 111, 41 and 70.

*An apparent gain was an artifact.* A first version of this experiment used
un-normalized EPSS and kept KEV-listed CVEs in the target. There, the logistic
model beat LEV (AP 0.435 against 0.397, test-only bootstrap +0.02 to +0.05).
The gain disappears when *either* condition is removed. Version-normalized
inputs give 0.398 against 0.399. Dropping KEV members gives a difference of
−0.051 to +0.006 against LEV, and −0.029 to −0.004 against current EPSS. This
is the circularity of §5.5 in another form: a model trained on lists that feed
EPSS learns the feedback.

*Learned maps calibrate, like isotonic.* The logistic map's prospective
pred/obs is 0.74-1.52x, against 2.0-6.3x for LEV. That is no better than the
monotone maps of §5.7.

*Nothing anticipates the lists, and most listings are out of reach (Table
A2).* Across three forward origins:
- no method's AP is significantly above current EPSS;
- the boosted model is significantly below it at two origins;
- the logistic model is significantly below it at one origin (−0.053 to
  −0.002).

LEV's accumulated history adds nothing measurable to current EPSS as a leading
indicator. Current EPSS is never significantly worse than LEV, and is
slightly better at two of the three origins with the CISA and SENSOR dates. More
importantly, **59-75% of the listings in each window concern CVEs first scored
less than 30 days before the window**. Any method that relies on a CVE's
history, LEV included, cannot see them in advance.

| test origin | positives / N | base rate | LEV | current EPSS | logistic | boosted trees |
|---|---|---|---|---|---|---|
| 2025-08-02 | 71 / 32,223 | 0.22% | 0.035 | 0.042 | 0.019 | 0.007 |
| 2025-10-31 | 105 / 43,059 | 0.24% | 0.029 | 0.027 | 0.038 | 0.026 |
| 2026-01-30 | 97 / 49,678 | 0.20% | 0.020 | 0.025 | 0.022 | 0.010 |

Table A2: Forward test, union target, AP for the next 182 days among unlisted
CVEs at least 30 days old.

**What this adds to the paper.**
1. LEV's rule is not what limits it. A learned rule on the same history does
   no better, so the information in EPSS history, not its aggregation, sets
   the ceiling.
2. Evaluations that train or test on KEV-fed lists can show gains that are
   pure feedback. We demonstrate one and remove it.
3. History-based metrics cannot serve the white paper's proposed use
   (flagging exploited CVEs before catalogues do) for most listings, which
   happen within a month of a CVE's first score.

**Threats.**
- Training sets are small (24-111 positives).
- We ran one prospective split for Experiment 1 and three forward origins.
- There are many intervals and no multiplicity correction, so these results
  are exploratory.
- SENSOR is an EPSS label source, so some circularity remains even without
  KEV.
- The forward population excludes CVEs younger than 30 days by design.

## Main-text sentences (to place in §5.7 or §6)

> Restricted to EPSS-history inputs, neither logistic regression nor boosted
> trees ranks exploited CVEs better than LEV or current EPSS a year ahead, and
> no method anticipates new list entries better than current EPSS. An apparent
> learned gain appears only with un-normalized inputs and KEV-listed CVEs in the
> target, and vanishes when either is removed (Appendix A).

## References used

[27] Elkan & Noto 2008; [28] Arp et al. 2022; [29] Pendlebury et al. 2019;
[30] Suciu et al. 2022; [23] ThreatLens; [43] Nucleus Security 2026. Full
entries in `references.md`.
