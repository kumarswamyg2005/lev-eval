# Where to submit

Checked 2026-10-28 against the venues' own pages and sec-deadlines.github.io.
Acceptance rates are not published consistently, so the "chance" column is a
judgement from fit, not a statistic.

| rank | venue | deadline | why it fits | chance |
|---|---|---|---|---|
| 1 | **WEIS 2027** (Munich, June) | **21 Jan 2027**, notification 11 Mar (both "tentative" on the site) | Measurement, statistics and policy audience. No format rules, anonymized review, **no refereed proceedings**, so it does not block a journal afterwards. The Section 6 policy paragraph is written for it. | good |
| 2 | **Journal of Cybersecurity** (Oxford) | rolling; WEIS authors are invited to a special issue | Same audience as WEIS, more room for the capture-recapture detail, and it published the exploit-prediction work EPSS grew from [32]. Natural second step after WEIS. | good |
| 3 | **ACM DTRAP** (Digital Threats: Research and Practice) | rolling | EPSS's own venue [2]. Asks for reproducible results on real-world threats, which `make reproduce` provides. ACM large-format template. Best fallback if WEIS says no. | good |

## Plan

1. **Mid-November:** arXiv preprint (establishes priority).
2. **21 Jan 2027:** WEIS, anonymized. Remove names, the CITATION file link and
   the repository link from the PDF; cite our own work in the third person.
3. **11 Mar:** if accepted, present in June and send the revised version to
   the Journal of Cybersecurity special issue. If rejected, revise from the
   reviews and submit to DTRAP.

## Considered and not recommended now

- **USENIX Security 2027** (26 Jan): it clashes with WEIS (no dual
  submission), and a top venue would want a bigger claim, such as re-scoring
  several prioritization tools against the truth bounds. Worth aiming at with
  that extension later.
- **IMC 2027** (7 Apr cycle): a measurement venue, but network-centric. A
  reasonable backup if WEIS rejects and a conference is preferred to DTRAP.
- **DIMVA 2027** (18 Feb cycle): fits "vulnerability assessment", but its
  audience is systems security rather than measurement and policy.
- **IEEE S&P (17 Nov), PAM (6 Nov):** too soon.

## Check when the WEIS 2027 call is published

- Whether a public arXiv preprint is allowed alongside anonymized review. If
  it is not, post to arXiv after the WEIS decision instead.
- Any page limit (the 2026 call set no formatting rules).
