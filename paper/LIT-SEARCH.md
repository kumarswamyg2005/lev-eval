# Prior-work search log

Run 2026-10-28. Purpose: protect the two novelty claims, (a) no empirical
evaluation of LEV exists, and (b) capture-recapture has not been applied to
vulnerability exploitation lists. Re-run the arXiv queries the week before
submission and add anything new here.

## arXiv API (papers submitted since 2025-05, abstracts screened)

| query (`search_query=`) | hits | relevant |
|---|---|---|
| `all:"likely exploited"` | 6 | none |
| `all:EPSS` | 40 | GPM [48], CAPE [50], ThreatLens [23], Shaffer & Voicu [24], Sherif et al. [22], Alpay [51], Koscinski [35], Shimizu [21]; none evaluates LEV |
| `all:"known exploited vulnerabilities"` | 18 | KEVGraph [49], GPM, CAPE; all take KEV as complete |
| `all:"capture-recapture" AND all:vulnerabilit*` | 0 | none |
| `all:"exploited in the wild"` | 13 | none on catalogue completeness |
| `cat:cs.CR AND all:exploitation AND all:"ground truth"` | 53 | none |

    curl -s 'https://export.arxiv.org/api/query?search_query=all:EPSS&max_results=80&sortBy=submittedDate&sortOrder=descending'

## Papers that cite CSWP 41

- Huang et al. [26]: uses LEV as an input.
- GPM [48]: cites LEV in related work; evaluates against CISA KEV and a pooled
  set that includes VulnCheck KEV (which contains CISA KEV).
- Shimizu & Hashimoto [21]: mentions LEV appeared during its study period.
- None computes LEV against exploitation data.

## Venues and the web

- WEIS 2026 programme: no paper on EPSS, KEV or prioritization.
- VulnGym (arXiv 2607.24552): RL simulation of patching policies against APTs;
  no LEV, no capture-recapture. Not cited.
- Closest capture-recapture work in security: Meurs et al., ransomware attack
  counts from police, incident-response and leak-site lists [8]. Different
  population (attacks on firms), so claim (b) stands; cited.
- Industry KEV-coverage reports already cited: [18, 40-43].
- Not cited, could not verify: Cyentia/FIRST "A Visual Exploration of Exploits
  in the Wild" (2024); its page returned 404.

## Verdict

Both claims stand as of 2026-10-28. The search is structured, not a formal
systematic review; peer-reviewed work not on arXiv may be missed (threats,
Section 7).

## Re-run 2026-11-08 (while writing main.tex)

- arXiv API, same queries, papers since 2026-10-20: no new hits.
- OpenAlex search "likely exploited vulnerabilities", newest first: one new
  relevant paper, Lu & Stiawan, *Queue Shock at Model Upgrades* (Cybersecurity
  Advances 3(1), 30 Oct 2026) [53]. It audits EPSS rank stability across the
  v2-v5 releases for queue workload and cites CSWP 41, but does not evaluate
  LEV or catalogue coverage. Cited as concurrent work in Related work; claim
  (a) and (b) still stand.
- arXiv 2609.37217 (scoring-system divergence on an OT grid model): not
  relevant, not cited.
- [21] and [26] are now published in IEEE Access; entries updated.
- NIST CSRC page for CSWP 41: still the 19 May 2025 final, no revision.

## Re-run 2026-11-11 (pre-submission review)

- arXiv API, the first five queries above plus `all:"multiple systems
  estimation" AND cat:cs.CR` and `all:KEV AND all:incomplete*`, papers since
  2026-10-15: no new hits (newest EPSS/KEV paper is still CAPE, 9 October).
- OpenAlex (`search=`, published since 2026-10-20) for "likely exploited
  vulnerabilities", "known exploited vulnerabilities", EPSS calibration and
  capture-recapture with exploited vulnerabilities: only Lu & Stiawan [38]
  (already cited) is relevant. Zenodo holds data and code for a paper titled
  "Patch Now or Wait? The Value of Waiting for Exploit Forecasts in
  Vulnerability Management" (October 2026); the paper itself was not found.
  It is about patch timing with EPSS, not LEV or catalogue coverage. Watch for
  it: it is the kind of paper WEIS attracts.
- Web search for LEV evaluations: none published. The first hit for an
  "empirical evaluation of LEV" is this project's own public GitHub repository.
- Claims (a) and (b) still stand.
- Source check against CSWP 41 itself (not done before): the white paper
  DOES state Table 5's date (2025-01-16) and each row's CVE count. The paper
  and `validate.py` now use that date; see Section 5.1.

## Re-run 2026-11-15 (before handing the paper to the supervisor)

- arXiv API, the six queries of 11 November, papers since 2026-10-10: no new
  hits (newest EPSS/KEV paper is still CAPE, 9 October).
- OpenAlex, published since 2026-10-20: only Lu & Stiawan (already cited).
- Web search: no LEV evaluation published. Found Almarashi, *Entropy-Resolved
  Exploitation Pressure* (IET Information Security 2026(1), online 27 October
  2026, doi:10.1049/ise2/5854622): EPSS-based pressure measure validated by
  top-5% KEV capture; does not cite or evaluate LEV, no catalogue-coverage
  estimate. Read from its abstract only (publisher page blocked). Now cited
  under "KEV as ground truth". Claims (a) and (b) still stand.
