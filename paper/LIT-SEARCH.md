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
