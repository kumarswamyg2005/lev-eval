# Phase 2 datasets — corrected 2026-09-06

> **Supersedes the 2026-09-05 version of this file.** That version claimed
> VulnCheck KEV gives a "free and unambiguous overlap" with CISA KEV for
> capture–recapture. That was **wrong** and would have produced a silent
> failure. Corrected below.

## The correction

**VulnCheck KEV is a superset of CISA KEV, not an independent list.** Their own
documentation: *"The offering encompasses all vulnerabilities listed in the
CISA KEV catalog, plus approximately 80% more reported as exploited in the
wild"* (<https://docs.vulncheck.com/community/vulncheck-kev>).

Running Lincoln–Petersen on CISA KEV x VulnCheck KEV as downloaded gives
`m = |L1|` by construction, so the estimate collapses to `|L2|`. The arithmetic
runs and returns a plausible number. That is the worst kind of bug.

The `cisa_date_added` field is therefore **the marker of contamination**, not
the convenient join I described.

### It can still be made independent

The schema exposes provenance per report, so a CISA-free list `L2'` can be
constructed:

1. Drop `cisa_date_added`.
2. Filter `vulncheck_reported_exploitation[]` to reports whose URL host is not
   `cisa.gov` / `www.cisa.gov`.
3. Keep a CVE only if a report survives step 2, **or**
   `reported_exploited_by_vulncheck_canaries == true`.
4. First-observation date for `L2'` = `min(date_added)` over surviving reports.

`reported_exploited_by_vulncheck_canaries` is VulnCheck's own honeypot
telemetry and is structurally independent of CISA. That subset alone is a
defensible `L2` if the URL filter draws objections.

**Document this filter in the paper.** It is a methodological contribution in
its own right.

## Second correction: three sources measure the wrong thing

Exploit-DB, Metasploit, Nuclei and AttackerKB record **exploit availability**
or **analyst assessment**, not **exploitation in the wild**. Using them as
capture lists estimates "CVEs with public tooling", a different and much larger
population.

**Exclude them as capture lists. Keep them as covariates** in a heterogeneity
model — a CVE with a public PoC is more likely to be captured by *every* list,
which is exactly the dependence that has to be modelled.

## Third correction: circularity with EPSS itself

EPSS's exploitation labels come from **Fortinet, AlienVault, Shadowserver and
GreyNoise** (Jacobs et al., arXiv:2302.14172). LEV is computed *from* EPSS. So
validating LEV against GreyNoise or Shadowserver is partly circular.

Worse, and this hits Phase 1 directly: **CISA KEV is an input *feature* to
EPSS v3** — "Public vulnerability lists (3 features): CISA KEV, Google Project
Zero, Trend Micro ZDI". See README threats 41–43 and `analysis/leakage.py`.
Removing that leak moves over-confidence from 11.9x to 32.7x.

VulnCheck is not, on available evidence, an EPSS labelling source — a further
point in its favour. **Unverified**; confirm against the EPSS v4 data
description before claiming it.

## Fourth correction: independence is violated everywhere — model it

Every catalogue reads the same vendor advisories. Naive two-source
Lincoln–Petersen assumes independent capture and will be rejected. Use:

- **Log-linear models with interaction terms** across >= 3 lists, so list
  dependence is a fitted parameter rather than an assumption.
- **Stratification** by vendor tier and disclosure year. Phase 1 already
  measured that capture probability varies 14x by vendor, so pooling produces
  the classic downward-biased estimate.
- **Chao's lower-bound estimator** as a robustness check — consistent under
  unmodelled heterogeneity, and gives a defensible floor.

A third list is what makes the log-linear approach possible.

## Ranking

| # | Source | Verdict |
|---|---|---|
| 1 | **VulnCheck KEV Community** | Best. The only source with per-report provenance and dates, so independence can be *constructed* rather than asserted. Free, one API key, single bulk download. |
| 2 | **CIRCL Vulnerability-Lookup sightings** | Best third list. No auth at all. Carries Shadowserver honeypot data via the ShadowSight feeder with `type=exploited` — real sensor telemetry without a Shadowserver contract. Coverage depth unverified. |
| 3 | **ENISA EUVD** | Good third/fourth list. No auth, EU-sourced. `/api/kev/dump` is explicitly a CISA+EU consolidation — use `/api/search?exploited=true` and treat the KEV dump as contaminated. |
| 4 | **GreyNoise** | Strong data, genuinely independent of CISA, but EPSS-circular and access is reviewed. Apply now regardless — it is the long pole. |
| 5 | **Project Zero 0day ITW** | Small N, browser/mobile skewed, and itself an EPSS feature. Not a second list; a high-precision stratum at best. |
| 6 | **Shadowserver (direct)** | Effectively unobtainable — reports are scoped to IP space you can prove you own. Route via CIRCL. |
| — | Exploit-DB, Metasploit, Nuclei, AttackerKB | Excluded on **estimand** grounds, not access grounds. |

**If only one: VulnCheck KEV Community** — the only candidate where the schema
itself lets you demonstrate independence to a reviewer rather than argue for it.

## Access

### No auth, no key

| what | where |
|---|---|
| CISA KEV (JSON) | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` |
| CISA KEV daily archive | `github.com/cisagov/kev-data`, `github.com/hrbrmstr/cisa-known-exploited-vulns` (MIT) |
| EPSS daily scores | `https://epss.empiricalsecurity.com/epss_scores-YYYY-MM-DD.csv.gz` |
| EPSS full history | `github.com/empiricalsec/epss_scores` (~2.5 GB, no licence declared) |
| ENISA EUVD, exploited | `https://euvdservices.enisa.europa.eu/api/search?exploited=true&page=0&size=100` |
| ENISA EUVD, id mapping | `https://euvdservices.enisa.europa.eu/api/dump/cve-euvd-mapping` |
| CIRCL sightings | `https://vulnerability.circl.lu/api/sighting/?vuln_id=CVE-XXXX-NNNNN&per_page=100` |

### Free API key

| what | where |
|---|---|
| **VulnCheck KEV bulk** | `https://api.vulncheck.com/v3/backup/vulncheck-kev`, `Authorization: Bearer <token>`. Take the bulk ZIP, not per-CVE calls. Community rate limit 1,000 req/min. |
| GreyNoise Community | `https://api.greynoise.io/v3/community/{ip}` — free-tier signup **rejects gmail**, needs an institutional address |

### Reviewed application

| what | where |
|---|---|
| GreyNoise Research Community | <https://info.greynoise.io/community/research-program-request> — human-reviewed, **start first** |
| Shadowserver direct | `https://transform.shadowserver.org/api2/` — normally granted only for IP space you own. Treat as unavailable. |

## Licensing — unresolved, settle before submission

VulnCheck's Attribution Notice covers use "in your own production, solution, or
service" with prominent attribution and no fee. It is **silent** on
peer-reviewed publication of derived data and on archiving raw data for
reproducibility. Email `community@vulncheck.com` and get it in writing. The
EPSS history repository declares no licence at all.

## Prior work

- **Capture–recapture on exploitation-catalogue completeness: none found.** The
  nearest adjacent work is descriptive overlap comparison, not estimation. This
  is the strongest novelty claim available.
- **Empirical evaluation of LEV since May 2025: none found peer-reviewed.**
  Nearest items to cite and differentiate:
  - Reference implementation, not evaluation: <https://github.com/RiskBasedPrioritization/LEV>
  - Theoretical objection worth engaging — that CSWP 41's "set EPSS to 1.0 for
    KEV-listed CVEs" misreads EPSS as past rather than next-30-days:
    <https://riskbasedprioritization.github.io/epss/LEV/>
  - Parla, *Efficacy of EPSS in High Severity CVEs found in CISA KEV*,
    <https://arxiv.org/abs/2411.02618>
  - arXiv:2506.01220 — KEV/EPSS/CVSS chaining; reports 48 exploited CVEs caught
    by neither KEV nor EPSS individually. Closest existing result; cite and
    differentiate.
  - NIST states it is seeking partners with real-world datasets to evaluate LEV
    empirically — cite as motivation.

**Search coverage:** targeted, not systematic. Before submission run a
systematic sweep of arXiv cs.CR, WEIS, eCrime, ACM CCS and IEEE S&P from
June 2025 onward for LEV specifically.

## Do this week

1. Register VulnCheck Community, pull `/v3/backup/vulncheck-kev`, build `L2'`
   per the filter above. Unblocks the study.
2. Apply to GreyNoise Research Community — reviewed, so it is the long pole.
3. Email `community@vulncheck.com` on publication and archival rights.
4. Systematic prior-art sweep before committing to the novelty claim.

## Re-running this search

Prompt in `RESEARCH-PROMPT.md`.
