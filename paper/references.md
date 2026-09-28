# References — with verification status

Status key:

- **verified** — title, authors and date checked against the source on 2026-09-28
- **standard** — a classic reference given from memory; details are almost
  certainly right but **check volume and pages before submission**
- **web** — a web resource with no formal publication; cite with access date

| # | Reference | Status |
|---|---|---|
| 1 | P. Mell and J. Spring. *Likely Exploited Vulnerabilities: A Proposed Metric for Vulnerability Exploitation Probability.* NIST Cybersecurity White Paper 41, 19 May 2025. doi:10.6028/NIST.CSWP.41 | verified |
| 2 | J. Jacobs, S. Romanosky, B. Edwards, I. Adjerid, M. Roytman. *Exploit Prediction Scoring System (EPSS).* Digital Threats: Research and Practice 2(3), 2021. | standard — check author order |
| 3 | J. Jacobs, S. Romanosky, O. Suciu, B. Edwards, A. Sarabi. *Enhancing Vulnerability Prioritization: Data-Driven Exploit Predictions with Community-Driven Insights.* arXiv:2302.14172, 2023. | verified (arXiv preprint; no formal venue listed) |
| 4 | CISA. *Known Exploited Vulnerabilities Catalog*, and Binding Operational Directive 22-01. | web |
| 5 | CIRCL. *Vulnerability-Lookup*, sightings API. vulnerability.circl.lu | web, accessed 2026-09-28 |
| 6 | ENISA. *EU Vulnerability Database* API. euvdservices.enisa.europa.eu | web, accessed 2026-09-28 |
| 7 | E. B. Wilson. *Probable inference, the law of succession, and statistical inference.* JASA 22(158):209-212, 1927. | standard |
| 8 | S. Holm. *A simple sequentially rejective multiple test procedure.* Scandinavian Journal of Statistics 6(2):65-70, 1979. | standard |
| 9 | G. W. Brier. *Verification of forecasts expressed in terms of probability.* Monthly Weather Review 78(1):1-3, 1950. | standard |
| 10 | M. P. Naeini, G. F. Cooper, M. Hauskrecht. *Obtaining well calibrated probabilities using Bayesian binning.* AAAI 2015. | standard |
| 11 | VulnCheck. *VulnCheck KEV* documentation. docs.vulncheck.com/community/vulncheck-kev | web — quote used: "encompasses all vulnerabilities listed in the CISA KEV catalog" |
| 12 | International Working Group for Disease Monitoring and Forecasting. *Capture-recapture and multiple-record systems estimation I: History and theoretical development.* American Journal of Epidemiology 142(10):1047-1058, 1995. | standard |
| 13 | Y. M. M. Bishop, S. E. Fienberg, P. W. Holland. *Discrete Multivariate Analysis: Theory and Practice.* MIT Press, 1975. | standard |
| 14 | A. Chao. *Estimating the population size for capture-recapture data with unequal catchability.* Biometrics 43(4):783-791, 1987. | standard |
| 15 | K. P. Burnham and D. R. Anderson. *Model Selection and Multimodel Inference*, 2nd ed. Springer, 2002. | standard |
| 16 | B. Zadrozny and C. Elkan. *Transforming classifier scores into accurate multiclass probability estimates.* KDD 2002. | standard |
| 17 | J. Platt. *Probabilistic outputs for support vector machines and comparisons to regularized likelihood methods.* In Advances in Large Margin Classifiers, MIT Press, 1999. | standard |
| 18 | M. Roytman. *The KEV Paradox.* Empirical Security, January 2026. research.empiricalsecurity.com/research/the-kev-paradox | web, verified 2026-09-28 |
| 19 | R. Parla. *Efficacy of EPSS in High Severity CVEs found in KEV.* arXiv:2411.02618, 2024. | verified |
| 20 | Risk Based Prioritization project. *NIST LEV.* riskbasedprioritization.github.io/epss/LEV | web, verified 2026-09-28; states it is not associated with the CSWP 41 authors |
| 21 | N. Shimizu and M. Hashimoto. *Vulnerability Management Chaining: An Integrated Framework for Efficient Cybersecurity Risk Prioritization.* arXiv:2506.01220, 2025. | verified |
| 22 | E. Sherif, I. Yevseyeva, V. Basto-Fernandes, A. Cook. *Bridging the Gap Between Security Metrics and Key Risk Indicators: An Empirical Framework for Vulnerability Prioritization.* arXiv:2603.12450, 2026. | verified |
| 23 | S. Motamedi Sedeh, P. Shahrivar, M. Qureshi, A. Devjiani, M. A. Tayebi. *ThreatLens: Evidence-Guided Ranking of High-Priority CVEs.* arXiv:2608.22306, 2026. | verified |
| 24 | S. Shaffer and L. Voicu. *Modeling Local Exploit Hazard: A Bayesian Framework for Quantifying Exploit Risk and Operational Efficiency.* arXiv:2607.24618, 2026. | verified |
| 25 | O. Binette and R. C. Steorts. *On the Reliability of Multiple Systems Estimation for the Quantification of Modern Slavery.* Journal of the Royal Statistical Society Series A, 2022. arXiv:2112.01594. | verified |
| 26 | S. Huang, C. M. Poskitt, L. K. Shar. *Bayesian and Multi-Objective Decision Support for Incident Mitigation in Cyber-Physical Systems.* arXiv:2509.00770, 2025. | verified 2026-09-29 (uses LEV as an input; does not evaluate it) |

## Before submission

1. Check volume/page details for the **standard** entries against the
   publisher's page; they were written from memory.
2. Run a **systematic** sweep for LEV evaluations and exploitation
   capture-recapture: arXiv cs.CR, WEIS, eCrime, CCS, IEEE S&P, USENIX
   Security, NDSS, from June 2025. The search behind this list was targeted
   (README threat 49); one missed paper costs the novelty claim.
3. Confirm with VulnCheck whether derived data may be published, and whether
   the EPSS history repository has a licence (neither states one).
