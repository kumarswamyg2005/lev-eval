# Data snapshot

Provenance for every input used in Phase 1. All analysis numbers in
[README.md](README.md) were produced against exactly these artifacts.

Retrieval dates are the local mtimes of the cached files. `cache/` is
gitignored (~1.5 GB), so this file is the record of what was in it. The two
sources served from moving refs (Exploit-DB, Metasploit) are committed to
`data/vendor/` instead, so nothing a reviewer re-fetches can change them.

Analysis date (`dn`) for all headline results: **2026-08-01** (the last EPSS
snapshot). Table 5 reproduction uses `dn` = 2025-03-01.

## EPSS — https://epss.empiricalsecurity.com/epss_scores-YYYY-MM-DD.csv.gz

| field | value |
|---|---|
| date range | 2021-04-14 to 2026-08-01 |
| snapshots used in analysis | 67 (monthly, 1st of month + Table 5 anchor dates) |
| files in cache | 238 (67 monthly + 171 daily: retraining-boundary probes and the daily-vs-monthly sampling check) |
| tidy rows | 14,456,555 |
| unique CVEs | 367,311 |
| KEV entries with EPSS data | 1,665 of 1,676 (11 have no score at any date) |
| retrieved | 2026-08-25 |
| missing dates encountered | 2024-12-01 (archive returns 403, not 404) — substituted 2024-12-02 |

Per-file SHA256 is not recorded: the archive is immutable per date, and the
filename carries the date. Cached frame: `cache/epss_tidy_2021-04-14_2026-08-01_67.pkl`.

**EPSS model versions spanned** (deployment date, not the version string —
see README threat 25):

| version | first snapshot carrying it | actual deployment |
|---|---|---|
| v1 (unversioned) | 2021-04-14 | — |
| v2022.01.01 | 2022-02-04 | 2022-02-04 |
| v2023.03.01 | 2023-03-07 | 2023-03-07 |
| v2025.03.14 | 2025-04-01 | **2025-03-17** |
| v2026.06.15 | 2026-07-01 | 2026-06-15 |

## CISA KEV — https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

| field | value |
|---|---|
| SHA256 | `4ddd617740b42cec165f6ce7a3dabe52b3935ebc51617e415968538677e3bb79` |
| catalogVersion | 2026.08.25 |
| dateReleased | 2026-08-25T17:00:12.6512Z |
| entries | 1,676 |
| dateAdded range | 2021-11-03 to 2026-08-25 |
| retrieved | 2026-08-25 |

## cvelistV5 — https://github.com/CVEProject/cvelistV5 releases

| field | value |
|---|---|
| release tag | `cve_2026-08-25_1700Z` |
| asset | `2026-08-25_all_CVEs_at_midnight.zip.zip` (586 MB, zip-in-a-zip) |
| SHA256 | `87ca8c2c259aeed76d8400b7455a2a34a6f0543562f269fd4826a24fa351e823` |
| records parsed (CVE-2022 onward) | 192,054 |
| field coverage | 80.5% CVSS v3, 81.9% vendor, 81.4% CWE |
| retrieved | 2026-08-26 |

Used instead of the NVD API: the API serves ~10 MB per 2000-record page at
roughly 75 KB/s, ~2.7 hours for this corpus, against one request here.

## Exploit-DB — https://gitlab.com/exploit-database/exploitdb (files_exploits.csv, main)

| field | value |
|---|---|
| SHA256 | `54b9167ecd066935aff7d659baad88f3f160b2827b5cffdaefba8d68addf9487` |
| rows | 47,135 |
| distinct CVEs referenced | 25,057 |
| retrieved | 2026-08-25 |
| location | **`data/vendor/files_exploits.csv` — committed to this repo** |

Upstream serves this from `main`, a moving ref, so re-fetching would silently
change the data under a published result. The snapshot is committed instead;
`make fetch` does not download it. `python data/download_exploits.py --refresh`
updates it deliberately (and invalidates the hash above).

## Metasploit — https://github.com/rapid7/metasploit-framework (db/modules_metadata_base.json, master)

| field | value |
|---|---|
| SHA256 | `c155aa27f1ee783c4d7238538bc112df6fbb265064df6267ccf9c161c3e5ee99` |
| modules | 7,151 |
| distinct CVEs referenced | 3,185 |
| retrieved | 2026-08-25 |
| location | **`data/vendor/modules_metadata_base.json` — committed to this repo** |

Same treatment: `master` is a moving ref, so the snapshot is committed rather
than fetched.

Combined Exploit-DB + Metasploit: **26,311 unique CVEs** with a public exploit.

## Environment

Python 3.14.6; exact package versions in [requirements.lock](requirements.lock).
