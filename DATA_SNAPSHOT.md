# Data snapshot

Provenance for every input. All analysis numbers in the paper,
`results/*.json` and [docs/RESULTS.md](docs/RESULTS.md) were produced against
exactly these artifacts. Every loader in `data/` asserts the SHA-256 recorded
here before using a file (VulnCheck only warns; see its section).

Retrieval dates are the local mtimes of the cached files. `cache/` is
gitignored (2.0 GB when populated), so this file is the record of what was in
it. Sources served from moving refs or live feeds (CISA KEV, Exploit-DB,
Metasploit, CIRCL, EUVD) are committed to `data/vendor/` instead, so nothing a
reviewer re-fetches can change them.

Analysis date (`dn`) for all headline results: **2026-08-01** (the last EPSS
snapshot). Table 5 reproduction uses `dn` = 2025-03-01.

## EPSS — https://epss.empiricalsecurity.com/epss_scores-YYYY-MM-DD.csv.gz

| field | value |
|---|---|
| date range | 2021-04-14 to 2026-08-01 |
| snapshots used in analysis | 67 (monthly, 1st of month + Table 5 anchor dates) |
| files in cache | 238 (67 monthly + 170 daily: retraining-boundary probes and the daily-vs-monthly sampling check; plus 2026-09-01, fetched before `ARCHIVE_END` was pinned and unused) |
| tidy rows | 14,456,555 |
| unique CVEs | 367,311 |
| KEV entries with EPSS data | 1,665 of 1,676 (11 have no score at any date) |
| retrieved | 2026-08-25 |
| missing dates encountered | 2024-12-01 (archive returns 403, not 404) — substituted 2024-12-02 |

Per-file SHA-256 for the 237 files the analysis reads (all of the above except
the unused 2026-09-01) is in [data/epss_manifest.sha256](data/epss_manifest.sha256).
`make fetch` pre-fetches every listed file (including the daily files
`analysis/sampling_error.py`, `epss_drift.py` and `version_normalize.py` read),
so `make reproduce` makes no network calls. Verify the cache with

    make verify-data      # = cd cache/epss && shasum -a 256 -c ../../data/epss_manifest.sha256

A freshly downloaded file that is listed in the manifest is also checked
against it on download. Cached frame: `cache/epss_tidy_2021-04-14_2026-08-01_67.pkl`.

**EPSS model versions spanned** (deployment date, not the version string —
see [docs/THREATS.md](docs/THREATS.md) threat 25):

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
| location | **`data/vendor/known_exploited_vulnerabilities.json` — committed to this repo** (public domain) |

The loader reads the committed copy; `python data/download_kev.py --refresh`
fetches the live feed deliberately (and invalidates the hash above).

## cvelistV5 — https://github.com/CVEProject/cvelistV5 releases

| field | value |
|---|---|
| release tag | `cve_2026-08-25_1700Z` |
| asset | `2026-08-25_all_CVEs_at_midnight.zip.zip` (586 MB, zip-in-a-zip) |
| SHA256 | `87ca8c2c259aeed76d8400b7455a2a34a6f0543562f269fd4826a24fa351e823` |
| records parsed (CVE-2022 onward) | 192,054 |
| field coverage | 80.5% CVSS v3, 81.9% vendor, 81.4% CWE |
| retrieved | 2026-08-26 |
| pinned in | `data/download_nvd.py` (`TAG`, downloads this exact asset, not `releases/latest`) |

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


## Phase 2 exploitation lists

Both feeds below are live and change daily, so each is **snapshotted into
`data/vendor/` and committed**; the pipeline reads the snapshot, never the live
API. `--refresh` on either loader re-pulls deliberately and invalidates the
hash.

### CIRCL Vulnerability-Lookup — "exploited" sightings

| field | value |
|---|---|
| endpoint | `https://vulnerability.circl.lu/api/sighting/?type=exploited` (no auth) |
| retrieved | 2026-09-28 |
| raw sightings | 68,191 (68,107 with a valid CVE id) across 6,159 CVEs |
| committed file | `data/vendor/circl_exploited.csv` (6.8 MB) |
| SHA256 | `b7dc2ec6d3b068dc5e1791fe18cade244bbfaadd320eb7850116d5618d239300` |

Each sighting is classified by its `source` field (`data/download_circl.py`):

| class | sightings | CVEs | used as | why |
|---|---|---|---|---|
| sensor | 45,013 | 969 | **list SENSOR** | Shadowserver honeypot telemetry; independent mechanism |
| social | 11,883 | 2,396 | **list SOCIAL** | Telegram and similar; 58% of shared CVEs appear here *before* CISA |
| kev_catalog | 8,571 | 3,149 | excluded | contains **all 1,676** CISA KEV CVEs — a superset, not independent |
| exploit_db | 2,461 | 2,226 | excluded | exploit availability, not exploitation |
| report | 159 | 125 | excluded | too small to model |
| other | 20 | 17 | excluded | unparseable source |

### ENISA EUVD — known-exploited dump

| field | value |
|---|---|
| endpoint | `https://euvdservices.enisa.europa.eu/api/kev/dump` (no auth) |
| retrieved | 2026-09-28 |
| entries | 1,740 (CISA KEV + EU KEV consolidated; each entry names its sources) |
| EU KEV entries | 66, of which 55 also on CISA KEV |
| committed file | `data/vendor/euvd_kev.json` (249 KB) |
| SHA256 | `22d58b6385f3f6f76ac202fa6939a0f4ed9b8f77263373d0935d0599cabe2970` |

**Not used as a list:** 88% of EU KEV's CISA overlap carries CISA's own
`dateAdded`, so it is derivative rather than independent.

### VulnCheck KEV — community backup

| field | value |
|---|---|
| endpoint | `https://api.vulncheck.com/v3/backup/vulncheck-kev` (free community token) |
| retrieved | 2026-09-28 (latest record `_timestamp` 2026-09-28T17:20:27) |
| records | 5,371 |
| cached file | `cache/vulncheck_kev.json` (82 MB) — **not committed** |
| SHA256 | `7163d33d4c4698591535af62b6b08b6784e9df0d2614f9fe9fdb33578402f811` |

**Not in the repository:** VulnCheck's attribution notice is silent on
redistribution, so the raw backup stays in gitignored `cache/`; only its hash
is recorded. Reproducing the four-list results needs a free community token
(`VULNCHECK_API_TOKEN`); without one the pipeline falls back to three lists.

Rebuilt as list VULNCHK by dropping every report hosted on cisa.gov **and** on
shadowserver.org (all 969 SENSOR CVEs appear in VulnCheck's Shadowserver
subset): 4,815 CVEs. A strict variant — sensor-observed or at least two
independent sources — has 2,912.

## Environment

Python 3.14.7; exact package versions in [requirements.lock](requirements.lock).
