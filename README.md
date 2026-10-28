# lev-eval

Empirical evaluation of NIST's Likely Exploited Vulnerabilities metric (LEV,
CSWP 41, Mell & Spring, May 2025): are LEV probabilities calibrated against
observed exploitation, and how much of the apparent error belongs to the
exploitation catalogue (CISA KEV) rather than to LEV? The paper is
[paper/draft.md](paper/draft.md).

- [docs/RESULTS.md](docs/RESULTS.md): per-task results and narrative (pre-review numbers)
- [docs/THREATS.md](docs/THREATS.md): the numbered threats to validity
- [DATA_SNAPSHOT.md](DATA_SNAPSHOT.md): provenance and hashes of every input
- `results/truth_bounds_no_vulncheck.csv`: the released per-CVE truth bounds
  (see `analysis/truth_bounds.py`). The primary-list version,
  `results/truth_bounds.csv`, contains VulnCheck-derived flags and is
  gitignored until VulnCheck agrees to its release

## Setup

Python **3.14.7**. Exact pinned versions in [requirements.lock](requirements.lock);
`requirements.txt` holds the unpinned direct dependencies.

    python -m venv .venv && .venv/bin/pip install -r requirements.lock

The Makefile uses `.venv/bin/python` if it exists, else `../.venv/bin/python`;
override with `make PY=/path/to/python ...`.

## Make targets

    make fetch        # download the pinned inputs into cache/ (once)
    make verify-data  # check cached EPSS files against data/epss_manifest.sha256
    make check        # models/lev.py self-test on a hand-computed example
    make reproduce    # every table and figure, offline, in dependency order
    make clean-cache  # delete derived intermediates (dn_sweep, version_normalize,
                      # sampling_error .pkl); raw downloads are kept
    make clean-figures
    make paper        # paper/draft.md -> paper/draft.pdf (needs pandoc and Chrome)

`reproduce` runs, in order: `validate`, `reconcile`, `calibration`, `dn_sweep`,
`epss_drift`, `version_normalize`, `plateau`, `top_bucket`, `vendor_ceiling`,
`sampling_error`, `leakage`, `capture_recapture`, `truth_bounds`, `recalibrate`, `learned_lev`
(all in `analysis/`). Each script also runs on its own: `python analysis/<name>.py`.

**Runtime.** Not yet timed end to end; `fetch` is dominated by the 586 MB CVE
list download. Developed on an Apple M2 with 8 GB RAM.

**Disk.** `cache/` is 2.0 GB when populated (measured 2026-10-11): 1.2 GB for
the CVE list (zip plus unwrapped inner zip), 389 MB of EPSS files, ~300 MB of
pickled intermediates, 86 MB VulnCheck, 58 MB CIRCL pages. `data/vendor/` is
29 MB and is committed.

## Data pinning

Every input is pinned to the snapshot recorded in
[DATA_SNAPSHOT.md](DATA_SNAPSHOT.md), and loaders assert its SHA-256 before use.

| source | how it is pinned |
|---|---|
| CISA KEV (catalogVersion 2026.08.25) | committed in `data/vendor/`; `python data/download_kev.py --refresh` fetches the live feed |
| CVE List (cvelistV5) | release tag `cve_2026-08-25_1700Z`, hash checked on download and before parsing |
| EPSS | one file per date (immutable); `data/epss_manifest.sha256` lists all 237 files used, `make verify-data` checks them, `make fetch` pre-fetches all of them so `reproduce` makes no network calls |
| Exploit-DB, Metasploit, CIRCL, EUVD | committed in `data/vendor/`; each loader takes `--refresh` |
| VulnCheck KEV | not redistributable; needs a free token (`VULNCHECK_API_TOKEN`). A re-download cannot match the pinned hash, so the loader warns instead of failing. Without a token the pipeline falls back to three lists |

Any `--refresh` deliberately replaces a pinned snapshot and invalidates its
hash; update `DATA_SNAPSHOT.md` (and the `SHA256` constant in the loader) in
the same commit.

## Licences and data terms

- **Code** (everything outside `data/vendor/`): MIT, see [LICENSE](LICENSE).
- **CISA KEV** (`data/vendor/known_exploited_vulnerabilities.json`): US
  government work, public domain.
- **EPSS** (not redistributed; fetched into `cache/`): FIRST publishes EPSS
  freely and requests attribution when it is used in publications
  ([EPSS FAQ](https://www.first.org/epss/faq); cite Jacobs et al., 2021,
  *Digital Threats: Research and Practice* 2(3)). The daily-file history
  archive served by [Empirical Security](https://epss.empiricalsecurity.com/)
  carries no explicit licence of its own.
- **CVE List** (not redistributed): [CVE Program terms of
  use](https://www.cve.org/Legal/TermsOfUse) (MITRE copyright licence).
- **CIRCL Vulnerability-Lookup** (`data/vendor/circl_exploited.csv`, derived
  from the public sightings API): the software is AGPL-3.0; no explicit licence
  is stated for sightings data. See [upstream](https://vulnerability.circl.lu/).
- **ENISA EUVD** (`data/vendor/euvd_kev.json`): see
  [upstream](https://euvd.enisa.europa.eu/) terms.
- **VulnCheck KEV Community**: snapshot **not** redistributed (the terms are
  silent on redistribution); a free community token is needed. Use requires
  [prominent attribution](https://docs.vulncheck.com/community/vulncheck-kev/attribution/)
  as "VulnCheck KEV".
- **Exploit-DB** (`data/vendor/files_exploits.csv`): GPL-2.0, as in the
  upstream repository; licence text in `data/vendor/LICENSE-exploitdb.md`.
- **Metasploit Framework** (`data/vendor/modules_metadata_base.json`):
  BSD-3-Clause, Copyright Rapid7, Inc.; licence text in
  `data/vendor/LICENSE-metasploit`.

## Layout

    analysis/     one script per analysis; writes figures/ and results/
    data/         one loader per source; data/vendor/ holds committed snapshots
    models/lev.py LEV and LEV2 (CSWP 41 Eq. 3 and 5), with self-test
    figures/      generated figures
    results/      generated JSON results (authoritative numbers)
    paper/        draft.md, references.md, build script
    docs/         RESULTS.md, THREATS.md; docs/archive/ holds superseded reports
    talk/         talk material for the supervisor; not part of the artifact
    cache/        downloads and intermediates (gitignored)
    DATASETS.md   Phase 2 data-sourcing notes (2026-09-06)

## How to cite

See [CITATION.cff](CITATION.cff).
