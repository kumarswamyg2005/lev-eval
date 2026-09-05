# Phase 2 datasets — what to use, verified 2026-09-05

The Phase 1 blocker is that CISA KEV is our only exploitation ground truth, and
it is incomplete. This lists the sources that fix that, checked for
availability, cost and format rather than taken from memory.

**Headline: the critical source is free.** VulnCheck KEV Community requires a
free account, no licence purchase.

---

## Tier 1 — get these first

### 1. VulnCheck KEV (Community) — *the one that unblocks the paper*

| | |
|---|---|
| Cost | **Free**, community account at `console.vulncheck.com` |
| Access | `GET https://api.vulncheck.com/v3/backup/vulncheck-kev` with `Authorization: Bearer <token>` — returns a bulk download link |
| Verified | Endpoint returns HTTP 401 without a token, i.e. it exists and needs only the free key |
| Rate limit | 1,000 requests/min for community users |
| Size | 884 KEVs added in 2026 vs CISA's 245 across the same period — ~3.6x |
| Attribution | VulnCheck asks for "prominent attribution"; formal redistribution terms are **not** published — confirm before republishing raw data |

**Why this one.** Its schema is close to purpose-built for what we need:

```
cve[], cwes[], vendorProject, product,
date_added,                          <- VulnCheck's own first-report date
cisa_date_added,                     <- CISA's, in the same record
vulncheck_reported_exploitation[]    <- {url, date_added} per reporting source
vulncheck_xdb[]                      <- {xdb_id, exploit_type, date_added}
reported_exploited_by_vulncheck_canaries  (bool)
```

`cisa_date_added` sitting inside every VulnCheck record means the CISA subset is
identifiable **without a join** — the overlap needed for capture–recapture comes
free and unambiguous. `vulncheck_reported_exploitation[]` goes further: it names
each independent reporting source with its own date, so the two-source estimator
can be extended to many sources without acquiring them separately.

`reported_exploited_by_vulncheck_canaries` is honeypot-observed exploitation —
sensor evidence, not curated advisories, so it is genuinely independent of the
advisory-driven process that builds CISA KEV.

### 2. CISA KEV daily archive — *fixes an existing threat, costs nothing*

| | |
|---|---|
| Source | `github.com/cisagov/kev-data` (official) or `github.com/hrbrmstr/cisa-known-exploited-vulns` (MIT, daily ISO-stamped snapshots) |
| Cost | Free |

We currently hold **one** snapshot of KEV and trust its `dateAdded` field.
Daily archives let us verify that `dateAdded` is never backdated or revised —
which is README threat 17, currently stated but unverified. It also makes the
as-of-`dn` KEV rates in `dn_sweep.py` and `plateau.py` genuinely point-in-time
rather than reconstructed from one file.

### 3. Full daily EPSS archive

| | |
|---|---|
| Source | `github.com/empiricalsec/epss_scores` (official historical repo, ~2.5 GB) |
| Cost | Free |
| Note | No licence declared on the repo — worth confirming for redistribution |

Removes the 3.9% monthly-sampling approximation entirely. Not urgent — the
error is measured and bounded — but needed if any claim ever turns on a
difference that size.

---

## Tier 2 — strengthens the independence argument

### 4. GreyNoise (Community Research Program)

| | |
|---|---|
| Cost | Free for non-commercial research; **application required** |
| Apply | `info.greynoise.io/community/research-program-request` |
| Gives | Full Enterprise API, including historical data |

Observed scanning and exploitation attempts from sensors. Its independence from
KEV is the strongest of any source here — it observes traffic rather than
curating advisories, so its misses are uncorrelated with CISA's. That is exactly
the assumption capture–recapture needs.

**Apply early**: it is a reviewed application, not a signup form.

### 5. Nuclei templates

| | |
|---|---|
| Source | `github.com/projectdiscovery/nuclei-templates` |
| Licence | **MIT** — cleanest licence of anything here |
| Cost | Free |

A community-written detection template for a CVE is evidence someone considered
it worth detecting in the wild. Weaker signal than the others, but MIT-licensed
and trivially joinable, and it extends the exploit-availability axis we already
built from Exploit-DB and Metasploit.

---

## Tier 3 — optional, low recall

- **Google Project Zero "0day In the Wild"** — ~150-200 CVEs, extremely high
  precision. Lives in a Google Sheet, not the GitHub repo (checked: the repo
  holds only root-cause analyses). Useful as a gold-standard spot check, too
  small to estimate with.
- **AttackerKB (Rapid7)** — read-only API, but only ~300 CVEs have usable
  ratings. Human judgement, not observation.
- **Shadowserver** — public dashboard needs no account; bulk research data
  needs an Alliance partnership or reciprocal data-sharing agreement, arranged
  via `contact@shadowserver.org`. Slow to obtain; start only if GreyNoise falls
  through.

---

## What this changes about the paper

With VulnCheck KEV alone we can, for the first time:

1. Estimate exploitation that **neither** catalog recorded, via stratified
   capture–recapture — replacing the vendor-ceiling hack, whose weakness is
   already flagged as a limitation.
2. Test whether LEV's over-confidence shrinks against a **broader** ground
   truth. VulnCheck is ~3.6x larger, so if the 17.2x gap is mostly catalog
   blindness it should fall sharply; if it barely moves, that is evidence the
   residual is LEV error. **Either result is publishable**, which is what makes
   this the right next step.
3. Use `vulncheck_reported_exploitation[]` to stratify by *reporting source* and
   check the visibility bias we found in CISA KEV (32.5% Microsoft vs 2.3%
   XWiki) reproduces in an independent catalog.

**Do not drop CISA KEV.** The comparison between the two catalogs is the
measurement, so both are needed.

---

## Re-running this search

The prompt is in `RESEARCH-PROMPT.md`. It asks for a machine-readable CSV/JSON
of sources, direct download links grouped by whether they need no auth / a free
key / an approved application, and a PDF or Markdown summary — so the result
can be loaded and used rather than re-researched by hand.

## Sources checked

- VulnCheck KEV: <https://www.vulncheck.com/kev>, <https://docs.vulncheck.com/community/vulncheck-kev/schema>, <https://docs.vulncheck.com/api/v3>
- VulnCheck 2026 counts: <https://www.vulncheck.com/blog/state-of-exploitation-2026>
- GreyNoise research program: <https://info.greynoise.io/community/research-program-request>
- CISA KEV mirror: <https://github.com/cisagov/kev-data>
- EPSS archive: <https://github.com/empiricalsec/epss_scores>, <https://www.first.org/epss/data>
- Nuclei templates: <https://github.com/projectdiscovery/nuclei-templates>
- Project Zero ITW: <https://googleprojectzero.blogspot.com/p/0day.html>
