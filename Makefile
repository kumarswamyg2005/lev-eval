# Regenerate every table and figure from the cached data, in dependency order.
#   make fetch         -- populate cache/ from the network (pinned inputs only)
#   make verify-data   -- check cached EPSS files against data/epss_manifest.sha256
#   make reproduce     -- everything, offline once `fetch` has run
#
# Every loader short-circuits on its cache and checks the SHA-256 pinned in
# DATA_SNAPSHOT.md, so `reproduce` is offline and fails loudly on drifted inputs.

# Repo-local venv if there is one, else the parent directory's (this machine).
PY ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,../.venv/bin/python)

.PHONY: reproduce fetch verify-data check clean-figures clean-cache paper

fetch:
	$(PY) data/download_epss.py --manifest
	$(PY) data/download_nvd.py
	$(PY) data/download_vulncheck.py
	@echo "CISA KEV, Exploit-DB, Metasploit, CIRCL and EUVD are pinned in data/vendor/ -- not fetched."
	@echo "Each loader takes --refresh to update its snapshot deliberately (invalidates the pinned hash)."

verify-data:
	cd cache/epss && shasum -a 256 -c --quiet ../../data/epss_manifest.sha256 && echo "EPSS: all files match the manifest"

check:
	$(PY) models/lev.py

reproduce: check
	$(PY) analysis/validate.py
	$(PY) analysis/reconcile.py
	$(PY) analysis/calibration.py
	$(PY) analysis/dn_sweep.py
	$(PY) analysis/epss_drift.py
	$(PY) analysis/version_normalize.py
	$(PY) analysis/plateau.py
	$(PY) analysis/top_bucket.py
	$(PY) analysis/vendor_ceiling.py
	$(PY) analysis/sampling_error.py
	$(PY) analysis/leakage.py
	$(PY) analysis/capture_recapture.py
	$(PY) analysis/truth_bounds.py
	$(PY) analysis/truth_bounds.py --no-vulncheck
	$(PY) analysis/recalibrate.py
	$(PY) analysis/learned_lev.py
	@echo
	@echo "figures/: $$(ls figures | tr '\n' ' ')"

clean-figures:
	rm -f figures/*.png

# Derived intermediates only; raw downloads in cache/ are never touched.
clean-cache:
	rm -f cache/dn_sweep.pkl cache/version_normalize.pkl cache/sampling_error.pkl

paper:
	bash paper/build.sh
