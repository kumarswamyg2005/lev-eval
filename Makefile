# Regenerate every table and figure from the cached data, in dependency order.
#   make reproduce     -- everything (assumes cache/ is populated)
#   make fetch         -- populate cache/ from the network first
#
# Nothing here re-downloads: each data module short-circuits on its cache, so
# `reproduce` is offline once `fetch` has run once.

PY ?= ../.venv/bin/python

.PHONY: reproduce fetch check clean-figures paper

fetch:
	$(PY) data/download_epss.py
	$(PY) data/download_kev.py
	$(PY) data/download_nvd.py
	$(PY) data/download_vulncheck.py
	@echo "Exploit-DB, Metasploit, CIRCL and EUVD are pinned in data/vendor/ -- not fetched."
	@echo "Run 'python data/download_exploits.py --refresh' to update them."

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
	$(PY) analysis/recalibrate.py
	@echo
	@echo "figures/: $$(ls figures | tr '\n' ' ')"

clean-figures:
	rm -f figures/*.png

paper:
	bash paper/build.sh
