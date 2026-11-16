#!/usr/bin/env bash
# Build the LaTeX paper: main.pdf (named), weis.pdf (anonymous WEIS submission),
# acm.pdf (DTRAP acmsmall format, for page count), submission.pdf (Computers & Security
# version: cas-body.tex, cas-abstract.tex, cas-appendix.tex).  Needs pdflatex and bibtex.
set -euo pipefail
cd "$(dirname "$0")"
for j in ${@:-main weis acm submission}; do
  pdflatex -interaction=nonstopmode -halt-on-error $j >/dev/null
  bibtex $j >/dev/null
  pdflatex -interaction=nonstopmode -halt-on-error $j >/dev/null
  pdflatex -interaction=nonstopmode -halt-on-error $j >/dev/null
  echo "$j.pdf: $(pdfinfo $j.pdf | awk '/^Pages/{print $2}') pages"
done
