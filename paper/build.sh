#!/usr/bin/env bash
# Build paper/draft.pdf from paper/draft.md.
#   pandoc   markdown -> standalone HTML, figures embedded, math as MathML
#   Chrome   HTML -> PDF (headless print)
# Needs pandoc >= 3 and Google Chrome.  Run from anywhere: bash paper/build.sh
# ANON=1 bash paper/build.sh  -> paper/draft-anon.pdf with the author line removed (WEIS review)
set -euo pipefail
cd "$(dirname "$0")"
OUT=draft${ANON:+-anon}
CHROME="${CHROME:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
pandoc draft.md --standalone --embed-resources --resource-path=. \
  --mathml --css=paper.css --metadata lang=en \
  ${ANON:+-M author="Anonymous submission"} -o $OUT.html
"$CHROME" --headless --disable-gpu --no-pdf-header-footer \
  --run-all-compositor-stages-before-draw --virtual-time-budget=20000 \
  --print-to-pdf="$PWD/$OUT.pdf" "file://$PWD/$OUT.html" 2>/dev/null
echo "wrote paper/$OUT.pdf"
