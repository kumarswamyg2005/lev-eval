#!/usr/bin/env bash
# Build paper/draft.pdf from paper/draft.md.
#   pandoc   markdown -> standalone HTML, figures embedded, math as MathML
#   Chrome   HTML -> PDF (headless print)
# Needs pandoc >= 3 and Google Chrome.  Run from anywhere: bash paper/build.sh
set -euo pipefail
cd "$(dirname "$0")"
CHROME="${CHROME:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
pandoc draft.md --standalone --embed-resources --resource-path=. \
  --mathml --css=paper.css --metadata lang=en -o draft.html
"$CHROME" --headless --disable-gpu --no-pdf-header-footer \
  --run-all-compositor-stages-before-draw --virtual-time-budget=20000 \
  --print-to-pdf="$PWD/draft.pdf" "file://$PWD/draft.html" 2>/dev/null
echo "wrote paper/draft.pdf"
