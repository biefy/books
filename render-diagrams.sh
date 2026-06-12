#!/usr/bin/env bash
# Regenerate every book diagram PNG from its source in diagrams/src/.
# Requires: d2, mmdc (@mermaid-js/mermaid-cli), dot (graphviz).
# Usage: ./render-diagrams.sh [linux-net|ebpf]   (default: both)
set -euo pipefail
books=("${1:-linux-net ebpf}")
for book in ${books[@]}; do
  srcdir="$book/src/diagrams/src"
  outdir="$book/src/diagrams"
  [ -d "$srcdir" ] || { echo "skip $book (no $srcdir)"; continue; }
  for f in "$srcdir"/*.d2 "$srcdir"/*.mmd "$srcdir"/*.dot; do
    [ -e "$f" ] || continue
    n=$(basename "$f"); base="${n%.*}"; ext="${n##*.}"
    out="$outdir/$base.png"
    case "$ext" in
      d2)  d2 "$f" "$out" >/dev/null 2>&1 ;;
      mmd) mmdc -i "$f" -o "$out" -b white >/dev/null 2>&1 ;;
      dot) dot -Tpng "$f" -o "$out" 2>/dev/null ;;
    esac
    echo "rendered $out"
  done
done
