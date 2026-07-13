#!/usr/bin/env bash
# Regenerate book diagram PNGs from a source tree's diagrams/src/ directory.
# Requires: d2, mmdc (@mermaid-js/mermaid-cli), dot (graphviz).
#
# Legacy/default usage is unchanged:
#   ./render-diagrams.sh [linux-net|ebpf]
# Locale-aware usage:
#   ./render-diagrams.sh --locale zh-CN [linux-net|ebpf]
#   ./render-diagrams.sh --source-root src.zh-CN [linux-net|ebpf]
set -euo pipefail

usage() {
  printf 'usage: %s [--locale LOCALE | --source-root DIR] [linux-net|ebpf]\n' "$0" >&2
}

source_root="src"
selected_book=""
while (($#)); do
  case "$1" in
    --locale)
      [[ $# -ge 2 && -n "$2" ]] || { usage; exit 2; }
      [[ "$source_root" == "src" ]] || { echo "--locale and --source-root are mutually exclusive" >&2; exit 2; }
      source_root="src.$2"
      shift 2
      ;;
    --source-root)
      [[ $# -ge 2 && -n "$2" ]] || { usage; exit 2; }
      [[ "$source_root" == "src" ]] || { echo "--locale and --source-root are mutually exclusive" >&2; exit 2; }
      source_root="${2%/}"
      shift 2
      ;;
    linux-net|ebpf)
      [[ -z "$selected_book" ]] || { usage; exit 2; }
      selected_book="$1"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

if [[ -n "$selected_book" ]]; then
  books=("$selected_book")
else
  books=(linux-net ebpf)
fi

for book in "${books[@]}"; do
  srcdir="$book/$source_root/diagrams/src"
  outdir="$book/$source_root/diagrams"
  [[ -d "$srcdir" ]] || { echo "skip $book (no $srcdir)"; continue; }
  mkdir -p "$outdir"
  for file in "$srcdir"/*.d2 "$srcdir"/*.mmd "$srcdir"/*.dot; do
    [[ -e "$file" ]] || continue
    name=$(basename "$file")
    base="${name%.*}"
    extension="${name##*.}"
    output="$outdir/$base.png"
    case "$extension" in
      d2)  d2 "$file" "$output" >/dev/null 2>&1 ;;
      mmd) mmdc -i "$file" -o "$output" -b white >/dev/null 2>&1 ;;
      dot) dot -Tpng "$file" -o "$output" 2>/dev/null ;;
    esac
    echo "rendered $output"
  done
done
