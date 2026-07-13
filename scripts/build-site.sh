#!/usr/bin/env bash
# Build and assemble both English and Simplified Chinese mdBooks, then index them.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
site_dir="$repo_root/_site"
staging_root=$(mktemp -d "${TMPDIR:-/tmp}/books-site.XXXXXX")
staging_site="$staging_root/site"
trap 'rm -rf "$staging_root"' EXIT

for command in mdbook npm; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "error: required command not found: $command" >&2
    exit 1
  }
done

# npm ci makes the package-lock pin authoritative even if a stale local
# node_modules directory exists.
npm --prefix "$repo_root" ci --ignore-scripts

mkdir -p "$staging_site/zh-CN"

build_english() {
  local book=$1
  echo "building $book (en)"
  mdbook build "$repo_root/$book" --dest-dir "$staging_site/$book"
}

build_chinese() {
  local book=$1
  local title=$2
  local source_root="$repo_root/$book/src.zh-CN"
  if [[ ! -f "$source_root/SUMMARY.md" ]]; then
    echo "error: missing $book/src.zh-CN/SUMMARY.md; translated chapters are required for a bilingual build" >&2
    exit 1
  fi

  echo "building $book (zh-CN)"
  env \
    MDBOOK_BOOK__SRC="src.zh-CN" \
    MDBOOK_BOOK__LANGUAGE="zh-CN" \
    MDBOOK_BOOK__TITLE="$title" \
    MDBOOK_OUTPUT__HTML__SITE_URL="/books/$book/zh-CN/" \
    MDBOOK_OUTPUT__HTML__EDIT_URL_TEMPLATE="https://github.com/biefy/books/edit/main/$book/{path}" \
    mdbook build "$repo_root/$book" --dest-dir "$staging_site/$book/zh-CN"
}

# Keep this order explicit: both canonical English builds precede localized builds.
build_english linux-net
build_english ebpf
build_chinese linux-net "Linux 网络子系统 30 天"
build_chinese ebpf "30 天 eBPF 实战"

install -m 0644 "$repo_root/index.html" "$staging_site/index.html"
install -m 0644 "$repo_root/zh-CN/index.html" "$staging_site/zh-CN/index.html"

"$repo_root/node_modules/.bin/pagefind" \
  --site "$staging_site" \
  --exclude-selectors ".sidebar,.menu-bar,.nav-chapters,.mobile-nav-chapters"

rm -rf "$site_dir"
mkdir -p "$site_dir"
cp -R "$staging_site/." "$site_dir/"
echo "assembled $site_dir"
