#!/usr/bin/env python3
"""Static smoke checks for the assembled bilingual site."""

from __future__ import annotations

import argparse
import re
import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit

BOOK_ROOTS = (
    "linux-net",
    "linux-net/zh-CN",
    "ebpf",
    "ebpf/zh-CN",
)
SHARED_ASSETS = (
    "language-switcher.css",
    "language-switcher.js",
    "pagefind-search.css",
    "pagefind-search.js",
)
PAGEFIND_ASSETS = (
    "pagefind/pagefind.js",
    "pagefind/pagefind-ui.css",
    "pagefind/pagefind-ui.js",
)


class DocumentParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.references: list[str] = []
        self.lang: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "html":
            self.lang = values.get("lang")
        for attribute in ("href", "src"):
            value = values.get(attribute)
            if value:
                self.references.append(value)


def candidates(site: Path, document: Path, reference: str) -> list[Path]:
    parsed = urlsplit(reference)
    if parsed.scheme or parsed.netloc or not parsed.path:
        return []
    path = unquote(parsed.path)
    if path.startswith("/books/"):
        target = site / path.removeprefix("/books/")
    elif path == "/books" or path == "/books/":
        target = site / "index.html"
    elif path.startswith("/"):
        target = site / path.lstrip("/")
    else:
        target = document.parent / path
    if path.endswith("/"):
        return [target / "index.html"]
    if target.suffix:
        return [target]
    return [target, target.with_suffix(".html"), target / "index.html"]


def check_links(site: Path, errors: list[str]) -> tuple[int, dict[str, int]]:
    checked = 0
    languages: dict[str, int] = {}
    for document in sorted(site.rglob("*.html")):
        parser = DocumentParser()
        try:
            parser.feed(document.read_text(encoding="utf-8"))
        except UnicodeDecodeError as exc:
            errors.append(f"{document}: invalid UTF-8: {exc}")
            continue
        language = parser.lang or "<missing>"
        languages[language] = languages.get(language, 0) + 1
        for reference in parser.references:
            paths = candidates(site, document, reference)
            if not paths:
                continue
            checked += 1
            if not any(path.exists() for path in paths):
                relative = document.relative_to(site)
                errors.append(f"{relative}: unresolved local reference {reference!r}")
    return checked, languages


def check_book_assets(site: Path, errors: list[str]) -> None:
    for root_name in BOOK_ROOTS:
        root = site / root_name
        index = root / "index.html"
        if not index.is_file():
            errors.append(f"{root_name}/index.html: missing book build")
            continue
        html = index.read_text(encoding="utf-8")
        expected_language = "zh-CN" if root_name.endswith("/zh-CN") else "en"
        if f'<html lang="{expected_language}"' not in html:
            errors.append(f"{root_name}/index.html: expected html lang={expected_language!r}")
        for asset in SHARED_ASSETS:
            stem, suffix = asset.rsplit(".", 1)
            fingerprinted = re.compile(re.escape(stem) + r"-[0-9a-f]+\." + re.escape(suffix))
            if not fingerprinted.search(html):
                errors.append(f"{root_name}/index.html: missing registered asset {asset}")
        if list(root.glob("searcher-*.js")) or list(root.glob("searchindex-*.js")):
            errors.append(f"{root_name}: mdBook built-in search artifacts are present")


def check_landing_pages(site: Path, errors: list[str]) -> None:
    english = site / "index.html"
    chinese = site / "zh-CN" / "index.html"
    if not english.is_file() or 'href="zh-CN/"' not in english.read_text(encoding="utf-8"):
        errors.append("index.html: missing Simplified Chinese landing-page link")
    if not chinese.is_file() or 'href="../"' not in chinese.read_text(encoding="utf-8"):
        errors.append("zh-CN/index.html: missing English landing-page link")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("site", nargs="?", type=Path, default=Path("_site"))
    args = parser.parse_args()
    site = args.site.resolve()
    if not site.is_dir():
        print(f"site smoke error: {site} is not a directory", file=sys.stderr)
        return 1

    errors: list[str] = []
    for relative in PAGEFIND_ASSETS:
        if not (site / relative).is_file():
            errors.append(f"{relative}: missing Pagefind output")
    metadata = [path.name for path in (site / "pagefind").glob("pagefind.*.pf_meta")]
    if not any(name.startswith("pagefind.en_") for name in metadata):
        errors.append("pagefind: missing English metadata index")
    if not any(name.startswith("pagefind.zh-cn_") for name in metadata):
        errors.append("pagefind: missing Simplified Chinese metadata index")
    check_landing_pages(site, errors)
    check_book_assets(site, errors)
    checked, languages = check_links(site, errors)
    if languages.get("en", 0) == 0 or languages.get("zh-CN", 0) == 0:
        errors.append(f"expected both en and zh-CN HTML documents; found {languages}")

    if errors:
        for error in errors:
            print(f"site smoke error: {error}", file=sys.stderr)
        print(f"site smoke failed with {len(errors)} error(s)", file=sys.stderr)
        return 1
    print(f"site smoke passed: {checked} local references, languages={languages}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
