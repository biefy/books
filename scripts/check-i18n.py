#!/usr/bin/env python3
"""Validate the English/Simplified Chinese mdBook localization contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from collections import Counter
from collections.abc import Iterable
from pathlib import Path

BOOKS = ("linux-net", "ebpf")
LOCALE = "zh-CN"
LOCK_VERSION = 1
DIAGRAM_SUFFIXES = {".d2", ".mmd", ".dot"}

LINK_RE = re.compile(r"(?<!!)\[[^\]]*\]\(([^)]+)\)")
IMAGE_RE = re.compile(r"!\[[^\]]*\]\(([^)]+)\)")
INCLUDE_RE = re.compile(r"\{\{#include\s+[^}]+\}\}")
INLINE_CODE_RE = re.compile(r"(?<!`)`([^`\n]+)`(?!`)")
URL_RE = re.compile(r"https?://[^\s<>`\])}]+")
HAN_RE = re.compile(r"[㐀-䶿一-鿿豈-﫿]")
LATIN_RE = re.compile(r"[A-Za-z]")
FENCE_OPEN_RE = re.compile(r"^(\s*)(`{3,}|~{3,})([^\r\n]*)$")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def source_hash(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8").replace("\r\n", "\n")


def destination(raw: str) -> str:
    """Return a Markdown inline-link destination, excluding an optional title."""
    value = raw.strip()
    if value.startswith("<") and ">" in value:
        return value[1 : value.index(">")]
    # Repository links do not contain unescaped spaces. Splitting here avoids
    # treating a translated optional title as part of the destination.
    return value.split(maxsplit=1)[0]


def logical_link_destination(value: str) -> str:
    value = destination(value)
    if value.startswith(("#", "http://", "https://", "mailto:")):
        return value
    path = value.split("#", 1)[0].split("?", 1)[0]
    parts = [part for part in Path(path).parts if part not in (".", "..", "zh-CN")]
    if parts and parts[-1] in BOOKS:
        return f"book:{parts[-1]}"
    return value


def local_markdown_destination(value: str) -> str | None:
    value = destination(value)
    if not value or value.startswith(("#", "http://", "https://", "mailto:")):
        return None
    path = value.split("#", 1)[0].split("?", 1)[0]
    return path if path.endswith(".md") else None


def summary_pages(path: Path) -> list[str]:
    return [
        item
        for raw in LINK_RE.findall(read_text(path))
        if (item := local_markdown_destination(raw)) is not None
    ]


def fenced_blocks(text: str) -> tuple[list[str], list[tuple[int, int]]]:
    """Extract complete Markdown fenced blocks and their line spans."""
    lines = text.splitlines(keepends=True)
    blocks: list[str] = []
    spans: list[tuple[int, int]] = []
    index = 0
    while index < len(lines):
        line = lines[index].rstrip("\r\n")
        match = FENCE_OPEN_RE.match(line)
        if not match:
            index += 1
            continue
        marker = match.group(2)
        close_re = re.compile(r"^\s*" + re.escape(marker[0]) + "{" + str(len(marker)) + r",}\s*$")
        start = index
        index += 1
        while index < len(lines) and not close_re.match(lines[index].rstrip("\r\n")):
            index += 1
        if index == len(lines):
            blocks.append("".join(lines[start:]))
            spans.append((start, len(lines)))
            break
        index += 1
        blocks.append("".join(lines[start:index]))
        spans.append((start, index))
    return blocks, spans


def without_fences(text: str) -> str:
    lines = text.splitlines(keepends=True)
    _, spans = fenced_blocks(text)
    hidden: set[int] = set()
    for start, end in spans:
        hidden.update(range(start, end))
    return "".join(line for index, line in enumerate(lines) if index not in hidden)


def digests(items: Iterable[str]) -> list[str]:
    return [sha256_bytes(item.encode("utf-8")) for item in items]


def image_destinations(text: str) -> list[str]:
    return [destination(item) for item in IMAGE_RE.findall(text)]


def image_stems(items: Iterable[str]) -> list[str]:
    return [Path(item.split("#", 1)[0].split("?", 1)[0]).stem for item in items]


def link_destinations(text: str) -> list[str]:
    return [destination(item) for item in LINK_RE.findall(text)]


def literal_contract(text: str) -> dict[str, list[str]]:
    outside_fences = without_fences(text)
    blocks, _ = fenced_blocks(text)
    return {
        "fenced-code digests": digests(blocks),
        "include directives": INCLUDE_RE.findall(text),
        "inline code": INLINE_CODE_RE.findall(outside_fences),
        "URLs": URL_RE.findall(outside_fences),
        "link destinations": link_destinations(outside_fences),
    }


def prose_for_han_check(text: str) -> str:
    prose = without_fences(text)
    prose = INCLUDE_RE.sub(" ", prose)
    prose = INLINE_CODE_RE.sub(" ", prose)
    prose = URL_RE.sub(" ", prose)
    prose = re.sub(r"!\[[^\]]*\]\([^)]+\)", " ", prose)
    prose = re.sub(r"\[([^\]]*)\]\([^)]+\)", r"\1", prose)
    return prose


def check_han(path: Path, text: str, errors: list[str]) -> None:
    prose = prose_for_han_check(text)
    han = len(HAN_RE.findall(prose))
    latin = len(LATIN_RE.findall(prose))
    minimum = 10 if path.name == "SUMMARY.md" else 20
    if han < minimum:
        errors.append(f"{path}: translated prose has only {han} Han characters (minimum {minimum})")
        return
    if latin and han / (han + latin) < 0.10:
        errors.append(f"{path}: translated prose is mostly Latin text ({han} Han, {latin} Latin letters)")


def tracked_diagram_sources(root: Path) -> list[Path]:
    repo = root.parents[1]
    relative = root.relative_to(repo).as_posix()
    result = subprocess.run(
        ["git", "-C", str(repo), "ls-files", "--", f"{relative}/diagrams/src/*"],
        check=True,
        capture_output=True,
        text=True,
    )
    return [repo / line for line in result.stdout.splitlines() if Path(line).suffix in DIAGRAM_SUFFIXES]


def diagram_stems(root: Path, *, tracked: bool = False) -> tuple[set[str], set[str]]:
    diagram_dir = root / "diagrams"
    source_dir = diagram_dir / "src"
    if tracked:
        sources = tracked_diagram_sources(root)
        source = {path.stem for path in sources}
        png = {
            path.stem
            for path in sources
            if (diagram_dir / f"{path.stem}.png").is_file()
        }
        return png, source
    png = {path.stem for path in diagram_dir.glob("*.png")} if diagram_dir.is_dir() else set()
    source = (
        {path.stem for path in source_dir.iterdir() if path.is_file() and path.suffix in DIAGRAM_SUFFIXES}
        if source_dir.is_dir()
        else set()
    )
    return png, source


def check_diagrams(root: Path, errors: list[str], *, tracked: bool = False) -> None:
    png, source = diagram_stems(root, tracked=tracked)
    for stem in sorted(source - png):
        errors.append(f"{root}/diagrams: source {stem!r} has no rendered PNG")
    for stem in sorted(png - source):
        errors.append(f"{root}/diagrams: PNG {stem!r} has no diagram source")


def expected_source_files(source_root: Path) -> list[str]:
    summary = source_root / "SUMMARY.md"
    if not summary.is_file():
        raise FileNotFoundError(summary)
    pages = summary_pages(summary)
    return ["SUMMARY.md", *pages]


def lock_payload(book: str, source_root: Path) -> dict[str, object]:
    files = expected_source_files(source_root)
    missing = [relative for relative in files if not (source_root / relative).is_file()]
    if missing:
        raise FileNotFoundError(f"{book}: source SUMMARY references missing files: {', '.join(missing)}")
    diagram_sources = tracked_diagram_sources(source_root)
    return {
        "version": LOCK_VERSION,
        "locale": LOCALE,
        "source": "src",
        "files": {relative: source_hash(source_root / relative) for relative in files},
        "diagrams": {
            path.relative_to(source_root).as_posix(): source_hash(path)
            for path in diagram_sources
        },
    }


def update_lock(repo: Path, book: str) -> None:
    source_root = repo / book / "src"
    lock = repo / book / "i18n" / f"{LOCALE}.lock.json"
    lock.parent.mkdir(parents=True, exist_ok=True)
    payload = lock_payload(book, source_root)
    lock.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"updated {lock.relative_to(repo)}")


def check_lock(repo: Path, book: str, errors: list[str]) -> None:
    source_root = repo / book / "src"
    lock = repo / book / "i18n" / f"{LOCALE}.lock.json"
    if not lock.is_file():
        errors.append(f"{lock}: missing; run update-lock after synchronizing translations")
        return
    try:
        actual = json.loads(lock.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        errors.append(f"{lock}: invalid JSON: {exc}")
        return
    expected = lock_payload(book, source_root)
    if actual.get("version") != LOCK_VERSION or actual.get("locale") != LOCALE or actual.get("source") != "src":
        errors.append(f"{lock}: unsupported lock metadata")
    for section in ("files", "diagrams"):
        actual_hashes = actual.get(section)
        if not isinstance(actual_hashes, dict):
            errors.append(f"{lock}: {section} must be an object")
            continue
        expected_hashes = expected[section]
        if set(actual_hashes) != set(expected_hashes):
            missing = sorted(set(expected_hashes) - set(actual_hashes))
            extra = sorted(set(actual_hashes) - set(expected_hashes))
            if missing:
                errors.append(f"{lock}: missing {section} source hashes: {', '.join(missing)}")
            if extra:
                errors.append(f"{lock}: stale {section} source hashes: {', '.join(extra)}")
        for relative in sorted(set(actual_hashes) & set(expected_hashes)):
            if actual_hashes[relative] != expected_hashes[relative]:
                errors.append(
                    f"{lock}: English source changed for {relative}; "
                    "synchronize the translation, then update-lock"
                )


def check_page(source: Path, translated: Path, errors: list[str]) -> None:
    source_text = read_text(source)
    translated_text = read_text(translated)
    source_contract = literal_contract(source_text)
    translated_contract = literal_contract(translated_text)
    for label, expected in source_contract.items():
        actual = translated_contract[label]
        if label == "inline code":
            matches = Counter(actual) == Counter(expected)
        elif label == "link destinations":
            matches = [logical_link_destination(item) for item in actual] == [
                logical_link_destination(item) for item in expected
            ]
        else:
            matches = actual == expected
        if not matches:
            errors.append(
                f"{translated}: {label} differ from {source} "
                f"(expected {len(expected)} item(s), found {len(actual)})"
            )
    source_images = image_destinations(source_text)
    translated_images = image_destinations(translated_text)
    if translated_images != source_images:
        errors.append(f"{translated}: image link destinations differ from {source}")
    if image_stems(translated_images) != image_stems(source_images):
        errors.append(f"{translated}: image stems differ from {source}")
    check_han(translated, translated_text, errors)


def check_book(repo: Path, book: str, errors: list[str]) -> None:
    source_root = repo / book / "src"
    translated_root = repo / book / f"src.{LOCALE}"
    source_summary = source_root / "SUMMARY.md"
    translated_summary = translated_root / "SUMMARY.md"

    if not translated_root.is_dir():
        errors.append(f"{translated_root}: canonical locale root is missing")
        return
    if not translated_summary.is_file():
        errors.append(f"{translated_summary}: missing translated SUMMARY")
        check_diagrams(source_root, errors, tracked=True)
        check_diagrams(translated_root, errors)
        check_lock(repo, book, errors)
        return

    source_pages = summary_pages(source_summary)
    translated_pages = summary_pages(translated_summary)
    if translated_pages != source_pages:
        errors.append(f"{translated_summary}: page destinations/order differ from {source_summary}")

    expected_markdown = {"SUMMARY.md", *source_pages}
    actual_markdown = {
        path.relative_to(translated_root).as_posix() for path in translated_root.rglob("*.md")
    }
    for relative in sorted(expected_markdown - actual_markdown):
        errors.append(f"{translated_root / relative}: translated page is missing")
    for relative in sorted(actual_markdown - expected_markdown):
        errors.append(f"{translated_root / relative}: page is not listed by the English SUMMARY")

    for relative in sorted(expected_markdown & actual_markdown):
        check_page(source_root / relative, translated_root / relative, errors)

    check_diagrams(source_root, errors, tracked=True)
    check_diagrams(translated_root, errors)
    source_png, source_diagram_sources = diagram_stems(source_root, tracked=True)
    translated_png, translated_diagram_sources = diagram_stems(translated_root)
    if translated_png != source_png:
        missing = sorted(source_png - translated_png)
        extra = sorted(translated_png - source_png)
        if missing:
            errors.append(
                f"{translated_root}/diagrams: missing localized PNG stems: {', '.join(missing)}"
            )
        if extra:
            errors.append(
                f"{translated_root}/diagrams: unexpected localized PNG stems: {', '.join(extra)}"
            )
    if translated_diagram_sources != source_diagram_sources:
        missing = sorted(source_diagram_sources - translated_diagram_sources)
        extra = sorted(translated_diagram_sources - source_diagram_sources)
        if missing:
            errors.append(
                f"{translated_root}/diagrams/src: missing localized source stems: {', '.join(missing)}"
            )
        if extra:
            errors.append(
                f"{translated_root}/diagrams/src: unexpected localized source stems: {', '.join(extra)}"
            )
    check_lock(repo, book, errors)


def check_shared_assets(repo: Path, errors: list[str]) -> None:
    names = (
        "kernel-source.css",
        "kernel-source.js",
        "lightbox.css",
        "lightbox.js",
        "language-switcher.css",
        "language-switcher.js",
        "pagefind-search.css",
        "pagefind-search.js",
    )
    for name in names:
        left = repo / "linux-net" / "src" / name
        right = repo / "ebpf" / "src" / name
        if not left.is_file() or not right.is_file():
            errors.append(f"shared asset {name}: both English source trees must contain a copy")
        elif left.read_bytes() != right.read_bytes():
            errors.append(f"shared asset {name}: book copies are not byte-identical")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=("check", "update-lock"),
        help="validate translations or refresh synchronized English source hashes",
    )
    parser.add_argument("--book", action="append", choices=BOOKS, dest="books")
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help=argparse.SUPPRESS,
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo = args.repo_root.resolve()
    books = tuple(args.books or BOOKS)
    if args.command == "update-lock":
        for book in books:
            update_lock(repo, book)
        return 0

    errors: list[str] = []
    for book in books:
        check_book(repo, book, errors)
    check_shared_assets(repo, errors)
    if errors:
        for error in errors:
            print(f"i18n error: {error}", file=sys.stderr)
        print(f"i18n check failed with {len(errors)} error(s)", file=sys.stderr)
        return 1
    print(f"i18n check passed for {', '.join(books)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
