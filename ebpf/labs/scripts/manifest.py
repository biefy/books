#!/usr/bin/env python3
"""Query and validate the Practical eBPF lab manifest."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

LABS = Path(__file__).resolve().parents[1]
BOOK = LABS.parent / "src"
MANIFEST = LABS / "manifest.json"
SUMMARY = BOOK / "SUMMARY.md"
DAY_RE = re.compile(r"\((day\d+(?:-\d+)?\.md)\)")
INCLUDE_RE = re.compile(r"\{\{#include\s+\.\./labs/([^}:]+)(?::[^}]+)?\}\}")
VALID_BACKENDS = {
    "standalone",
    "standalone-object",
    "kernel-selftest",
    "kernel-derivative",
    "sched-ext-upstream",
    "sched-ext-derivative",
}


def load_manifest() -> dict[str, Any]:
    try:
        with MANIFEST.open(encoding="utf-8") as stream:
            data = json.load(stream)
    except (OSError, json.JSONDecodeError) as error:
        raise SystemExit(f"manifest: cannot read {MANIFEST}: {error}") from error
    if data.get("schema") != 1 or not isinstance(data.get("labs"), list):
        raise SystemExit("manifest: expected schema 1 and a labs array")
    return data


def entries(data: dict[str, Any]) -> list[dict[str, Any]]:
    return data["labs"]


def published_days() -> list[str]:
    return [Path(match).stem for match in DAY_RE.findall(SUMMARY.read_text(encoding="utf-8"))]


def fail(errors: list[str], message: str) -> None:
    errors.append(message)


def validate(data: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    labs = entries(data)
    ids = [entry.get("id") for entry in labs]
    published = published_days()

    if len(ids) != len(set(ids)):
        duplicates = sorted({day for day in ids if ids.count(day) > 1})
        fail(errors, f"duplicate manifest ids: {', '.join(duplicates)}")
    missing = sorted(set(published) - set(ids))
    extra = sorted(set(ids) - set(published))
    if missing:
        fail(errors, f"published days missing from manifest: {', '.join(missing)}")
    if extra:
        fail(errors, f"manifest days absent from SUMMARY.md: {', '.join(extra)}")
    if ids != published:
        fail(errors, "manifest order must match ebpf/src/SUMMARY.md")

    for entry in labs:
        day = entry.get("id", "<missing-id>")
        chapter_name = entry.get("chapter")
        backend = entry.get("backend")
        sources = entry.get("sources")
        book_sources = entry.get("book_sources")

        if chapter_name != f"{day}.md":
            fail(errors, f"{day}: chapter must be {day}.md")
            continue
        chapter = BOOK / chapter_name
        if not chapter.is_file():
            fail(errors, f"{day}: missing chapter {chapter.relative_to(BOOK.parent)}")
            continue
        if backend not in VALID_BACKENDS:
            fail(errors, f"{day}: unknown backend {backend!r}")
        if not isinstance(sources, list) or not sources:
            fail(errors, f"{day}: sources must be a non-empty list")
            sources = []
        if not isinstance(book_sources, list) or not book_sources:
            fail(errors, f"{day}: book_sources must be a non-empty list")
            book_sources = []

        source_set = set(sources)
        if not set(book_sources).issubset(source_set):
            fail(errors, f"{day}: every book_sources entry must also be in sources")

        for relative in sources:
            path = LABS / relative
            if not path.is_file():
                fail(errors, f"{day}: missing declared source {relative}")

        chapter_includes = set(INCLUDE_RE.findall(chapter.read_text(encoding="utf-8")))
        for relative in book_sources:
            if relative not in chapter_includes:
                fail(errors, f"{day}: chapter does not include declared book source {relative}")

        if backend == "standalone":
            programs = entry.get("apps")
            required_suffixes = (".bpf.c", ".c")
            label = "app"
        elif backend == "standalone-object":
            programs = entry.get("objects")
            required_suffixes = (".bpf.c",)
            label = "object"
        else:
            programs = None
            required_suffixes = ()
            label = "program"
            if not entry.get("target"):
                fail(errors, f"{day}: {backend} backend requires an upstream/build target")

        if backend in {"standalone", "standalone-object"}:
            if not isinstance(programs, list) or not programs:
                fail(errors, f"{day}: {backend} backend requires {label}s")
                programs = []
            for program in programs:
                if not isinstance(program, str) or not program.startswith(f"{day}/"):
                    fail(errors, f"{day}: invalid {label} path {program!r}")
                    continue
                for suffix in required_suffixes:
                    relative = f"{program}{suffix}"
                    if relative not in source_set:
                        fail(errors, f"{day}: {label} {program} does not declare {relative}")

        tools = entry.get("tools", [])
        if not isinstance(tools, list):
            fail(errors, f"{day}: tools must be a list")
            tools = []
        for tool in tools:
            if not isinstance(tool, str) or not tool.startswith(f"{day}/"):
                fail(errors, f"{day}: invalid userspace tool path {tool!r}")
                continue
            relative = f"{tool}.c"
            if relative not in source_set:
                fail(errors, f"{day}: userspace tool {tool} does not declare {relative}")

        runtime = entry.get("runtime")
        if not isinstance(runtime, dict) or "proof" not in runtime or "smoke" not in runtime:
            fail(errors, f"{day}: runtime must declare proof and smoke")

    return errors


def select(data: dict[str, Any], day: str | None, backend: str | None) -> list[dict[str, Any]]:
    result = entries(data)
    if day:
        result = [entry for entry in result if entry["id"] == day]
    if backend:
        result = [entry for entry in result if entry["backend"] == backend]
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("check")

    apps_parser = subparsers.add_parser("apps")
    apps_parser.add_argument("--day")
    apps_parser.add_argument("--backend", default="standalone")

    objects_parser = subparsers.add_parser("objects")
    objects_parser.add_argument("--day")
    objects_parser.add_argument("--backend", default="standalone-object")

    programs_parser = subparsers.add_parser("programs")
    programs_parser.add_argument("--day")
    programs_parser.add_argument("--backend")

    tools_parser = subparsers.add_parser("tools")
    tools_parser.add_argument("--day")
    tools_parser.add_argument("--backend")

    days_parser = subparsers.add_parser("days")
    days_parser.add_argument("--backend")

    sources_parser = subparsers.add_parser("sources")
    sources_parser.add_argument("--day")
    sources_parser.add_argument("--backend")

    args = parser.parse_args()
    data = load_manifest()

    if args.command == "check":
        errors = validate(data)
        for error in errors:
            print(f"manifest: {error}", file=sys.stderr)
        if errors:
            print(f"manifest: {len(errors)} check(s) failed", file=sys.stderr)
            return 1
        print(f"manifest: OK ({len(entries(data))} published lab entries)")
        return 0

    chosen = select(data, getattr(args, "day", None), getattr(args, "backend", None))
    if args.command == "apps":
        print(" ".join(app for entry in chosen for app in entry.get("apps", [])))
    elif args.command == "objects":
        print(" ".join(obj for entry in chosen for obj in entry.get("objects", [])))
    elif args.command == "programs":
        print(" ".join(
            program
            for entry in chosen
            for program in entry.get("apps", []) + entry.get("objects", [])
        ))
    elif args.command == "tools":
        print(" ".join(tool for entry in chosen for tool in entry.get("tools", [])))
    elif args.command == "days":
        print(" ".join(entry["id"] for entry in chosen))
    elif args.command == "sources":
        print(" ".join(source for entry in chosen for source in entry.get("sources", [])))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
