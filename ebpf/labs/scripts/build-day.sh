#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
DAY=${1:-}
[[ $DAY =~ ^day([0-9]{2}|28-30)$ ]] || {
    printf 'build-day: expected dayNN or day28-30, got %q\n' "$DAY" >&2
    exit 2
}

mapfile -t fields < <(python3 - "$ROOT/manifest.json" "$DAY" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    entries = json.load(stream)["labs"]
entry = next((item for item in entries if item["id"] == sys.argv[2]), None)
if entry is None:
    raise SystemExit(f"build-day: {sys.argv[2]} is not declared in the manifest")
print(entry["backend"])
print(" ".join(entry.get("apps", []) + entry.get("objects", []) + entry.get("tools", [])))
print(entry.get("build", ""))
PY
)

backend=${fields[0]}
apps=${fields[1]}
build=${fields[2]}

case $backend in
    standalone|standalone-object) "$ROOT/scripts/preflight.sh" ;;
    *) "$ROOT/scripts/preflight.sh" --kernel ;;
esac

case $backend in
    standalone|standalone-object)
        [[ -n $apps ]] || {
            printf 'build-day: %s declares no standalone programs\n' "$DAY" >&2
            exit 1
        }
        # Manifest app paths contain no whitespace by contract.
        # shellcheck disable=SC2086
        exec make -C "$ROOT" $apps
        ;;
    kernel-selftest|kernel-derivative|sched-ext-upstream|sched-ext-derivative)
        [[ -n $build && -x "$ROOT/$build" ]] || {
            printf 'build-day: %s has no executable build wrapper\n' "$DAY" >&2
            exit 1
        }
        exec "$ROOT/$build"
        ;;
    *)
        printf 'build-day: unknown backend %s for %s\n' "$backend" "$DAY" >&2
        exit 1
        ;;
esac
