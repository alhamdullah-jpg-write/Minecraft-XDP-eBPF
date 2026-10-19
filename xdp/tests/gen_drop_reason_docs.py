#!/usr/bin/env python3
"""Regenerates the generated tables inside docs/drop-reasons.md.

`xdp/stats.h` is the single source of truth for the drop-reason ABI: it
defines the enum, and `build.rs` turns the same enum into the Rust label list
for the `minecraft_drop_reason` metric (so the C side and the metric can never
drift apart). This script derives two tables from that enum:

  * the *registry*: every value with its stable name and description, and
  * the *emitted set*: the reasons some code path in xdp/ actually assigns,
    which is computed mechanically - a reason counts as emitted when its name
    appears anywhere under xdp/ except the enum definition itself. Anything
    else is reserved: documented and stable, but no counter will ever move for
    it in this build, so a zero value does not prove the traffic was absent.

Usage:
    python3 xdp/tests/gen_drop_reason_docs.py [--check]

--check exits non-zero when the file is stale (useful from CI or a hook);
without it the two generated regions are rewritten in place.
"""

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HEADER = ROOT / "xdp" / "stats.h"
DOC = ROOT / "docs" / "drop-reasons.md"

BEGIN_REGISTRY = "<!-- BEGIN GENERATED: registry (edit xdp/stats.h, then run xdp/tests/gen_drop_reason_docs.py) -->"
END_REGISTRY = "<!-- END GENERATED: registry -->"
BEGIN_EMITTED = "<!-- BEGIN GENERATED: emitted (edit xdp/stats.h, then run xdp/tests/gen_drop_reason_docs.py) -->"
END_EMITTED = "<!-- END GENERATED: emitted -->"

ENUM_RE = re.compile(r"enum\s+drop_reason\s*\{(.*?)\n\};", re.DOTALL)
ENTRY_RE = re.compile(
    r"^\s*(DROP_[A-Z0-9_]+)\s*=\s*(\d+)\s*,\s*(?://[ \t]*(.*))?$", re.MULTILINE
)
REGISTRY_RE = re.compile(r"^#(\d+)\s+(.*)$")


def parse_enum() -> list[tuple[int, str, str]]:
    """Returns [(value, name, description)] in enum order."""
    text = HEADER.read_text()
    match = ENUM_RE.search(text)
    if not match:
        sys.exit(f"error: no 'enum drop_reason' block found in {HEADER}")
    entries = []
    for name, value, comment in ENTRY_RE.findall(match.group(1)):
        entries.append((int(value), name, (comment or "").strip()))
    if not entries:
        sys.exit(f"error: no enum entries parsed from {HEADER}")
    values = [value for value, _, _ in entries]
    if values != list(range(len(values))):
        sys.exit("error: enum values are not contiguous from 0; fix xdp/stats.h")
    return entries


def parse_registry_number(description: str) -> tuple[str, str]:
    """Splits '#195 packet rate limit exceeded' into ('195', 'packet rate...')."""
    match = REGISTRY_RE.match(description)
    if match:
        return match.group(1), match.group(2)
    return "", description


def referenced_in_code() -> dict[str, list[str]]:
    """Maps every DROP_* name to the compiled xdp/ sources that reference it.

    Only the kernel sources at the top level of xdp/ count: header/source
    files under xdp/tests/ are host-side test programs, and a mention there
    cannot move a kernel counter.
    """
    references: dict[str, list[str]] = {}
    for path in sorted((ROOT / "xdp").rglob("*")):
        if not path.is_file() or path.suffix not in (".c", ".h"):
            continue
        if "tests" in path.parts:
            continue  # host tests reference names, they do not emit
        if path.name == "stats.h":
            continue  # the definition itself does not count as a use
        text = path.read_text(errors="replace")
        for name in set(re.findall(r"\bDROP_[A-Z0-9_]+\b", text)):
            references.setdefault(name, []).append(str(path.relative_to(ROOT)))
    return references


def escape(text: str) -> str:
    # table cells: the descriptions are plain text, but a pipe would break a row
    return text.replace("|", "\\|")


def build_registry_table(entries, references) -> str:
    lines = [
        "| Value | Registry | Name (`minecraft_drop_reason{reason=...}`) | Meaning | Referenced by |",
        "|---|---|---|---|---|",
    ]
    for value, name, description in entries:
        number, meaning = parse_registry_number(description)
        label = name.removeprefix("DROP_").lower()
        used = ", ".join(f"`{path}`" for path in references.get(name, []))
        lines.append(
            f"| {value} | {number} | `{label}` | {escape(meaning)} | {used or '—'} |"
        )
    return "\n".join(lines) + "\n"


def build_emitted_table(entries, references) -> str:
    emitted = [entry for entry in entries if references.get(entry[1])]
    lines = [
        "| Value | Name (`minecraft_drop_reason{reason=...}`) | Meaning | Emitted by |",
        "|---|---|---|---|",
    ]
    for value, name, description in emitted:
        _, meaning = parse_registry_number(description)
        label = name.removeprefix("DROP_").lower()
        used = ", ".join(f"`{path}`" for path in references[name])
        lines.append(f"| {value} | `{label}` | {escape(meaning)} | {used} |")
    return "\n".join(lines) + "\n"


def replace_region(text: str, begin: str, end: str, body: str) -> str:
    start = text.find(begin)
    stop = text.find(end)
    if start < 0 or stop < 0 or stop < start:
        sys.exit(f"error: markers not found in {DOC}: {begin}")
    return text[: start + len(begin)] + "\n\n" + body + "\n" + text[stop:]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail when stale")
    args = parser.parse_args()

    entries = parse_enum()
    references = referenced_in_code()
    registry = build_registry_table(entries, references)
    emitted = build_emitted_table(entries, references)

    text = DOC.read_text()
    updated = replace_region(text, BEGIN_REGISTRY, END_REGISTRY, registry)
    updated = replace_region(updated, BEGIN_EMITTED, END_EMITTED, emitted)

    emitted_count = sum(1 for _, name, _ in entries if references.get(name))
    reserved_count = len(entries) - emitted_count
    summary = (
        f"{len(entries)} documented values: {emitted_count} emitted by this "
        f"build, {reserved_count} reserved (never incremented here)"
    )

    if args.check:
        if updated != text:
            print(f"stale: {DOC} does not match xdp/stats.h ({summary})")
            return 1
        print(f"ok: {DOC} matches xdp/stats.h ({summary})")
        return 0

    DOC.write_text(updated)
    print(f"wrote {DOC} ({summary})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
