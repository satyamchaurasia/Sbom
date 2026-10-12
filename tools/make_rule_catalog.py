"""Regenerate the rule tables from the code: docs/rule-catalog.md and section 15.4 of docs/SBOM_Fixer_Rule_Book.md.

Usage (from the repository folder, with the environment activated):

    python tools/make_rule_catalog.py

Replaces the former `sbom-fixer rules --markdown` command.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sbom_fixer.rules import RULES  # noqa: E402

START, END = "<!-- RULES:START -->", "<!-- RULES:END -->"


def table() -> str:
    rows = ["| Rule | Case | Kind | Hop | Title | Description | Fix at the source |", "|---|---|---|---|---|---|---|"]
    for r in RULES:
        hop = f"{r.hop[0]} -> {r.hop[1]}" if r.hop else ""
        cells = [r.id, r.case, r.kind, hop, r.title, r.description, r.source_fix or ""]
        rows.append("| " + " | ".join(c.replace("|", "\\|") for c in cells) + " |")
    return "\n".join(rows)


def main() -> None:
    body = table()
    catalog = ROOT / "docs" / "rule-catalog.md"
    catalog.write_text(
        "# Rule catalog\n\n"
        "Generated with `python tools/make_rule_catalog.py`. Case A = same-version repair, B = version hop, "
        "C = importer-specific. Kind: repair and sanitize run at the file's version; hop only for CycloneDX 1.8+ or with "
        "allow_downgrade; final runs once at the end; canonical writes the Checkmarx layout (last).\n\n"
        f"{len(RULES)} rules.\n\n" + body + "\n",
        encoding="utf-8", newline="\n")
    book = ROOT / "docs" / "SBOM_Fixer_Rule_Book.md"
    text = book.read_text(encoding="utf-8")
    if START in text and END in text:
        head, rest = text.split(START, 1)
        _, tail = rest.split(END, 1)
        book.write_text(f"{head}{START}\n{body}\n{END}{tail}", encoding="utf-8", newline="\n")
    print(f"{len(RULES)} rules written to {catalog.relative_to(ROOT)} and {book.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
