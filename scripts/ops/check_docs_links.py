#!/usr/bin/env python3
"""Check internal links in the documentation.

Scans every Markdown file under docs/ (plus the top-level README files) for
links to other Markdown files and to in-page anchors, and fails when a target
file or heading does not exist. External links (http/https/mailto) and
non-Markdown targets (images, historical file:// references) are ignored —
only links that are supposed to resolve inside the repository are checked.

Usage: python scripts/ops/check_docs_links.py [repo-root]
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

LINK_RE = re.compile(r"\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
HEADING_RE = re.compile(r"^#{1,6}\s+(.*)$")
HTML_ID_RE = re.compile(r"<a\s+id=\"([^\"]+)\"")


def slugify(text: str) -> str:
    text = text.strip().lower()
    text = re.sub(r"[^\w\s-]", "", text)
    text = re.sub(r"[\s]+", "-", text)
    return text


def headings_of(path: Path) -> set[str]:
    """Collects every linkable anchor: Markdown heading slugs plus explicit
    HTML anchor ids (the translated READMEs use `<a id="english-id">` above
    Vietnamese headings)."""
    slugs: set[str] = set()
    inside_fence = False
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.lstrip().startswith("```"):
            inside_fence = not inside_fence
            continue
        if inside_fence:
            continue
        match = HEADING_RE.match(line)
        if match:
            slugs.add(slugify(match.group(1)))
        for anchor in HTML_ID_RE.finditer(line):
            slugs.add(anchor.group(1))
    return slugs


def main() -> int:
    repo_root = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path.cwd()
    docs_dir = repo_root / "docs"
    targets = sorted(docs_dir.rglob("*.md"))
    for name in ("README.md", "README.vi.md", "DECISION.md", "CHANGELOG.md"):
        candidate = repo_root / name
        if candidate.exists():
            targets.append(candidate)

    anchors: dict[Path, set[str]] = {}
    for target in targets:
        anchors[target.resolve()] = headings_of(target)

    broken: list[str] = []
    for source in targets:
        text = source.read_text(encoding="utf-8", errors="replace")
        inside_fence = False
        for line_no, line in enumerate(text.splitlines(), start=1):
            if line.lstrip().startswith("```"):
                inside_fence = not inside_fence
                continue
            if inside_fence:
                continue
            for match in LINK_RE.finditer(line):
                target = match.group(1)
                if target.startswith(("http://", "https://", "mailto:", "file://")):
                    continue
                if not target.endswith(".md") and not target.startswith("#"):
                    continue
                file_part, _, anchor = target.partition("#")
                if file_part == "":
                    resolved = source.resolve()
                else:
                    resolved = (source.parent / file_part).resolve()
                if not resolved.exists():
                    broken.append(f"{source.relative_to(repo_root)}:{line_no}: broken file link -> {target}")
                    continue
                if anchor and slugify(anchor) not in anchors.get(resolved, set()):
                    broken.append(f"{source.relative_to(repo_root)}:{line_no}: broken anchor -> {target}")

    if broken:
        for entry in broken:
            print(entry)
        print(f"check_docs_links: {len(broken)} broken internal link(s)")
        return 1
    print(f"check_docs_links: {len(targets)} files, all internal links resolve")
    return 0


if __name__ == "__main__":
    sys.exit(main())
