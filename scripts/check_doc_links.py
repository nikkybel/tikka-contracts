#!/usr/bin/env python3
"""
Check for broken intra-repo links and file paths in Rust doc comments.

This script scans Rust files under contracts/ for doc comments (/// and //!)
containing markdown links, backticked file paths, and backticked Rust intra-doc
links to locally defined functions. It validates that referenced local files
and function symbols exist.
"""

import os
import re
import sys
from pathlib import Path
from typing import List, Tuple

# Patterns to match links and paths in doc comments
MARKDOWN_LINK_PATTERN = re.compile(r'\[([^\]]+)\]\(([^)]+)\)')
BACKTICK_PATTERN = re.compile(r'`([^`\n]+)`')
RUST_INTRA_DOC_LINK_PATTERN = re.compile(
    r"\[`([A-Za-z_]\w*(?:::[A-Za-z_]\w*)*)`\](?!\s*\()"
)
RUST_FUNCTION_PATTERN = re.compile(
    r"^\s*(?:(?:pub(?:\([^)]*\))?|const|unsafe|async)\s+)*fn\s+([A-Za-z_]\w*)"
)
RUST_MODULE_PATTERN = re.compile(
    r"^\s*(?:(?:pub(?:\([^)]*\))?)\s+)?mod\s+([A-Za-z_]\w*)\s*;"
)

# Directories to skip
SKIP_DIRS = {
    "target",
    ".git",
    "node_modules",
}

# Directories to scan for Rust source files
SCAN_DIRS = [
    "contracts",
]


def is_file_reference(val: str) -> bool:
    """Determine if a backticked string looks like an intra-repo file or directory path."""
    val = val.strip()
    # Exclude code snippets, commands, or expressions with spaces
    if " " in val or "\t" in val:
        return False
    # Common code patterns that might contain slashes or dots
    if any(val.startswith(p) for p in ("http://", "https://", "crate::", "super::")):
        return False
    # Check for file extensions or known directory prefixes
    if val.endswith(".rs") or val.endswith(".md"):
        return True
    if any(val.startswith(prefix) for prefix in ("docs/", "contracts/", "oracle/", "../")):
        return True
    return False


def check_doc_links(repo_root: Path) -> List[Tuple[Path, int, str, str]]:
    """Scan Rust files and find broken file links in doc comments.

    Returns a list of tuples: (file_path, line_number, link_text, target)
    """
    broken_links = []
    rust_functions = set()
    rust_modules = set()

    for scan_dir in SCAN_DIRS:
        scan_path = repo_root / scan_dir
        if not scan_path.exists():
            continue

        for root, dirs, files in os.walk(scan_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for file in files:
                if not file.endswith(".rs"):
                    continue

                file_path = Path(root) / file
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        for line in f:
                            match = RUST_FUNCTION_PATTERN.match(line)
                            if match:
                                rust_functions.add(match.group(1))
                            match = RUST_MODULE_PATTERN.match(line)
                            if match:
                                rust_modules.add(match.group(1))
                except Exception as e:
                    print(f"Warning: Could not read {file_path}: {e}", file=sys.stderr)

    for scan_dir in SCAN_DIRS:
        scan_path = repo_root / scan_dir
        if not scan_path.exists():
            continue

        for root, dirs, files in os.walk(scan_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for file in files:
                if not file.endswith(".rs"):
                    continue

                file_path = Path(root) / file
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        lines = f.readlines()
                except Exception as e:
                    print(f"Warning: Could not read {file_path}: {e}", file=sys.stderr)
                    continue

                for line_idx, line in enumerate(lines, start=1):
                    line_str = line.strip()
                    # Only inspect doc comments
                    if not (line_str.startswith("///") or line_str.startswith("//!")):
                        continue

                    # Resolve bare Rust intra-doc links to locally defined
                    # functions. Markdown links with explicit destinations
                    # and links into external crates are handled separately.
                    for m in RUST_INTRA_DOC_LINK_PATTERN.finditer(line_str):
                        target = m.group(1)
                        parts = target.split("::")
                        leaf = parts[-1]
                        is_local = (
                            len(parts) == 1
                            or parts[0] in {"crate", "self", "super", "Self"}
                            or parts[0] in rust_modules
                        )
                        if is_local and leaf[0].islower() and leaf not in rust_functions:
                            broken_links.append((file_path, line_idx, target, target))

                    targets_to_check = []

                    # 1. Check markdown links: [label](target)
                    for m in MARKDOWN_LINK_PATTERN.finditer(line_str):
                        label = m.group(1).strip()
                        target = m.group(2).strip()

                        # Skip external URLs, intra-doc Rust links, and pure anchors
                        if target.startswith(("http://", "https://", "mailto:", "#")):
                            continue
                        if target.startswith(("crate::", "super::")) or "::" in target:
                            continue

                        targets_to_check.append((label, target))

                    # 2. Check backticked file path references: `path`
                    for m in BACKTICK_PATTERN.finditer(line_str):
                        val = m.group(1).strip()
                        if is_file_reference(val):
                            targets_to_check.append((val, val))

                    # Validate each target
                    for label, raw_target in targets_to_check:
                        # Strip URL fragment / anchor if present
                        clean_target = raw_target.split("#")[0].strip()
                        if not clean_target:
                            continue

                        # Check relative to file location
                        target_path = Path(clean_target)
                        resolved_from_file = (file_path.parent / target_path).resolve()

                        # Check relative to repo root
                        resolved_from_root = (repo_root / target_path).resolve()

                        exists_from_file = resolved_from_file.exists()
                        exists_from_root = resolved_from_root.exists()

                        if not (exists_from_file or exists_from_root):
                            broken_links.append((file_path, line_idx, label, raw_target))

    return broken_links


def main():
    repo_root = Path(__file__).resolve().parent.parent

    print(f"Checking doc comments in {repo_root} for broken intra-repo file links...")
    broken = check_doc_links(repo_root)

    if broken:
        print(f"\nERROR: Found {len(broken)} broken link(s) in doc comments:\n", file=sys.stderr)
        for file_path, line_no, label, target in broken:
            rel_file = file_path.relative_to(repo_root)
            print(f"  {rel_file}:{line_no}: target '{target}' does not exist (link text: '{label}')", file=sys.stderr)
        sys.exit(1)

    print("OK: All intra-repo links and file paths in doc comments are valid.")
    sys.exit(0)


if __name__ == "__main__":
    main()
