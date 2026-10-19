"""Tests for Rust intra-doc link validation in check_doc_links.py."""

from __future__ import annotations

import sys
from pathlib import Path

# Make the scripts package importable without installation.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from check_doc_links import check_doc_links  # noqa: E402


def test_bare_rust_function_link_must_resolve(tmp_path: Path) -> None:
    source_dir = tmp_path / "contracts" / "example" / "src"
    source_dir.mkdir(parents=True)
    (source_dir / "lib.rs").write_text(
        "/// Calls [`missing_function`].\n"
        "pub fn present_function() {}\n",
        encoding="utf-8",
    )

    broken = check_doc_links(tmp_path)

    assert [(label, target) for _, _, label, target in broken] == [
        ("missing_function", "missing_function")
    ]


def test_bare_rust_function_link_accepts_declared_function(tmp_path: Path) -> None:
    source_dir = tmp_path / "contracts" / "example" / "src"
    source_dir.mkdir(parents=True)
    (source_dir / "lib.rs").write_text(
        "/// Calls [`present_function`] and uses [i] in an example.\n"
        "pub fn present_function() {}\n",
        encoding="utf-8",
    )

    assert check_doc_links(tmp_path) == []