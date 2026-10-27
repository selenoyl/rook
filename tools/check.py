#!/usr/bin/env python3
"""Review checks from Rook's engineering rules that the compiler can't do.

  1. `unsafe` appears only in the low-level modules the doc allows
     (keep/src/arch, and user/src/sys.rs for the user programs), and
     UNSAFE.md lists every use: its per-file counts must match the code.
  2. The Keep stays under its line budget (10,000 lines of Rust, not
     counting blank lines and comments). The user programs and the shared
     ABI are small and separate, and don't count against it.

Usage: check.py   (run from the repository root)
"""
import os
import re
import sys

# Rust crates to check, and where each one is allowed to use `unsafe`.
CRATES = ["keep/src", "user/src", "abi/src", "crypto/src", "drawbridge/src", "vault/src"]
LOW_LEVEL = ["keep/src/arch", "user/src/sys.rs"]
# The line budget covers the Keep only.
BUDGET_DIR = "keep/src"
LINE_BUDGET = 10_000
UNSAFE_USE = re.compile(r"unsafe\s*\{|#\[unsafe\(|\bunsafe\s+(?:fn|extern|impl)\b")


def rust_files(root):
    for dirpath, _, names in os.walk(root):
        for name in sorted(names):
            if name.endswith(".rs"):
                yield os.path.join(dirpath, name)


def code_lines(path):
    """Lines of the file with line comments removed."""
    out = []
    for line in open(path, encoding="utf-8"):
        stripped = line.strip()
        if stripped.startswith("//"):
            out.append("")
            continue
        out.append(line.split("//", 1)[0] if "//" in line and '"' not in line else line)
    return out


def allowed(path):
    """Whether `path` (repo-relative) may contain unsafe."""
    return any(path == a or path.startswith(a + os.sep) for a in LOW_LEVEL)


def unsafe_counts():
    counts = {}
    for crate in CRATES:
        for path in rust_files(crate):
            n = sum(len(UNSAFE_USE.findall(line)) for line in code_lines(path))
            if n:
                counts[path] = n
    return counts


def listed_counts():
    counts = {}
    for line in open("UNSAFE.md", encoding="utf-8"):
        cells = [c.strip().strip("`") for c in line.strip().strip("|").split("|")]
        if len(cells) == 5 and cells[2].isdigit():
            counts[cells[0]] = counts.get(cells[0], 0) + int(cells[2])
    return counts


def main():
    errors = []

    found, listed = unsafe_counts(), listed_counts()
    for path, n in sorted(found.items()):
        if not allowed(path):
            errors.append(f"{path}: unsafe outside the low-level modules")
        if listed.get(path, 0) != n:
            errors.append(f"{path}: {n} unsafe uses in code, {listed.get(path, 0)} in UNSAFE.md")
    for path in sorted(set(listed) - set(found)):
        errors.append(f"{path}: listed in UNSAFE.md but has no unsafe code")

    lines = 0
    for path in rust_files(BUDGET_DIR):
        lines += sum(1 for line in code_lines(path) if line.strip())
    if lines > LINE_BUDGET:
        errors.append(f"the Keep has {lines} lines of Rust; the budget is {LINE_BUDGET}")

    total = sum(found.values())
    if errors:
        for e in errors:
            print("check:", e)
        sys.exit(1)
    print(f"check: {total} unsafe uses, all in the low-level modules and listed in UNSAFE.md")
    print(f"check: {lines} lines of Rust in the Keep (budget {LINE_BUDGET})")


if __name__ == "__main__":
    main()
