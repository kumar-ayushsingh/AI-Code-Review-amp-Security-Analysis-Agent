"""
detectors/duplicate_code.py
----------------------------
Detects duplicate and structurally similar code blocks.

Two detection passes are used:

Pass 1 — Token-fingerprint clones (both Python and Java)
---------------------------------------------------------
Normalises source lines (strip comments, replace string literals, collapse
whitespace), then builds rolling MD5 fingerprints over sliding windows.
Buckets with 2+ entries that share the same fingerprint are reported.
This catches *exact* and *near-exact* clones (Type-1 / Type-2 by text).

Pass 2 — AST structural clones (Python only)
--------------------------------------------
For each top-level function or method in the file, we walk its AST and
generate a *structural fingerprint*: a sequence of AST node type names
(e.g. ``"If|For|Assign|Return"``), ignoring all identifier names and
literal values.  Two functions that share the same structural fingerprint
have identical control-flow skeletons even if every variable name and
constant is different.  This catches copy-paste-and-rename clones that
the token pass misses (Type-3 structural clones).

The structural pass is deliberately coarser: it compares whole functions,
not sliding windows, and only triggers when two functions have ≥ 10
structural nodes in their fingerprint (trivial one-liners are excluded).

Severity scale — token pass
---------------------------
- critical : duplicated block ≥ 20 lines
- high     : duplicated block ≥ 15 lines
- medium   : duplicated block ≥ 10 lines
- low      : duplicated block ≥  6 lines  (default threshold)

Severity — structural AST pass
-------------------------------
- high   : structural fingerprint with ≥ 30 nodes
- medium : structural fingerprint with ≥ 20 nodes
- low    : structural fingerprint with ≥ 10 nodes
"""

from __future__ import annotations

import ast
import hashlib
import re
from collections import defaultdict
from typing import List, Tuple

from ..models import Finding, Severity, SmellType


# ──────────────────────────────────────────────────────────────────────────────
# Pass 1: Token-fingerprint clones (Python + Java)
# ──────────────────────────────────────────────────────────────────────────────

_PYTHON_COMMENT = re.compile(r"#.*$")
_JAVA_COMMENT_INLINE = re.compile(r"//.*$")
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_STRING_LITERAL = re.compile(r'("(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\')')


def _canonicalise(lines: List[str], language: str) -> List[str]:
    """Normalise source lines to stripped, comment-free, literal-free strings."""
    source = "\n".join(lines)
    if language == "java":
        source = _BLOCK_COMMENT.sub("", source)

    canonical: List[str] = []
    for line in source.splitlines():
        if language == "python":
            line = _PYTHON_COMMENT.sub("", line)
        else:
            line = _JAVA_COMMENT_INLINE.sub("", line)
        line = _STRING_LITERAL.sub('"STR"', line)
        line = " ".join(line.split())
        canonical.append(line)
    return canonical


def _window_fingerprint(window: List[str]) -> str:
    return hashlib.md5("\n".join(window).encode()).hexdigest()  # noqa: S324


def _token_clone_severity(block_size: int) -> Severity:
    if block_size >= 20:
        return Severity.CRITICAL
    if block_size >= 15:
        return Severity.HIGH
    if block_size >= 10:
        return Severity.MEDIUM
    return Severity.LOW


def _detect_token_clones(
    lines: List[str], language: str, min_block_lines: int
) -> List[Finding]:
    """Sliding-window MD5 fingerprint clone detection."""
    canonical = _canonicalise(lines, language)
    n = len(canonical)
    if n < min_block_lines:
        return []

    buckets: dict[str, List[Tuple[int, List[str]]]] = defaultdict(list)
    for i in range(n - min_block_lines + 1):
        window = canonical[i : i + min_block_lines]
        non_blank = [ln for ln in window if ln.strip()]
        if len(non_blank) < min_block_lines // 2:
            continue
        fp = _window_fingerprint(window)
        buckets[fp].append((i, window))

    findings: List[Finding] = []
    reported: set[Tuple[int, int]] = set()

    for fp, occurrences in buckets.items():
        if len(occurrences) < 2:
            continue
        ref_start, _ = occurrences[0]
        for dup_start, _ in occurrences[1:]:
            key = (min(ref_start, dup_start), max(ref_start, dup_start))
            if key in reported:
                continue
            reported.add(key)

            ref_line = ref_start + 1
            dup_line = dup_start + 1
            sev = _token_clone_severity(min_block_lines)
            findings.append(Finding(
                type=SmellType.DUPLICATE_CODE,
                severity=sev,
                line_number=ref_line,
                description=(
                    f"Duplicate block of {min_block_lines}+ lines found at "
                    f"lines {ref_line}-{ref_line + min_block_lines - 1} and "
                    f"{dup_line}-{dup_line + min_block_lines - 1}. "
                    f"Extract shared logic into a reusable function/method."
                ),
                extra={
                    "clone_type": "token",
                    "clone_a_start": ref_line,
                    "clone_a_end": ref_line + min_block_lines - 1,
                    "clone_b_start": dup_line,
                    "clone_b_end": dup_line + min_block_lines - 1,
                    "block_size": min_block_lines,
                },
            ))

    findings.sort(key=lambda f: f.line_number)
    return findings


# ──────────────────────────────────────────────────────────────────────────────
# Pass 2: AST structural clone detection (Python only)
# ──────────────────────────────────────────────────────────────────────────────

def _structural_fingerprint(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    """
    Walk the entire AST subtree of *func_node* and build a string that
    captures only the *structure* of the function — the sequence of AST
    node type names encountered in depth-first order.

    By using only ``type(node).__name__`` we ignore:
      - All identifier names (variable names, function names, etc.)
      - All literal values (numbers, strings, booleans)
      - Whitespace and formatting

    Two functions that share the same structural fingerprint have identical
    control-flow skeletons regardless of the names/values they use.
    """
    parts: List[str] = []
    for node in ast.walk(func_node):
        # Skip the function header itself; only care about body structure.
        # Also skip trivial leaf expression types to reduce noise.
        node_type = type(node).__name__
        if node_type in ("Load", "Store", "Del", "Add", "Sub", "Mult",
                         "Div", "FloorDiv", "Mod", "Pow", "LShift", "RShift",
                         "BitOr", "BitXor", "BitAnd", "MatMult",
                         "Invert", "Not", "UAdd", "USub",
                         "Eq", "NotEq", "Lt", "LtE", "Gt", "GtE",
                         "Is", "IsNot", "In", "NotIn",
                         "And", "Or", "arguments"):
            continue
        parts.append(node_type)

    return "|".join(parts)


def _structural_severity(node_count: int) -> Severity | None:
    if node_count >= 30:
        return Severity.HIGH
    if node_count >= 20:
        return Severity.MEDIUM
    if node_count >= 10:
        return Severity.LOW
    return None  # too trivial to report


def _detect_structural_clones(lines: List[str]) -> List[Finding]:
    """
    Parse the source, walk to every top-level function or class method,
    compute a structural fingerprint from each function's AST, and report
    pairs that share the same fingerprint.

    Only functions with ≥ 10 structural AST nodes are considered, to
    avoid false positives from trivial one-liners.
    """
    source = "\n".join(lines)
    findings: List[Finding] = []

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return findings

    # Collect all function defs with their fingerprints and line numbers
    # using ast.walk so we find methods inside classes too.
    functions: List[Tuple[str, int, str, int]] = []
    # (name, lineno, fingerprint, node_count)

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        fp = _structural_fingerprint(node)
        node_count = fp.count("|") + 1 if fp else 0

        sev = _structural_severity(node_count)
        if sev is None:
            continue  # too simple to bother

        functions.append((node.name, node.lineno, fp, node_count))

    # Group by fingerprint
    by_fp: dict[str, List[Tuple[str, int, int]]] = defaultdict(list)
    for name, lineno, fp, node_count in functions:
        by_fp[fp].append((name, lineno, node_count))

    reported_pairs: set[Tuple[int, int]] = set()

    for fp, entries in by_fp.items():
        if len(entries) < 2:
            continue

        # Report each unique pair once
        for i in range(len(entries)):
            for j in range(i + 1, len(entries)):
                name_a, line_a, node_count = entries[i]
                name_b, line_b, _ = entries[j]

                pair_key = (min(line_a, line_b), max(line_a, line_b))
                if pair_key in reported_pairs:
                    continue
                reported_pairs.add(pair_key)

                sev = _structural_severity(node_count)
                if sev is None:
                    continue

                findings.append(Finding(
                    type=SmellType.DUPLICATE_CODE,
                    severity=sev,
                    line_number=min(line_a, line_b),
                    description=(
                        f"Functions '{name_a}' (line {line_a}) and '{name_b}' "
                        f"(line {line_b}) share an identical AST structure "
                        f"({node_count} structural nodes). They likely implement "
                        f"the same algorithm with different variable names. "
                        f"Merge or extract the shared logic."
                    ),
                    extra={
                        "clone_type": "structural_ast",
                        "function_a": name_a,
                        "function_a_line": line_a,
                        "function_b": name_b,
                        "function_b_line": line_b,
                        "structural_node_count": node_count,
                    },
                ))

    findings.sort(key=lambda f: f.line_number)
    return findings


# ──────────────────────────────────────────────────────────────────────────────
# Public entry point
# ──────────────────────────────────────────────────────────────────────────────

def detect(
    lines: List[str],
    language: str,
    min_block_lines: int = 6,
) -> List[Finding]:
    """
    Detect duplicate code blocks.

    For Python: runs both the token-fingerprint pass and the AST structural
    clone pass.  For Java: runs only the token-fingerprint pass.

    Parameters
    ----------
    lines          : Source lines.
    language       : "python" or "java".
    min_block_lines: Minimum consecutive lines for the token-clone pass (default 6).
    """
    findings = _detect_token_clones(lines, language, min_block_lines)

    if language == "python":
        findings += _detect_structural_clones(lines)
        findings.sort(key=lambda f: f.line_number)

    return findings
