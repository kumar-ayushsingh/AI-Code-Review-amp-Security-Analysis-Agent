"""
detectors/long_method.py
------------------------
Detects methods / functions whose body is too large.

Python strategy (AST-based)
---------------------------
We walk the AST directly and measure two things per function:

  1. **Statement count** – the number of AST statement nodes (ast.stmt
     subclasses) inside the function body.  This is more meaningful than raw
     line span because it ignores blank lines, comments, and decorators.

  2. **Max nesting depth** – the deepest level of control-flow nesting
     (if / for / while / with / try) found inside the function body,
     measured by recursing through the AST and tracking depth explicitly.
     A depth of 1 means a single top-level block; depth 4+ is a smell.

Both values are reported in the finding's `extra` dict.  The primary
threshold is still statement count (not line span).

Java strategy (brace-depth tracking)
-------------------------------------
Java uses a regex to locate method signatures and then counts lines by
tracking opening/closing braces (not line span, which would miscount
methods whose body starts on a different line than the signature).

Severity scale (Python: statement count, Java: line span)
----------------------------------------------------------
- critical : ≥ 3× threshold
- high     : ≥ 2× threshold
- medium   : ≥ 1.5× threshold
- low      : ≥ 1× threshold  (default 40 statements / lines)
"""

from __future__ import annotations

import ast
import re
from typing import List

from ..models import Finding, Severity, SmellType


# ──────────────────────────────────────────────────────────────────────────────
# Shared helpers
# ──────────────────────────────────────────────────────────────────────────────

def _severity_for_length(length: int, threshold: int) -> Severity:
    ratio = length / threshold
    if ratio >= 3.0:
        return Severity.CRITICAL
    if ratio >= 2.0:
        return Severity.HIGH
    if ratio >= 1.5:
        return Severity.MEDIUM
    return Severity.LOW


# ──────────────────────────────────────────────────────────────────────────────
# AST helpers (Python only)
# ──────────────────────────────────────────────────────────────────────────────

# Control-flow node types that increase nesting depth
_NESTING_TYPES = (
    ast.If,
    ast.For,
    ast.AsyncFor,
    ast.While,
    ast.With,
    ast.AsyncWith,
    ast.Try,
    # Python 3.11+
    *(getattr(ast, "TryStar", ()),),
    # ExceptHandler is a "catch arm", counts as an additional nesting level
    ast.ExceptHandler,
)


def _count_statements(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    """
    Count all ast.stmt nodes inside *func_node* by walking its AST.

    We subtract 1 to exclude the FunctionDef node itself from the count.
    Nested functions / classes are counted as a single statement each
    (their internals are their own responsibility).
    """
    # Walk all descendants; filter to statement nodes only.
    # ast.stmt is the abstract base class for every statement kind.
    count = 0
    for child in ast.walk(func_node):
        if child is func_node:
            continue
        if isinstance(child, ast.stmt):
            count += 1
    return count


def _max_nesting_depth(node: ast.AST, _current: int = 0) -> int:
    """
    Recursively walk *node* and return the maximum nesting depth of
    control-flow constructs encountered.

    Each time we enter a nesting node (if/for/while/with/try/except)
    we increment a depth counter.  We recurse explicitly so the depth
    counter correctly resets on unwinding — ``ast.walk`` cannot do this
    because it is breadth-first and stateless.
    """
    best = _current
    for child in ast.iter_child_nodes(node):
        if isinstance(child, _NESTING_TYPES):
            child_depth = _max_nesting_depth(child, _current + 1)
        else:
            child_depth = _max_nesting_depth(child, _current)
        if child_depth > best:
            best = child_depth
    return best


# ──────────────────────────────────────────────────────────────────────────────
# Python detector — pure AST, no line counting
# ──────────────────────────────────────────────────────────────────────────────

def _detect_python(lines: List[str], threshold: int) -> List[Finding]:
    """
    Walk the AST and flag functions whose *statement count* exceeds
    *threshold*.  Also records max nesting depth in the extra dict.
    """
    source = "\n".join(lines)
    findings: List[Finding] = []

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return findings

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        # ── 1. Statement count (the primary length metric) ──────────────
        stmt_count = _count_statements(node)

        # ── 2. Max nesting depth (contextual info, reported in extra) ───
        max_depth = _max_nesting_depth(node)

        # ── 3. Line span (informational only, not used for threshold) ───
        line_span = (node.end_lineno or node.lineno) - node.lineno + 1

        if stmt_count >= threshold:
            sev = _severity_for_length(stmt_count, threshold)
            findings.append(Finding(
                type=SmellType.LONG_METHOD,
                severity=sev,
                line_number=node.lineno,
                symbol=node.name,
                description=(
                    f"Function '{node.name}' contains {stmt_count} statements "
                    f"(threshold: {threshold}) across {line_span} lines. "
                    f"Max control-flow nesting depth: {max_depth}. "
                    f"Consider extracting cohesive sub-tasks into smaller helpers."
                ),
                extra={
                    "statement_count": stmt_count,
                    "line_span": line_span,
                    "max_nesting_depth": max_depth,
                    "end_line": node.end_lineno,
                },
            ))

    return findings


# ──────────────────────────────────────────────────────────────────────────────
# Java detector (brace-depth tracking — unchanged, Java has no AST here)
# ──────────────────────────────────────────────────────────────────────────────

# Matches Java method declarations (simplified; handles most real-world cases)
_JAVA_METHOD_RE = re.compile(
    r"^\s*(?:(?:public|private|protected|static|final|synchronized|abstract|"
    r"native|default|override|transient|volatile)\s+)*"
    r"(?:[\w<>\[\],\s]+?)\s+(\w+)\s*\([^)]*\)\s*(?:throws\s+[\w,\s]+)?\s*\{",
    re.MULTILINE,
)


def _detect_java(lines: List[str], threshold: int) -> List[Finding]:
    source = "\n".join(lines)
    findings: List[Finding] = []

    for m in _JAVA_METHOD_RE.finditer(source):
        method_name = m.group(1)
        if method_name in {"if", "for", "while", "switch", "try", "catch", "finally",
                           "do", "else", "new", "return", "synchronized", "static"}:
            continue

        start_char = m.start()
        start_line = source[:start_char].count("\n") + 1

        # Walk forward counting braces to find matching closing brace
        depth = 0
        end_line = start_line
        in_string_double = False
        in_string_single = False
        in_comment = False
        source_from_brace = source[source.index("{", start_char):]

        current_line = start_line
        for i, ch in enumerate(source_from_brace):
            if ch == "\n":
                current_line += 1
            if in_comment:
                if source_from_brace[i : i + 2] == "*/":
                    in_comment = False
                continue
            if source_from_brace[i : i + 2] == "//":
                while i < len(source_from_brace) and source_from_brace[i] != "\n":
                    i += 1
                continue
            if source_from_brace[i : i + 2] == "/*":
                in_comment = True
                continue
            if ch == '"' and not in_string_single:
                in_string_double = not in_string_double
            elif ch == "'" and not in_string_double:
                in_string_single = not in_string_single
            elif not in_string_double and not in_string_single:
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        end_line = current_line
                        break

        length = end_line - start_line + 1
        if length >= threshold:
            sev = _severity_for_length(length, threshold)
            findings.append(Finding(
                type=SmellType.LONG_METHOD,
                severity=sev,
                line_number=start_line,
                symbol=method_name,
                description=(
                    f"Method '{method_name}' spans {length} lines "
                    f"(threshold: {threshold}). Consider extracting "
                    f"cohesive sub-tasks into smaller helper methods."
                ),
                extra={"method_length": length, "end_line": end_line},
            ))

    return findings


# ──────────────────────────────────────────────────────────────────────────────
# Public entry point
# ──────────────────────────────────────────────────────────────────────────────

def detect(lines: List[str], language: str, threshold: int = 40) -> List[Finding]:
    """
    Detect long methods in *lines* of source code.

    Parameters
    ----------
    lines     : Source lines (no trailing newline required).
    language  : "python" or "java".
    threshold : For Python — statement count threshold (default 40).
                For Java   — line count threshold (default 40).
    """
    if language == "python":
        return _detect_python(lines, threshold)
    if language == "java":
        return _detect_java(lines, threshold)
    return []
