"""
detectors/high_complexity.py
-----------------------------
Two complementary AST-based complexity metrics for Python functions:

  1. **McCabe Cyclomatic Complexity (CC)**
     CC = decision_points + 1.  Counts every branching statement in the
     function's AST.  A high CC indicates many independent execution paths
     and is hard to test exhaustively.

  2. **Max Control-Flow Nesting Depth**
     The deepest level of nested control-flow blocks (if / for / while /
     with / try / except), measured by *recursively walking the AST* and
     incrementing a depth counter as we descend into each nesting node.
     This is distinct from CC: a single long if-elif chain has high CC but
     low nesting depth; deeply nested ifs have high depth but lower CC.

Both metrics produce separate Finding objects so callers can filter on
the one they care about.

Python decision points counted by the CC visitor
-------------------------------------------------
    if / elif                           +1
    for / async for                     +1
    while                               +1
    ExceptHandler (each except clause)  +1
    with (per context manager item)     +1
    assert                              +1
    BoolOp (and / or)                   +1 per extra operand
    IfExp  (ternary a if c else b)      +1
    comprehension (each for clause)     +1

Java (regex state machine — unchanged)
--------------------------------------
    if / else if / for / while / do / case / catch  +1
    && / ||                                          +1
    ?   (ternary)                                    +1

Severity scales
---------------
Cyclomatic Complexity:
    CC  1-5   → omit
    CC  6-10  → low
    CC 11-15  → medium
    CC 16-20  → high
    CC ≥ 21   → critical

Nesting Depth (Python only):
    depth 1-3 → omit
    depth 4   → low
    depth 5   → medium
    depth 6   → high
    depth ≥ 7 → critical
"""

from __future__ import annotations

import ast
import re
from typing import List

from shared.models import Finding, Severity, SmellType


# ──────────────────────────────────────────────────────────────────────────────
# Severity helpers
# ──────────────────────────────────────────────────────────────────────────────

def _cc_severity(cc: int) -> Severity | None:
    if cc <= 5:
        return None
    if cc <= 10:
        return Severity.LOW
    if cc <= 15:
        return Severity.MEDIUM
    if cc <= 20:
        return Severity.HIGH
    return Severity.CRITICAL


def _nesting_severity(depth: int) -> Severity | None:
    if depth <= 3:
        return None
    if depth == 4:
        return Severity.LOW
    if depth == 5:
        return Severity.MEDIUM
    if depth == 6:
        return Severity.HIGH
    return Severity.CRITICAL


# ──────────────────────────────────────────────────────────────────────────────
# AST Visitor 1: Cyclomatic Complexity
# ──────────────────────────────────────────────────────────────────────────────

class _CCVisitor(ast.NodeVisitor):
    """
    Walks a function's AST subtree and accumulates decision points.

    Uses ``generic_visit`` to recurse into each node after counting it,
    so nested functions / classes inside the target function are also
    counted (they share the enclosing function's complexity budget).
    """

    def __init__(self) -> None:
        self.count: int = 1  # baseline: one linear path

    def visit_If(self, node: ast.If) -> None:
        self.count += 1
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        self.count += 1
        self.generic_visit(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self.count += 1
        self.generic_visit(node)

    def visit_While(self, node: ast.While) -> None:
        self.count += 1
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        self.count += 1
        self.generic_visit(node)

    def visit_With(self, node: ast.With) -> None:
        # Each context-manager item in `with A(), B():` is a separate path
        self.count += len(node.items)
        self.generic_visit(node)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        self.count += len(node.items)
        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert) -> None:
        self.count += 1
        self.generic_visit(node)

    def visit_BoolOp(self, node: ast.BoolOp) -> None:
        # `a and b and c` → 2 extra paths (len(values) - 1)
        self.count += len(node.values) - 1
        self.generic_visit(node)

    def visit_IfExp(self, node: ast.IfExp) -> None:
        # Ternary: `x if cond else y`
        self.count += 1
        self.generic_visit(node)

    def visit_comprehension(self, node: ast.comprehension) -> None:
        # Each `for` clause in a comprehension / generator
        self.count += 1
        self.generic_visit(node)


# ──────────────────────────────────────────────────────────────────────────────
# AST Visitor 2: Maximum Nesting Depth
# ──────────────────────────────────────────────────────────────────────────────

# Node types that begin a new nesting level
_NESTING_NODE_TYPES = (
    ast.If,
    ast.For,
    ast.AsyncFor,
    ast.While,
    ast.With,
    ast.AsyncWith,
    ast.Try,
    ast.ExceptHandler,
    # Python 3.11+ exception groups
    *(getattr(ast, "TryStar", ()),),
)


def _compute_max_nesting_depth(root: ast.AST, _depth: int = 0) -> int:
    """
    Recursively walk *root*'s AST children and return the maximum
    control-flow nesting depth encountered.

    *_depth* is the nesting level of *root* itself. We pass it along
    explicitly so that each recursive call knows how deep it is — this
    is the correct way to measure depth in a tree and cannot be replicated
    with a flat ``ast.walk`` iterator.

    The function increments *_depth* before recursing into a nesting node,
    then lets the stack unwind naturally, so sibling branches each see the
    correct base depth (no global state needed).
    """
    max_depth = _depth
    for child in ast.iter_child_nodes(root):
        if isinstance(child, _NESTING_NODE_TYPES):
            child_max = _compute_max_nesting_depth(child, _depth + 1)
        else:
            child_max = _compute_max_nesting_depth(child, _depth)
        if child_max > max_depth:
            max_depth = child_max
    return max_depth


# ──────────────────────────────────────────────────────────────────────────────
# Python detector — walks the AST once per function
# ──────────────────────────────────────────────────────────────────────────────

def _detect_python(lines: List[str]) -> List[Finding]:
    """
    Parse source into an AST, walk to every function definition, and
    apply both the CC visitor and the nesting-depth recursion.
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

        # ── Cyclomatic Complexity ────────────────────────────────────────
        cc_visitor = _CCVisitor()
        cc_visitor.visit(node)
        cc = cc_visitor.count

        cc_sev = _cc_severity(cc)
        if cc_sev is not None:
            findings.append(Finding(
                type=SmellType.HIGH_COMPLEXITY,
                severity=cc_sev,
                line_number=node.lineno,
                symbol=node.name,
                source_agent="code_analysis",
                    description=(
                    f"Function '{node.name}' has cyclomatic complexity {cc} "
                    f"(threshold: 5). "
                    f"{'Critical: extremely difficult to test exhaustively. ' if cc >= 21 else ''}"
                    f"Decompose into smaller, single-responsibility functions "
                    f"targeting CC <= 10."
                ),
                extra={"cyclomatic_complexity": cc, "metric": "cc"},
            ))

        # ── Max Nesting Depth ────────────────────────────────────────────
        # We recurse from the function node with depth=0 so that top-level
        # statements inside the function body register at depth 1.
        max_depth = _compute_max_nesting_depth(node, _depth=0)

        depth_sev = _nesting_severity(max_depth)
        if depth_sev is not None:
            findings.append(Finding(
                type=SmellType.HIGH_COMPLEXITY,
                severity=depth_sev,
                line_number=node.lineno,
                symbol=node.name,
                source_agent="code_analysis",
                    description=(
                    f"Function '{node.name}' has a maximum control-flow nesting "
                    f"depth of {max_depth} (threshold: 3). "
                    f"Deeply nested code is hard to read and test. "
                    f"Apply early returns, guard clauses, or extract inner blocks "
                    f"into helper functions."
                ),
                extra={"max_nesting_depth": max_depth, "metric": "nesting_depth"},
            ))

    return findings


# ──────────────────────────────────────────────────────────────────────────────
# Java: regex-based CC counter (unchanged — no AST available)
# ──────────────────────────────────────────────────────────────────────────────

_JAVA_DECISION_PATTERNS = [
    re.compile(r"\bif\s*\("),
    re.compile(r"\belse\s+if\s*\("),
    re.compile(r"\bfor\s*\("),
    re.compile(r"\bwhile\s*\("),
    re.compile(r"\bdo\s*\{"),
    re.compile(r"\bcase\s+\w"),
    re.compile(r"\bcatch\s*\("),
    re.compile(r"\?"),
]

_JAVA_BOOL_OP = re.compile(r"&&|\|\|")

_JAVA_METHOD_START = re.compile(
    r"^\s*(?:(?:public|private|protected|static|final|synchronized|abstract|"
    r"native|default|override|transient|volatile)\s+)*"
    r"(?:[\w<>\[\],\s]+?)\s+(\w+)\s*\([^)]*\)\s*(?:throws\s+[\w,\s]+)?\s*\{",
)

_SKIP_KEYWORDS = frozenset(
    ["if", "for", "while", "switch", "try", "catch", "finally",
     "do", "else", "new", "return", "synchronized", "static"]
)


def _detect_java(lines: List[str]) -> List[Finding]:
    findings: List[Finding] = []

    in_method = False
    method_name = ""
    method_start_line = 0
    brace_depth = 0
    method_brace_entry_depth = 0
    cc = 1

    for line_no, raw in enumerate(lines, start=1):
        line = raw.strip()

        if not in_method:
            m = _JAVA_METHOD_START.match(raw)
            if m and m.group(1) not in _SKIP_KEYWORDS:
                in_method = True
                method_name = m.group(1)
                method_start_line = line_no
                cc = 1
                brace_depth += line.count("{") - line.count("}")
                method_brace_entry_depth = brace_depth
            else:
                brace_depth += line.count("{") - line.count("}")
            continue

        for pat in _JAVA_DECISION_PATTERNS:
            cc += len(pat.findall(line))
        cc += len(_JAVA_BOOL_OP.findall(line))

        brace_depth += line.count("{") - line.count("}")

        if brace_depth <= method_brace_entry_depth - 1:
            sev = _cc_severity(cc)
            if sev is not None:
                findings.append(Finding(
                    type=SmellType.HIGH_COMPLEXITY,
                    severity=sev,
                    line_number=method_start_line,
                    symbol=method_name,
                    source_agent="code_analysis",
                    description=(
                        f"Method '{method_name}' has cyclomatic complexity {cc}. "
                        f"{'Critical: extremely difficult to test exhaustively. ' if cc >= 21 else ''}"
                        f"Decompose into smaller, single-responsibility methods "
                        f"targeting CC <= 10."
                    ),
                    extra={"cyclomatic_complexity": cc, "metric": "cc"},
                ))
            in_method = False
            method_name = ""
            cc = 1

    return findings


# ──────────────────────────────────────────────────────────────────────────────
# Public entry point
# ──────────────────────────────────────────────────────────────────────────────

def detect(lines: List[str], language: str) -> List[Finding]:
    """
    Detect high cyclomatic complexity and deep nesting in *lines*.

    For Python, both CC and nesting depth are measured by walking the AST.
    For Java, only CC is measured (regex-based; no AST available).
    """
    if language == "python":
        return _detect_python(lines)
    if language == "java":
        return _detect_java(lines)
    return []
