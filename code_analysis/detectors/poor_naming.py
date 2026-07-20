"""
detectors/poor_naming.py
-------------------------
Detects identifiers that hint at poor naming practices:

  • Single-letter names (excluding conventional loop variables i, j, k, x, y, z,
    e for exceptions, f for file handles, n for counts, etc.)
  • Generic / meaningless names from a configurable blocklist
    (temp, tmp, data, info, obj, foo, bar, baz, val, var, res, result,
     buf, helper, util, misc, stuff, test, myvar, flag, num, count2, etc.)
  • All-uppercase or all-numeric names (e.g. DATA, TEMP in variables)

Severity scale
--------------
- high   : single-letter name in a non-loop, non-lambda context
- medium : generic name that conveys no domain meaning
- low    : borderline case (e.g. single letter used in a comprehension)
"""

from __future__ import annotations

import ast
import re
from typing import List, Set

from shared.models import Finding, Severity, SmellType


# ──────────────────────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────────────────────

# Letters that are idiomatic in their respective contexts and should NOT be flagged
_ALLOWED_SINGLE_LETTERS: Set[str] = {
    "i", "j", "k",        # loop indices
    "x", "y", "z",        # coordinates / math
    "n", "m",             # counts / dimensions
    "e",                  # exception
    "f",                  # file handle
    "s",                  # string shorthand (common)
    "t",                  # time / type
    "v",                  # value in simple lambdas
    "_",                  # intentional throwaway
}

_GENERIC_NAMES: Set[str] = {
    "temp", "tmp", "data", "info", "obj", "object_",
    "foo", "bar", "baz", "qux",
    "val", "var", "res", "result", "retval", "ret",
    "buf", "buffer",
    "helper", "util", "utils", "misc",
    "stuff", "thing", "things",
    "test", "test1", "test2",
    "myvar", "myobj", "mylist",
    "flag", "status",
    "num", "number",
    "count2", "count3",
    "dummy", "placeholder",
    "xxx", "yyy", "zzz",
    "a", "b", "c",          # when used as variable names (not loop bodies)
    "aa", "bb", "cc",
    "p", "q",               # generic pointers
}

# Java-specific single-letter type names that ARE acceptable
_JAVA_TYPE_PARAMS: Set[str] = {"T", "E", "K", "V", "R", "N", "U", "S"}


# ──────────────────────────────────────────────────────────────────────────────
# Python detector
# ──────────────────────────────────────────────────────────────────────────────

def _is_loop_variable(node: ast.Name, tree: ast.AST) -> bool:
    """True when the Name node is the target of a for loop / comprehension."""
    for parent in ast.walk(tree):
        for field, value in ast.iter_fields(parent):
            if isinstance(value, list):
                if node in value and field in ("targets",):
                    # Check if the parent is a For loop
                    if isinstance(parent, (ast.For, ast.AsyncFor)):
                        return True
            # Comprehension targets
            if isinstance(parent, (ast.ListComp, ast.SetComp,
                                   ast.GeneratorExp, ast.DictComp)):
                for gen in getattr(parent, "generators", []):
                    if gen.target is node or (
                        isinstance(gen.target, ast.Tuple)
                        and node in ast.walk(gen.target)
                    ):
                        return True
    return False


def _check_name_python(
    name: str,
    line_no: int,
    context: str,
    is_loop: bool = False,
) -> Finding | None:
    if not name or name.startswith("_"):
        return None

    name_lower = name.lower()

    # Single-letter check
    if len(name) == 1:
        if name in _ALLOWED_SINGLE_LETTERS:
            return None
        sev = Severity.LOW if is_loop else Severity.HIGH
        return Finding(
            type=SmellType.POOR_NAMING,
            severity=sev,
            line_number=line_no,
            symbol=name,
            source_agent="code_analysis",
                    description=(
                f"Single-letter {context} name '{name}' is not self-documenting. "
                f"Use a descriptive name that reflects its purpose."
            ),
            extra={"context": context, "is_loop_var": is_loop},
        )

    # Generic name check
    if name_lower in _GENERIC_NAMES:
        return Finding(
            type=SmellType.POOR_NAMING,
            severity=Severity.MEDIUM,
            line_number=line_no,
            symbol=name,
            source_agent="code_analysis",
                    description=(
                f"Generic {context} name '{name}' conveys no domain meaning. "
                f"Replace with a name that describes the value's role."
            ),
            extra={"context": context, "matched_pattern": "generic_blocklist"},
        )

    return None


def _detect_python(lines: List[str]) -> List[Finding]:
    source = "\n".join(lines)
    findings: List[Finding] = []

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return findings

    for node in ast.walk(tree):
        # Function / method names
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            f = _check_name_python(node.name, node.lineno, "function")
            if f:
                findings.append(f)

            # Parameter names
            for arg in node.args.args + node.args.posonlyargs + node.args.kwonlyargs:
                if arg.arg in ("self", "cls"):
                    continue
                f = _check_name_python(arg.arg, arg.lineno, "parameter")
                if f:
                    findings.append(f)

        # Class names
        elif isinstance(node, ast.ClassDef):
            f = _check_name_python(node.name, node.lineno, "class")
            if f:
                findings.append(f)

        # Variable assignments
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    is_loop = _is_loop_variable(target, tree)
                    f = _check_name_python(
                        target.id, target.lineno, "variable", is_loop
                    )
                    if f:
                        findings.append(f)
                elif isinstance(target, ast.Tuple):
                    for elt in target.elts:
                        if isinstance(elt, ast.Name):
                            f = _check_name_python(
                                elt.id, elt.lineno, "variable", True
                            )
                            if f:
                                findings.append(f)

        # For loop targets
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            if isinstance(node.target, ast.Name):
                f = _check_name_python(
                    node.target.id, node.lineno, "loop variable", True
                )
                if f:
                    findings.append(f)

    # Deduplicate (same symbol + line can appear from multiple AST walks)
    seen: Set[tuple] = set()
    unique: List[Finding] = []
    for f in findings:
        key = (f.symbol, f.line_number)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return unique


# ──────────────────────────────────────────────────────────────────────────────
# Java detector (regex-based)
# ──────────────────────────────────────────────────────────────────────────────

# Matches: type varName (with optional initialiser)
_JAVA_VAR_DECL = re.compile(
    r"\b(?:int|long|double|float|boolean|String|char|byte|short|var|Object"
    r"|List|Map|Set|Queue|Deque|Collection|Iterator|Optional|"
    r"[\w<>\[\]]+)\s+([a-zA-Z_$][\w$]*)\s*(?:=|;|,|\))",
)

# Matches method declarations
_JAVA_METHOD_DECL = re.compile(
    r"\b(?:public|private|protected|static|final|synchronized|abstract|"
    r"native|default|override|transient|volatile)\s+(?:[\w<>\[\],\s]+?)\s+"
    r"([a-zA-Z_$][\w$]*)\s*\(",
)

# Matches class declarations
_JAVA_CLASS_DECL = re.compile(
    r"\b(?:public|private|protected|abstract|final|static)?\s*"
    r"(?:class|interface|enum|record)\s+([A-Za-z_$][\w$]*)",
)

_JAVA_GENERIC_BLOCKLIST = _GENERIC_NAMES | {
    "temp2", "temp3", "tmp2", "data2", "obj2", "helper2",
}


def _check_java_name(
    name: str, line_no: int, context: str
) -> Finding | None:
    if not name or name.startswith("_") or name in _JAVA_TYPE_PARAMS:
        return None

    name_lower = name.lower()

    if len(name) == 1 and name.lower() not in _ALLOWED_SINGLE_LETTERS:
        return Finding(
            type=SmellType.POOR_NAMING,
            severity=Severity.HIGH,
            line_number=line_no,
            symbol=name,
            source_agent="code_analysis",
                    description=(
                f"Single-letter {context} name '{name}' is not self-documenting. "
                f"Use a descriptive name that reflects its purpose."
            ),
            extra={"context": context},
        )

    if name_lower in _JAVA_GENERIC_BLOCKLIST:
        return Finding(
            type=SmellType.POOR_NAMING,
            severity=Severity.MEDIUM,
            line_number=line_no,
            symbol=name,
            source_agent="code_analysis",
                    description=(
                f"Generic {context} name '{name}' conveys no domain meaning. "
                f"Replace with a name that describes the value's role."
            ),
            extra={"context": context, "matched_pattern": "generic_blocklist"},
        )

    return None


def _detect_java(lines: List[str]) -> List[Finding]:
    findings: List[Finding] = []
    seen: Set[tuple] = set()

    for line_no, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("//"):
            continue

        for m in _JAVA_VAR_DECL.finditer(line):
            name = m.group(1)
            f = _check_java_name(name, line_no, "variable")
            if f:
                key = (f.symbol, f.line_number)
                if key not in seen:
                    seen.add(key)
                    findings.append(f)

        for m in _JAVA_METHOD_DECL.finditer(line):
            name = m.group(1)
            f = _check_java_name(name, line_no, "method")
            if f:
                key = (f.symbol, f.line_number)
                if key not in seen:
                    seen.add(key)
                    findings.append(f)

        for m in _JAVA_CLASS_DECL.finditer(line):
            name = m.group(1)
            f = _check_java_name(name, line_no, "class")
            if f:
                key = (f.symbol, f.line_number)
                if key not in seen:
                    seen.add(key)
                    findings.append(f)

    return findings


# ──────────────────────────────────────────────────────────────────────────────
# Public entry point
# ──────────────────────────────────────────────────────────────────────────────

def detect(lines: List[str], language: str) -> List[Finding]:
    """Detect poor naming in *lines* for the given *language*."""
    if language == "python":
        return _detect_python(lines)
    if language == "java":
        return _detect_java(lines)
    return []
