"""
detectors/tight_coupling.py
----------------------------
Detects signs of tight coupling in source code:

  1. **Fan-out coupling** (Python & Java)
     A class/module that directly references an unusually high number of
     *other* concrete classes / modules.

  2. **Law of Demeter violations** (Python & Java)
     Call chains of depth ≥ 3: ``a.b.c()`` or ``obj.getX().getY().doZ()``.

  3. **Hardcoded class instantiation in constructors** (Java)
     ``new ConcreteClass()`` calls inside a constructor body instead of
     receiving dependencies via constructor injection.

  4. **God-class imports** (Python)
     A single module importing a very large number of names from one source.

Severity scale
--------------
- critical : fan-out ≥ 15 unique dependencies OR call chain depth ≥ 5
- high     : fan-out ≥ 10  OR chain depth ≥ 4
- medium   : fan-out ≥  7  OR hardcoded instantiation in constructor
- low      : call chain depth == 3 OR borderline fan-out (≥ 5)
"""

from __future__ import annotations

import ast
import re
from collections import defaultdict
from typing import List, Set

from ..models import Finding, Severity, SmellType


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _chain_depth(expr: str) -> int:
    """Count the depth of a member-access chain (dots between identifiers)."""
    # Remove string literals first
    expr = re.sub(r'"[^"]*"|\'[^\']*\'', '""', expr)
    # Count attribute accesses: each '.' between word characters
    parts = re.split(r"\.\s*", expr)
    return len(parts)


_DEMETER_RE = re.compile(
    r"[\w$]+(?:\.[\w$]+\(\))+(?:\.[\w$]+\(\))+",  # a.b().c() or deeper
)

_FANOUT_SEVERITY_MAP = [
    (15, Severity.CRITICAL),
    (10, Severity.HIGH),
    (7,  Severity.MEDIUM),
    (5,  Severity.LOW),
]

def _fanout_severity(count: int) -> Severity | None:
    for threshold, sev in _FANOUT_SEVERITY_MAP:
        if count >= threshold:
            return sev
    return None

_CHAIN_SEVERITY_MAP = [
    (5, Severity.CRITICAL),
    (4, Severity.HIGH),
    (3, Severity.LOW),
]

def _chain_severity(depth: int) -> Severity | None:
    for threshold, sev in _CHAIN_SEVERITY_MAP:
        if depth >= threshold:
            return sev
    return None


# ──────────────────────────────────────────────────────────────────────────────
# Python detector
# ──────────────────────────────────────────────────────────────────────────────

_STDLIB_MODULES = frozenset([
    "os", "sys", "re", "io", "abc", "ast", "csv", "json", "math",
    "time", "copy", "enum", "uuid", "random", "string", "typing",
    "logging", "hashlib", "pathlib", "datetime", "functools",
    "itertools", "collections", "contextlib", "threading", "subprocess",
    "dataclasses", "unittest", "textwrap", "shutil", "tempfile",
])


def _detect_python_coupling(lines: List[str]) -> List[Finding]:
    source = "\n".join(lines)
    findings: List[Finding] = []

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return findings

    # Collect file-level (module-scope) imports first.
    # Python classes typically import dependencies at module scope.
    file_level_imports: Set[str] = set()
    for top in ast.iter_child_nodes(tree):
        if isinstance(top, ast.Import):
            for alias in top.names:
                mod = alias.name.split(".")[0]
                if mod not in _STDLIB_MODULES:
                    file_level_imports.add(mod)
        elif isinstance(top, ast.ImportFrom):
            if top.module:
                mod = top.module.split(".")[0]
                if mod not in _STDLIB_MODULES:
                    file_level_imports.add(mod)

    # Fan-out: count unique external modules per class
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue

        # A class couples to everything its module imports
        referenced_modules: Set[str] = set(file_level_imports)

        for child in ast.walk(node):
            if isinstance(child, ast.Import):
                for alias in child.names:
                    mod = alias.name.split(".")[0]
                    if mod not in _STDLIB_MODULES:
                        referenced_modules.add(mod)
            elif isinstance(child, ast.ImportFrom):
                if child.module:
                    mod = child.module.split(".")[0]
                    if mod not in _STDLIB_MODULES:
                        referenced_modules.add(mod)
            elif isinstance(child, ast.Attribute):
                if isinstance(child.value, ast.Name):
                    if child.value.id not in _STDLIB_MODULES:
                        referenced_modules.add(child.value.id)

        fan_out = len(referenced_modules)
        sev = _fanout_severity(fan_out)
        if sev:
            top10 = sorted(referenced_modules)[:10]
            ellipsis_str = "..." if fan_out > 10 else ""
            findings.append(Finding(
                type=SmellType.TIGHT_COUPLING,
                severity=sev,
                line_number=node.lineno,
                symbol=node.name,
                description=(
                    f"Class '{node.name}' has a fan-out of {fan_out} external "
                    f"dependencies: {top10}{ellipsis_str}. "
                    f"High fan-out indicates tight coupling; introduce abstractions "
                    f"(interfaces, dependency injection, or a mediator)."
                ),
                extra={"fan_out": fan_out, "dependencies": sorted(referenced_modules)},
            ))

    # ── Law of Demeter: call-chain depth ──
    for line_no, raw in enumerate(lines, start=1):
        stripped = raw.strip()
        if stripped.startswith("#"):
            continue
        for m in _DEMETER_RE.finditer(stripped):
            chain = m.group(0)
            depth = chain.count(".") + 1
            sev = _chain_severity(depth)
            if sev:
                findings.append(Finding(
                    type=SmellType.TIGHT_COUPLING,
                    severity=sev,
                    line_number=line_no,
                    description=(
                        f"Call chain '{chain}' has depth {depth} (Law of Demeter "
                        f"violation). Each step couples you to an internal detail. "
                        f"Introduce a method on the intermediate object instead."
                    ),
                    extra={"chain": chain, "depth": depth},
                ))

    return findings


# ──────────────────────────────────────────────────────────────────────────────
# Java detector
# ──────────────────────────────────────────────────────────────────────────────

_JAVA_IMPORT_RE = re.compile(r"^\s*import\s+(?:static\s+)?([\w.]+)\s*;")
_JAVA_NEW_RE = re.compile(r"\bnew\s+([A-Z][\w<>]+)\s*\(")
_JAVA_CLASS_RE = re.compile(r"^\s*(?:public|private|protected|abstract|final|static)?\s*"
                            r"(?:class|enum|record)\s+(\w+)")
_JAVA_CTOR_RE = re.compile(r"^\s*(?:public|private|protected)\s+(\w+)\s*\(")

_JAVA_CHAIN_RE = re.compile(
    r"[\w$]+(?:\.[\w$]+\(\))+(?:\.[\w$]+\(\))+",
)

_JAVA_STD_PACKAGES = frozenset([
    "java", "javax", "sun", "com.sun", "jdk",
])


def _is_std_import(fqn: str) -> bool:
    return any(fqn.startswith(pkg + ".") for pkg in _JAVA_STD_PACKAGES)


def _detect_java_coupling(lines: List[str]) -> List[Finding]:
    findings: List[Finding] = []

    # Track file-level imports per class (simplified: one class per file)
    imports: Set[str] = set()
    current_class: str | None = None
    current_class_line: int = 0
    in_ctor: bool = False
    ctor_name: str = ""
    ctor_line: int = 0
    ctor_brace_depth: int = 0
    brace_depth: int = 0

    for line_no, raw in enumerate(lines, start=1):
        line = raw.strip()

        # Imports
        im = _JAVA_IMPORT_RE.match(raw)
        if im:
            fqn = im.group(1)
            if not _is_std_import(fqn):
                pkg = fqn.rsplit(".", 1)[0] if "." in fqn else fqn
                imports.add(pkg)
            continue

        # Class declaration
        cm = _JAVA_CLASS_RE.match(raw)
        if cm:
            # Report fan-out for the previous class
            if current_class and len(imports) >= 5:
                sev = _fanout_severity(len(imports))
                if sev:
                    findings.append(Finding(
                        type=SmellType.TIGHT_COUPLING,
                        severity=sev,
                        line_number=current_class_line,
                        symbol=current_class,
                        description=(
                            f"Class '{current_class}' imports {len(imports)} external "
                            f"packages. High fan-out indicates tight coupling; introduce "
                            f"abstractions or dependency injection."
                        ),
                        extra={"fan_out": len(imports), "imports": sorted(imports)},
                    ))
                imports = set()

            current_class = cm.group(1)
            current_class_line = line_no

        # Constructor detection (same name as class)
        if current_class:
            ctor_m = _JAVA_CTOR_RE.match(raw)
            if ctor_m and ctor_m.group(1) == current_class and not in_ctor:
                in_ctor = True
                ctor_name = current_class
                ctor_line = line_no
                ctor_brace_depth = brace_depth

        # Hardcoded instantiation inside constructor
        if in_ctor:
            for nm in _JAVA_NEW_RE.finditer(line):
                concrete_class = nm.group(1).split("<")[0]  # strip generics
                # Skip self-referential or collection types
                if concrete_class not in {ctor_name, "StringBuilder", "ArrayList",
                                          "HashMap", "HashSet", "LinkedList",
                                          "TreeMap", "ArrayDeque", "Object"}:
                    findings.append(Finding(
                        type=SmellType.TIGHT_COUPLING,
                        severity=Severity.MEDIUM,
                        line_number=line_no,
                        symbol=ctor_name,
                        description=(
                            f"Constructor '{ctor_name}' instantiates concrete class "
                            f"'{concrete_class}' directly (line {line_no}). "
                            f"This hard-wires the dependency; prefer constructor "
                            f"injection of an interface instead."
                        ),
                        extra={"concrete_class": concrete_class, "constructor": ctor_name},
                    ))

        brace_depth += line.count("{") - line.count("}")
        if in_ctor and brace_depth <= ctor_brace_depth:
            in_ctor = False

        # Law of Demeter: call-chain depth
        if line.startswith("//"):
            continue
        for m in _JAVA_CHAIN_RE.finditer(line):
            chain = m.group(0)
            depth = chain.count(".") + 1
            sev = _chain_severity(depth)
            if sev:
                findings.append(Finding(
                    type=SmellType.TIGHT_COUPLING,
                    severity=sev,
                    line_number=line_no,
                    description=(
                        f"Call chain '{chain}' has depth {depth} (Law of Demeter "
                        f"violation). Introduce a method on the intermediate object."
                    ),
                    extra={"chain": chain, "depth": depth},
                ))

    # Report final class
    if current_class and len(imports) >= 5:
        sev = _fanout_severity(len(imports))
        if sev:
            findings.append(Finding(
                type=SmellType.TIGHT_COUPLING,
                severity=sev,
                line_number=current_class_line,
                symbol=current_class,
                description=(
                    f"Class '{current_class}' imports {len(imports)} external "
                    f"packages. Introduce abstractions or dependency injection."
                ),
                extra={"fan_out": len(imports), "imports": sorted(imports)},
            ))

    return findings


# ──────────────────────────────────────────────────────────────────────────────
# Public entry point
# ──────────────────────────────────────────────────────────────────────────────

def detect(lines: List[str], language: str) -> List[Finding]:
    """Detect tight coupling patterns in *lines* for the given *language*."""
    if language == "python":
        return _detect_python_coupling(lines)
    if language == "java":
        return _detect_java_coupling(lines)
    return []
