"""
agent.py
--------
The main CodeAnalysisAgent — orchestrates all detectors and returns a
unified, deduplicated, sorted list of Finding objects.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Literal, Optional

from .models import Finding, Severity, SmellType
from .detectors import (
    long_method,
    duplicate_code,
    poor_naming,
    high_complexity,
    tight_coupling,
)

logger = logging.getLogger(__name__)

Language = Literal["python", "java"]

# Priority order used for final sort (critical first)
_SEVERITY_ORDER: Dict[str, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}


class CodeAnalysisAgent:
    """
    Analyses source code for common code smells and returns structured findings.

    Parameters
    ----------
    long_method_threshold : int
        Number of lines above which a method is considered "long" (default 40).
    min_duplicate_lines : int
        Minimum block size to flag as a duplicate (default 6).
    enable_long_method : bool
        Toggle individual detectors on/off (all enabled by default).
    enable_duplicate_code : bool
    enable_poor_naming : bool
    enable_high_complexity : bool
    enable_tight_coupling : bool

    Usage
    -----
    >>> agent = CodeAnalysisAgent()
    >>> findings = agent.analyze(source_code, language="python")
    >>> for f in findings:
    ...     print(f)
    """

    def __init__(
        self,
        *,
        long_method_threshold: int = 40,
        min_duplicate_lines: int = 6,
        enable_long_method: bool = True,
        enable_duplicate_code: bool = True,
        enable_poor_naming: bool = True,
        enable_high_complexity: bool = True,
        enable_tight_coupling: bool = True,
    ) -> None:
        self.long_method_threshold = long_method_threshold
        self.min_duplicate_lines = min_duplicate_lines
        self.enable_long_method = enable_long_method
        self.enable_duplicate_code = enable_duplicate_code
        self.enable_poor_naming = enable_poor_naming
        self.enable_high_complexity = enable_high_complexity
        self.enable_tight_coupling = enable_tight_coupling

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def analyze(
        self,
        source_code: str,
        language: Language = "python",
        *,
        filename: Optional[str] = None,
    ) -> List[Finding]:
        """
        Analyse *source_code* for code smells.

        Parameters
        ----------
        source_code : str
            Raw source code text.
        language : "python" | "java"
            Programming language of the source.  Defaults to "python".
        filename : str, optional
            For informational purposes only; included in log messages.

        Returns
        -------
        List[Finding]
            Sorted list of findings: critical → high → medium → low, then
            by ascending line number within each severity bucket.
        """
        lang = language.lower().strip()
        if lang not in ("python", "java"):
            raise ValueError(
                f"Unsupported language '{language}'. Supported: 'python', 'java'."
            )

        label = filename or f"<{lang} source>"
        logger.info("CodeAnalysisAgent: analysing %s", label)

        lines = source_code.splitlines()
        findings: List[Finding] = []

        # ── Run each enabled detector ──────────────────────────────────
        if self.enable_long_method:
            try:
                findings += long_method.detect(
                    lines, lang, threshold=self.long_method_threshold
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("long_method detector failed: %s", exc)

        if self.enable_duplicate_code:
            try:
                findings += duplicate_code.detect(
                    lines, lang, min_block_lines=self.min_duplicate_lines
                )
            except Exception as exc:
                logger.warning("duplicate_code detector failed: %s", exc)

        if self.enable_poor_naming:
            try:
                findings += poor_naming.detect(lines, lang)
            except Exception as exc:
                logger.warning("poor_naming detector failed: %s", exc)

        if self.enable_high_complexity:
            try:
                findings += high_complexity.detect(lines, lang)
            except Exception as exc:
                logger.warning("high_complexity detector failed: %s", exc)

        if self.enable_tight_coupling:
            try:
                findings += tight_coupling.detect(lines, lang)
            except Exception as exc:
                logger.warning("tight_coupling detector failed: %s", exc)

        # ── Deduplicate identical findings ─────────────────────────────
        findings = self._deduplicate(findings)

        # ── Sort: severity DESC, then line number ASC ──────────────────
        findings.sort(
            key=lambda f: (
                _SEVERITY_ORDER.get(f.severity, 99),
                f.line_number,
            )
        )

        logger.info(
            "CodeAnalysisAgent: %d findings in %s", len(findings), label
        )
        return findings

    def analyze_file(self, path: str, language: Optional[Language] = None) -> List[Finding]:
        """
        Convenience wrapper: read a file from disk and analyse it.

        If *language* is omitted it is inferred from the file extension
        (.py → python, .java → java).
        """
        from pathlib import Path

        p = Path(path)
        if language is None:
            _ext_map = {".py": "python", ".java": "java"}
            language = _ext_map.get(p.suffix.lower())  # type: ignore[assignment]
            if language is None:
                raise ValueError(
                    f"Cannot infer language from extension '{p.suffix}'. "
                    f"Pass language='python' or language='java' explicitly."
                )

        source = p.read_text(encoding="utf-8", errors="replace")
        return self.analyze(source, language=language, filename=str(p))

    # ------------------------------------------------------------------ #
    # Private helpers                                                      #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _deduplicate(findings: List[Finding]) -> List[Finding]:
        """Remove exact duplicates (same type + severity + line + description)."""
        seen: set[tuple] = set()
        unique: List[Finding] = []
        for f in findings:
            key = (f.type, f.severity, f.line_number, f.description[:80])
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    # ------------------------------------------------------------------ #
    # Reporting helpers                                                    #
    # ------------------------------------------------------------------ #

    @staticmethod
    def findings_to_dict(findings: List[Finding]) -> List[dict]:
        """Serialise findings to a list of plain dicts (JSON-ready)."""
        return [f.to_dict() for f in findings]

    @staticmethod
    def summary(findings: List[Finding]) -> Dict[str, int]:
        """Return a severity → count summary dict."""
        counts: Dict[str, int] = {s.value: 0 for s in Severity}
        for f in findings:
            counts[f.severity.value] += 1
        counts["total"] = len(findings)
        return counts
