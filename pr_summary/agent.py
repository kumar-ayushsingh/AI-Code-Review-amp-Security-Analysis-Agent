"""
pr_summary/agent.py
--------------------
PRSummaryAgent – takes the full unified findings list (with remediations
attached) and produces a structured PRSummary object suitable for use as a
pull-request review comment, CI gate, or dashboard card.

The PRSummary contains:
  - executive_overview    1-2 sentence plain-language health verdict
  - severity_breakdown    Counts of critical / high / medium / low findings
  - prioritized_fixes     All findings ranked by severity then line number,
                          each with a one-liner and a fix_action sentence
  - agent_contributions   Dict mapping source_agent → finding count
  - has_critical          True if any CRITICAL finding exists (CI gate flag)
  - has_blocking          True if any CRITICAL or HIGH finding exists
"""

from __future__ import annotations

import logging
from collections import Counter
from typing import List

from shared.models import (
    Finding,
    FindingSummary,
    PRSummary,
    Severity,
    SeverityBreakdown,
)

logger = logging.getLogger(__name__)

# Severity sort order (lower = more urgent)
_SEVERITY_RANK: dict[str, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}


class PRSummaryAgent:
    """
    Produces a structured PRSummary from a list of remediated Finding objects.

    Usage
    -----
    >>> agent = PRSummaryAgent()
    >>> summary = agent.summarize(findings, filename="auth_service.py")
    >>> print(summary.executive_overview)
    >>> print(summary.severity_breakdown.total)
    >>> for fix in summary.prioritized_fixes:
    ...     print(fix.rank, fix.severity, fix.one_liner)
    """

    def summarize(
        self,
        findings: List[Finding],
        filename: str = "submitted file",
    ) -> PRSummary:
        """
        Build and return a structured PRSummary.

        Parameters
        ----------
        findings : List[Finding]
            The unified, sorted, remediated findings list from the pipeline.
        filename : str
            Name of the file being reviewed (used in the executive overview).

        Returns
        -------
        PRSummary
            A fully structured summary object. All sub-fields are also
            structured (not raw strings), making it easy to serialise to JSON,
            render in a UI, or assert against in tests.
        """
        if not findings:
            return self._empty_summary(filename)

        # ── 1. Severity breakdown ─────────────────────────────────────────
        breakdown = self._build_breakdown(findings)

        # ── 2. Prioritized fix list ────────────────────────────────────────
        sorted_findings = sorted(
            findings,
            key=lambda f: (
                _SEVERITY_RANK.get(f.severity, 99),
                f.line_number or 0,
            ),
        )
        prioritized = [
            self._to_finding_summary(rank + 1, f)
            for rank, f in enumerate(sorted_findings)
        ]

        # ── 3. Agent contributions ────────────────────────────────────────
        contributions: dict[str, int] = dict(
            Counter(f.source_agent for f in findings)
        )

        # ── 4. Flags ──────────────────────────────────────────────────────
        has_critical = breakdown.critical > 0
        has_blocking = breakdown.critical > 0 or breakdown.high > 0

        # ── 5. Executive overview ─────────────────────────────────────────
        overview = self._build_overview(filename, breakdown, has_blocking)

        return PRSummary(
            executive_overview=overview,
            severity_breakdown=breakdown,
            prioritized_fixes=prioritized,
            agent_contributions=contributions,
            has_critical=has_critical,
            has_blocking=has_blocking,
        )

    # ------------------------------------------------------------------ #
    # Private helpers                                                      #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _build_breakdown(findings: List[Finding]) -> SeverityBreakdown:
        counts: dict[str, int] = Counter(f.severity.value for f in findings)
        return SeverityBreakdown(
            critical=counts.get("critical", 0),
            high=counts.get("high", 0),
            medium=counts.get("medium", 0),
            low=counts.get("low", 0),
        )

    @staticmethod
    def _to_finding_summary(rank: int, finding: Finding) -> FindingSummary:
        """Convert a Finding into a compact FindingSummary for the PR report."""
        type_str = (
            finding.type.value
            if hasattr(finding.type, "value")
            else str(finding.type)
        )

        # Derive a crisp one-liner (first sentence of description, max 120 chars)
        raw_desc = finding.description or ""
        one_liner = raw_desc.split(".")[0].strip()
        if len(one_liner) > 120:
            one_liner = one_liner[:117] + "..."

        # Derive the fix_action from the remediation explanation if available
        fix_action = ""
        principle  = ""
        if finding.remediation:
            principle = finding.remediation.principle

            # Extract the base explanation (strip the [RAG Guideline] header)
            explanation = finding.remediation.explanation
            if "[RAG Guideline]" in explanation:
                # Split: header block \n\n base explanation
                parts = explanation.split("\n\n", 1)
                base_exp = parts[1] if len(parts) > 1 else explanation
            else:
                base_exp = explanation

            # Take the first sentence of the base explanation as the fix action
            fix_sentence = base_exp.split(".")[0].strip()
            if len(fix_sentence) > 150:
                fix_sentence = fix_sentence[:147] + "..."
            fix_action = fix_sentence + "."

        return FindingSummary(
            rank=rank,
            severity=finding.severity.value,
            finding_type=type_str,
            line_number=finding.line_number or 0,
            source_agent=finding.source_agent,
            one_liner=one_liner,
            fix_action=fix_action,
            principle=principle,
        )

    @staticmethod
    def _build_overview(
        filename: str,
        breakdown: SeverityBreakdown,
        has_blocking: bool,
    ) -> str:
        """Generate a 1-2 sentence executive overview."""
        total = breakdown.total

        if total == 0:
            return (
                f"`{filename}` passed review with no findings. "
                "Code quality and security posture look healthy."
            )

        parts: list[str] = []
        if breakdown.critical:
            parts.append(f"{breakdown.critical} critical")
        if breakdown.high:
            parts.append(f"{breakdown.high} high")
        if breakdown.medium:
            parts.append(f"{breakdown.medium} medium")
        if breakdown.low:
            parts.append(f"{breakdown.low} low")

        breakdown_str = ", ".join(parts)

        if has_blocking:
            verdict = (
                f"`{filename}` requires attention before merging: "
                f"{total} finding(s) detected ({breakdown_str}). "
                "Address all critical and high-severity issues immediately — "
                "they represent active security risks or serious maintainability blockers."
            )
        else:
            verdict = (
                f"`{filename}` is in fair shape with {total} finding(s) "
                f"({breakdown_str}). "
                "No blocking issues were detected; address medium and low findings "
                "in the next maintenance cycle."
            )

        return verdict

    @staticmethod
    def _empty_summary(filename: str) -> PRSummary:
        return PRSummary(
            executive_overview=(
                f"`{filename}` passed review with no findings. "
                "Code quality and security posture look healthy."
            ),
            severity_breakdown=SeverityBreakdown(),
            prioritized_fixes=[],
            agent_contributions={},
            has_critical=False,
            has_blocking=False,
        )
