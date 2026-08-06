"""
remediation/agent.py
--------------------
RemediationAgent – takes a list of Finding objects and enriches each one
with a Remediation object (corrected_code, explanation, principle).

The agent uses a rule-based lookup table keyed on finding.type so that:
  1. It works with zero external dependencies (consistent with the project's
     mock-LLM approach).
  2. It is trivially swappable for a real LLM call: just replace
     _generate_remediation() with an LLM invocation.
"""

from __future__ import annotations

import logging
from typing import List

from shared.models import Finding, Remediation
from .remediation_rules import RULES, FALLBACK_RULE

logger = logging.getLogger(__name__)


class RemediationAgent:
    """
    Enriches a list of Finding objects with auto-generated remediation advice.

    Usage
    -----
    >>> agent = RemediationAgent()
    >>> remediated = agent.remediate(findings)
    >>> for f in remediated:
    ...     print(f.remediation.corrected_code)
    """

    def remediate(self, findings: List[Finding]) -> List[Finding]:
        """
        Attach a Remediation to every Finding in *findings*.

        Findings are mutated in-place (remediation field is set) and the same
        list is returned so callers can chain: ``agent.remediate(findings)``.

        Parameters
        ----------
        findings : List[Finding]
            Findings produced by any analysis agent.

        Returns
        -------
        List[Finding]
            The same list, with each finding's .remediation field populated.
        """
        for finding in findings:
            try:
                finding.remediation = self._generate_remediation(finding)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "RemediationAgent: could not generate remediation for "
                    "%s at line %s — %s",
                    finding.type,
                    finding.line_number,
                    exc,
                )
        return findings

    # ------------------------------------------------------------------ #
    # Private helpers                                                      #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _generate_remediation(finding: Finding) -> Remediation:
        """
        Look up the remediation rule for *finding.type* and return a
        Remediation object.  Falls back to a generic template if the type
        has no specific rule yet.
        """
        # finding.type is a SmellType / VulnerabilityType enum; its .value
        # is the string key used in RULES.
        type_key: str = (
            finding.type.value
            if hasattr(finding.type, "value")
            else str(finding.type)
        )

        rule = RULES.get(type_key, FALLBACK_RULE)

        return Remediation(
            corrected_code=rule["corrected_code"],
            explanation=rule["explanation"],
            principle=rule["principle"],
        )
