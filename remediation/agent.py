"""
remediation/agent.py
--------------------
RemediationAgent – takes a list of Finding objects and enriches each one
with a Remediation object (corrected_code, explanation, principle).

For every finding the agent:
  1. Calls retrieve_context() from the shared RAG client to pull the
     relevant secure-coding / clean-code guideline from the indexed knowledge
     base.  This grounds the explanation in documented OWASP / Clean Code
     standards rather than in the model's general knowledge.
  2. Looks up the corrected-code snippet and base explanation from the
     rule table in remediation_rules.py.
  3. Prepends the RAG-retrieved guideline to the explanation so the source
     of the advice is always explicit and traceable.
"""

from __future__ import annotations

import logging
from typing import List

from shared.models import Finding, Remediation
from .remediation_rules import RULES, FALLBACK_RULE
from security_vulnerability.rag_client import retrieve_context

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Map each finding type.value → a focused natural-language query string.
# These queries are designed to maximise keyword overlap with the guideline
# entries in rag_client._GUIDELINES so we always retrieve the best match.
# ---------------------------------------------------------------------------
_RAG_QUERIES: dict[str, str] = {
    # Security vulnerabilities
    "sql_injection":          "sql injection query database parameterized",
    "xss":                    "xss cross-site scripting html output encoding escape",
    "csrf":                   "csrf forgery anti-csrf synchronizer token",
    "hardcoded_secret":       "secret credential api key password hardcode",
    "insecure_auth":          "auth hash md5 sha1 bcrypt password hashing",
    "broken_access_control":  "access control authorization rbac ownership idor broken access",
    # Code smells
    "long_method":            "long method long function single responsibility method length",
    "duplicate_code":         "duplicate duplicated code copy-paste dry",
    "poor_naming":            "naming poor naming variable name generic name meaningful name",
    "high_complexity":        "complexity cyclomatic nesting deeply nested guard clause",
    "tight_coupling":         "coupling dependency fan-out law of demeter di dependency injection",
}


class RemediationAgent:
    """
    Enriches a list of Finding objects with RAG-grounded remediation advice.

    For each finding:
    - ``retrieve_context()`` is called with a focused query derived from the
      finding type to pull the matching OWASP / Clean-Code guideline.
    - The guideline is prepended to the base explanation from the rule table,
      making the source of every recommendation explicit.

    Usage
    -----
    >>> agent = RemediationAgent()
    >>> remediated = agent.remediate(findings)
    >>> for f in remediated:
    ...     print(f.remediation.explanation)
    """

    def remediate(self, findings: List[Finding]) -> List[Finding]:
        """
        Attach a RAG-grounded Remediation to every Finding in *findings*.

        Findings are mutated in-place and the same list is returned so callers
        can chain: ``findings = agent.remediate(findings)``.

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
    def _rag_query(finding: Finding) -> str:
        """
        Build the natural-language query string to send to retrieve_context().

        Uses the type-specific query from _RAG_QUERIES when available, falling
        back to the raw type key so the RAG client always receives something
        meaningful.
        """
        type_key: str = (
            finding.type.value
            if hasattr(finding.type, "value")
            else str(finding.type)
        )
        return _RAG_QUERIES.get(type_key, type_key.replace("_", " "))

    @staticmethod
    def _generate_remediation(finding: Finding) -> Remediation:
        """
        1. Call retrieve_context() with a focused query for this finding type.
        2. Look up the corrected-code snippet and base explanation from RULES.
        3. Prepend the RAG guideline to the explanation so every Remediation
           object carries a clearly attributed, knowledge-base-backed reference.
        """
        type_key: str = (
            finding.type.value
            if hasattr(finding.type, "value")
            else str(finding.type)
        )

        # ── Step 1: retrieve grounding context from the RAG knowledge base ──
        rag_query = _RAG_QUERIES.get(type_key, type_key.replace("_", " "))
        guideline: str = retrieve_context(rag_query)
        logger.debug(
            "RAG context for %s: %s", type_key, guideline[:80]
        )

        # ── Step 2: fetch the rule-based snippet + base explanation ─────────
        rule = RULES.get(type_key, FALLBACK_RULE)

        # ── Step 3: blend — guideline header + base explanation ─────────────
        grounded_explanation = (
            f"[RAG Guideline] {guideline}\n\n"
            f"{rule['explanation']}"
        )

        return Remediation(
            corrected_code=rule["corrected_code"],
            explanation=grounded_explanation,
            principle=rule["principle"],
        )
