import logging
import concurrent.futures
from typing import List

from shared.models import Finding
from code_analysis.agent import CodeAnalysisAgent
from security_vulnerability.agent import SecurityVulnerabilityAgent

logger = logging.getLogger(__name__)

class UnifiedOrchestrator:
    """
    Orchestrates the parallel execution of the Code Analysis Agent and 
    the Security Vulnerability Agent, returning a merged and sorted list of findings.
    """

    def __init__(self):
        self.code_agent = CodeAnalysisAgent()
        self.security_agent = SecurityVulnerabilityAgent()

    def analyze_concurrently(self, source_code: str, language: str = "python", filename: str = "unknown") -> List[Finding]:
        """
        Runs both agents in parallel using a ThreadPoolExecutor.
        Merges the findings and sorts them by severity (Critical -> High -> Medium -> Low),
        and then by line number.
        """
        if not source_code.strip():
            return []

        all_findings: List[Finding] = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            # Submit both tasks to the executor
            future_code = executor.submit(self.code_agent.analyze, source_code, language, filename=filename)
            future_security = executor.submit(self.security_agent.analyze, source_code, language, filename=filename)

            # Wait for both to complete and gather results, handling failures gracefully
            try:
                code_findings = future_code.result()
                all_findings.extend(code_findings)
            except Exception as e:
                logger.error(f"Code Analysis Agent failed during execution: {e}", exc_info=True)

            try:
                security_findings = future_security.result()
                all_findings.extend(security_findings)
            except Exception as e:
                logger.error(f"Security Vulnerability Agent failed during execution: {e}", exc_info=True)

        # Sort findings.
        # We need a custom sort order for severity. 
        # By defining a rank, we can sort effectively: CRITICAL=0, HIGH=1, MEDIUM=2, LOW=3
        severity_rank = {
            "critical": 0,
            "high": 1,
            "medium": 2,
            "low": 3
        }

        all_findings.sort(key=lambda f: (
            severity_rank.get(f.severity.value, 99),
            f.line_number or 0
        ))

        return all_findings
