import pytest
import time
from orchestration import UnifiedOrchestrator
from shared.models import Finding, Severity

@pytest.fixture
def orchestrator():
    return UnifiedOrchestrator()

class TestOrchestrator:
    def test_combined_findings(self, orchestrator):
        src = """
def my_func(b):
    # Security: SQL Injection
    query = f"SELECT * FROM users WHERE id={b}"
    # Smell: single letter variable
    c = 10
    return c
"""
        findings = orchestrator.analyze_concurrently(src, "python")
        
        # We should find both the SQL injection (security agent) and Poor Naming (code analysis agent)
        types = [f.type.value for f in findings]
        assert "sql_injection" in types
        assert "poor_naming" in types
        
    def test_severity_sorting(self, orchestrator):
        src = """
def my_func(x):
    # Security: SQL Injection (CRITICAL)
    query = f"SELECT * FROM users WHERE id={x}"
    # Smell: poor naming (HIGH for single letter function/param)
    # We also have an insecure auth (HIGH)
    import hashlib
    hashlib.md5(b"password")
    
    # Let's add something nested to get CC (MEDIUM)
    if True:
        if True:
            if True:
                if True:
                    if True:
                        if True:
                            pass
                            
    a = 1 # LOW smell poor naming
    return a
"""
        findings = orchestrator.analyze_concurrently(src, "python")
        assert len(findings) > 0
        
        # Assert that the findings are sorted by severity: CRITICAL -> HIGH -> MEDIUM -> LOW
        severities = [f.severity for f in findings]
        
        severity_rank = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3
        }
        
        ranks = [severity_rank[s] for s in severities]
        assert ranks == sorted(ranks), f"Findings are not correctly sorted by severity. Got {severities}"
        
    def test_parallel_execution_time(self, orchestrator, monkeypatch):
        # We mock one agent's analyze method to sleep for 0.5s, 
        # and the other agent's to sleep for 0.5s.
        # If they run in sequence, it takes 1.0s. If parallel, it takes ~0.5s.
        
        def mock_sleep_code(*args, **kwargs):
            time.sleep(0.5)
            return []
            
        def mock_sleep_security(*args, **kwargs):
            time.sleep(0.5)
            return []
            
        monkeypatch.setattr(orchestrator.code_agent, "analyze", mock_sleep_code)
        monkeypatch.setattr(orchestrator.security_agent, "analyze", mock_sleep_security)
        
        start = time.time()
        orchestrator.analyze_concurrently("pass", "python")
        duration = time.time() - start
        
        # We allow a little overhead for ThreadPoolExecutor setup
        assert duration < 0.8, f"Execution took {duration}s, which means it likely ran synchronously!"

    def test_agent_failure_handling(self, orchestrator, monkeypatch, caplog):
        # We mock the security agent to raise an exception
        def mock_failing_agent(*args, **kwargs):
            raise RuntimeError("Simulated agent crash")
            
        monkeypatch.setattr(orchestrator.security_agent, "analyze", mock_failing_agent)
        
        src = """
def my_func(a):
    y = 10
    return y
"""
        # The code agent should still find the single-letter variable smells
        findings = orchestrator.analyze_concurrently(src, "python")
        
        # Security agent failed, but code analysis agent still returned findings
        assert len(findings) > 0
        assert all(f.source_agent == "code_analysis" for f in findings)
        
        # Verify the error was logged
        assert "Security Vulnerability Agent failed during execution: Simulated agent crash" in caplog.text
