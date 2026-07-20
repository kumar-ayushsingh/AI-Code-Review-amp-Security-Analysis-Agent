"""
code_analysis
=============
A code smell detection agent for Python and Java source code.

Public API
----------
>>> from code_analysis import CodeAnalysisAgent, Finding
>>> agent = CodeAnalysisAgent()
>>> findings = agent.analyze(source_code, language="python")
"""

from .models import Finding, Severity, SmellType
from .agent import CodeAnalysisAgent

__all__ = ["CodeAnalysisAgent", "Finding", "Severity", "SmellType"]
