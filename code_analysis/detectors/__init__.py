"""
detectors/__init__.py
---------------------
Convenience re-exports so callers can do:
    from code_analysis.detectors import long_method, duplicate_code, ...
"""

from . import long_method, duplicate_code, poor_naming, high_complexity, tight_coupling

__all__ = [
    "long_method",
    "duplicate_code",
    "poor_naming",
    "high_complexity",
    "tight_coupling",
]
