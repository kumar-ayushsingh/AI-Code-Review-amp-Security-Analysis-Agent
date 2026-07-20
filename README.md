# Code Analysis Agent

A pure-Python code smell detection module for **Python** and **Java** source files. Requires **no external dependencies** — only the standard library.

## Detected Smells

| Smell | Detection Strategy | Severity Criteria |
|---|---|---|
| **Long Method** | Python: AST node span; Java: brace-depth tracking | `low` ≥40 lines → `critical` ≥120 lines |
| **Duplicate Code** | Rolling MD5 fingerprints on normalised token windows | `low` ≥6 lines → `critical` ≥20 lines |
| **Poor Naming** | Python: AST walker; Java: regex | `high` = single-letter (non-idiomatic); `medium` = generic blocklist |
| **High Complexity** | Python: AST decision-point visitor; Java: regex counter | `low` CC 6–10 → `critical` CC ≥21 |
| **Tight Coupling** | Fan-out, Law of Demeter chains, hardcoded constructors | `low` chain depth 3 → `critical` fan-out ≥15 |

## Finding Schema

Every finding is a `Finding` dataclass:

```python
@dataclass
class Finding:
    type: SmellType        # e.g. SmellType.LONG_METHOD
    severity: Severity     # Severity.CRITICAL / HIGH / MEDIUM / LOW
    line_number: int       # 1-based
    description: str       # Human-readable explanation + remedy
    source_agent: str      # Always "code_analysis"
    symbol: str | None     # Method/class/variable name (if applicable)
    extra: dict            # Detector-specific metadata
```

## Quick Start

```python
from code_analysis import CodeAnalysisAgent

agent = CodeAnalysisAgent()

with open("my_module.py") as fh:
    source = fh.read()

findings = agent.analyze(source, language="python")

for f in findings:
    print(f)

# JSON-ready output
import json
print(json.dumps(agent.findings_to_dict(findings), indent=2))

# Summary
print(agent.summary(findings))
# → {'critical': 1, 'high': 3, 'medium': 5, 'low': 2, 'total': 11}
```

### Analyse a file directly

```python
findings = agent.analyze_file("src/OrderService.java")
```

### CLI

```bash
# Pretty-printed table
python -m code_analysis.cli path/to/file.py

# JSON output
python -m code_analysis.cli path/to/file.java --json

# Custom thresholds
python -m code_analysis.cli app.py --threshold 30 --min-dupes 8
```

## Configuration

```python
agent = CodeAnalysisAgent(
    long_method_threshold=40,   # lines; default 40
    min_duplicate_lines=6,      # lines; default 6
    enable_long_method=True,
    enable_duplicate_code=True,
    enable_poor_naming=True,
    enable_high_complexity=True,
    enable_tight_coupling=True,
)
```

## Running Tests

```bash
python -m pytest tests/ -v
```

## Project Structure

```
milestone 2/
├── code_analysis/
│   ├── __init__.py          # Public API
│   ├── agent.py             # CodeAnalysisAgent orchestrator
│   ├── models.py            # Finding, Severity, SmellType
│   ├── cli.py               # Command-line interface
│   └── detectors/
│       ├── __init__.py
│       ├── long_method.py
│       ├── duplicate_code.py
│       ├── poor_naming.py
│       ├── high_complexity.py
│       └── tight_coupling.py
├── tests/
│   └── test_code_analysis.py
├── pyproject.toml
└── README.md
```
