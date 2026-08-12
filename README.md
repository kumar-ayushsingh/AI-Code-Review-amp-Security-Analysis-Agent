# AI Code Review & Security Analysis Agent

> **A multi-agent Python system that performs automated code review, security vulnerability detection, remediation suggestion, and conversational Q&A — all in one unified pipeline.**

---

## 🚀 Features

| Feature | Description |
|---|---|
| 🔍 **Code Quality Analysis** | Detects long methods, duplicate code, poor naming, high cyclomatic complexity, and tight coupling |
| 🔐 **Security Vulnerability Detection** | Identifies SQL injection, XSS, CSRF, hardcoded secrets, weak auth, and broken access control |
| 🤖 **LLM-Powered Detection** | Combines regex/pattern matching with a mock LLM for subtle, multi-step vulnerabilities |
| 📚 **RAG Grounding** | All findings are grounded against OWASP Top 10 and Clean Code guidelines via a keyword-based RAG client |
| 🛠️ **Remediation Agent** | Auto-generates "before/after" corrected code snippets and human-readable explanations for every finding |
| 📋 **PR Summary Agent** | Produces a structured pull-request-style review: executive overview, severity breakdown, and prioritised fix list |
| 🌐 **Developer Portal** | A React/Vite frontend displaying findings with GitHub PR thread styling, syntax-highlighted code blocks, and a health score gauge |
| 💬 **Conversational Code Assistant** | Per-finding chat panel: ask follow-up questions like "Why is this a problem?" and get RAG-grounded answers with multi-turn context |

---

## 🏗️ Architecture

```
Source Code
    │
    ▼
┌─────────────────────────────────────────────┐
│           UnifiedOrchestrator               │
│  (ThreadPoolExecutor — parallel agents)     │
└────────────┬────────────────────────────────┘
             │
    ┌────────┴────────┐
    ▼                 ▼
CodeAnalysisAgent   SecurityVulnerabilityAgent
(5 detectors)       (6 detectors + LLM + RAG)
    │                 │
    └────────┬────────┘
             ▼
       [Unified Finding List]
             │
             ▼
      RemediationAgent
   (corrected code + explanation)
             │
             ▼
       PRSummaryAgent
   (structured PRSummary object)
             │
             ▼
    React Developer Portal
  (health score + chat assistant)
```

---

## 📦 Project Structure

```
milestone 2/
├── code_analysis/              # Code quality detection agent
│   ├── agent.py
│   └── detectors/
│       ├── long_method.py
│       ├── duplicate_code.py
│       ├── poor_naming.py
│       ├── high_complexity.py
│       └── tight_coupling.py
│
├── security_vulnerability/     # Security vulnerability detection agent
│   ├── agent.py
│   ├── llm_client.py           # Mock LLM + chat response generator
│   ├── rag_client.py           # RAG knowledge base (OWASP + Clean Code)
│   └── detectors/
│       ├── sqli.py
│       ├── xss.py
│       ├── csrf.py
│       ├── secrets.py
│       ├── auth.py
│       ├── access_control.py
│       └── llm_detector.py
│
├── remediation/                # Remediation suggestion agent
│   ├── agent.py
│   └── remediation_rules.py
│
├── pr_summary/                 # PR Summary agent
│   └── agent.py
│
├── orchestration/              # Parallel pipeline orchestrator
│   └── pipeline.py
│
├── shared/                     # Shared data models
│   └── models.py               # Finding, Remediation, PRSummary dataclasses
│
├── portal/                     # React/Vite developer portal
│   ├── src/
│   │   ├── App.jsx
│   │   ├── components/
│   │   │   ├── FindingCard.jsx     # GitHub-style PR thread + chat panel
│   │   │   ├── HealthScore.jsx     # Animated health score gauge
│   │   │   └── SeverityBadges.jsx
│   │   └── data/
│   │       └── prSummary.js        # Health score computation logic
│   └── package.json
│
├── chat_server.py              # Python http.server backend for chat API
├── test_scenarios/             # Sample vulnerable files for demo
│   ├── sql_injection.py
│   ├── hardcoded_password.py
│   ├── xss.py
│   └── missing_auth.py
│
├── tests/                      # Pytest test suite
├── pyproject.toml
└── README.md
```

---

## ⚡ Quick Start

### 1. Install dependencies

```bash
uv sync
# or
pip install -e .
```

### 2. Run the full pipeline

```python
from orchestration.pipeline import UnifiedOrchestrator

orchestrator = UnifiedOrchestrator()

with open("test_scenarios/sql_injection.py") as f:
    source = f.read()

results = orchestrator.run(source, language="python")
print(results.pr_summary)
```

### 3. Start the Developer Portal

```bash
# Terminal 1 — React frontend (http://localhost:5173)
cd portal
npm install
npm run dev

# Terminal 2 — Chat backend API (http://localhost:8000)
uv run python chat_server.py
```

---

## 🏥 Health Score Formula

The portal displays a **0–100 health score** computed as:

```
score = 100 - (15 × critical) - (8 × high) - (3 × medium) - (1 × low)
score = max(0, score)
```

| Severity | Deduction |
|---|---|
| 🔴 Critical | −15 |
| 🟠 High     | −8  |
| 🟡 Medium   | −3  |
| ⚪ Low      | −1  |

---

## 💬 Conversational Code Assistant

Each finding card in the portal includes a chat panel powered by the backend API. Developers can ask natural follow-up questions:

- *"Why is this a problem?"*
- *"How do I fix it properly?"*
- *"Can you explain that differently?"*

The assistant maintains **multi-turn conversation context** per finding session (in-memory) and grounds every response using the RAG knowledge base (OWASP Top 10 + Clean Code guidelines).

**API Endpoint:**
```
POST http://localhost:8000/api/chat

{
  "message": "Why is this a problem?",
  "finding_context": { "finding_type": "sql_injection", "line_number": 12, ... },
  "chat_history": [{ "role": "user", "text": "..." }, { "role": "bot", "text": "..." }]
}
```

---

## 🔐 Security Detectors

| Detector | OWASP Category | CWE |
|---|---|---|
| SQL Injection | A03:2021 – Injection | CWE-89 |
| Cross-Site Scripting (XSS) | A03:2021 – Injection | CWE-79 |
| CSRF | A01:2021 – Broken Access Control | CWE-352 |
| Hardcoded Secrets | A02:2021 – Cryptographic Failures | CWE-798 |
| Weak Auth / Password Hashing | A07:2021 – Auth Failures | CWE-916 |
| Broken Access Control | A01:2021 – Broken Access Control | CWE-639 |

---

## 🧪 Running Tests

```bash
uv run python -m pytest tests/ -v
```

---

## 📸 Demo

Run a test scenario through the full pipeline:

```bash
uv run python demo_pr_summary.py
```

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Backend agents | Python 3.12+ (zero external dependencies) |
| Parallelism | `concurrent.futures.ThreadPoolExecutor` |
| RAG client | Keyword-based OWASP/Clean Code guideline matcher |
| Chat API server | Python built-in `http.server` |
| Frontend | React 18 + Vite |
| Syntax highlighting | `react-syntax-highlighter` (VSCode Dark+ theme) |
| Package manager | `uv` |

---

## 👤 Author

**Ayush Singh** — `kumar-ayushsingh`
