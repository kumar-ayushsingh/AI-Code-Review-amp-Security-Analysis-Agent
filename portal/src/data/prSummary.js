// Sample PR Summary data mirroring real pipeline output
export const PR_SUMMARY = {
  filename: "auth_service.py",
  executive_overview:
    "`auth_service.py` requires attention before merging: 5 finding(s) detected (2 critical, 1 high, 1 medium, 1 low). Address all critical and high-severity issues immediately — they represent active security risks or serious maintainability blockers.",
  severity_breakdown: { critical: 2, high: 1, medium: 1, low: 1, total: 5 },
  has_critical: true,
  has_blocking: true,
  agent_contributions: { security_vulnerability: 2, code_analysis: 3 },
  prioritized_fixes: [
    {
      rank: 1,
      severity: "critical",
      finding_type: "hardcoded_secret",
      line_number: 3,
      source_agent: "security_vulnerability",
      one_liner: "Hardcoded API key found in source code",
      fix_action:
        "Credentials embedded in source code are exposed to anyone with read access to the repository. Store secrets in environment variables or a dedicated secrets manager.",
      principle: "OWASP A02:2021 – Cryptographic Failures; CWE-798",
      remediation: {
        corrected_code: `# BEFORE – secret in source code (VULNERABLE)
API_KEY = 'sk_live_9f8a7b6c5d4e3f2a'
DB_PASSWORD = 'SuperSecret123!'

# AFTER – read from environment at runtime
import os
API_KEY     = os.environ['API_KEY']       # set in .env / secrets manager
DB_PASSWORD = os.environ['DB_PASSWORD']

# Or with python-decouple:
from decouple import config
API_KEY = config('API_KEY')`,
        explanation:
          "[RAG Guideline] Guideline SEC-04: Never hardcode credentials in source code. Store secrets in environment variables or a dedicated secrets manager such as AWS Secrets Manager or HashiCorp Vault (OWASP A02:2021).\n\nCredentials embedded in source code are exposed to anyone with read access to the repository, including contributors and CI systems. Storing secrets in environment variables separates configuration from code and allows rotation without a code change.",
        principle: "OWASP A02:2021 – Cryptographic Failures; CWE-798 (Hard-coded Credentials)",
      },
    },
    {
      rank: 2,
      severity: "critical",
      finding_type: "sql_injection",
      line_number: 15,
      source_agent: "security_vulnerability",
      one_liner: "SQL injection via string concatenation in login query",
      fix_action:
        "Replace string-concatenated queries with parameterized queries so user input is never treated as executable SQL.",
      principle: "OWASP A03:2021 – Injection; CWE-89",
      remediation: {
        corrected_code: `# BEFORE – string-concatenated query (VULNERABLE)
query = "SELECT * FROM users WHERE username='" + username + "'"
cursor.execute(query)

# AFTER – parameterized query (SAFE)
cursor.execute(
    "SELECT * FROM users WHERE username = %s",
    (username,),
)

# SQLAlchemy ORM alternative
user = session.query(User).filter_by(username=username).first()`,
        explanation:
          "[RAG Guideline] Guideline SEC-01: Always use parameterized queries or ORMs to prevent SQL Injection (OWASP A03:2021; CWE-89). Never concatenate user-supplied input directly into SQL strings.\n\nParameterized queries send the SQL template and user data as separate payloads to the database engine, which treats the data strictly as a value — never as executable SQL. This completely prevents an attacker from escaping the string context and injecting arbitrary commands.",
        principle: "OWASP A03:2021 – Injection; CWE-89",
      },
    },
    {
      rank: 3,
      severity: "high",
      finding_type: "high_complexity",
      line_number: 40,
      source_agent: "code_analysis",
      one_liner: "Function process() has cyclomatic complexity 14 (threshold: 5)",
      fix_action:
        "Apply guard clauses (early returns) to flatten deep nesting and reduce cyclomatic complexity below 10.",
      principle: "Refactoring – Replace Nested Conditional with Guard Clauses; Martin Fowler",
      remediation: {
        corrected_code: `# BEFORE – deeply nested, CC = 14
def process(req):
    if req.user:
        if req.user.is_active:
            if req.data:
                if req.data.get('type') == 'order':
                    # ... more nesting ...

# AFTER – guard clauses flatten nesting, CC = 4
def process(req):
    if not req.user:           raise AuthError('No user')
    if not req.user.is_active: raise AuthError('Inactive user')
    if not req.data:           raise ValueError('No payload')
    if req.data.get('type') != 'order': return _handle_other(req)
    return _process_order(req)`,
        explanation:
          "[RAG Guideline] Guideline CC-04: Keep cyclomatic complexity below 10 per function. Use guard clauses (early returns) to avoid deep nesting and reduce cognitive load.\n\nHigh cyclomatic complexity means exponentially more test cases are required for full coverage, and bugs hide in untested paths. Guard clauses invert nested conditionals, reducing nesting depth and making the happy path read top-to-bottom without mental stack-tracking.",
        principle: "Refactoring – Replace Nested Conditional with Guard Clauses; Martin Fowler",
      },
    },
    {
      rank: 4,
      severity: "medium",
      finding_type: "poor_naming",
      line_number: 7,
      source_agent: "code_analysis",
      one_liner: "Single-letter variable 'x' is not self-documenting",
      fix_action:
        "Replace single-letter or generic names with intention-revealing names that describe the variable's role.",
      principle: "Clean Code – Meaningful Names; Robert C. Martin (Chapter 2)",
      remediation: {
        corrected_code: `# BEFORE – cryptic single-letter names
def calc(a, b):
    t = a * 1.18
    return t + b

# AFTER – names reveal intent
def calculate_price_with_tax(
    base_price: float, shipping_cost: float
) -> float:
    price_with_vat = base_price * 1.18
    return price_with_vat + shipping_cost`,
        explanation:
          "[RAG Guideline] Guideline CC-03: Use intention-revealing names. Names should tell the reader why the variable exists, what it does, and how it is used.\n\nSingle-letter or generic names force readers to trace execution to understand intent, increasing cognitive load. Descriptive names act as inline documentation, making the code self-explanatory and reducing the chance of misuse.",
        principle: "Clean Code – Meaningful Names; Robert C. Martin (Chapter 2)",
      },
    },
    {
      rank: 5,
      severity: "low",
      finding_type: "duplicate_code",
      line_number: 22,
      source_agent: "code_analysis",
      one_liner: "Duplicate block of 6+ lines found at lines 22-28 and 45-51",
      fix_action:
        "Extract the shared logic into a single reusable function to eliminate duplication and apply the DRY principle.",
      principle: "DRY – Don't Repeat Yourself (Hunt & Thomas, The Pragmatic Programmer)",
      remediation: {
        corrected_code: `# BEFORE – same logic copy-pasted in two places
def send_welcome_email(user):
    msg = build_email(user.email, 'Welcome', welcome_body(user))
    smtp.send(msg)

def send_reset_email(user):
    msg = build_email(user.email, 'Reset', reset_body(user))
    smtp.send(msg)

# AFTER – shared helper eliminates duplication
def _send_email(user, subject, body_fn):
    msg = build_email(user.email, subject, body_fn(user))
    smtp.send(msg)

def send_welcome_email(user): _send_email(user, 'Welcome', welcome_body)
def send_reset_email(user):   _send_email(user, 'Reset',   reset_body)`,
        explanation:
          "[RAG Guideline] Guideline CC-02: Don't Repeat Yourself (DRY). Every piece of knowledge should have a single, authoritative representation in the system.\n\nDuplicated code means that any bug fix or behaviour change must be applied in multiple places simultaneously, which is error-prone. Extracting shared logic into a single function makes future changes atomic and guarantees both call sites behave identically.",
        principle: "DRY – Don't Repeat Yourself (Hunt & Thomas, The Pragmatic Programmer)",
      },
    },
  ],
};

export function computeHealthScore(breakdown) {
  const penalties = {
    critical: 15,
    high: 8,
    medium: 3,
    low: 1,
  };
  const deduction =
    (breakdown.critical || 0) * penalties.critical +
    (breakdown.high || 0) * penalties.high +
    (breakdown.medium || 0) * penalties.medium +
    (breakdown.low || 0) * penalties.low;
  return Math.max(0, 100 - deduction);
}
