"""
remediation/remediation_rules.py
---------------------------------
Rule-based lookup table that maps every SmellType and VulnerabilityType
to a Remediation recipe (corrected_code snippet, explanation, principle).

Each entry is a dict with three string keys:
  corrected_code – illustrative fixed snippet (language-neutral pseudocode or Python)
  explanation    – 2-3 sentences on *why* the fix works
  principle      – named standard / guideline being applied
"""

RULES: dict[str, dict[str, str]] = {

    # ── Code Smells ────────────────────────────────────────────────────────

    "long_method": {
        "corrected_code": (
            "# BEFORE (long monolithic method)\n"
            "def process_order(order):\n"
            "    # 80 lines of validation, pricing, inventory, email ...\n\n"
            "# AFTER (decomposed into focused helpers)\n"
            "def process_order(order):\n"
            "    _validate_order(order)\n"
            "    price = _calculate_price(order)\n"
            "    _reserve_inventory(order)\n"
            "    _send_confirmation_email(order, price)\n\n"
            "def _validate_order(order): ...\n"
            "def _calculate_price(order) -> float: ...\n"
            "def _reserve_inventory(order): ...\n"
            "def _send_confirmation_email(order, price): ..."
        ),
        "explanation": (
            "Long methods violate the Single Responsibility Principle and become "
            "hard to test and reason about in isolation. Extracting cohesive blocks "
            "into named helpers makes each piece independently testable and gives "
            "readers a high-level narrative of what the parent method does without "
            "drowning in implementation detail."
        ),
        "principle": "Clean Code – Single Responsibility Principle (SRP); Robert C. Martin",
    },

    "duplicate_code": {
        "corrected_code": (
            "# BEFORE – same logic copy-pasted in two places\n"
            "def send_welcome_email(user):\n"
            "    msg = build_email(user.email, 'Welcome', welcome_body(user))\n"
            "    smtp.send(msg)\n\n"
            "def send_reset_email(user):\n"
            "    msg = build_email(user.email, 'Reset', reset_body(user))\n"
            "    smtp.send(msg)\n\n"
            "# AFTER – shared helper eliminates duplication\n"
            "def _send_email(user, subject, body_fn):\n"
            "    msg = build_email(user.email, subject, body_fn(user))\n"
            "    smtp.send(msg)\n\n"
            "def send_welcome_email(user): _send_email(user, 'Welcome', welcome_body)\n"
            "def send_reset_email(user):   _send_email(user, 'Reset',   reset_body)"
        ),
        "explanation": (
            "Duplicated code means that any bug fix or behaviour change must be "
            "applied in multiple places simultaneously, which is error-prone. "
            "Extracting the shared logic into a single function makes future changes "
            "atomic and guarantees both call sites behave identically."
        ),
        "principle": "DRY – Don't Repeat Yourself (Hunt & Thomas, The Pragmatic Programmer)",
    },

    "poor_naming": {
        "corrected_code": (
            "# BEFORE – cryptic single-letter or generic names\n"
            "def calc(a, b):\n"
            "    t = a * 1.18\n"
            "    return t + b\n\n"
            "# AFTER – names reveal intent\n"
            "def calculate_price_with_tax(base_price: float, shipping_cost: float) -> float:\n"
            "    price_with_vat = base_price * 1.18\n"
            "    return price_with_vat + shipping_cost"
        ),
        "explanation": (
            "Names are the primary communication tool in source code. "
            "Single-letter or generic names force readers to trace execution to "
            "understand intent, increasing cognitive load. Descriptive names act as "
            "inline documentation, making the code self-explanatory and reducing "
            "the chance of misuse."
        ),
        "principle": "Clean Code – Meaningful Names; Robert C. Martin (Chapter 2)",
    },

    "high_complexity": {
        "corrected_code": (
            "# BEFORE – deeply nested, CC = 12\n"
            "def process(req):\n"
            "    if req.user:\n"
            "        if req.user.is_active:\n"
            "            if req.data:\n"
            "                if req.data.get('type') == 'order':\n"
            "                    # ... more nesting ...\n\n"
            "# AFTER – guard clauses flatten the nesting, CC = 4\n"
            "def process(req):\n"
            "    if not req.user:          raise AuthError('No user')\n"
            "    if not req.user.is_active: raise AuthError('Inactive user')\n"
            "    if not req.data:           raise ValueError('No payload')\n"
            "    if req.data.get('type') != 'order': return _handle_other(req)\n"
            "    return _process_order(req)"
        ),
        "explanation": (
            "High cyclomatic complexity (many branches) means exponentially more "
            "test cases are required for full coverage, and bugs hide in untested "
            "paths. Guard clauses (early returns on invalid preconditions) invert "
            "nested conditionals, reducing nesting depth and making the happy path "
            "read top-to-bottom without mental stack-tracking."
        ),
        "principle": "Refactoring – Replace Nested Conditional with Guard Clauses; Martin Fowler",
    },

    "tight_coupling": {
        "corrected_code": (
            "# BEFORE – hard-wired dependency, impossible to unit-test\n"
            "class OrderService:\n"
            "    def __init__(self):\n"
            "        self.db = MySQLDatabase()   # concrete class\n\n"
            "# AFTER – depend on an abstraction (Dependency Injection)\n"
            "from abc import ABC, abstractmethod\n\n"
            "class DatabasePort(ABC):\n"
            "    @abstractmethod\n"
            "    def save(self, record): ...\n\n"
            "class OrderService:\n"
            "    def __init__(self, db: DatabasePort):\n"
            "        self.db = db   # injected – swap for FakeDB in tests"
        ),
        "explanation": (
            "Instantiating concrete dependencies inside a class creates tight "
            "coupling — the class cannot be used without its dependency, and tests "
            "cannot substitute fakes. Dependency Injection decouples the consumer "
            "from the provider, enabling polymorphism, easier testing, and painless "
            "replacement of implementations."
        ),
        "principle": "SOLID – Dependency Inversion Principle (DIP); Robert C. Martin",
    },

    # ── Security Vulnerabilities ───────────────────────────────────────────

    "sql_injection": {
        "corrected_code": (
            "# BEFORE – string-concatenated query (VULNERABLE)\n"
            "query = \"SELECT * FROM users WHERE username='\" + username + \"'\"\n"
            "cursor.execute(query)\n\n"
            "# AFTER – parameterized query (SAFE)\n"
            "cursor.execute(\n"
            "    \"SELECT * FROM users WHERE username = %s\",\n"
            "    (username,),\n"
            ")\n\n"
            "# SQLAlchemy ORM alternative\n"
            "user = session.query(User).filter_by(username=username).first()"
        ),
        "explanation": (
            "Parameterized queries send the SQL template and user data as separate "
            "payloads to the database engine, which treats the data strictly as a "
            "value — never as executable SQL. This completely prevents an attacker "
            "from escaping the string context and injecting arbitrary SQL commands, "
            "regardless of the characters in the input."
        ),
        "principle": "OWASP A03:2021 – Injection; CWE-89",
    },

    "xss": {
        "corrected_code": (
            "# BEFORE – raw user input reflected into HTML (VULNERABLE)\n"
            "response.write('<p>' + user_comment + '</p>')\n\n"
            "# AFTER – HTML-encode all user-controlled values\n"
            "import html\n"
            "safe_comment = html.escape(user_comment)\n"
            "response.write(f'<p>{safe_comment}</p>')\n\n"
            "# In a template engine (Jinja2 auto-escaping, recommended)\n"
            "# {{ user_comment }}   ← auto-escaped when autoescape=True"
        ),
        "explanation": (
            "XSS occurs when untrusted data is inserted into an HTML context without "
            "encoding, allowing attackers to inject <script> tags or event handlers "
            "that execute in victims' browsers. HTML-encoding converts dangerous "
            "characters (< > & \" ') into their entity equivalents, making them "
            "display as text instead of being interpreted as markup."
        ),
        "principle": "OWASP A03:2021 – Injection (XSS); CWE-79",
    },

    "csrf": {
        "corrected_code": (
            "# BEFORE – state-changing POST with no CSRF protection (VULNERABLE)\n"
            "@app.route('/transfer', methods=['POST'])\n"
            "def transfer():\n"
            "    amount = request.form['amount']\n"
            "    ...\n\n"
            "# AFTER – validate a synchronizer token on every mutating request\n"
            "from flask_wtf.csrf import CSRFProtect\n"
            "csrf = CSRFProtect(app)\n\n"
            "@app.route('/transfer', methods=['POST'])\n"
            "def transfer():\n"
            "    # flask-wtf automatically validates the CSRF token\n"
            "    # In your form: {{ form.hidden_tag() }} or X-CSRFToken header\n"
            "    amount = request.form['amount']\n"
            "    ..."
        ),
        "explanation": (
            "CSRF exploits the browser's automatic inclusion of session cookies in "
            "cross-origin requests, tricking an authenticated user's browser into "
            "performing unintended actions. A synchronizer token (a unique, "
            "unpredictable value tied to the session) must be present in every "
            "mutating request. Because an attacker's page cannot read the token "
            "(same-origin policy), forged requests are rejected."
        ),
        "principle": "OWASP A01:2021 – Broken Access Control (CSRF); CWE-352",
    },

    "hardcoded_secret": {
        "corrected_code": (
            "# BEFORE – secret in source code (VULNERABLE)\n"
            "API_KEY = 'sk_live_9f8a7b6c5d4e3f2a'\n"
            "DB_PASSWORD = 'SuperSecret123!'\n\n"
            "# AFTER – read from environment at runtime\n"
            "import os\n"
            "API_KEY    = os.environ['API_KEY']       # set in .env / secrets manager\n"
            "DB_PASSWORD = os.environ['DB_PASSWORD']\n\n"
            "# Or with python-decouple / pydantic-settings:\n"
            "from decouple import config\n"
            "API_KEY = config('API_KEY')"
        ),
        "explanation": (
            "Credentials embedded in source code are exposed to anyone with read "
            "access to the repository, including contributors, CI systems, and "
            "anyone who ever clones the repo. Storing secrets in environment "
            "variables or a dedicated secrets manager (AWS Secrets Manager, "
            "HashiCorp Vault) separates configuration from code and allows rotation "
            "without a code change or redeployment."
        ),
        "principle": "OWASP A02:2021 – Cryptographic Failures; CWE-798 (Hard-coded Credentials)",
    },

    "insecure_auth": {
        "corrected_code": (
            "# BEFORE – MD5/SHA1 for password hashing (VULNERABLE)\n"
            "import hashlib\n"
            "hashed = hashlib.md5(password.encode()).hexdigest()\n\n"
            "# AFTER – use a slow, salted adaptive hash (bcrypt)\n"
            "import bcrypt\n\n"
            "# Hashing (on registration)\n"
            "hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))\n\n"
            "# Verification (on login)\n"
            "is_valid = bcrypt.checkpw(password.encode(), hashed)"
        ),
        "explanation": (
            "MD5 and SHA-1 are fast, general-purpose hash functions — attackers can "
            "compute billions of candidates per second on commodity hardware. "
            "Password hashing requires a deliberately slow, salted adaptive algorithm "
            "(bcrypt, Argon2, scrypt) so that even if the hash database is stolen, "
            "brute-forcing each password takes prohibitive time. The random salt also "
            "prevents precomputed rainbow-table attacks."
        ),
        "principle": "OWASP A07:2021 – Identification and Authentication Failures; CWE-916",
    },

    "broken_access_control": {
        "corrected_code": (
            "# BEFORE – route deletes any account with no ownership check (VULNERABLE)\n"
            "@app.route('/account/<account_id>/delete', methods=['POST'])\n"
            "def delete_account(account_id):\n"
            "    delete_account_from_db(account_id)\n"
            "    return {'status': 'deleted'}\n\n"
            "# AFTER – enforce that the session user owns the resource\n"
            "@app.route('/account/<account_id>/delete', methods=['POST'])\n"
            "@login_required\n"
            "def delete_account(account_id):\n"
            "    account = get_account_or_404(account_id)\n"
            "    if account.owner_id != current_user.id:\n"
            "        abort(403)   # Forbidden\n"
            "    delete_account_from_db(account_id)\n"
            "    return {'status': 'deleted'}"
        ),
        "explanation": (
            "Without an ownership or role check, any authenticated (or even "
            "unauthenticated) user can manipulate another user's resources by "
            "guessing or enumerating identifiers — an Insecure Direct Object "
            "Reference (IDOR). The fix verifies that the requesting user is "
            "actually authorised to act on the specific resource before executing "
            "the operation, enforcing the principle of least privilege."
        ),
        "principle": "OWASP A01:2021 – Broken Access Control; CWE-639 (IDOR)",
    },
}

# ── Fallback for any type not in the table ────────────────────────────────────
FALLBACK_RULE: dict[str, str] = {
    "corrected_code": (
        "# Review the flagged code and apply the relevant best-practice fix.\n"
        "# Consult the description field for specific guidance."
    ),
    "explanation": (
        "This finding type does not yet have a specific remediation template. "
        "Refer to the finding description and the principle reference for guidance."
    ),
    "principle": "OWASP Top 10 / Clean Code best practices",
}
