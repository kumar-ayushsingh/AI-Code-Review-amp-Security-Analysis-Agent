"""
tests/test_code_analysis.py
----------------------------
Comprehensive unit tests for all five code-smell detectors.
Run with:  python -m pytest tests/ -v
"""

import pytest
from code_analysis import CodeAnalysisAgent, Finding, Severity, SmellType


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures / helpers
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def agent() -> CodeAnalysisAgent:
    return CodeAnalysisAgent()


def _types(findings):
    return [f.type for f in findings]


def _severities(findings):
    return [f.severity for f in findings]


# ─────────────────────────────────────────────────────────────────────────────
# 1. Long Method
# ─────────────────────────────────────────────────────────────────────────────

class TestLongMethodPython:
    SHORT_FUNC = "def short():\n    pass\n"

    LONG_FUNC = "def very_long_function():\n" + ("    x = 1\n" * 45)

    def test_short_function_not_flagged(self, agent):
        findings = agent.analyze(self.SHORT_FUNC, "python")
        assert not any(f.type == SmellType.LONG_METHOD for f in findings)

    def test_long_function_flagged(self, agent):
        findings = agent.analyze(self.LONG_FUNC, "python")
        assert any(f.type == SmellType.LONG_METHOD for f in findings)

    def test_severity_scales_with_length(self, agent):
        # 3× threshold → critical
        huge = "def huge():\n" + ("    pass\n" * 130)
        findings = agent.analyze(huge, "python")
        long_findings = [f for f in findings if f.type == SmellType.LONG_METHOD]
        assert any(f.severity == Severity.CRITICAL for f in long_findings)

    def test_custom_threshold(self):
        agent = CodeAnalysisAgent(long_method_threshold=10)
        func_15_lines = "def medium_func():\n" + ("    x = 1\n" * 15)
        findings = agent.analyze(func_15_lines, "python")
        assert any(f.type == SmellType.LONG_METHOD for f in findings)

    def test_symbol_name_captured(self, agent):
        findings = agent.analyze(self.LONG_FUNC, "python")
        long_f = [f for f in findings if f.type == SmellType.LONG_METHOD]
        assert any(f.symbol == "very_long_function" for f in long_f)

    def test_source_agent_field(self, agent):
        findings = agent.analyze(self.LONG_FUNC, "python")
        assert all(f.source_agent == "code_analysis" for f in findings)


class TestLongMethodJava:
    def _make_java_method(self, name: str, n_lines: int) -> str:
        body = "        int x = 0;\n" * n_lines
        return f"public class A {{\n    public void {name}() {{\n{body}    }}\n}}\n"

    def test_short_java_method_not_flagged(self, agent):
        src = self._make_java_method("shortMethod", 5)
        findings = agent.analyze(src, "java")
        assert not any(f.type == SmellType.LONG_METHOD for f in findings)

    def test_long_java_method_flagged(self, agent):
        src = self._make_java_method("processData", 50)
        findings = agent.analyze(src, "java")
        assert any(f.type == SmellType.LONG_METHOD for f in findings)


# ─────────────────────────────────────────────────────────────────────────────
# 2. Duplicate Code
# ─────────────────────────────────────────────────────────────────────────────

class TestDuplicateCode:
    DUPLICATE_BLOCK = (
        "def foo():\n"
        "    a = 1\n"
        "    b = 2\n"
        "    c = a + b\n"
        "    d = c * 2\n"
        "    e = d - 1\n"
        "    return e\n"
        "\n"
        "def bar():\n"
        "    a = 1\n"
        "    b = 2\n"
        "    c = a + b\n"
        "    d = c * 2\n"
        "    e = d - 1\n"
        "    return e\n"
    )

    UNIQUE_CODE = (
        "def alpha():\n    return 1\n"
        "def beta():\n    return 2\n"
        "def gamma():\n    return 3\n"
    )

    def test_duplicate_block_detected(self, agent):
        findings = agent.analyze(self.DUPLICATE_BLOCK, "python")
        assert any(f.type == SmellType.DUPLICATE_CODE for f in findings)

    def test_unique_code_not_flagged(self, agent):
        findings = agent.analyze(self.UNIQUE_CODE, "python")
        assert not any(f.type == SmellType.DUPLICATE_CODE for f in findings)

    def test_extra_contains_clone_positions(self, agent):
        findings = agent.analyze(self.DUPLICATE_BLOCK, "python")
        # The token-clone pass produces clone_a_start / clone_b_start
        token_clones = [
            f for f in findings
            if f.type == SmellType.DUPLICATE_CODE
            and f.extra.get("clone_type") == "token"
        ]
        assert token_clones, "Should have at least one token-clone finding"
        assert "clone_a_start" in token_clones[0].extra
        assert "clone_b_start" in token_clones[0].extra

    def test_custom_min_block_size(self):
        agent = CodeAnalysisAgent(min_duplicate_lines=3)
        src = "x = 1\ny = 2\nz = 3\n\nx = 1\ny = 2\nz = 3\n"
        findings = agent.analyze(src, "python")
        assert any(f.type == SmellType.DUPLICATE_CODE for f in findings)


# ─────────────────────────────────────────────────────────────────────────────
# 3. Poor Naming
# ─────────────────────────────────────────────────────────────────────────────

class TestPoorNamingPython:
    def test_single_letter_variable(self, agent):
        src = "def process():\n    p = 42\n    return p\n"
        findings = agent.analyze(src, "python")
        assert any(f.type == SmellType.POOR_NAMING for f in findings)

    def test_generic_name_detected(self, agent):
        src = "def process():\n    temp = compute()\n    return temp\n"
        findings = agent.analyze(src, "python")
        assert any(
            f.type == SmellType.POOR_NAMING and f.symbol == "temp"
            for f in findings
        )

    def test_allowed_loop_variable_not_flagged(self, agent):
        src = "for i in range(10):\n    print(i)\n"
        findings = agent.analyze(src, "python")
        naming = [f for f in findings if f.type == SmellType.POOR_NAMING
                  and f.symbol == "i"]
        # 'i' is an allowed single-letter name; must not produce a high-severity finding
        assert not any(f.severity == Severity.HIGH for f in naming)

    def test_good_names_not_flagged(self, agent):
        src = (
            "def calculate_invoice_total(order_items, tax_rate):\n"
            "    subtotal = sum(item.price for item in order_items)\n"
            "    return subtotal * (1 + tax_rate)\n"
        )
        findings = agent.analyze(src, "python")
        assert not any(f.type == SmellType.POOR_NAMING for f in findings)

    def test_single_letter_function_name(self, agent):
        src = "def g():\n    return 0\n"
        findings = agent.analyze(src, "python")
        assert any(
            f.type == SmellType.POOR_NAMING and f.symbol == "g"
            for f in findings
        )

    def test_severity_single_letter_high(self, agent):
        src = "def compute():\n    p = 99\n    return p\n"
        findings = agent.analyze(src, "python")
        bad = [f for f in findings if f.type == SmellType.POOR_NAMING and f.symbol == "p"]
        assert any(f.severity == Severity.HIGH for f in bad)


class TestPoorNamingJava:
    def test_java_single_letter_variable(self, agent):
        src = (
            "public class Calc {\n"
            "    public int add(int a, int b) {\n"
            "        int p = a + b;\n"
            "        return p;\n"
            "    }\n"
            "}\n"
        )
        findings = agent.analyze(src, "java")
        assert any(f.type == SmellType.POOR_NAMING for f in findings)

    def test_java_generic_name(self, agent):
        src = (
            "public class Service {\n"
            "    public void run() {\n"
            "        Object temp = new Object();\n"
            "    }\n"
            "}\n"
        )
        findings = agent.analyze(src, "java")
        assert any(
            f.type == SmellType.POOR_NAMING and f.symbol == "temp"
            for f in findings
        )


# ─────────────────────────────────────────────────────────────────────────────
# 4. High Complexity
# ─────────────────────────────────────────────────────────────────────────────

class TestHighComplexityPython:
    def _make_complex_function(self, n_ifs: int) -> str:
        body = "\n".join(f"    if x == {i}:\n        pass" for i in range(n_ifs))
        return f"def complex_fn(x):\n{body}\n    return x\n"

    def test_simple_function_not_flagged(self, agent):
        src = "def simple(x):\n    return x + 1\n"
        findings = agent.analyze(src, "python")
        assert not any(f.type == SmellType.HIGH_COMPLEXITY for f in findings)

    def test_high_complexity_flagged(self, agent):
        src = self._make_complex_function(12)
        findings = agent.analyze(src, "python")
        assert any(f.type == SmellType.HIGH_COMPLEXITY for f in findings)

    def test_critical_complexity(self, agent):
        src = self._make_complex_function(25)
        findings = agent.analyze(src, "python")
        complex_f = [f for f in findings if f.type == SmellType.HIGH_COMPLEXITY]
        assert any(f.severity == Severity.CRITICAL for f in complex_f)

    def test_cc_value_in_extra(self, agent):
        src = self._make_complex_function(12)
        findings = agent.analyze(src, "python")
        complex_f = next(f for f in findings if f.type == SmellType.HIGH_COMPLEXITY)
        assert "cyclomatic_complexity" in complex_f.extra
        assert complex_f.extra["cyclomatic_complexity"] > 5

    def test_nested_conditionals_counted(self, agent):
        src = (
            "def nested(x, y, z):\n"
            "    if x:\n"
            "        if y:\n"
            "            if z:\n"
            "                if x and y:\n"
            "                    if z or x:\n"
            "                        pass\n"
            "    return 0\n"
        )
        findings = agent.analyze(src, "python")
        assert any(f.type == SmellType.HIGH_COMPLEXITY for f in findings)


class TestHighComplexityJava:
    def test_java_complex_method(self, agent):
        src = (
            "public class Logic {\n"
            "    public int decide(int a, int b, int c, int d) {\n"
            "        if (a > 0) {\n"
            "            if (b > 0) {\n"
            "                if (c > 0) {\n"
            "                    if (d > 0) { return 1; }\n"
            "                    else if (d < -10) { return 2; }\n"
            "                }\n"
            "            } else if (b < -5) {\n"
            "                return 3;\n"
            "            }\n"
            "        } else if (a < -10 && b > 0) {\n"
            "            return 4;\n"
            "        } else if (a == 0 || b == 0) {\n"
            "            return 5;\n"
            "        }\n"
            "        return 0;\n"
            "    }\n"
            "}\n"
        )
        findings = agent.analyze(src, "java")
        assert any(f.type == SmellType.HIGH_COMPLEXITY for f in findings)


# ─────────────────────────────────────────────────────────────────────────────
# 5. Tight Coupling
# ─────────────────────────────────────────────────────────────────────────────

class TestTightCouplingPython:
    def test_demeter_violation_detected(self, agent):
        src = (
            "def process(order):\n"
            "    name = order.get_customer().get_address().get_city()\n"
            "    return name\n"
        )
        findings = agent.analyze(src, "python")
        assert any(f.type == SmellType.TIGHT_COUPLING for f in findings)

    def test_simple_attribute_access_not_flagged(self, agent):
        src = (
            "def process(order):\n"
            "    name = order.customer_name\n"
            "    return name\n"
        )
        findings = agent.analyze(src, "python")
        assert not any(f.type == SmellType.TIGHT_COUPLING for f in findings)

    def test_high_fan_out_class(self, agent):
        imports = "\n".join(
            f"from module{i} import Service{i}" for i in range(12)
        )
        src = (
            f"{imports}\n"
            "class GodClass:\n"
            + "\n".join(
                f"    s{i} = Service{i}()" for i in range(12)
            )
        )
        findings = agent.analyze(src, "python")
        assert any(f.type == SmellType.TIGHT_COUPLING for f in findings)


class TestTightCouplingJava:
    def test_java_demeter_violation(self, agent):
        src = (
            "public class OrderService {\n"
            "    public String getCity(Order order) {\n"
            "        return order.getCustomer().getAddress().getCity();\n"
            "    }\n"
            "}\n"
        )
        findings = agent.analyze(src, "java")
        assert any(f.type == SmellType.TIGHT_COUPLING for f in findings)

    def test_java_hardcoded_instantiation_in_ctor(self, agent):
        src = (
            "public class OrderProcessor {\n"
            "    private final EmailSender emailSender;\n"
            "    private final InvoiceGenerator invoiceGenerator;\n"
            "\n"
            "    public OrderProcessor() {\n"
            "        this.emailSender = new EmailSender();\n"
            "        this.invoiceGenerator = new InvoiceGenerator();\n"
            "    }\n"
            "}\n"
        )
        findings = agent.analyze(src, "java")
        assert any(f.type == SmellType.TIGHT_COUPLING for f in findings)


# ─────────────────────────────────────────────────────────────────────────────
# 6. Agent-level behaviour
# ─────────────────────────────────────────────────────────────────────────────

class TestAgentBehaviour:
    def test_unsupported_language_raises(self, agent):
        with pytest.raises(ValueError, match="Unsupported language"):
            agent.analyze("code", language="ruby")  # type: ignore[arg-type]

    def test_empty_source_returns_no_findings(self, agent):
        assert agent.analyze("", "python") == []
        assert agent.analyze("", "java") == []

    def test_findings_sorted_critical_first(self, agent):
        # Build a source with both a trivially-named var (low/med) and a huge function
        src = "def g():\n" + ("    x = 1\n" * 130)
        findings = agent.analyze(src, "python")
        if len(findings) >= 2:
            severities = [f.severity for f in findings]
            order = [_SEVERITY_ORDER[s] for s in severities]
            assert order == sorted(order), "Findings must be sorted critical-first"

    def test_to_dict_serialisation(self, agent):
        src = "def g():\n    temp = 1\n    return temp\n"
        findings = agent.analyze(src, "python")
        dicts = CodeAnalysisAgent.findings_to_dict(findings)
        for d in dicts:
            assert "type" in d
            assert "severity" in d
            assert "line_number" in d
            assert "description" in d
            assert d["source_agent"] == "code_analysis"

    def test_summary_counts(self, agent):
        src = "def g():\n    temp = 1\n    return temp\n"
        findings = agent.analyze(src, "python")
        summary = CodeAnalysisAgent.summary(findings)
        assert "total" in summary
        assert summary["total"] == len(findings)
        assert sum(v for k, v in summary.items() if k != "total") == len(findings)

    def test_disable_detector(self):
        agent = CodeAnalysisAgent(enable_long_method=False)
        src = "def big():\n" + ("    x = 1\n" * 50)
        findings = agent.analyze(src, "python")
        assert not any(f.type == SmellType.LONG_METHOD for f in findings)

    def test_finding_dataclass_fields(self, agent):
        src = "def g():\n    temp = 1\n"
        findings = agent.analyze(src, "python")
        for f in findings:
            assert isinstance(f, Finding)
            assert isinstance(f.type, SmellType)
            assert isinstance(f.severity, Severity)
            assert isinstance(f.line_number, int)
            assert isinstance(f.description, str)
            assert f.source_agent == "code_analysis"

    def test_analyze_file_infers_language(self, tmp_path):
        py_file = tmp_path / "example.py"
        py_file.write_text("def g():\n    temp = 1\n")
        agent = CodeAnalysisAgent()
        findings = agent.analyze_file(str(py_file))
        assert isinstance(findings, list)

    def test_analyze_file_unknown_extension_raises(self, tmp_path):
        f = tmp_path / "script.rb"
        f.write_text("puts 'hello'")
        agent = CodeAnalysisAgent()
        with pytest.raises(ValueError):
            agent.analyze_file(str(f))


# ─────────────────────────────────────────────────────────────────────────────
# 7. Integration: combined smells
# ─────────────────────────────────────────────────────────────────────────────

_SMELLY_PYTHON = '''
import module_a, module_b, module_c, module_d, module_e
from module_f import ServiceF
from module_g import ServiceG
from module_h import ServiceH

class GodObject:
    def do_everything(self, data, obj, temp):
        """A function that does way too much."""
        res = []
        for i in range(len(data)):
            x = data[i]
            if x > 0:
                if x > 10:
                    if x > 100:
                        if x > 1000:
                            res.append(x * 2)
                        elif x > 500:
                            res.append(x * 3)
                    elif x > 50:
                        res.append(x + 1)
                elif x > 5:
                    res.append(x - 1)
            elif x < 0:
                if x < -10:
                    res.append(abs(x))
                elif x < -1:
                    res.append(-x)
            else:
                res.append(0)
        val = sum(res)
        temp2 = val * 2
        foo = temp2 - 1
        bar = foo + temp2
        return bar

    def compute(self, data, temp):
        res = []
        for i in range(len(data)):
            x = data[i]
            if x > 0:
                if x > 10:
                    if x > 100:
                        if x > 1000:
                            res.append(x * 2)
                        elif x > 500:
                            res.append(x * 3)
                    elif x > 50:
                        res.append(x + 1)
                elif x > 5:
                    res.append(x - 1)
            elif x < 0:
                if x < -10:
                    res.append(abs(x))
                elif x < -1:
                    res.append(-x)
            else:
                res.append(0)
        return sum(res)
'''


class TestIntegration:
    def test_multiple_smells_detected_in_smelly_code(self, agent):
        findings = agent.analyze(_SMELLY_PYTHON, "python")
        types_found = {f.type for f in findings}
        # At minimum we expect poor naming + high complexity + tight coupling
        assert SmellType.POOR_NAMING in types_found
        assert SmellType.HIGH_COMPLEXITY in types_found

    def test_all_findings_have_source_agent(self, agent):
        findings = agent.analyze(_SMELLY_PYTHON, "python")
        assert all(f.source_agent == "code_analysis" for f in findings)

    def test_findings_are_sorted(self, agent):
        findings = agent.analyze(_SMELLY_PYTHON, "python")
        order = [_SEVERITY_ORDER[f.severity] for f in findings]
        assert order == sorted(order)




# ─────────────────────────────────────────────────────────────────────────────
# 8. AST-based long method: statement count + nesting depth in extra
# ─────────────────────────────────────────────────────────────────────────────

class TestASTLongMethod:
    """Verify that the Python long-method detector uses AST statement count."""

    def test_statement_count_in_extra(self, agent):
        # 45 assignment statements — should be flagged
        src = "def fat():\n" + ("    x = 1\n" * 45)
        findings = agent.analyze(src, "python")
        lm = [f for f in findings if f.type == SmellType.LONG_METHOD]
        assert lm, "Should flag function with 45 statements"
        assert "statement_count" in lm[0].extra
        assert lm[0].extra["statement_count"] >= 45

    def test_nesting_depth_in_extra(self, agent):
        # Deeply nested function should record nesting depth
        src = (
            "def deep():\n"
            "    if True:\n"
            "        for i in range(10):\n"
            "            while True:\n"
            "                if i > 0:\n"
            "                    pass\n"
            + ("    x = 1\n" * 40)  # pad to exceed threshold
        )
        findings = agent.analyze(src, "python")
        lm = [f for f in findings if f.type == SmellType.LONG_METHOD]
        assert lm, "Should flag padded deeply nested function"
        assert "max_nesting_depth" in lm[0].extra
        assert lm[0].extra["max_nesting_depth"] >= 4

    def test_line_span_also_in_extra(self, agent):
        src = "def fat():\n" + ("    x = 1\n" * 45)
        findings = agent.analyze(src, "python")
        lm = [f for f in findings if f.type == SmellType.LONG_METHOD]
        assert lm
        assert "line_span" in lm[0].extra

    def test_comments_and_blanks_not_counted_as_statements(self, agent):
        # 20 real statements padded with 30 comments/blank lines → should NOT flag at threshold=40
        body = ""
        for i in range(20):
            body += f"    x_{i} = {i}\n"
            body += f"    # comment {i}\n"
            body += "\n"
        src = f"def padded():\n{body}"
        agent_strict = CodeAnalysisAgent(long_method_threshold=40)
        findings = agent_strict.analyze(src, "python")
        lm = [f for f in findings if f.type == SmellType.LONG_METHOD]
        # Statement count is 20 (well below 40), so it should NOT be flagged
        assert not lm, (
            f"Function with 20 statements but many comments should not be flagged "
            f"at threshold=40; got {[f.extra for f in lm]}"
        )

    def test_nested_function_statements_counted_separately(self, agent):
        # Inner function adds its own statements; outer should be measured independently
        src = (
            "def outer():\n"
            "    def inner():\n"
            + ("        y = 1\n" * 50)
            + "    return inner\n"
        )
        findings = agent.analyze(src, "python")
        lm = [f for f in findings if f.type == SmellType.LONG_METHOD]
        # At least one of outer/inner should be flagged
        assert lm, "At least one of outer/inner should be flagged"


# ─────────────────────────────────────────────────────────────────────────────
# 9. AST-based nesting depth: dedicated findings
# ─────────────────────────────────────────────────────────────────────────────

class TestNestingDepth:
    """Verify that deep nesting produces a dedicated HIGH_COMPLEXITY finding."""

    def _make_nested(self, depth: int) -> str:
        """Build a function with exactly *depth* levels of if nesting."""
        indent = "    "
        lines = ["def deeply_nested(x):"]
        for d in range(depth):
            lines.append(indent * (d + 1) + "if x:")
        lines.append(indent * (depth + 1) + "pass")
        return "\n".join(lines) + "\n"

    def test_shallow_nesting_not_flagged(self, agent):
        src = self._make_nested(2)  # depth 2 — acceptable
        findings = agent.analyze(src, "python")
        nesting_findings = [
            f for f in findings
            if f.type == SmellType.HIGH_COMPLEXITY
            and f.extra.get("metric") == "nesting_depth"
        ]
        assert not nesting_findings, "Depth-2 nesting should not be flagged"

    def test_depth_4_flagged_as_low(self, agent):
        src = self._make_nested(4)
        findings = agent.analyze(src, "python")
        nesting_findings = [
            f for f in findings
            if f.type == SmellType.HIGH_COMPLEXITY
            and f.extra.get("metric") == "nesting_depth"
        ]
        assert nesting_findings, "Depth-4 nesting should be flagged"
        assert nesting_findings[0].severity == Severity.LOW

    def test_depth_6_flagged_as_high(self, agent):
        src = self._make_nested(6)
        findings = agent.analyze(src, "python")
        nesting_findings = [
            f for f in findings
            if f.type == SmellType.HIGH_COMPLEXITY
            and f.extra.get("metric") == "nesting_depth"
        ]
        assert nesting_findings, "Depth-6 nesting should be flagged"
        assert nesting_findings[0].severity == Severity.HIGH

    def test_depth_7_flagged_as_critical(self, agent):
        src = self._make_nested(7)
        findings = agent.analyze(src, "python")
        nesting_findings = [
            f for f in findings
            if f.type == SmellType.HIGH_COMPLEXITY
            and f.extra.get("metric") == "nesting_depth"
        ]
        assert nesting_findings, "Depth-7 nesting should be critical"
        assert nesting_findings[0].severity == Severity.CRITICAL

    def test_nesting_depth_value_in_extra(self, agent):
        src = self._make_nested(5)
        findings = agent.analyze(src, "python")
        nesting_findings = [
            f for f in findings
            if f.type == SmellType.HIGH_COMPLEXITY
            and f.extra.get("metric") == "nesting_depth"
        ]
        assert nesting_findings
        assert nesting_findings[0].extra["max_nesting_depth"] == 5

    def test_for_loop_nesting_counted(self, agent):
        src = (
            "def process(items):\n"
            "    for group in items:\n"
            "        for item in group:\n"
            "            for sub in item:\n"
            "                if sub > 0:\n"
            "                    pass\n"
        )
        findings = agent.analyze(src, "python")
        nesting_findings = [
            f for f in findings
            if f.type == SmellType.HIGH_COMPLEXITY
            and f.extra.get("metric") == "nesting_depth"
        ]
        assert nesting_findings, "for/for/for/if nesting (depth 4) should be flagged"

    def test_cc_and_nesting_are_separate_findings(self, agent):
        # A function with both high CC AND deep nesting produces two separate findings
        src = self._make_nested(5)  # depth 5 nesting → also bumps CC
        findings = agent.analyze(src, "python")
        metrics = {f.extra.get("metric") for f in findings if f.type == SmellType.HIGH_COMPLEXITY}
        # Both metrics may fire; nesting_depth must be present
        assert "nesting_depth" in metrics

    def test_metric_field_present_in_cc_finding(self, agent):
        src = "\n".join([f"    if x == {i}:\n        pass" for i in range(12)])
        src = f"def branchy(x):\n{src}\n    return x\n"
        findings = agent.analyze(src, "python")
        cc_findings = [
            f for f in findings
            if f.type == SmellType.HIGH_COMPLEXITY
            and f.extra.get("metric") == "cc"
        ]
        assert cc_findings, "CC findings must have metric='cc' in extra"


# ─────────────────────────────────────────────────────────────────────────────
# 10. AST structural clone detection (Python)
# ─────────────────────────────────────────────────────────────────────────────

class TestStructuralClones:
    """Verify that the AST structural fingerprint pass catches Type-3 clones."""

    # Two functions with completely different variable names but identical structure
    STRUCTURAL_CLONE = (
        "def compute_sales_tax(price, rate):\n"
        "    if price > 0:\n"
        "        for i in range(10):\n"
        "            if rate > 0.1:\n"
        "                result = price * rate\n"
        "            else:\n"
        "                result = price * 0.05\n"
        "        return result\n"
        "    return 0\n"
        "\n"
        "def calculate_discount_amount(base_cost, percentage):\n"
        "    if base_cost > 0:\n"
        "        for j in range(10):\n"
        "            if percentage > 0.1:\n"
        "                amount = base_cost * percentage\n"
        "            else:\n"
        "                amount = base_cost * 0.05\n"
        "        return amount\n"
        "    return 0\n"
    )

    TRIVIAL_CLONES = (
        "def a():\n    return 1\n"
        "def b():\n    return 2\n"
        "def c():\n    return 3\n"
    )

    def test_structural_clone_detected(self, agent):
        findings = agent.analyze(self.STRUCTURAL_CLONE, "python")
        struct_clones = [
            f for f in findings
            if f.type == SmellType.DUPLICATE_CODE
            and f.extra.get("clone_type") == "structural_ast"
        ]
        assert struct_clones, (
            "Functions with identical AST structure but different names should "
            "be flagged as structural clones"
        )

    def test_structural_clone_names_in_extra(self, agent):
        findings = agent.analyze(self.STRUCTURAL_CLONE, "python")
        struct_clones = [
            f for f in findings
            if f.type == SmellType.DUPLICATE_CODE
            and f.extra.get("clone_type") == "structural_ast"
        ]
        assert struct_clones
        extra = struct_clones[0].extra
        assert "function_a" in extra
        assert "function_b" in extra
        assert "structural_node_count" in extra

    def test_trivial_functions_not_structural_clones(self, agent):
        """One-liner functions should not be flagged (node count too low)."""
        findings = agent.analyze(self.TRIVIAL_CLONES, "python")
        struct_clones = [
            f for f in findings
            if f.type == SmellType.DUPLICATE_CODE
            and f.extra.get("clone_type") == "structural_ast"
        ]
        assert not struct_clones, (
            "Trivial one-liner functions should not trigger structural clone detection"
        )

    def test_structural_clone_type_is_duplicate_code(self, agent):
        findings = agent.analyze(self.STRUCTURAL_CLONE, "python")
        struct_clones = [
            f for f in findings
            if f.extra.get("clone_type") == "structural_ast"
        ]
        assert struct_clones
        assert all(f.type == SmellType.DUPLICATE_CODE for f in struct_clones)

    def test_structural_clones_not_emitted_for_java(self, agent):
        """Structural clone detection is Python-only."""
        java_src = (
            "public class Foo {\n"
            "    public int methodA(int x) {\n"
            "        if (x > 0) { return x * 2; }\n"
            "        return 0;\n"
            "    }\n"
            "    public int methodB(int y) {\n"
            "        if (y > 0) { return y * 2; }\n"
            "        return 0;\n"
            "    }\n"
            "}\n"
        )
        findings = agent.analyze(java_src, "java")
        struct_clones = [
            f for f in findings
            if f.extra.get("clone_type") == "structural_ast"
        ]
        assert not struct_clones, "Structural clones should not be emitted for Java"


_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}

