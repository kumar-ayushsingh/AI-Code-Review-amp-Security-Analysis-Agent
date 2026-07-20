"""
cli.py
------
Simple command-line entry point.

Usage:
    python -m code_analysis.cli <file.py|file.java> [--json]
    python -m code_analysis.cli --help
"""

from __future__ import annotations

import argparse
import json
import sys

from .agent import CodeAnalysisAgent


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="code-analysis",
        description="Detect code smells in Python or Java source files.",
    )
    parser.add_argument("file", help="Path to the source file to analyse.")
    parser.add_argument(
        "--language", "-l",
        choices=["python", "java"],
        default=None,
        help="Override language detection (default: infer from extension).",
    )
    parser.add_argument(
        "--json", "-j",
        action="store_true",
        help="Output findings as JSON array.",
    )
    parser.add_argument(
        "--threshold", "-t",
        type=int,
        default=40,
        help="Long-method line threshold (default: 40).",
    )
    parser.add_argument(
        "--min-dupes", "-d",
        type=int,
        default=6,
        help="Minimum duplicate block size in lines (default: 6).",
    )
    args = parser.parse_args()

    agent = CodeAnalysisAgent(
        long_method_threshold=args.threshold,
        min_duplicate_lines=args.min_dupes,
    )

    try:
        findings = agent.analyze_file(args.file, language=args.language)
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    if args.json:
        print(json.dumps(CodeAnalysisAgent.findings_to_dict(findings), indent=2))
    else:
        if not findings:
            print(f"[OK] No code smells found in '{args.file}'.")
            return

        summary = CodeAnalysisAgent.summary(findings)
        print(f"\n[*] Analysis of '{args.file}'")
        print(f"    Total findings: {summary['total']}  "
              f"(critical={summary['critical']}  high={summary['high']}  "
              f"medium={summary['medium']}  low={summary['low']})\n")

        for f in findings:
            icon = {"critical": "[CRIT]", "high": "[HIGH]", "medium": "[MED] ", "low": "[LOW] "}.get(
                f.severity.value, "[    ]"
            )
            sym = f"[{f.symbol}] " if f.symbol else ""
            print(f"  {icon} | "
                  f"line {f.line_number:>5} | {f.type.value:18s} | "
                  f"{sym}{f.description[:90]}")
        print()


if __name__ == "__main__":
    main()
