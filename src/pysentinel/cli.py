"""Command line interface for PySentinel security linter."""

import argparse
import json
from pathlib import Path
import sys
from typing import Optional

# Ensure UTF-8 output on Windows terminals
if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from pysentinel import __version__
from pysentinel.engine import Engine
from pysentinel.explain import format_rule_explanation, list_all_rules
from pysentinel.formatters import format_json, format_sarif, format_text
from pysentinel.models import Severity


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pysentinel",
        description="Zero-dependency, high-precision Python security linter with SARIF support.",
    )
    parser.add_argument("-v", "--version", action="version", version=f"PySentinel v{__version__}")

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # 1. scan command
    scan_parser = subparsers.add_parser("scan", help="Scan Python files or directories for security vulnerabilities")
    scan_parser.add_argument("paths", nargs="*", default=["."], help="Files or directories to scan (default: current directory)")
    scan_parser.add_argument(
        "-f",
        "--format",
        choices=["text", "json", "sarif"],
        default="text",
        help="Output report format (default: text)",
    )
    scan_parser.add_argument(
        "-o",
        "--output",
        help="Optional file path to write the scan results to instead of stdout",
    )
    scan_parser.add_argument(
        "--min-severity",
        choices=["low", "medium", "high", "critical"],
        default="low",
        help="Minimum severity threshold to report (default: low)",
    )
    scan_parser.add_argument(
        "--baseline",
        help="Path to baseline JSON file to suppress known existing findings",
    )
    scan_parser.add_argument(
        "--generate-baseline",
        help="Scan and save all current findings as a baseline JSON file, then exit 0",
    )
    scan_parser.add_argument(
        "--exit-zero",
        action="store_true",
        help="Always return exit code 0 even if security findings are detected",
    )

    # 2. explain command
    explain_parser = subparsers.add_parser("explain", help="Show vulnerability mechanics and safe remediation guides")
    explain_parser.add_argument(
        "rule_id",
        nargs="?",
        default=None,
        help="Specific rule ID to explain (e.g. PYSEC-001). If omitted, lists all rules.",
    )

    return parser


def load_baseline(baseline_path: str) -> set[str]:
    """Loads baseline fingerprints from a JSON file."""
    path = Path(baseline_path)
    if not path.exists():
        print(f"Warning: Baseline file '{baseline_path}' not found. No findings suppressed.", file=sys.stderr)
        return set()

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, list):
            # List of fingerprints or finding dicts
            return {item["fingerprint"] if isinstance(item, dict) else str(item) for item in data}
        elif isinstance(data, dict) and "findings" in data:
            return {f["fingerprint"] for f in data["findings"] if "fingerprint" in f}
    except Exception as e:
        print(f"Warning: Failed to parse baseline file '{baseline_path}': {e}", file=sys.stderr)

    return set()


def main(args: Optional[list[str]] = None) -> int:
    parser = build_parser()
    parsed = parser.parse_args(args)

    if not parsed.command:
        # Default behavior if paths are passed without 'scan' or if empty
        if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
            # Assume scan
            parsed = parser.parse_args(["scan"] + sys.argv[1:])
        else:
            parser.print_help()
            return 0

    # Command: explain
    if parsed.command == "explain":
        if parsed.rule_id:
            print(format_rule_explanation(parsed.rule_id))
        else:
            print(list_all_rules())
        return 0

    # Command: scan
    if parsed.command == "scan":
        baseline_fingerprints = set()
        if parsed.baseline:
            baseline_fingerprints = load_baseline(parsed.baseline)

        min_sev = Severity(parsed.min_severity)
        engine = Engine(min_severity=min_sev, baseline_fingerprints=baseline_fingerprints)

        findings, errors, files_count = engine.scan_paths(parsed.paths)

        # Handle --generate-baseline
        if parsed.generate_baseline:
            baseline_data = {
                "version": __version__,
                "findings": [f.to_dict() for f in findings],
            }
            out_path = Path(parsed.generate_baseline)
            out_path.write_text(json.dumps(baseline_data, indent=2), encoding="utf-8")
            print(f"Generated baseline with {len(findings)} finding(s) at '{out_path}'.")
            return 0

        # Format output
        if parsed.format == "json":
            content = format_json(findings, errors, files_count)
        elif parsed.format == "sarif":
            content = format_sarif(findings)
        else:
            content = format_text(findings, errors, files_count)

        if parsed.output:
            out_file = Path(parsed.output)
            out_file.parent.mkdir(parents=True, exist_ok=True)
            out_file.write_text(content, encoding="utf-8")
            print(f"Report written to '{parsed.output}'.")
        else:
            print(content)

        if parsed.exit_zero:
            return 0

        # Return 1 if security findings exist, 0 if clean
        return 1 if findings else 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
