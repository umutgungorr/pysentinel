"""Colorized human-readable terminal formatter for PySentinel."""

import sys
from pysentinel.models import Finding, Severity


# ANSI escape sequences
USE_COLOR = sys.stdout.isatty()


def _color(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text


def bold(text: str) -> str:
    return _color("1", text)


def red(text: str) -> str:
    return _color("31;1", text)


def yellow(text: str) -> str:
    return _color("33;1", text)


def blue(text: str) -> str:
    return _color("34;1", text)


def cyan(text: str) -> str:
    return _color("36;1", text)


def green(text: str) -> str:
    return _color("32;1", text)


def gray(text: str) -> str:
    return _color("90", text)


def format_severity(sev: Severity) -> str:
    if sev == Severity.CRITICAL:
        return red("[CRITICAL]")
    elif sev == Severity.HIGH:
        return red("[HIGH]")
    elif sev == Severity.MEDIUM:
        return yellow("[MEDIUM]")
    else:
        return blue("[LOW]")


def format_text(findings: list[Finding], errors: list[str], files_count: int) -> str:
    """Formats findings and summary as clean terminal output."""
    output = []
    output.append(bold(cyan("\n🛡️  PySentinel Security Audit Report")))
    output.append(gray("=" * 64))

    if errors:
        output.append(bold(red("\n⚠️  Parsing Errors / Warnings:")))
        for err in errors:
            output.append(f"  {gray('•')} {err}")

    if not findings:
        output.append(f"\n{green('✅ No security vulnerabilities detected.')}")
        output.append(gray(f"   Scanned {files_count} Python file(s).\n"))
        return "\n".join(output)

    # Group findings by file
    findings_by_file: dict[str, list[Finding]] = {}
    for f in findings:
        findings_by_file.setdefault(f.file_path, []).append(f)

    for file_path, file_findings in findings_by_file.items():
        output.append(f"\n{bold('📁 File:')} {cyan(file_path)}")
        output.append(gray("-" * 64))

        for f in file_findings:
            sev_badge = format_severity(f.severity)
            conf_badge = gray(f"({f.confidence.value} confidence)")
            cwe_tag = gray(f"[{f.cwe_id}]")

            output.append(f"  {sev_badge} {bold(f.rule_id)}: {f.title} {cwe_tag} {conf_badge}")
            output.append(f"  {gray('-->')} {file_path}:{f.line_number}:{f.column}")

            # Code snippet
            if f.code_snippet:
                line_str = str(f.line_number)
                pad = " " * len(line_str)
                output.append(f"  {gray(pad)} {gray('|')}")
                output.append(f"  {gray(line_str)} {gray('|')} {f.code_snippet}")
                output.append(f"  {gray(pad)} {gray('|')}")

            output.append(f"  {bold('Reason:')} {f.message}")
            output.append(f"  {green('Remediation:')} {f.remediation_hint}\n")

    # Summary box
    crit_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
    high_count = sum(1 for f in findings if f.severity == Severity.HIGH)
    med_count = sum(1 for f in findings if f.severity == Severity.MEDIUM)
    low_count = sum(1 for f in findings if f.severity == Severity.LOW)

    output.append(gray("=" * 64))
    summary_parts = []
    if crit_count:
        summary_parts.append(red(f"{crit_count} Critical"))
    if high_count:
        summary_parts.append(red(f"{high_count} High"))
    if med_count:
        summary_parts.append(yellow(f"{med_count} Medium"))
    if low_count:
        summary_parts.append(blue(f"{low_count} Low"))

    summary_str = ", ".join(summary_parts) if summary_parts else "0 Issues"
    output.append(bold(f"Summary: {len(findings)} total finding(s) across {files_count} file(s) ({summary_str}).\n"))

    return "\n".join(output)
