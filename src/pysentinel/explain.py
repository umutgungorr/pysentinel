"""Educational explanations, vulnerability mechanics, and remediation guides for PySentinel rules."""

from pysentinel.formatters.text import bold, cyan, format_severity, gray, green, red, yellow
from pysentinel.rules import ALL_RULES, RULES_BY_ID


def format_rule_explanation(rule_id: str) -> str:
    """Returns a formatted educational breakdown for a specific rule ID."""
    rule_id_upper = rule_id.upper()
    rule = RULES_BY_ID.get(rule_id_upper)

    if not rule:
        available = ", ".join(sorted(RULES_BY_ID.keys()))
        return f"{red('Error:')} Rule '{rule_id}' not found. Available rules: {available}"

    m = rule.metadata
    out = []
    out.append(bold(cyan(f"\n📖 PySentinel Rule Specification: {m.rule_id}")))
    out.append(gray("=" * 64))
    out.append(f"{bold('Title:')}       {m.title}")
    out.append(f"{bold('CWE:')}         {cyan(m.cwe_id)}")
    out.append(f"{bold('Severity:')}    {format_severity(m.severity)}")
    out.append(f"{bold('Confidence:')}  {m.confidence.value.capitalize()}")

    out.append(bold("\n📌 Vulnerability Mechanics:"))
    out.append(f"  {m.description}")

    out.append(bold("\n🛠️  Safe Remediation Guidance:"))
    out.append(f"  {m.remediation}")

    out.append(bold(red("\n❌ Vulnerable Code Pattern:")))
    for line in m.unsafe_example.splitlines():
        out.append(f"    {red(line)}")

    out.append(bold(green("\n✅ Recommended Secure Pattern:")))
    for line in m.safe_example.splitlines():
        out.append(f"    {green(line)}")

    out.append(bold(yellow("\n🔇 Line-Level Suppression Syntax:")))
    out.append(f"    # pysentinel: ignore[{m.rule_id}]\n")

    return "\n".join(out)


def list_all_rules() -> str:
    """Returns a table of all registered rules."""
    out = []
    out.append(bold(cyan("\n🛡️  PySentinel Registered Security Rules")))
    out.append(gray("=" * 72))
    out.append(f"{bold('Rule ID')}   {bold('CWE')}       {bold('Severity')}   {bold('Title')}")
    out.append(gray("-" * 72))

    for r in ALL_RULES:
        m = r.metadata
        out.append(f"{cyan(m.rule_id):<10} {m.cwe_id:<10} {m.severity.value.upper():<11} {m.title}")

    out.append(gray("=" * 72))
    out.append(gray("Run 'pysentinel explain <RULE_ID>' for comprehensive remediation guides.\n"))
    return "\n".join(out)
