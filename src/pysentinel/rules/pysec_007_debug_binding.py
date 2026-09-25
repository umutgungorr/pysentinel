"""PYSEC-007: Insecure Debug Mode & Unrestricted Host Binding."""

import ast
from pysentinel.models import Confidence, Finding, RuleMetadata, Severity
from pysentinel.rules.base import BaseRule


class DebugBindingRule(BaseRule):
    metadata = RuleMetadata(
        rule_id="PYSEC-007",
        cwe_id="CWE-489",
        title="Insecure Debug Mode / Unrestricted Host Binding",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description=(
            "Running web servers with debug=True enables interactive debuggers (e.g. Werkzeug PIN console), "
            "often allowing arbitrary Python code execution. Binding to host='0.0.0.0' exposes the service to all public network interfaces."
        ),
        remediation=(
            "Disable debug mode (debug=False) in production and staging environments. "
            "Bind explicitly to localhost ('127.0.0.1') for local development or behind a hardened reverse proxy."
        ),
        unsafe_example='app.run(debug=True, host="0.0.0.0", port=5000)',
        safe_example='app.run(debug=False, host="127.0.0.1", port=5000)',
    )

    SERVER_RUN_CALLS = {"app.run", "run", "server.run"}

    def check(self, node: ast.AST, file_path: str, lines: list[str]) -> list[Finding]:
        if not isinstance(node, ast.Call):
            return []

        call_name = self.get_call_name(node)
        if not (call_name in self.SERVER_RUN_CALLS or call_name.endswith(".run")):
            return []

        findings: list[Finding] = []

        # Check debug=True
        debug_kw = self.get_keyword(node, "debug")
        if debug_kw and self.is_truthy(debug_kw.value):
            findings.append(
                Finding(
                    rule_id=self.metadata.rule_id,
                    cwe_id=self.metadata.cwe_id,
                    title=self.metadata.title,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    file_path=file_path,
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self.get_snippet(lines, node.lineno),
                    message="Web application started with debug=True. Interactive web debug consoles expose Remote Code Execution (CWE-489).",
                    remediation_hint="Set debug=False or retrieve from environment variables securely.",
                )
            )

        # Check host="0.0.0.0"
        host_kw = self.get_keyword(node, "host")
        if host_kw and isinstance(host_kw.value, ast.Constant) and host_kw.value.value == "0.0.0.0":
            # If debug is already flagged, this is extra context, or flag separately if debug isn't true
            if not any(f.message.startswith("Web application started with debug=True") for f in findings):
                findings.append(
                    Finding(
                        rule_id=self.metadata.rule_id,
                        cwe_id="CWE-200",
                        title="Unrestricted Network Host Binding (0.0.0.0)",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        file_path=file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        code_snippet=self.get_snippet(lines, node.lineno),
                        message="Web application binds to '0.0.0.0' listening on all interfaces, exposing internal dev services.",
                        remediation_hint="Bind to '127.0.0.1' unless intentionally deployed as a public endpoint.",
                    )
                )

        return findings
