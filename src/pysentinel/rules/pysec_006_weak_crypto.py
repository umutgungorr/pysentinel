"""PYSEC-006: Broken / Insecure Cryptographic Hashes."""

import ast
from pysentinel.models import Confidence, Finding, RuleMetadata, Severity
from pysentinel.rules.base import BaseRule


class WeakCryptoHashRule(BaseRule):
    metadata = RuleMetadata(
        rule_id="PYSEC-006",
        cwe_id="CWE-328",
        title="Broken / Insecure Cryptographic Hash (MD5 / SHA-1)",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        description=(
            "MD5 and SHA-1 algorithms suffer from known collision attacks and are broken for security applications "
            "(digital signatures, certificate verification, password hashing, and integrity checks)."
        ),
        remediation=(
            "Use secure collision-resistant hash algorithms such as SHA-256 or SHA-3 (e.g. hashlib.sha256()). "
            "For non-security use cases like caching, pass usedforsecurity=False."
        ),
        unsafe_example='import hashlib\ntoken_hash = hashlib.md5(secret_token.encode()).hexdigest()',
        safe_example='import hashlib\ntoken_hash = hashlib.sha256(secret_token.encode()).hexdigest()\n# Or non-security cache:\ncache_key = hashlib.md5(data, usedforsecurity=False).hexdigest()',
    )

    DANGEROUS_CALLS = {"hashlib.md5", "hashlib.sha1", "md5", "sha1"}

    def check(self, node: ast.AST, file_path: str, lines: list[str]) -> list[Finding]:
        if not isinstance(node, ast.Call):
            return []

        call_name = self.get_call_name(node)

        # High-confidence check: if usedforsecurity=False is passed, it is NOT a security finding!
        sec_kw = self.get_keyword(node, "usedforsecurity")
        if sec_kw and isinstance(sec_kw.value, ast.Constant) and sec_kw.value.value is False:
            return []

        # 1. Direct hashlib.md5(...) or hashlib.sha1(...)
        if call_name in self.DANGEROUS_CALLS:
            return [
                Finding(
                    rule_id=self.metadata.rule_id,
                    cwe_id=self.metadata.cwe_id,
                    title=self.metadata.title,
                    severity=self.metadata.severity,
                    confidence=self.metadata.confidence,
                    file_path=file_path,
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self.get_snippet(lines, node.lineno),
                    message=f"Weak hash algorithm detected in '{call_name}()'. MD5 and SHA-1 are cryptographically broken (CWE-328).",
                    remediation_hint="Upgrade to hashlib.sha256() or pass usedforsecurity=False if non-security cache/checksum.",
                )
            ]

        # 2. hashlib.new("md5") or hashlib.new("sha1")
        if call_name in ("hashlib.new", "new") and node.args:
            first_arg = node.args[0]
            if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                algo = first_arg.value.lower()
                if algo in ("md5", "sha1"):
                    return [
                        Finding(
                            rule_id=self.metadata.rule_id,
                            cwe_id=self.metadata.cwe_id,
                            title=self.metadata.title,
                            severity=self.metadata.severity,
                            confidence=self.metadata.confidence,
                            file_path=file_path,
                            line_number=node.lineno,
                            column=node.col_offset,
                            code_snippet=self.get_snippet(lines, node.lineno),
                            message=f"Weak hash algorithm '{algo}' requested in hashlib.new() (CWE-328).",
                            remediation_hint="Use hashlib.sha256() or pass usedforsecurity=False.",
                        )
                    ]

        return []
