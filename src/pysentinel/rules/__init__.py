"""Rules registry and rule loader for PySentinel."""

from pysentinel.rules.base import BaseRule
from pysentinel.rules.pysec_001_command_injection import CommandInjectionRule
from pysentinel.rules.pysec_002_deserialization import DeserializationRule
from pysentinel.rules.pysec_003_dynamic_exec import DynamicExecutionRule
from pysentinel.rules.pysec_004_sql_interpolation import SqlInterpolationRule
from pysentinel.rules.pysec_005_tempfile import InsecureTempfileRule
from pysentinel.rules.pysec_006_weak_crypto import WeakCryptoHashRule
from pysentinel.rules.pysec_007_debug_binding import DebugBindingRule

ALL_RULES: list[BaseRule] = [
    CommandInjectionRule(),
    DeserializationRule(),
    DynamicExecutionRule(),
    SqlInterpolationRule(),
    InsecureTempfileRule(),
    WeakCryptoHashRule(),
    DebugBindingRule(),
]

RULES_BY_ID: dict[str, BaseRule] = {
    rule.metadata.rule_id: rule for rule in ALL_RULES
}

__all__ = [
    "BaseRule",
    "CommandInjectionRule",
    "DeserializationRule",
    "DynamicExecutionRule",
    "SqlInterpolationRule",
    "InsecureTempfileRule",
    "WeakCryptoHashRule",
    "DebugBindingRule",
    "ALL_RULES",
    "RULES_BY_ID",
]
