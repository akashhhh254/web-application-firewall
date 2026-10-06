"""
WAF Package Initialization.
Exports core middleware, detector, rule engine, and logger.
"""

from waf.rule_engine import RuleEngine
from waf.detector import AttackDetector
from waf.logger import SecurityLogger
from waf.security_rules import DEFAULT_RULES

try:
    from waf.request_handler import WAFMiddleware
except ImportError:
    WAFMiddleware = None

__all__ = [
    "WAFMiddleware",
    "RuleEngine",
    "AttackDetector",
    "SecurityLogger",
    "DEFAULT_RULES"
]

