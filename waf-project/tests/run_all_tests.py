"""
Universal Test Runner for the WAF Project.
Runs all tests with standard Python library (no external test runner dependencies needed)
or passes through to pytest if available.

Usage:
    python tests/run_all_tests.py
"""

import sys
import unittest
from pathlib import Path

# Add project root to sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from waf.detector import AttackDetector
from waf.rule_engine import RuleEngine
from waf.security_rules import DEFAULT_RULES

class TestWAFDetectionEngine(unittest.TestCase):
    """Unit tests for the WAF threat detection engine."""

    def setUp(self):
        self.engine = RuleEngine()

    def test_normal_legitimate_requests(self):
        """Verify normal requests are allowed."""
        decision = self.engine.evaluate_request(
            path="/search",
            query_params={"q": "laptop"},
            body_params=None
        )
        self.assertFalse(decision["is_blocked"])
        self.assertEqual(decision["action"], "ALLOWED")
        self.assertEqual(decision["attack_type"], "None")

    def test_sql_injection_tautology(self):
        """Verify ' OR 1=1 is blocked."""
        decision = self.engine.evaluate_request(
            path="/search",
            query_params={"q": "' OR 1=1--"},
            body_params=None
        )
        self.assertTrue(decision["is_blocked"])
        self.assertEqual(decision["action"], "BLOCKED")
        self.assertEqual(decision["attack_type"], "SQL Injection")

    def test_sql_injection_union_select(self):
        """Verify UNION SELECT is blocked."""
        decision = self.engine.evaluate_request(
            path="/products",
            query_params={"cat": "1' UNION SELECT 1,2,3--"},
            body_params=None
        )
        self.assertTrue(decision["is_blocked"])
        self.assertEqual(decision["attack_type"], "SQL Injection")

    def test_xss_script_tags(self):
        """Verify script tag injection is blocked."""
        decision = self.engine.evaluate_request(
            path="/comment",
            query_params={},
            body_params={"message": "<script>alert('pwned')</script>"}
        )
        self.assertTrue(decision["is_blocked"])
        self.assertEqual(decision["attack_type"], "Cross-Site Scripting")

    def test_xss_inline_event_handler(self):
        """Verify onerror= event handler is blocked."""
        decision = self.engine.evaluate_request(
            path="/profile",
            query_params={"avatar": "<img src=x onerror=alert(1)>"},
            body_params=None
        )
        self.assertTrue(decision["is_blocked"])
        self.assertEqual(decision["attack_type"], "Cross-Site Scripting")

    def test_path_traversal_dot_dot_slash(self):
        """Verify ../../etc/passwd is blocked."""
        decision = self.engine.evaluate_request(
            path="/view-file",
            query_params={"file": "../../etc/passwd"},
            body_params=None
        )
        self.assertTrue(decision["is_blocked"])
        self.assertEqual(decision["attack_type"], "Path Traversal")

    def test_path_traversal_double_url_encoded(self):
        """Verify double URL-encoded %252e%252e%252f is blocked."""
        decision = self.engine.evaluate_request(
            path="/view-file",
            query_params={"file": "%252e%252e%252fetc/passwd"},
            body_params=None
        )
        self.assertTrue(decision["is_blocked"])
        self.assertEqual(decision["attack_type"], "Path Traversal")

if __name__ == "__main__":
    print("=" * 65)
    print("  RUNNING WAF SYSTEM SECURITY UNIT TESTS (ACADEMIC VALIDATION)")
    print("=" * 65)
    unittest.main(verbosity=2)
