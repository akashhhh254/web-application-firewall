"""
Attack Detection Module for the Web Application Firewall.
Provides modular pattern-matching detectors for:
1. SQL Injection (SQLi)
2. Cross-Site Scripting (XSS)
3. Path Traversal (Directory Traversal)
"""

import re
import urllib.parse

class AttackDetector:
    """
    Core threat detection engine.
    Analyzes decoded request input against rule sets.
    """

    @staticmethod
    def normalize_input(value):
        """
        Normalize input by URL-decoding multiple passes to defeat obfuscation
        like double encoding (%252e%252e%252f -> ..%).
        """
        if not isinstance(value, str):
            value = str(value)

        decoded = value
        # Decode up to 2 times to handle double URL-encoding without infinite loop
        for _ in range(2):
            new_decoded = urllib.parse.unquote_plus(decoded)
            if new_decoded == decoded:
                break
            decoded = new_decoded

        return decoded

    @classmethod
    def inspect_text(cls, raw_value, rules_list):
        """
        Inspect a string value against a list of active rules.
        Returns match dict if triggered, or None if clean.
        """
        if not raw_value:
            return None

        normalized = cls.normalize_input(raw_value)

        for rule in rules_list:
            if not rule.get("is_enabled", 1):
                continue

            pattern = rule.get("pattern", "")
            if not pattern:
                continue

            try:
                # Test against both normalized and original text
                match = re.search(pattern, normalized, re.IGNORECASE)
                if not match and raw_value != normalized:
                    match = re.search(pattern, raw_value, re.IGNORECASE)

                if match:
                    matched_snippet = match.group(0)
                    return {
                        "matched": True,
                        "rule_id": rule.get("rule_id"),
                        "rule_name": rule.get("name"),
                        "attack_type": rule.get("attack_type"),
                        "risk_level": rule.get("risk_level", "HIGH"),
                        "action": rule.get("action", "BLOCK"),
                        "reason": f"Matched rule [{rule.get('rule_id')}]: {rule.get('name')}",
                        "matched_token": matched_snippet[:100],
                        "description": rule.get("description", "")
                    }
            except re.error as err:
                # Avoid crashing the WAF on invalid custom regex
                continue

        return None

    @classmethod
    def detect_sql_injection(cls, value, rules=None):
        """
        Specialized detection method for SQL Injection patterns.
        """
        sqli_rules = [r for r in (rules or []) if r.get("attack_type") == "SQL Injection"]
        return cls.inspect_text(value, sqli_rules)

    @classmethod
    def detect_xss(cls, value, rules=None):
        """
        Specialized detection method for Cross-Site Scripting patterns.
        """
        xss_rules = [r for r in (rules or []) if r.get("attack_type") == "Cross-Site Scripting"]
        return cls.inspect_text(value, xss_rules)

    @classmethod
    def detect_path_traversal(cls, value, rules=None):
        """
        Specialized detection method for Directory/Path Traversal patterns.
        """
        pt_rules = [r for r in (rules or []) if r.get("attack_type") == "Path Traversal"]
        return cls.inspect_text(value, pt_rules)
