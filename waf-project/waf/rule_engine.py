"""
Rule Engine module for the Web Application Firewall.
Coordinates rule evaluation across request URL path, query params, body payloads, and headers.
"""

from waf.security_rules import DEFAULT_RULES
from waf.detector import AttackDetector

class RuleEngine:
    """
    Evaluates incoming request context against loaded security rules.
    """

    def __init__(self, db_path=None):
        self.db_path = db_path
        self._rules_cache = None

    def get_rules(self, force_refresh=False):
        """Fetch active rules from database or fallback to static defaults."""
        if self._rules_cache is None or force_refresh:
            try:
                from database.database import get_enabled_rules
                db_rules = get_enabled_rules(self.db_path)
                if db_rules:
                    self._rules_cache = db_rules
                else:
                    self._rules_cache = [r for r in DEFAULT_RULES if r.get("is_enabled", 1)]
            except Exception:
                self._rules_cache = [r for r in DEFAULT_RULES if r.get("is_enabled", 1)]
        return self._rules_cache

    def refresh(self):
        """Force cache refresh when admin enables or disables rules."""
        self._rules_cache = None

    def evaluate_request(self, path, query_params, body_params=None, headers=None):
        """
        Comprehensive inspection of all HTTP request components.

        Parameters:
            path (str): The requested URI path.
            query_params (dict): Request query parameters.
            body_params (dict or str): Form data or decoded JSON body.
            headers (dict): Selected request headers (User-Agent, Referer, etc.).

        Returns:
            dict: Decision object with keys:
                  'is_blocked', 'action', 'attack_type', 'risk_level',
                  'reason', 'matched_rule_id', 'offending_value'
        """
        active_rules = self.get_rules(force_refresh=True)

        inspection_targets = []

        # 1. Inspect URI path (crucial for path traversal attacks like /etc/passwd)
        if path:
            inspection_targets.append(("Path", path))

        # 2. Inspect Query parameters
        if query_params:
            for key, val in query_params.items():
                inspection_targets.append((f"Query Param '{key}'", str(val)))

        # 3. Inspect Body parameters (Form / JSON)
        if body_params:
            if isinstance(body_params, dict):
                for key, val in body_params.items():
                    # Skip passwords from evaluation matching false positives if needed,
                    # but test for SQLi/XSS in typical fields
                    inspection_targets.append((f"Body Field '{key}'", str(val)))
            elif isinstance(body_params, str):
                inspection_targets.append(("Raw Body", body_params))

        # 4. Inspect selected HTTP headers
        if headers:
            for h_name in ("User-Agent", "Referer", "X-Forwarded-For"):
                val = headers.get(h_name)
                if val:
                    inspection_targets.append((f"Header '{h_name}'", str(val)))

        # Evaluate each target against detector
        for location, target_value in inspection_targets:
            match = AttackDetector.inspect_text(target_value, active_rules)
            if match:
                return {
                    "is_blocked": True,
                    "action": "BLOCKED",
                    "attack_type": match["attack_type"],
                    "risk_level": match["risk_level"],
                    "reason": f"{match['reason']} in {location}",
                    "matched_rule_id": match["rule_id"],
                    "matched_rule_name": match["rule_name"],
                    "offending_value": match["matched_token"],
                    "location": location
                }

        # Request passed all rule checks
        return {
            "is_blocked": False,
            "action": "ALLOWED",
            "attack_type": "None",
            "risk_level": "LOW",
            "reason": "No malicious signatures detected in request parameters or path",
            "matched_rule_id": None,
            "matched_rule_name": None,
            "offending_value": None,
            "location": None
        }
