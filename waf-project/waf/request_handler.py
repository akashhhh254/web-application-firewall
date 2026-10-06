"""
Request Handler & Middleware Interceptor for the Flask WAF.
Intercepts all incoming HTTP traffic before hitting application routes.
"""

from datetime import datetime
from flask import request, render_template, jsonify
from config import Config
from waf.rule_engine import RuleEngine
from waf.logger import SecurityLogger

class WAFMiddleware:
    """
    Flask extension / middleware for intercepting and inspecting HTTP requests.
    """

    def __init__(self, app=None, db_path=None):
        self.rule_engine = RuleEngine(db_path=db_path)
        self.logger = SecurityLogger()
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        """Register the before_request hook on the Flask application."""
        app.before_request(self.intercept_request)

    def get_client_ip(self):
        """Extract reliable client IP from headers or remote_addr."""
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # First IP in the list is the original client
            return forwarded_for.split(",")[0].strip()
        return request.remote_addr or "127.0.0.1"

    def intercept_request(self):
        """
        Main interceptor executed before every Flask route handler.
        """
        # 1. Skip static assets
        path = request.path
        for bypass in Config.BYPASS_STATIC_PATHS:
            if path.startswith(bypass):
                return None

        # 2. Extract request components
        client_ip = self.get_client_ip()
        method = request.method
        full_url = request.url

        # Extract query params as flat dict
        query_params = request.args.to_dict()

        # Extract body params safely
        body_params = None
        if request.is_json:
            try:
                body_params = request.get_json(silent=True)
            except Exception:
                body_params = {}
        elif request.form:
            body_params = request.form.to_dict()

        headers = {
            "User-Agent": request.headers.get("User-Agent", ""),
            "Referer": request.headers.get("Referer", "")
        }

        # 3. Evaluate via Rule Engine
        decision = self.rule_engine.evaluate_request(
            path=path,
            query_params=query_params,
            body_params=body_params,
            headers=headers
        )

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # 4. Handle Decision
        if decision["is_blocked"]:
            # Record security incident in database and audit log
            log_id = self.logger.log(
                ip_address=client_ip,
                method=method,
                url=full_url,
                path=path,
                attack_type=decision["attack_type"],
                risk_level=decision["risk_level"],
                action="BLOCKED",
                reason=decision["reason"],
                matched_rule_id=decision["matched_rule_id"],
                raw_payload={"query": query_params, "body": body_params}
            )

            # Return JSON for API calls or clients requesting application/json
            is_api = path.startswith("/api/") or "application/json" in request.headers.get("Accept", "")
            if is_api:
                return jsonify({
                    "error": "Request Blocked by Web Application Firewall",
                    "incident_id": log_id,
                    "status": 403,
                    "attack_type": decision["attack_type"],
                    "risk_level": decision["risk_level"],
                    "reason": decision["reason"],
                    "timestamp": now_str,
                    "ip_address": client_ip
                }), 403

            # Render clean Blocked template for regular browser navigation
            return render_template(
                "blocked.html",
                incident_id=log_id,
                attack_type=decision["attack_type"],
                risk_level=decision["risk_level"],
                reason=decision["reason"],
                timestamp=now_str,
                ip_address=client_ip,
                rule_id=decision["matched_rule_id"],
                rule_name=decision.get("matched_rule_name", ""),
                offending_snippet=decision.get("offending_value", "")
            ), 403

        else:
            # Log clean request (for telemetry, admin dashboard and statistics)
            # Only log non-admin polling API endpoints to prevent log flooding
            if not path.startswith("/api/logs") and not path.startswith("/api/stats"):
                self.logger.log(
                    ip_address=client_ip,
                    method=method,
                    url=full_url,
                    path=path,
                    attack_type="None",
                    risk_level="LOW",
                    action="ALLOWED",
                    reason="Clean request verified by WAF rule engine",
                    matched_rule_id=None,
                    raw_payload={"query": query_params, "body": body_params}
                )

            # Allow request to proceed to Flask view handler
            return None
