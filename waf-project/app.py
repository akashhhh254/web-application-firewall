"""
Web Application Firewall (WAF) - Main Application Entrypoint.
Academic Minor Project - B.Tech Computer Engineering.

Architecture:
    User Request -> Flask WAF Middleware -> Rule Engine -> Attack Detector
    -> Allow/Block Decision -> Target Application -> Security Logger -> Admin Dashboard
"""

import os
from flask import Flask, render_template, jsonify
from config import Config
from database.database import init_db
from waf.request_handler import WAFMiddleware
from routes.main import main_bp
from routes.admin import admin_bp
from routes.api import api_bp

def create_app(config_class=Config):
    """Application factory for the Flask WAF application."""
    app = Flask(__name__)
    app.config.from_object(config_class)

    # 1. Initialize SQLite Database & default threat rules
    with app.app_context():
        init_db(app.config.get("DATABASE_PATH"))

    # 2. Attach WAF Interception Middleware
    waf = WAFMiddleware(app, db_path=app.config.get("DATABASE_PATH"))

    # 3. Register Application Blueprints
    app.register_blueprint(main_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(api_bp)

    # 4. Global Error Handlers (Clean, academic, no stack traces leaked)
    @app.errorhandler(400)
    def bad_request(error):
        return render_template(
            "blocked.html",
            incident_id="ERR-400",
            attack_type="Bad Request",
            risk_level="LOW",
            reason="The request could not be understood or was missing required syntax.",
            timestamp="",
            ip_address="Client",
            rule_id="SYS-400",
            rule_name="HTTP Malformed Request"
        ), 400

    @app.errorhandler(403)
    def forbidden(error):
        return render_template(
            "blocked.html",
            incident_id="ERR-403",
            attack_type="Access Forbidden",
            risk_level="MEDIUM",
            reason="Access to this resource is restricted or blocked by security policies.",
            timestamp="",
            ip_address="Client",
            rule_id="SYS-403",
            rule_name="Access Control Enforcement"
        ), 403

    @app.errorhandler(404)
    def page_not_found(error):
        return render_template(
            "blocked.html",
            incident_id="ERR-404",
            attack_type="Resource Not Found",
            risk_level="LOW",
            reason="The requested URL endpoint was not found on this protected server.",
            timestamp="",
            ip_address="Client",
            rule_id="SYS-404",
            rule_name="Endpoint Resolution Failure"
        ), 404

    @app.errorhandler(500)
    def internal_server_error(error):
        return render_template(
            "blocked.html",
            incident_id="ERR-500",
            attack_type="Server Internal Error",
            risk_level="MEDIUM",
            reason="An unexpected internal condition occurred. Detailed stack traces are suppressed for security.",
            timestamp="",
            ip_address="Client",
            rule_id="SYS-500",
            rule_name="Internal Server Error Shield"
        ), 500

    return app

# Instantiate application
app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"[*] Starting WAF Protected Server on http://127.0.0.1:{port}")
    print(f"[*] Admin SOC Dashboard: http://127.0.0.1:{port}/admin")
    app.run(host="0.0.0.0", port=port, debug=Config.DEBUG)
