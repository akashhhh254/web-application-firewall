"""
Admin routes for the WAF Security Operations Center (SOC).
Provides dashboard views, telemetry, and rule configuration interfaces.
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash
from database.database import (
    get_statistics,
    get_recent_logs,
    get_all_rules,
    toggle_rule,
    reset_rules_to_default,
    clear_logs
)

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")

@admin_bp.route("/")
@admin_bp.route("/dashboard")
def dashboard():
    """Main security telemetry dashboard."""
    stats = get_statistics()
    recent_logs = get_recent_logs(limit=30)
    rules = get_all_rules()
    
    return render_template(
        "dashboard.html",
        stats=stats,
        logs=recent_logs,
        rules=rules,
        active_tab="overview"
    )

@admin_bp.route("/logs")
def logs():
    """Security audit logs view with filtering."""
    attack_filter = request.args.get("attack_type", "ALL")
    action_filter = request.args.get("action", "ALL")
    
    filtered_logs = get_recent_logs(
        limit=100,
        attack_type=attack_filter if attack_filter != "ALL" else None,
        action=action_filter if action_filter != "ALL" else None
    )
    stats = get_statistics()
    rules = get_all_rules()

    return render_template(
        "dashboard.html",
        stats=stats,
        logs=filtered_logs,
        rules=rules,
        active_tab="logs",
        selected_attack=attack_filter,
        selected_action=action_filter
    )

@admin_bp.route("/rules")
def rules():
    """Security rules configuration interface."""
    stats = get_statistics()
    recent_logs = get_recent_logs(limit=10)
    all_rules = get_all_rules()

    return render_template(
        "dashboard.html",
        stats=stats,
        logs=recent_logs,
        rules=all_rules,
        active_tab="rules"
    )

@admin_bp.route("/testing")
def testing():
    """WAF controlled testing interface."""
    stats = get_statistics()
    recent_logs = get_recent_logs(limit=10)
    rules = get_all_rules()

    return render_template(
        "dashboard.html",
        stats=stats,
        logs=recent_logs,
        rules=rules,
        active_tab="testing"
    )

@admin_bp.route("/settings")
def settings():
    """WAF system settings and maintenance interface."""
    stats = get_statistics()
    recent_logs = get_recent_logs(limit=10)
    rules = get_all_rules()

    return render_template(
        "dashboard.html",
        stats=stats,
        logs=recent_logs,
        rules=rules,
        active_tab="settings"
    )

@admin_bp.route("/rules/toggle/<rule_id>", methods=["POST"])
def rule_toggle(rule_id):
    """Toggle a rule on or off from the admin interface."""
    toggle_rule(rule_id)
    return redirect(url_for("admin.rules"))

@admin_bp.route("/rules/reset", methods=["POST"])
def rules_reset():
    """Reset rules to system defaults."""
    reset_rules_to_default()
    return redirect(url_for("admin.rules"))

@admin_bp.route("/logs/clear", methods=["POST"])
def logs_clear():
    """Truncate security event logs."""
    clear_logs()
    return redirect(url_for("admin.dashboard"))
