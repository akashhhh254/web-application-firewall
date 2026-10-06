"""
RESTful API endpoints for external tools, Postman, and AJAX dashboard updates.
"""

from flask import Blueprint, jsonify, request
from database.database import (
    get_statistics,
    get_recent_logs,
    get_all_rules,
    toggle_rule,
    add_custom_rule,
    reset_rules_to_default,
    clear_logs
)
from waf.rule_engine import RuleEngine

api_bp = Blueprint("api", __name__, url_prefix="/api")
rule_engine = RuleEngine()

@api_bp.route("/stats", methods=["GET"])
def api_stats():
    """Return real-time WAF telemetry statistics."""
    stats = get_statistics()
    return jsonify(stats), 200

@api_bp.route("/logs", methods=["GET"])
def api_logs():
    """Return recent security audit logs with optional filtering."""
    limit = int(request.args.get("limit", 100))
    attack_type = request.args.get("attack_type", None)
    action = request.args.get("action", None)
    
    logs = get_recent_logs(limit=limit, attack_type=attack_type, action=action)
    return jsonify(logs), 200

@api_bp.route("/rules", methods=["GET"])
def api_rules():
    """List all configured security rules."""
    rules = get_all_rules()
    return jsonify(rules), 200

@api_bp.route("/rules/<rule_id>/toggle", methods=["POST"])
def api_toggle_rule(rule_id):
    """Toggle the enabled status of a specific security rule."""
    success = toggle_rule(rule_id)
    if success:
        rule_engine.refresh()
        return jsonify({"status": "success", "message": f"Rule {rule_id} status updated"}), 200
    return jsonify({"status": "error", "message": f"Rule {rule_id} not found"}), 404

@api_bp.route("/rules", methods=["POST"])
def api_add_rule():
    """Create a new custom detection rule."""
    data = request.get_json(silent=True) or {}
    required = ["rule_id", "name", "attack_type", "pattern"]
    if not all(k in data for k in required):
        return jsonify({"status": "error", "message": "Missing required fields"}), 400

    try:
        new_id = add_custom_rule(data)
        rule_engine.refresh()
        return jsonify({"status": "success", "id": new_id, "message": "Rule created"}), 201
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

@api_bp.route("/rules/reset", methods=["POST"])
def api_reset_rules():
    """Reset rules to system defaults."""
    reset_rules_to_default()
    rule_engine.refresh()
    return jsonify({"status": "success", "message": "Rules reset to default signatures"}), 200

@api_bp.route("/logs/clear", methods=["POST"])
def api_clear_logs():
    """Purge security event logs."""
    clear_logs()
    return jsonify({"status": "success", "message": "Logs cleared"}), 200

@api_bp.route("/inspect", methods=["POST"])
def api_inspect_payload():
    """
    Direct inspection endpoint for penetration testing simulation without blocking.
    Useful for interactive labs and Postman demonstrations.
    """
    data = request.get_json(silent=True) or {}
    path = data.get("path", "/")
    query = data.get("query", {})
    body = data.get("body", {})
    
    result = rule_engine.evaluate_request(path=path, query_params=query, body_params=body)
    return jsonify(result), 200
