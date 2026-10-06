"""
Database access layer for the Web Application Firewall.
Provides clean SQLite operations for logging security events and managing rules.
"""

import sqlite3
import os
from pathlib import Path
from config import Config
from database.models import SECURITY_LOGS_SCHEMA, SECURITY_RULES_SCHEMA, INDEXES_SCHEMA
from waf.security_rules import DEFAULT_RULES

def get_db_path(custom_path=None):
    """Resolve database path, ensuring parent directory exists."""
    db_path = custom_path or Config.DATABASE_PATH
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    return db_path

def get_connection(custom_path=None):
    """Return a configured SQLite connection."""
    path = get_db_path(custom_path)
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(custom_path=None):
    """
    Initialize SQLite database tables and seed default rules if absent.
    Safe to run repeatedly.
    """
    conn = get_connection(custom_path)
    with conn:
        cursor = conn.cursor()
        cursor.executescript(SECURITY_LOGS_SCHEMA)
        cursor.executescript(SECURITY_RULES_SCHEMA)
        cursor.executescript(INDEXES_SCHEMA)

        # Check if rules table is already populated
        cursor.execute("SELECT COUNT(*) AS count FROM security_rules")
        count = cursor.fetchone()["count"]

        if count == 0:
            for rule in DEFAULT_RULES:
                cursor.execute("""
                    INSERT INTO security_rules 
                    (rule_id, name, attack_type, pattern, risk_level, action, is_enabled, description)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    rule["rule_id"],
                    rule["name"],
                    rule["attack_type"],
                    rule["pattern"],
                    rule["risk_level"],
                    rule.get("action", "BLOCK"),
                    rule.get("is_enabled", 1),
                    rule.get("description", "")
                ))
    conn.close()

def log_event(event_data, custom_path=None):
    """
    Persist an inspected request event to the database.
    
    event_data keys:
        ip_address, method, url, path, attack_type, risk_level, action,
        reason, matched_rule_id, payload_snippet
    """
    conn = get_connection(custom_path)
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO security_logs 
                (ip_address, method, url, path, attack_type, risk_level, action, reason, matched_rule_id, payload_snippet)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event_data.get("ip_address", "127.0.0.1"),
                event_data.get("method", "GET"),
                event_data.get("url", "/"),
                event_data.get("path", "/"),
                event_data.get("attack_type", "None"),
                event_data.get("risk_level", "LOW"),
                event_data.get("action", "ALLOWED"),
                event_data.get("reason", "Clean request"),
                event_data.get("matched_rule_id", None),
                event_data.get("payload_snippet", "")
            ))
            return cursor.lastrowid
    finally:
        conn.close()

def get_recent_logs(limit=100, attack_type=None, action=None, custom_path=None):
    """Retrieve recent security audit logs with optional filters."""
    conn = get_connection(custom_path)
    try:
        cursor = conn.cursor()
        query = "SELECT * FROM security_logs WHERE 1=1"
        params = []

        if attack_type and attack_type != "ALL":
            query += " AND attack_type = ?"
            params.append(attack_type)

        if action and action != "ALL":
            query += " AND action = ?"
            params.append(action)

        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        cursor.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()

def get_statistics(custom_path=None):
    """
    Compute aggregate security metrics for the admin dashboard.
    Returns:
        total_requests, allowed_requests, blocked_requests,
        attack_counts dictionary, and recent activity metrics.
    """
    conn = get_connection(custom_path)
    try:
        cursor = conn.cursor()
        
        # Overall totals
        cursor.execute("SELECT COUNT(*) as total FROM security_logs")
        total_requests = cursor.fetchone()["total"]

        cursor.execute("SELECT COUNT(*) as allowed FROM security_logs WHERE action = 'ALLOWED'")
        allowed_requests = cursor.fetchone()["allowed"]

        cursor.execute("SELECT COUNT(*) as blocked FROM security_logs WHERE action = 'BLOCKED'")
        blocked_requests = cursor.fetchone()["blocked"]

        # Attack breakdown
        cursor.execute("""
            SELECT attack_type, COUNT(*) as count 
            FROM security_logs 
            WHERE action = 'BLOCKED'
            GROUP BY attack_type
        """)
        breakdown_rows = cursor.fetchall()
        
        attack_distribution = {
            "SQL Injection": 0,
            "Cross-Site Scripting": 0,
            "Path Traversal": 0,
            "Other": 0
        }
        for row in breakdown_rows:
            att = row["attack_type"]
            if att in attack_distribution:
                attack_distribution[att] = row["count"]
            else:
                attack_distribution["Other"] += row["count"]

        # Risk breakdown
        cursor.execute("""
            SELECT risk_level, COUNT(*) as count 
            FROM security_logs 
            WHERE action = 'BLOCKED'
            GROUP BY risk_level
        """)
        risk_breakdown = {row["risk_level"]: row["count"] for row in cursor.fetchall()}

        return {
            "total_requests": total_requests,
            "allowed_requests": allowed_requests,
            "blocked_requests": blocked_requests,
            "attack_distribution": attack_distribution,
            "risk_breakdown": risk_breakdown
        }
    finally:
        conn.close()

def get_all_rules(custom_path=None):
    """Retrieve all security rules."""
    conn = get_connection(custom_path)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM security_rules ORDER BY attack_type ASC, id ASC")
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()

def get_enabled_rules(custom_path=None):
    """Retrieve only active rules for the detection engine."""
    conn = get_connection(custom_path)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM security_rules WHERE is_enabled = 1")
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()

def toggle_rule(rule_id, new_state=None, custom_path=None):
    """Toggle a rule's enabled status or set explicitly."""
    conn = get_connection(custom_path)
    try:
        with conn:
            cursor = conn.cursor()
            if new_state is None:
                cursor.execute("""
                    UPDATE security_rules 
                    SET is_enabled = CASE WHEN is_enabled = 1 THEN 0 ELSE 1 END 
                    WHERE rule_id = ?
                """, (rule_id,))
            else:
                cursor.execute("""
                    UPDATE security_rules 
                    SET is_enabled = ? 
                    WHERE rule_id = ?
                """, (1 if new_state else 0, rule_id))
            return cursor.rowcount > 0
    finally:
        conn.close()

def add_custom_rule(rule_data, custom_path=None):
    """Add a new rule created by the administrator."""
    conn = get_connection(custom_path)
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO security_rules 
                (rule_id, name, attack_type, pattern, risk_level, action, is_enabled, description)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                rule_data["rule_id"],
                rule_data["name"],
                rule_data["attack_type"],
                rule_data["pattern"],
                rule_data.get("risk_level", "MEDIUM"),
                rule_data.get("action", "BLOCK"),
                rule_data.get("is_enabled", 1),
                rule_data.get("description", "Custom administrative rule")
            ))
            return cursor.lastrowid
    finally:
        conn.close()

def reset_rules_to_default(custom_path=None):
    """Reset rules table to default rule set."""
    conn = get_connection(custom_path)
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM security_rules")
            for rule in DEFAULT_RULES:
                cursor.execute("""
                    INSERT INTO security_rules 
                    (rule_id, name, attack_type, pattern, risk_level, action, is_enabled, description)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    rule["rule_id"],
                    rule["name"],
                    rule["attack_type"],
                    rule["pattern"],
                    rule["risk_level"],
                    rule.get("action", "BLOCK"),
                    rule.get("is_enabled", 1),
                    rule.get("description", "")
                ))
    finally:
        conn.close()

def clear_logs(custom_path=None):
    """Truncate security event logs (useful for fresh demonstrations)."""
    conn = get_connection(custom_path)
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM security_logs")
    finally:
        conn.close()
