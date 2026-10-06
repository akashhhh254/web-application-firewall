"""
Database Models and Table Schemas for the WAF System.

Defines schemas for:
1. security_logs - stores every inspected HTTP transaction (both ALLOWED and BLOCKED).
2. security_rules - stores configurable detection rules with enable/disable states.
"""

# Schema for security event logs
SECURITY_LOGS_SCHEMA = """
CREATE TABLE IF NOT EXISTS security_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    ip_address TEXT NOT NULL,
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    path TEXT NOT NULL,
    attack_type TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    action TEXT NOT NULL,
    reason TEXT NOT NULL,
    matched_rule_id TEXT,
    payload_snippet TEXT
);
"""

# Schema for dynamic security rules
SECURITY_RULES_SCHEMA = """
CREATE TABLE IF NOT EXISTS security_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    attack_type TEXT NOT NULL,
    pattern TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    action TEXT NOT NULL DEFAULT 'BLOCK',
    is_enabled INTEGER NOT NULL DEFAULT 1,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
"""

# Schema index for faster querying on high-volume logs
INDEXES_SCHEMA = """
CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON security_logs (timestamp);
CREATE INDEX IF NOT EXISTS idx_logs_action ON security_logs (action);
CREATE INDEX IF NOT EXISTS idx_logs_attack_type ON security_logs (attack_type);
"""
