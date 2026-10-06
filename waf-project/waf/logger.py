"""
Security Logger module for the WAF.
Persists inspection events to SQLite and writes structured audit logs to disk.
Implements automatic redaction of sensitive parameters (passwords, auth tokens).
"""

import logging
import os
import json
from datetime import datetime
from config import Config

# Sensitive parameter keys that must never be recorded in plain text
REDACTED_KEYS = {
    "password", "passwd", "pwd", "secret", "token", "auth",
    "access_token", "api_key", "credit_card", "ssn", "cvv"
}

class SecurityLogger:
    """Manages dual logging to SQLite database and append-only audit log file."""

    def __init__(self, audit_file_path=None):
        self.audit_file_path = audit_file_path or Config.AUDIT_LOG_FILE
        self._setup_file_logger()

    def _setup_file_logger(self):
        """Configure rotating or standard file logger for audit trail."""
        self.file_logger = logging.getLogger("WAF_Audit")
        self.file_logger.setLevel(logging.INFO)
        
        # Avoid duplicate handlers if reinitialized
        if not self.file_logger.handlers:
            os.makedirs(os.path.dirname(os.path.abspath(self.audit_file_path)), exist_ok=True)
            handler = logging.FileHandler(self.audit_file_path, encoding="utf-8")
            formatter = logging.Formatter(
                "[%(asctime)s] [%(levelname)s] [ACTION=%(action)s] [TYPE=%(attack_type)s] %(message)s"
            )
            handler.setFormatter(formatter)
            self.file_logger.addHandler(handler)

    @staticmethod
    def sanitize_payload(payload_dict):
        """Mask sensitive keys to prevent credential leakage in audit logs."""
        if not isinstance(payload_dict, dict):
            return str(payload_dict)

        sanitized = {}
        for key, value in payload_dict.items():
            if any(sensitive in key.lower() for sensitive in REDACTED_KEYS):
                sanitized[key] = "[REDACTED]"
            elif isinstance(value, dict):
                sanitized[key] = SecurityLogger.sanitize_payload(value)
            else:
                sanitized[key] = value
        return sanitized

    def log(self, ip_address, method, url, path, attack_type, risk_level, action, reason, matched_rule_id=None, raw_payload=None):
        """
        Record a security event.
        Writes to SQLite and appends to audit log file.
        """
        payload_snippet = ""
        if raw_payload:
            if isinstance(raw_payload, (dict, list)):
                sanitized = self.sanitize_payload(raw_payload) if isinstance(raw_payload, dict) else raw_payload
                payload_snippet = json.dumps(sanitized, ensure_ascii=False)[:500]
            else:
                payload_snippet = str(raw_payload)[:500]

        event_data = {
            "ip_address": ip_address,
            "method": method,
            "url": url,
            "path": path,
            "attack_type": attack_type or "None",
            "risk_level": risk_level or "LOW",
            "action": action,  # 'ALLOWED' or 'BLOCKED'
            "reason": reason,
            "matched_rule_id": matched_rule_id,
            "payload_snippet": payload_snippet
        }

        # 1. Store in SQLite
        from database.database import log_event
        log_id = log_event(event_data)

        # 2. Append to audit file
        extra = {
            "action": action,
            "attack_type": attack_type or "Clean"
        }
        msg = (
            f"IP={ip_address} METHOD={method} PATH={path} "
            f"RULE={matched_rule_id} RISK={risk_level} REASON={reason}"
        )
        self.file_logger.info(msg, extra=extra)

        return log_id
