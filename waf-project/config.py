"""
Configuration settings for the Web Application Firewall (WAF) prototype.
Academic Minor Project - B.Tech Computer Engineering.
"""

import os
from pathlib import Path

# Base directory of the project
BASE_DIR = Path(__file__).resolve().parent

class Config:
    """Base application configuration."""
    SECRET_KEY = os.environ.get("SECRET_KEY", "academic-waf-secret-key-2026")
    
    # SQLite Database location
    DATABASE_PATH = os.environ.get(
        "DATABASE_PATH",
        str(BASE_DIR / "database" / "waf_security.db")
    )
    
    # Audit log file location
    AUDIT_LOG_FILE = os.environ.get(
        "AUDIT_LOG_FILE",
        str(BASE_DIR / "waf_audit.log")
    )
    
    # WAF Operational Modes:
    # - 'BLOCKING': Detects and blocks threats with HTTP 403
    # - 'MONITORING': Detects and logs threats, but permits request through
    WAF_MODE = os.environ.get("WAF_MODE", "BLOCKING")
    
    # Bypass paths that the WAF should not inspect (e.g. static files and admin endpoints)
    # Admin is not bypassed from inspection, but static assets like stylesheets are skipped.
    BYPASS_STATIC_PATHS = [
        "/static/",
        "/favicon.ico"
    ]
    
    # Debug mode flag
    DEBUG = os.environ.get("FLASK_DEBUG", "True").lower() in ("true", "1", "yes")

class TestingConfig(Config):
    """Configuration used during automated tests."""
    TESTING = True
    DATABASE_PATH = str(BASE_DIR / "database" / "test_waf.db")
    WAF_MODE = "BLOCKING"
