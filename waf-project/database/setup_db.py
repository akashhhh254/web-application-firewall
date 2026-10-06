"""
Database setup script.
Run this script to initialize the SQLite database tables and seed default rules.

Usage:
    python database/setup_db.py
"""

import sys
from pathlib import Path

# Add project root to python path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from database.database import init_db, get_all_rules, get_db_path

def main():
    print("=" * 60)
    print("  Web Application Firewall (WAF) - Database Initializer")
    print("=" * 60)
    db_file = get_db_path()
    print(f"[*] Target SQLite Database: {db_file}")
    
    init_db()
    print("[+] Tables created successfully (security_logs, security_rules).")
    
    rules = get_all_rules()
    print(f"[+] Loaded {len(rules)} security detection rules:")
    for rule in rules:
        status = "ENABLED" if rule["is_enabled"] else "DISABLED"
        print(f"    - [{rule['rule_id']}] ({rule['attack_type']}) [{rule['risk_level']}] : {rule['name']} ({status})")
        
    print("=" * 60)
    print("[+] Database initialization complete. Ready for WAF execution.")
    print("=" * 60)

if __name__ == "__main__":
    main()
