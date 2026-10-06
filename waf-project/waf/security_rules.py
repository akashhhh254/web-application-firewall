"""
Default Security Rule Definitions for the Web Application Firewall.

Contains categorized threat signatures:
1. SQL Injection (SQLi)
2. Cross-Site Scripting (XSS)
3. Path Traversal (Directory Traversal)
"""

DEFAULT_RULES = [
    # =========================================================================
    # SQL INJECTION (SQLi) RULES
    # =========================================================================
    {
        "rule_id": "RULE-SQLI-001",
        "name": "SQLi - Boolean-based Tautology Pattern",
        "attack_type": "SQL Injection",
        "pattern": r"(?i)(\b(or|and)\b\s+[\'\"]?\w+[\'\"]?\s*=\s*[\'\"]?\w+|\'\s*or\s*\'1\'\s*=\s*\'1|1\s*=\s*1|\btrue\s*=\s*true)",
        "risk_level": "HIGH",
        "action": "BLOCK",
        "is_enabled": 1,
        "description": "Detects classic OR/AND authentication bypass conditions like ' OR '1'='1."
    },
    {
        "rule_id": "RULE-SQLI-002",
        "name": "SQLi - UNION Operator Data Extraction",
        "attack_type": "SQL Injection",
        "pattern": r"(?i)(\bunion(\s+all)?\s+select\b)",
        "risk_level": "CRITICAL",
        "action": "BLOCK",
        "is_enabled": 1,
        "description": "Detects UNION SELECT queries used to extract sensitive data from other tables."
    },
    {
        "rule_id": "RULE-SQLI-003",
        "name": "SQLi - Destructive Database Keywords",
        "attack_type": "SQL Injection",
        "pattern": r"(?i)(;\s*\b(drop|alter|truncate)\s+\b(table|database|schema)\b|\bdrop\s+table\b)",
        "risk_level": "CRITICAL",
        "action": "BLOCK",
        "is_enabled": 1,
        "description": "Detects destructive DDL/DML injection commands designed to drop or alter database structures."
    },
    {
        "rule_id": "RULE-SQLI-004",
        "name": "SQLi - SQL Comment Exploitation",
        "attack_type": "SQL Injection",
        "pattern": r"(?i)(--\s+|--$|\/\*[\s\S]*?\*\/|;\s*--)",
        "risk_level": "MEDIUM",
        "action": "BLOCK",
        "is_enabled": 1,
        "description": "Detects SQL comment markers commonly used to truncate backend query syntax."
    },
    {
        "rule_id": "RULE-SQLI-005",
        "name": "SQLi - Time-Based Blind Injection",
        "attack_type": "SQL Injection",
        "pattern": r"(?i)(\b(sleep|benchmark|waitfor\s+delay)\s*\(|\bpg_sleep\s*\()",
        "risk_level": "HIGH",
        "action": "BLOCK",
        "is_enabled": 1,
        "description": "Detects time delay functions used in blind SQL injection reconnaissance."
    },

    # =========================================================================
    # CROSS-SITE SCRIPTING (XSS) RULES
    # =========================================================================
    {
        "rule_id": "RULE-XSS-001",
        "name": "XSS - Explicit Script Tag Injection",
        "attack_type": "Cross-Site Scripting",
        "pattern": r"(?i)(<\s*script\b[^>]*>[\s\S]*?<\s*\/\s*script\s*>|<\s*script\b[^>]*>)",
        "risk_level": "CRITICAL",
        "action": "BLOCK",
        "is_enabled": 1,
        "description": "Detects raw HTML <script> elements injected into request parameters."
    },
    {
        "rule_id": "RULE-XSS-002",
        "name": "XSS - Inline HTML Event Handlers",
        "attack_type": "Cross-Site Scripting",
        "pattern": r"(?i)(\bon(load|error|click|mouseover|mouseenter|focus|blur|change|submit)\s*=)",
        "risk_level": "HIGH",
        "action": "BLOCK",
        "is_enabled": 1,
        "description": "Detects injected event attributes such as <img src=x onerror=alert(1)>."
    },
    {
        "rule_id": "RULE-XSS-003",
        "name": "XSS - Pseudo-Protocol Execution",
        "attack_type": "Cross-Site Scripting",
        "pattern": r"(?i)(javascript\s*:\s*|vbscript\s*:\s*|data\s*:\s*text\/html)",
        "risk_level": "HIGH",
        "action": "BLOCK",
        "is_enabled": 1,
        "description": "Detects JavaScript or VBScript pseudo-protocols within links or source attributes."
    },
    {
        "rule_id": "RULE-XSS-004",
        "name": "XSS - Potentially Dangerous Tags",
        "attack_type": "Cross-Site Scripting",
        "pattern": r"(?i)(<\s*(iframe|embed|object|svg)\b[^>]*>)",
        "risk_level": "MEDIUM",
        "action": "BLOCK",
        "is_enabled": 1,
        "description": "Detects HTML tags frequently exploited for framing, clickjacking, or vector delivery."
    },
    {
        "rule_id": "RULE-XSS-005",
        "name": "XSS - Malicious Execution Primitives",
        "attack_type": "Cross-Site Scripting",
        "pattern": r"(?i)(\bdocument\.(cookie|location|domain)\b|\balert\s*\([^)]*\)|\beval\s*\()",
        "risk_level": "HIGH",
        "action": "BLOCK",
        "is_enabled": 1,
        "description": "Detects standard client-side payload signatures targeting cookies or executing alert boxes."
    },

    # =========================================================================
    # PATH TRAVERSAL RULES
    # =========================================================================
    {
        "rule_id": "RULE-PT-001",
        "name": "Path Traversal - Directory Climbing Sequences",
        "attack_type": "Path Traversal",
        "pattern": r"(?i)(\.\.[\/\\]|\.\.%2f|%2e%2e\/|%2e%2e%2f|\.\.%5c)",
        "risk_level": "CRITICAL",
        "action": "BLOCK",
        "is_enabled": 1,
        "description": "Detects parent directory climbing patterns (../, ..\\, and URL-encoded variants)."
    },
    {
        "rule_id": "RULE-PT-002",
        "name": "Path Traversal - Sensitive Unix System Files",
        "attack_type": "Path Traversal",
        "pattern": r"(?i)(\/etc\/(passwd|shadow|hosts|issue|group)|\/proc\/self\/environ)",
        "risk_level": "CRITICAL",
        "action": "BLOCK",
        "is_enabled": 1,
        "description": "Detects attempts to access standard UNIX configuration or password files."
    },
    {
        "rule_id": "RULE-PT-003",
        "name": "Path Traversal - Sensitive Windows System Files",
        "attack_type": "Path Traversal",
        "pattern": r"(?i)([a-zA-Z]:\\(windows|winnt)|boot\.ini|win\.ini|windows[\\\/]system32)",
        "risk_level": "HIGH",
        "action": "BLOCK",
        "is_enabled": 1,
        "description": "Detects attempts to access Windows system roots, boot configuration, or system32 binaries."
    },
    {
        "rule_id": "RULE-PT-004",
        "name": "Path Traversal - Null Byte String Termination",
        "attack_type": "Path Traversal",
        "pattern": r"(%00|\x00|\\0)",
        "risk_level": "HIGH",
        "action": "BLOCK",
        "is_enabled": 1,
        "description": "Detects poison null byte characters used to bypass file extension checks."
    }
]
