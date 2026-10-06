/**
 * WAF Rule-Based Threat Detection Engine in TypeScript
 * Mirrors the Python Flask WAF engine (waf/detector.py, waf/rule_engine.py, waf/security_rules.py).
 */

export interface SecurityRule {
  rule_id: string;
  name: string;
  attack_type: "SQL Injection" | "Cross-Site Scripting" | "Path Traversal" | "System Violation";
  pattern: string;
  risk_level: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  action: "BLOCK" | "ALLOW";
  is_enabled: boolean;
  description: string;
}

export interface SecurityLog {
  id: number;
  timestamp: string;
  ip_address: string;
  method: string;
  url: string;
  path: string;
  attack_type: string;
  risk_level: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  action: "ALLOWED" | "BLOCKED";
  reason: string;
  matched_rule_id: string | null;
  matched_rule_name?: string;
  payload_snippet: string;
  offending_token?: string;
}

export const INITIAL_RULES: SecurityRule[] = [
  // SQL Injection
  {
    rule_id: "RULE-SQLI-001",
    name: "SQLi - Boolean-based Tautology Pattern",
    attack_type: "SQL Injection",
    pattern: "(\\b(or|and)\\b\\s+['\"]?\\w+['\"]?\\s*=\\s*['\"]?\\w+|'\\s*or\\s*'1'\\s*=\\s*'1|1\\s*=\\s*1|\\btrue\\s*=\\s*true)",
    risk_level: "HIGH",
    action: "BLOCK",
    is_enabled: true,
    description: "Detects classic OR/AND authentication bypass conditions like ' OR '1'='1."
  },
  {
    rule_id: "RULE-SQLI-002",
    name: "SQLi - UNION Operator Data Extraction",
    attack_type: "SQL Injection",
    pattern: "(\\bunion(\\s+all)?\\s+select\\b)",
    risk_level: "CRITICAL",
    action: "BLOCK",
    is_enabled: true,
    description: "Detects UNION SELECT queries used to extract sensitive data from other tables."
  },
  {
    rule_id: "RULE-SQLI-003",
    name: "SQLi - Destructive Database Keywords",
    attack_type: "SQL Injection",
    pattern: "(;\\s*\\b(drop|alter|truncate)\\s+\\b(table|database|schema)\\b|\\bdrop\\s+table\\b)",
    risk_level: "CRITICAL",
    action: "BLOCK",
    is_enabled: true,
    description: "Detects destructive DDL/DML injection commands designed to drop or alter database structures."
  },
  {
    rule_id: "RULE-SQLI-004",
    name: "SQLi - SQL Comment Exploitation",
    attack_type: "SQL Injection",
    pattern: "(--\\s+|--$|/\\*[\\s\\S]*?\\*/|;\\s*--)",
    risk_level: "MEDIUM",
    action: "BLOCK",
    is_enabled: true,
    description: "Detects SQL comment markers commonly used to truncate backend query syntax."
  },
  {
    rule_id: "RULE-SQLI-005",
    name: "SQLi - Time-Based Blind Injection",
    attack_type: "SQL Injection",
    pattern: "(\\b(sleep|benchmark|waitfor\\s+delay)\\s*\\(|\\bpg_sleep\\s*\\()",
    risk_level: "HIGH",
    action: "BLOCK",
    is_enabled: true,
    description: "Detects time delay functions used in blind SQL injection reconnaissance."
  },

  // Cross-Site Scripting
  {
    rule_id: "RULE-XSS-001",
    name: "XSS - Explicit Script Tag Injection",
    attack_type: "Cross-Site Scripting",
    pattern: "(<\\s*script\\b[^>]*>[\\s\\S]*?<\\s*/\\s*script\\s*>|<\\s*script\\b[^>]*>)",
    risk_level: "CRITICAL",
    action: "BLOCK",
    is_enabled: true,
    description: "Detects raw HTML <script> elements injected into request parameters."
  },
  {
    rule_id: "RULE-XSS-002",
    name: "XSS - Inline HTML Event Handlers",
    attack_type: "Cross-Site Scripting",
    pattern: "(\\bon(load|error|click|mouseover|mouseenter|focus|blur|change|submit)\\s*=)",
    risk_level: "HIGH",
    action: "BLOCK",
    is_enabled: true,
    description: "Detects injected event attributes such as <img src=x onerror=alert(1)>."
  },
  {
    rule_id: "RULE-XSS-003",
    name: "XSS - Pseudo-Protocol Execution",
    attack_type: "Cross-Site Scripting",
    pattern: "(javascript\\s*:\\s*|vbscript\\s*:\\s*|data\\s*:\\s*text/html)",
    risk_level: "HIGH",
    action: "BLOCK",
    is_enabled: true,
    description: "Detects JavaScript or VBScript pseudo-protocols within links or source attributes."
  },
  {
    rule_id: "RULE-XSS-004",
    name: "XSS - Potentially Dangerous Tags",
    attack_type: "Cross-Site Scripting",
    pattern: "(<\\s*(iframe|embed|object|svg)\\b[^>]*>)",
    risk_level: "MEDIUM",
    action: "BLOCK",
    is_enabled: true,
    description: "Detects HTML tags frequently exploited for framing, clickjacking, or vector delivery."
  },
  {
    rule_id: "RULE-XSS-005",
    name: "XSS - Malicious Execution Primitives",
    attack_type: "Cross-Site Scripting",
    pattern: "(\\bdocument\\.(cookie|location|domain)\\b|\\balert\\s*\\([^)]*\\)|\\beval\\s*\\()",
    risk_level: "HIGH",
    action: "BLOCK",
    is_enabled: true,
    description: "Detects standard client-side payload signatures targeting cookies or executing alert boxes."
  },

  // Path Traversal
  {
    rule_id: "RULE-PT-001",
    name: "Path Traversal - Directory Climbing Sequences",
    attack_type: "Path Traversal",
    pattern: "(\\.\\.[\\/\\\\]|\\.\\.%2f|%2e%2e\\/|%2e%2e%2f|\\.\\.%5c)",
    risk_level: "CRITICAL",
    action: "BLOCK",
    is_enabled: true,
    description: "Detects parent directory climbing patterns (../, ..\\, and URL-encoded variants)."
  },
  {
    rule_id: "RULE-PT-002",
    name: "Path Traversal - Sensitive Unix System Files",
    attack_type: "Path Traversal",
    pattern: "(\\/etc\\/(passwd|shadow|hosts|issue|group)|\\/proc\\/self\\/environ)",
    risk_level: "CRITICAL",
    action: "BLOCK",
    is_enabled: true,
    description: "Detects attempts to access standard UNIX configuration or password files."
  },
  {
    rule_id: "RULE-PT-003",
    name: "Path Traversal - Sensitive Windows System Files",
    attack_type: "Path Traversal",
    pattern: "([a-zA-Z]:\\\\(windows|winnt)|boot\\.ini|win\\.ini|windows[\\\\\\/]system32)",
    risk_level: "HIGH",
    action: "BLOCK",
    is_enabled: true,
    description: "Detects attempts to access Windows system roots, boot configuration, or system32 binaries."
  },
  {
    rule_id: "RULE-PT-004",
    name: "Path Traversal - Null Byte String Termination",
    attack_type: "Path Traversal",
    pattern: "(%00|\\x00|\\\\0)",
    risk_level: "HIGH",
    action: "BLOCK",
    is_enabled: true,
    description: "Detects poison null byte characters used to bypass file extension checks."
  }
];

export interface InspectionResult {
  is_blocked: boolean;
  action: "ALLOWED" | "BLOCKED";
  attack_type: string;
  risk_level: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  reason: string;
  matched_rule_id: string | null;
  matched_rule_name?: string;
  offending_value?: string;
  location?: string;
}

/**
 * Normalizes input with multi-pass URL decoding.
 */
function normalizeInput(val: string): string {
  let decoded = val;
  try {
    for (let i = 0; i < 2; i++) {
      const next = decodeURIComponent(decoded);
      if (next === decoded) break;
      decoded = next;
    }
  } catch {
    // If malformed URI sequence, keep current
  }
  return decoded;
}

/**
 * Evaluates an input against active security rules.
 */
export function evaluateRequest(
  path: string,
  queryParams: Record<string, string>,
  bodyParams: Record<string, string> = {},
  rules: SecurityRule[],
  mode: "BLOCKING" | "MONITORING" = "BLOCKING"
): InspectionResult {
  const activeRules = rules.filter((r) => r.is_enabled);

  const targets: [string, string][] = [];
  if (path) targets.push(["Path", path]);

  for (const [k, v] of Object.entries(queryParams)) {
    if (v) targets.push([`Query Param '${k}'`, String(v)]);
  }

  for (const [k, v] of Object.entries(bodyParams)) {
    if (v) targets.push([`Body Field '${k}'`, String(v)]);
  }

  for (const [location, rawVal] of targets) {
    const normalized = normalizeInput(rawVal);

    for (const rule of activeRules) {
      try {
        const regex = new RegExp(rule.pattern, "i");
        const match = regex.exec(normalized) || (rawVal !== normalized ? regex.exec(rawVal) : null);

        if (match) {
          const isBlocked = mode === "BLOCKING";
          return {
            is_blocked: isBlocked,
            action: isBlocked ? "BLOCKED" : "ALLOWED",
            attack_type: rule.attack_type,
            risk_level: rule.risk_level,
            reason: isBlocked
              ? `Triggered rule [${rule.rule_id}]: ${rule.name} in ${location}`
              : `[MONITORING ONLY] Detected [${rule.rule_id}]: ${rule.name} in ${location}`,
            matched_rule_id: rule.rule_id,
            matched_rule_name: rule.name,
            offending_value: match[0],
            location
          };
        }
      } catch (err) {
        console.warn(`Invalid regex in rule ${rule.rule_id}:`, err);
      }
    }
  }

  return {
    is_blocked: false,
    action: "ALLOWED",
    attack_type: "None",
    risk_level: "LOW",
    reason: "Clean request verified by WAF rule engine",
    matched_rule_id: null,
    matched_rule_name: undefined,
    offending_value: undefined,
    location: undefined
  };
}
