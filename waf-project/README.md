# Web Application Firewall (WAF) &ndash; Rule-Based Web Security and Threat Detection System

**Academic Minor Project &bull; B.Tech Computer Engineering**

---

## 1. Project Overview

The **Web Application Firewall (WAF)** is an educational, modular, reverse-proxy security barrier positioned in front of a web application to inspect inbound HTTP traffic. It actively identifies and mitigates the most pervasive OWASP web security vulnerabilities:

1. **SQL Injection (SQLi)** &ndash; Prevents unauthorized query manipulation and authentication bypass.
2. **Cross-Site Scripting (XSS)** &ndash; Intercepts browser script injection and malicious event handlers.
3. **Path Traversal (Directory Climbing)** &ndash; Blocks unauthorized traversal to sensitive host files (e.g., `/etc/passwd`, `boot.ini`).

The system uses an explainable, deterministic, regular-expression-based pattern matching rule engine backed by persistent SQLite audit logging and an interactive Security Operations Center (SOC) dashboard.

> **Safety Notice:** This project was developed strictly for academic evaluation and authorized local defensive testing. Testing should only be conducted against this local testbed or systems you have explicit authorization to audit.

---

## 2. Key Features

- **Inline Request Interception:** Inspects HTTP URI path, query parameters, form data, JSON payloads, and sensitive request headers prior to routing.
- **Explainable Rule Engine:** Decoupled detection logic with categorized threat signatures and risk levels (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
- **Dynamic Rule Management:** Admin can toggle rules (`ENABLE` / `DISABLE`) at runtime to demonstrate changed firewall enforcement without restarting the server.
- **Professional 403 Blocked Page:** Displays an incident reference ID, timestamp, violation reason, offending token snippet, and client IP without leaking server stack traces.
- **Tamper-Resistant Logging:** Stores all transactions in SQLite and writes structured audit logs to disk with automatic sanitization of sensitive credentials (passwords, tokens).
- **Interactive SOC Admin Dashboard:** Real-time statistics, threat distribution bars, risk categorization, and audit log filtering.
- **RESTful API & Postman Suite:** Programmatic endpoints for security telemetry and payload inspection.
- **Automated Test Suite:** PyTest and standard library unittest runners verifying true positives and clean traffic.

---

## 3. System Architecture

```text
       [ User / Attacker Browser / Postman ]
                         │
                         ▼ HTTP Request
             ┌───────────────────────┐
             │   Flask Application   │
             └───────────┬───────────┘
                         │
                         ▼
        ┌───────────────────────────────────┐
        │     WAF Middleware Interceptor    │
        │     (request_handler.py)          │
        └───────────────┬───────────────────┘
                        │
                        ▼ Extracts: Path, Query, Body, Headers
        ┌───────────────────────────────────┐
        │       Rule Engine Evaluator       │
        │       (rule_engine.py)            │
        └───────────────┬───────────────────┘
                        │
                        ▼ Normalizes & Evaluates
        ┌───────────────────────────────────┐
        │      Attack Detector Matrix       │
        │  ┌──────────────┬──────────────┐  │
        │  │ SQLi Detect  │  XSS Detect  │  │
        │  ├──────────────┼──────────────┤  │
        │  │ Path Travers │ Custom Rules │  │
        │  └──────────────┴──────────────┘  │
        └───────────────┬───────────────────┘
                        │
            ┌───────────┴───────────┐
            ▼                       ▼
      [ MATCH DETECTED ]      [ CLEAN / NO MATCH ]
            │                       │
            ▼                       ▼
┌───────────────────────┐ ┌───────────────────────┐
│ ACTION: BLOCKED (403) │ │ ACTION: ALLOWED (200) │
│ - Render blocked.html │ │ - Route to Application│
│ - Record security log │ │ - Record audit log    │
└───────────┬───────────┘ └───────────┬───────────┘
            │                         │
            └───────────┬─────────────┘
                        │
                        ▼
        ┌───────────────────────────────────┐
        │      SQLite Security Database     │
        │   (security_logs & rules tables)  │
        └───────────────┬───────────────────┘
                        │
                        ▼
        ┌───────────────────────────────────┐
        │     Admin SOC Dashboard / API     │
        │  (Charts, Filters, Rule Toggles)  │
        └───────────────────────────────────┘
```

---

## 4. Technology Stack

| Component | Technology | Role |
| :--- | :--- | :--- |
| **Backend** | Python 3.10+ / Flask | Application framework & middleware interception |
| **WSGI / Routing**| Werkzeug | Request parsing & header handling |
| **Database** | SQLite 3 | Persistent storage of audit logs and rule configurations |
| **Frontend UI** | HTML5, CSS3, JavaScript | Interactive web portal & SOC dashboard |
| **UI Framework** | Bootstrap 5, Bootstrap Icons | Responsive, clean cybersecurity layout |
| **Testing** | PyTest & Python unittest | Automated security test cases |
| **API Testing** | Postman Collection v2.1 | Demonstration requests for examiner evaluation |
| **VCS** | Git & GitHub | Version tracking |

---

## 5. Folder Structure

```text
waf-project/
│
├── app.py                      # Main application factory & error handlers
├── config.py                   # Centralized configuration settings
├── requirements.txt            # Python dependencies
├── README.md                   # Comprehensive documentation & viva guide
├── .gitignore                  # Git ignore rules
├── waf_audit.log               # Append-only text audit log file
│
├── waf/                        # Core Web Application Firewall Engine
│   ├── __init__.py             # WAF package exports
│   ├── request_handler.py      # Flask middleware request interceptor
│   ├── detector.py             # Modular attack detectors (SQLi, XSS, Path Traversal)
│   ├── rule_engine.py          # Rule loader & payload evaluator
│   ├── logger.py               # Security logger with credential redaction
│   └── security_rules.py       # Default threat signatures & regex patterns
│
├── database/                   # Database Layer
│   ├── __init__.py             # Database package init
│   ├── database.py             # SQLite helper queries & CRUD operations
│   ├── models.py               # Table schemas (security_logs, security_rules)
│   └── setup_db.py             # Database initialization script
│
├── routes/                     # Application Blueprints
│   ├── __init__.py             # Routes package init
│   ├── main.py                 # Sample protected business application
│   ├── admin.py                # Admin SOC dashboard & log viewer
│   └── api.py                  # JSON REST endpoints for telemetry & rules
│
├── templates/                  # Jinja2 HTML Templates
│   ├── index.html              # Protected web app with live testbed
│   ├── login.html              # Protected login page with SQLi demo presets
│   ├── dashboard.html          # Professional SOC Admin Dashboard
│   └── blocked.html            # Professional 403 Forbidden Blocked Page
│
├── static/                     # Static Assets
│   ├── css/
│   │   └── style.css           # Cybersecurity SOC dark stylesheet
│   └── js/
│       └── dashboard.js        # Dashboard client interactions
│
├── tests/                      # Automated Test Suite
│   ├── test_normal_requests.py # Normal requests (ALLOWED)
│   ├── test_sql_injection.py   # SQL injection attack suite (BLOCKED)
│   ├── test_xss.py             # Cross-Site Scripting attack suite (BLOCKED)
│   ├── test_path_traversal.py  # Path Traversal attack suite (BLOCKED)
│   └── run_all_tests.py        # Universal runner (runs with unittest or pytest)
│
└── postman/
    └── WAF_Threat_Detection.postman_collection.json  # Postman test collection
```

---

## 6. Installation & Local Setup

### Step 1: Clone or Open the Repository
```bash
git clone <repository-url>
cd waf-project
```

### Step 2: Create a Python Virtual Environment
On macOS / Linux:
```bash
python3 -m venv venv
source venv/bin/activate
```

On Windows (Command Prompt):
```cmd
python -m venv venv
venv\Scripts\activate.bat
```

On Windows (PowerShell):
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### Step 3: Install Required Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Initialize the SQLite Database
```bash
python database/setup_db.py
```
*This creates `database/waf_security.db` and populates the 14 default threat signatures.*

### Step 5: Start the WAF Server
```bash
python app.py
```

Open your browser:
- **Protected Web App:** `http://127.0.0.1:5000/`
- **Admin SOC Dashboard:** `http://127.0.0.1:5000/admin`
- **Login Portal:** `http://127.0.0.1:5000/login`

---

## 7. Automated Testing

### Option A: Using PyTest
```bash
pytest -v tests/
```

### Option B: Using Universal Python Test Runner (No Extra Dependencies)
```bash
python tests/run_all_tests.py
```

Expected Output:
```text
test_normal_legitimate_requests ... ok
test_path_traversal_dot_dot_slash ... ok
test_path_traversal_double_url_encoded ... ok
test_sql_injection_tautology ... ok
test_sql_injection_union_select ... ok
test_xss_inline_event_handler ... ok
test_xss_script_tags ... ok
----------------------------------------------------------------------
Ran 7 tests in 0.013s
OK
```

---

## 8. Step-by-Step Viva Demonstration Flow

Follow this exact sequence to demonstrate the project to the examiner:

1. **Start the Application:** Run `python app.py` and open `http://127.0.0.1:5000/`.
2. **Send Normal Request:** Click "Clean: `q=Firewall`".
   - *Observation:* HTTP 200 OK, matching products display, clean user experience.
3. **Inspect Admin SOC Dashboard:** Navigate to `http://127.0.0.1:5000/admin`.
   - *Observation:* Total Requests = 1, Allowed = 1, Blocked = 0.
4. **Demonstrate SQL Injection Detection:**
   - Return to Home, click "Attack: `' OR 1=1--`".
   - *Observation:* WAF immediately halts execution, returning HTTP 403 with `blocked.html`, Incident ID, Attack Type `SQL Injection`, and the offending token `' OR 1=1`.
5. **Demonstrate XSS Detection:**
   - On Home, click "Attack: `<script>alert('XSS')</script>`".
   - *Observation:* Request blocked with HTTP 403, Attack Type `Cross-Site Scripting`.
6. **Demonstrate Path Traversal Detection:**
   - On Home, click "Attack: `../../etc/passwd`".
   - *Observation:* Request blocked with HTTP 403, Attack Type `Path Traversal`.
7. **Review Telemetry:** Go to `/admin`.
   - *Observation:* Counters updated, Attack Vector Breakdown displays distribution bars.
8. **Demonstrate Dynamic Rule Toggling:**
   - Click "Rule Management" tab in Admin.
   - Locate `RULE-SQLI-001` (Boolean Tautology) and click **Disable**.
   - Return to Home and resubmit `' OR 1=1--`.
   - *Observation:* The request is now ALLOWED because the signature is deactivated.
   - Return to Admin and click **Enable** &rarr; behavior reverts back to BLOCKED.
   - *This demonstrates real-time firewall policy administration without code modification!*

---

## 9. Academic Module Explanations (For Viva Voce)

### 1. `request_handler.py` (Middleware Interceptor)
- **What it does:** Hooks into Flask's `before_request` lifecycle. It extracts client IP, method, requested URL, query string, request body, and headers.
- **Why it is needed:** Implements the core reverse-proxy security model. By inspecting traffic before route handlers execute, malicious payloads are stopped before reaching the application code or database.
- **How it works:** It checks if the path is an asset bypass (e.g. `/static/`), passes the context to `rule_engine.py`, and either returns HTTP 403 (`blocked.html`) or permits execution to continue (`return None`).

### 2. `detector.py` (Attack Detection Matrix)
- **What it does:** Contains dedicated detection algorithms for SQL Injection, XSS, and Path Traversal.
- **Why it is needed:** Different attack categories possess distinct syntactic traits. Separating them ensures high explainability, precision, and low false-positive rates.
- **How it works:** Normalizes input by performing recursive URL decoding (to counter double-encoding evasion like `%252e%252e%252f`), then compiles and evaluates case-insensitive regular expressions against the payload.

### 3. `rule_engine.py` (Rule Evaluator)
- **What it does:** Orchestrates the rules loaded from SQLite and iterates over each component of the HTTP request (path, query parameters, form body, JSON, and select headers).
- **Why it is needed:** Attackers may inject payloads in diverse HTTP locations (e.g., in a path for traversal, in a query param for SQLi, in a form field for XSS).
- **How it works:** Compiles an inspection checklist of `(Location, Value)` pairs, passes each to `detector.py`, and returns an authoritative decision dictionary containing risk level, matched rule ID, and reason.

### 4. `logger.py` (Security Logger)
- **What it does:** Writes structured logs to SQLite (`security_logs`) and an append-only audit file (`waf_audit.log`).
- **Why it is needed:** Post-incident forensics, audit compliance, and live telemetry in SOC dashboards require verifiable event records.
- **How it works:** Sanitizes sensitive parameter keys (`password`, `token`, `secret`) with `[REDACTED]` before saving, preventing credentials from leaking into log storage.

---

## 10. Limitations & Future Scope

### Current Prototype Limitations:
1. **Rule-Based Rigidity:** Regular expressions can be vulnerable to unknown zero-day variants and sophisticated novel obfuscation techniques.
2. **Single Server Process:** Designed for single-instance applications; not integrated with distributed caches (e.g., Redis).
3. **No Automatic Rate Limiting / IP Jailing:** Currently inspects syntax rather than volumetric flood attacks (e.g., DDoS).

### Future Improvements:
1. **Anomaly & Heuristic Scoring:** Assign numeric threat scores instead of immediate binary allow/block.
2. **Machine Learning / NLP Classification:** Integrate lightweight TF-IDF or Bayesian classifiers to detect anomalous payloads without rigid regex.
3. **Automated IP Reputation & Rate Limiting:** Implement sliding-window rate limiters with automatic temporary IP blacklisting (Fail2ban style).
4. **ModSecurity Rule Compatibility:** Support importing OWASP Core Rule Set (CRS) syntax.

---

## 11. Viva Voce Q&A Cheat Sheet

**Q1: What layer of the OSI model does a WAF operate on?**
*Answer:* Layer 7 (Application Layer). Unlike network firewalls (Layer 3/4) that inspect IP addresses and TCP/UDP ports, a WAF parses HTTP/HTTPS syntax, query parameters, headers, and payload bodies.

**Q2: How does the WAF prevent false positives?**
*Answer:* By requiring multi-token syntactic structure in regex patterns (e.g., requiring both `UNION` and `SELECT`, or `OR` followed by an equality comparison) rather than matching standalone isolated keywords.

**Q3: How does the WAF prevent evasion via URL encoding?**
*Answer:* The `AttackDetector.normalize_input()` method executes recursive URL-decoding (`urllib.parse.unquote_plus`) up to two passes, converting representations like `%252e%252e%252f` into `../` before regex evaluation.

**Q4: Why store rules in SQLite instead of hardcoding them in Python?**
*Answer:* Decoupling rules into SQLite enables runtime policy administration. Administrators can enable, disable, or adjust rule actions via the Admin Dashboard without taking down or restarting the application.
