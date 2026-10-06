"""
Main routes for the sample protected web application.
This represents the backend business application that sits behind the WAF.
"""

from flask import Blueprint, render_template, request, flash, redirect, url_for

main_bp = Blueprint("main", __name__)

# Sample mock data for application display
MOCK_PRODUCTS = [
    {"id": 1, "name": "Enterprise Security Gateway", "category": "Network", "price": "$1,200"},
    {"id": 2, "name": "Endpoint Threat Sentinel", "category": "Host", "price": "$450"},
    {"id": 3, "name": "Cloud Access Security Broker", "category": "Cloud", "price": "$890"},
    {"id": 4, "name": "Vulnerability Scanner Pro", "category": "Audit", "price": "$600"}
]

@main_bp.route("/")
def index():
    """Application home page with interactive test forms."""
    return render_template("index.html", products=MOCK_PRODUCTS)

@main_bp.route("/login", methods=["GET", "POST"])
def login():
    """Sample login endpoint demonstrating SQL injection authentication protection."""
    error = None
    success = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        
        # Standard clean authentication check
        if username == "admin" and password == "SecurPass2026!":
            success = "Welcome, Administrator! You have logged into the portal securely."
        else:
            error = "Invalid username or password. (Try username: admin / password: SecurPass2026!)"

    return render_template("login.html", error=error, success=success)

@main_bp.route("/search")
def search():
    """Sample search endpoint vulnerable to SQLi / XSS if unprotected."""
    query = request.args.get("q", "").strip()
    results = []
    if query:
        # Search mock catalog
        results = [p for p in MOCK_PRODUCTS if query.lower() in p["name"].lower() or query.lower() in p["category"].lower()]
    
    return render_template("index.html", products=results, search_query=query, is_search=True)

@main_bp.route("/view-file")
def view_file():
    """
    Sample document reader endpoint.
    If unprotected, an attacker could supply `file=../../etc/passwd`.
    Behind WAF, the rule engine intercepts and blocks the request.
    """
    filename = request.args.get("file", "whitepaper.pdf")
    
    # In a safe demo app, return simulated document view
    safe_docs = {
        "whitepaper.pdf": "Cybersecurity Architecture Whitepaper v2.4 (Legitimate Content)",
        "guidelines.txt": "Corporate Access Policy and Guidelines 2026",
        "release_notes.md": "Release notes for Web Application Firewall v1.0"
    }
    
    content = safe_docs.get(filename, f"Document [{filename}] loaded successfully from internal archive.")
    return render_template("index.html", doc_content=content, doc_name=filename, is_doc=True)

@main_bp.route("/contact", methods=["POST"])
def contact():
    """Feedback submission endpoint prone to stored/reflected XSS if unprotected."""
    name = request.form.get("name", "")
    message = request.form.get("message", "")
    return render_template("index.html", contact_ack=f"Thank you, {name}! Your message was securely received.")
