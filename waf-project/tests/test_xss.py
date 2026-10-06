"""
PyTest Test Suite: Cross-Site Scripting (XSS) Detection
Verifies that malicious HTML/JavaScript vectors are intercepted and blocked with HTTP 403.
"""

import sys
from pathlib import Path
import pytest

# Add parent directory to path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from app import create_app
from config import TestingConfig
from database.database import init_db

@pytest.fixture
def client():
    """Create a configured Flask test client."""
    app = create_app(TestingConfig)
    with app.test_client() as client:
        with app.app_context():
            init_db(TestingConfig.DATABASE_PATH)
        yield client

def test_xss_script_tag_blocked(client):
    """Test raw <script> tag injection in query parameter is BLOCKED."""
    response = client.get("/search?q=<script>alert('XSS')</script>")
    assert response.status_code == 403
    assert b"Cross-Site Scripting" in response.data

def test_xss_inline_onerror_event_blocked(client):
    """Test HTML inline event handler onerror=alert(1) is BLOCKED."""
    response = client.get("/search?q=<img src=x onerror=alert(1)>")
    assert response.status_code == 403
    assert b"Cross-Site Scripting" in response.data

def test_xss_pseudo_protocol_blocked(client):
    """Test javascript: protocol injection is BLOCKED."""
    response = client.post("/contact", data={
        "name": "Attacker",
        "message": "<a href='javascript:alert(document.cookie)'>Click me</a>"
    })
    assert response.status_code == 403
    assert b"Cross-Site Scripting" in response.data

def test_xss_iframe_injection_blocked(client):
    """Test iframe injection vector is BLOCKED."""
    response = client.get("/search?q=<iframe src='https://malicious.example'></iframe>")
    assert response.status_code == 403
    assert b"Cross-Site Scripting" in response.data

if __name__ == "__main__":
    pytest.main(["-v", __file__])
