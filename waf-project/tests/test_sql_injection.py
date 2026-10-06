"""
PyTest Test Suite: SQL Injection (SQLi) Detection
Verifies that malicious SQL patterns are intercepted and blocked with HTTP 403.
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

def test_sqli_boolean_tautology_blocked(client):
    """Test SQLi boolean tautology (' OR '1'='1) in query parameter is BLOCKED."""
    response = client.get("/search?q=' OR '1'='1")
    assert response.status_code == 403
    assert b"REQUEST BLOCKED" in response.data or b"Request Blocked" in response.data
    assert b"SQL Injection" in response.data

def test_sqli_union_select_blocked(client):
    """Test SQLi UNION SELECT statement is BLOCKED."""
    response = client.get("/search?q=' UNION SELECT null, username, password FROM users--")
    assert response.status_code == 403
    assert b"SQL Injection" in response.data

def test_sqli_destructive_drop_table_blocked(client):
    """Test SQLi DROP TABLE statement in form post is BLOCKED."""
    response = client.post("/login", data={
        "username": "admin'; DROP TABLE users--",
        "password": "password"
    })
    assert response.status_code == 403
    assert b"SQL Injection" in response.data

def test_sqli_json_api_blocked(client):
    """Test SQLi in API request returns JSON 403."""
    response = client.post("/api/inspect", json={
        "path": "/products",
        "query": {"id": "1 OR 1=1"}
    })
    assert response.status_code == 200  # Note: inspect API returns analysis dict without blocking
    json_data = response.get_json()
    assert json_data["is_blocked"] is True
    assert json_data["attack_type"] == "SQL Injection"

if __name__ == "__main__":
    pytest.main(["-v", __file__])
