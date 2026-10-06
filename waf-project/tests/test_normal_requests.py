"""
PyTest Test Suite: Normal / Legitimate HTTP Requests
Verifies that benign traffic passes through the WAF without false positives.
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

def test_home_page_allowed(client):
    """Test accessing the home page returns 200 OK (ALLOWED)."""
    response = client.get("/")
    assert response.status_code == 200
    assert b"SecurCorp Enterprise" in response.data

def test_legitimate_search_allowed(client):
    """Test standard alphanumeric search query is ALLOWED."""
    response = client.get("/search?q=Firewall")
    assert response.status_code == 200
    assert b"Request Blocked" not in response.data

def test_legitimate_file_view_allowed(client):
    """Test accessing a standard whitelist document is ALLOWED."""
    response = client.get("/view-file?file=whitepaper.pdf")
    assert response.status_code == 200
    assert b"Request Blocked" not in response.data

def test_legitimate_login_post_allowed(client):
    """Test normal credentials post is ALLOWED."""
    response = client.post("/login", data={"username": "alice", "password": "SafePassword123"})
    assert response.status_code == 200
    assert b"Request Blocked" not in response.data

if __name__ == "__main__":
    pytest.main(["-v", __file__])
