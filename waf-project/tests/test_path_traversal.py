"""
PyTest Test Suite: Path Traversal (Directory Climbing) Detection
Verifies that path manipulation vectors and system file references are blocked with HTTP 403.
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

def test_path_traversal_dot_dot_slash_blocked(client):
    """Test classic ../ directory traversal is BLOCKED."""
    response = client.get("/view-file?file=../../etc/passwd")
    assert response.status_code == 403
    assert b"Path Traversal" in response.data

def test_path_traversal_url_encoded_blocked(client):
    """Test URL-encoded traversal sequence ..%2f..%2f is BLOCKED."""
    response = client.get("/view-file?file=..%2f..%2fetc/passwd")
    assert response.status_code == 403
    assert b"Path Traversal" in response.data

def test_path_traversal_windows_system_file_blocked(client):
    """Test Windows boot.ini access attempt is BLOCKED."""
    response = client.get("/view-file?file=boot.ini")
    assert response.status_code == 403
    assert b"Path Traversal" in response.data

def test_path_traversal_null_byte_blocked(client):
    """Test poison null byte attempt is BLOCKED."""
    response = client.get("/view-file?file=document.pdf%00.exe")
    assert response.status_code == 403
    assert b"Path Traversal" in response.data

if __name__ == "__main__":
    pytest.main(["-v", __file__])
