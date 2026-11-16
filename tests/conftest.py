import os
import tempfile
from pathlib import Path
import pytest

@pytest.fixture
def temp_data_file():
    """Create a temporary JSON file for testing."""
    fd, path = tempfile.mkstemp(suffix='.json')
    os.close(fd)
    yield Path(path)
    if Path(path).exists():
        try:
            Path(path).unlink()
        except:
            pass

@pytest.fixture
def sample_report():
    """Return a sample valid report dictionary."""
    return {
        "report_id": "PG-00001",
        "sender_name": "IT Support",
        "sender_email": "support@example.com",
        "subject": "Urgent: Verify your account",
        "body": "Please click the link and enter your password.",
        "viewed": False,
        "reason_for_suspicion": "Looks suspicious"
    }
