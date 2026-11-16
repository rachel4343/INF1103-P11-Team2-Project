# Shared fixtures for all tests
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
    # Cleanup after test
    if Path(path).exists():
        try:
            Path(path).unlink()
        except:
            pass