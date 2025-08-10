"""
Conftest for coverage tests - disables sandboxing and network blocking.
"""

import pytest
import os
from unittest.mock import patch, MagicMock


@pytest.fixture(autouse=True, scope="session")
def disable_sandboxing():
    """Disable sandboxing for all tests."""
    os.environ["IMAGE_CONVERTER_ENABLE_SANDBOXING"] = "false"
    os.environ["TESTING"] = "true"
    yield
    # Cleanup
    os.environ.pop("IMAGE_CONVERTER_ENABLE_SANDBOXING", None)
    os.environ.pop("TESTING", None)


@pytest.fixture(autouse=True)
def mock_network_blocking():
    """Mock network blocking to allow tests."""
    with patch('socket.socket') as mock_socket:
        # Allow socket creation for tests
        mock_socket.return_value = MagicMock()
        yield


@pytest.fixture(autouse=True)
def mock_subprocess_sandbox():
    """Mock subprocess sandboxing."""
    with patch('app.core.security.sandbox.subprocess') as mock_subprocess:
        mock_subprocess.run.return_value = MagicMock(
            returncode=0,
            stdout=b"fake_output",
            stderr=b""
        )
        yield