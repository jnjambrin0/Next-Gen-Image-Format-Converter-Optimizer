"""
from typing import Any
CLI Utilities Package
Helper utilities for the CLI
"""

import sys
from pathlib import Path


def setup_sdk_path() -> None:
    """Setup SDK path for imports"""
    # Find the SDK path relative to backend directory
    backend_dir = Path(__file__).parent.parent.parent
    sdk_path = backend_dir.parent / "sdks" / "python"

    # Add to path if not already there
    sdk_path_str = str(sdk_path)
    if sdk_path_str not in sys.path:
        sys.path.insert(0, sdk_path_str)
