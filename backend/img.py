#!/usr/bin/env python3
"""
Image Converter CLI - Main entry point
Professional CLI for next-gen image format conversion
"""

import sys
from pathlib import Path

# Add the backend directory to Python path for imports
backend_dir = Path(__file__).parent
sys.path.insert(0, str(backend_dir))

from app.cli.main import app

if __name__ == "__main__":
    app()
