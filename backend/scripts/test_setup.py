#!/usr/bin/env python3
"""
Test Infrastructure Setup Script
Ensures consistent test environment and memory limits
"""

import os
import sys
import tempfile
from pathlib import Path


def setup_test_environment():
    """Setup critical test environment variables"""

    # Core environment variables required for testing
    test_env = {
        "IMAGE_CONVERTER_ENABLE_SANDBOXING": "false",  # Critical: Sandboxing blocks test execution
        "TESTING": "true",
        "IMAGE_CONVERTER_SECRET_KEY": "test-secret-key-for-testing-only-32chars",
        "PYTHONPATH": str(Path(__file__).parent.parent),
        # Memory and performance settings for tests
        "IMAGE_CONVERTER_SANDBOX_STRICTNESS": "standard",
        "MAX_MEMORY_PER_TEST": "256MB",
        "TEST_TIMEOUT": "300",  # 5 minutes
        # Database settings for tests
        "DATABASE_URL": "sqlite:///test_db.sqlite",
        "TEST_DATA_DIR": str(Path(__file__).parent.parent / "tests" / "fixtures"),
        # Disable external services during testing
        "DISABLE_TELEMETRY": "true",
        "DISABLE_ANALYTICS": "true",
        "OFFLINE_MODE": "true",
    }

    print("Setting up test environment...")
    for key, value in test_env.items():
        os.environ[key] = value
        print(f"  {key}={value}")

    # Ensure test directories exist
    setup_test_directories()

    print("Test environment setup complete!")
    return test_env


def setup_test_directories():
    """Ensure all required test directories exist"""

    base_dir = Path(__file__).parent.parent
    required_dirs = [
        base_dir / "data",
        base_dir / "test_models",
        base_dir / "tests" / "fixtures",
        base_dir / "logs",
    ]

    for directory in required_dirs:
        directory.mkdir(parents=True, exist_ok=True)
        print(f"  Created/verified directory: {directory}")


def check_memory_limits():
    """Check and configure memory limits for tests"""
    try:
        import psutil

        available_memory = psutil.virtual_memory().available / (1024 * 1024)  # MB

        if available_memory < 1024:  # Less than 1GB available
            print(f"WARNING: Low available memory: {available_memory:.0f}MB")
            print("Consider reducing test concurrency")
            return False
        else:
            print(f"Available memory: {available_memory:.0f}MB - OK")
            return True

    except ImportError:
        print("WARNING: psutil not available, cannot check memory limits")
        return True


def verify_test_dependencies():
    """Verify all required test dependencies are available"""

    required_modules = ["pytest", "asyncio", "PIL", "numpy", "structlog"]

    missing_modules = []
    for module in required_modules:
        try:
            __import__(module)
            print(f"  ✓ {module}")
        except ImportError:
            missing_modules.append(module)
            print(f"  ✗ {module} - MISSING")

    if missing_modules:
        print(f"ERROR: Missing required modules: {', '.join(missing_modules)}")
        sys.exit(1)

    print("All test dependencies verified!")


def main():
    """Main test setup function"""
    print("=== Test Infrastructure Hardening ===\n")

    # Setup environment
    setup_test_environment()
    print()

    # Check system resources
    print("Checking system resources...")
    memory_ok = check_memory_limits()
    print()

    # Verify dependencies
    print("Verifying test dependencies...")
    verify_test_dependencies()
    print()

    if memory_ok:
        print("✅ Test infrastructure setup complete - ready to run tests!")
        return 0
    else:
        print("⚠️  Test infrastructure setup complete with warnings")
        return 1


if __name__ == "__main__":
    sys.exit(main())
