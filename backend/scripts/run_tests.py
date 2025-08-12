#!/usr/bin/env python3
"""
Robust Test Runner Script
Runs tests with proper memory limits, error handling, and infrastructure hardening
"""

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional

# Import test setup
sys.path.insert(0, str(Path(__file__).parent))
from test_setup import (
    check_memory_limits,
    setup_test_environment,
    verify_test_dependencies,
)


class TestRunner:
    """Manages test execution with resource monitoring and error handling"""

    def __init__(self):
        self.base_dir = Path(__file__).parent.parent
        self.max_memory_mb = 2048  # 2GB memory limit
        self.timeout_seconds = 1800  # 30 minute timeout

    def run_test_suite(
        self, suite_name: str, specific_test: Optional[str] = None
    ) -> bool:
        """Run a specific test suite with proper error handling"""

        suite_mapping = {
            "core": "tests/suite_1_core/",
            "security": "tests/suite_2_security/",
            "performance": "tests/suite_3_performance/",
            "integration": "tests/suite_4_integration/",
            "unit": "tests/unit/",
            "all": "tests/",
        }

        if suite_name not in suite_mapping:
            print(f"ERROR: Unknown test suite '{suite_name}'")
            print(f"Available suites: {', '.join(suite_mapping.keys())}")
            return False

        test_path = suite_mapping[suite_name]
        if specific_test:
            test_path = f"{test_path}::{specific_test}"

        print(f"Running test suite: {suite_name}")
        print(f"Test path: {test_path}")

        # Build pytest command with optimizations
        cmd = [
            sys.executable,
            "-m",
            "pytest",
            test_path,
            "-v",  # Verbose output
            "--tb=short",  # Short traceback format
            "--durations=10",  # Show 10 slowest tests
            f"--timeout={self.timeout_seconds}",  # Per-test timeout
            "--timeout-method=thread",
            "-x",  # Stop on first failure for debugging
        ]

        # Add memory-conscious options for performance tests
        if suite_name == "performance":
            cmd.extend(
                [
                    "--maxfail=3",  # Stop after 3 failures
                    "-n",
                    "auto",  # Parallel execution based on CPU count
                ]
            )

        # Add coverage for unit tests
        if suite_name in ["unit", "core"]:
            cmd.extend(
                [
                    "--cov=app",
                    "--cov-report=term-missing",
                    "--cov-fail-under=40",  # Realistic coverage target
                ]
            )

        return self._execute_command(cmd, test_path)

    def _execute_command(self, cmd: List[str], test_description: str) -> bool:
        """Execute pytest command with resource monitoring"""

        print(f"Executing: {' '.join(cmd)}")
        print("-" * 60)

        try:
            # Set working directory to backend
            os.chdir(self.base_dir)

            # Start process with memory limits
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True,
            )

            # Monitor process output and memory
            start_time = time.time()

            for line in iter(process.stdout.readline, ""):
                print(line.rstrip())

                # Check for memory issues in output
                if any(
                    keyword in line.lower()
                    for keyword in ["memoryerror", "out of memory", "killed"]
                ):
                    print("⚠️  Memory issue detected in test output")

            # Wait for completion
            return_code = process.wait()
            elapsed_time = time.time() - start_time

            print("-" * 60)
            print(f"Test execution completed in {elapsed_time:.2f} seconds")

            if return_code == 0:
                print("✅ All tests passed!")
                return True
            else:
                print(f"❌ Tests failed with return code: {return_code}")
                return False

        except subprocess.TimeoutExpired:
            print(f"❌ Tests timed out after {self.timeout_seconds} seconds")
            if process:
                process.kill()
            return False
        except Exception as e:
            print(f"❌ Test execution error: {e}")
            return False

    def run_health_check(self) -> bool:
        """Run a quick health check of critical tests"""

        critical_tests = [
            "tests/unit/test_intelligence_engine.py::TestIntelligenceEngine::test_classify_content_cascade_architecture",
            "tests/unit/test_conversion_manager_new.py::TestConversionManager::test_convert_png_to_avif_success",
        ]

        print("Running critical test health check...")
        all_passed = True

        for test in critical_tests:
            print(f"\nTesting: {test}")
            cmd = [sys.executable, "-m", "pytest", test, "-v", "--tb=short"]

            if not self._execute_command(cmd, f"Health check: {test}"):
                all_passed = False
                break  # Stop on first failure

        return all_passed


def main():
    """Main test runner function"""

    parser = argparse.ArgumentParser(
        description="Robust test runner with infrastructure hardening"
    )
    parser.add_argument(
        "suite",
        nargs="?",
        default="health",
        help="Test suite to run (core, security, performance, integration, unit, all, health)",
    )
    parser.add_argument("--test", "-t", help="Specific test to run within the suite")
    parser.add_argument(
        "--no-setup", action="store_true", help="Skip test environment setup"
    )

    args = parser.parse_args()

    print("=== Robust Test Runner ===\n")

    # Setup test environment unless skipped
    if not args.no_setup:
        print("Setting up test environment...")
        setup_test_environment()

        print("\nVerifying test dependencies...")
        verify_test_dependencies()

        print("\nChecking memory limits...")
        if not check_memory_limits():
            print("WARNING: Proceeding with limited memory")

        print("\n" + "=" * 50 + "\n")

    # Create test runner
    runner = TestRunner()

    # Run requested tests
    if args.suite == "health":
        success = runner.run_health_check()
    else:
        success = runner.run_test_suite(args.suite, args.test)

    if success:
        print("\n🎉 Test execution completed successfully!")
        return 0
    else:
        print("\n💥 Test execution failed!")
        return 1


if __name__ == "__main__":
    sys.exit(main())
