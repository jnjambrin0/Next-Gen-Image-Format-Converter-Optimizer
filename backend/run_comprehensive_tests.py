#!/usr/bin/env python3
"""Run comprehensive tests for the Intelligence Engine.

This script runs all test suites to validate robustness, security, and performance.
"""

import subprocess
import sys
import time
from pathlib import Path

def run_test_suite(name: str, command: list) -> bool:
    """Run a test suite and return success status."""
    print(f"\n{'='*60}")
    print(f"Running {name}")
    print(f"{'='*60}")
    
    start_time = time.time()
    result = subprocess.run(command, capture_output=True, text=True)
    elapsed = time.time() - start_time
    
    if result.returncode == 0:
        print(f"✅ {name} PASSED in {elapsed:.2f}s")
        return True
    else:
        print(f"❌ {name} FAILED in {elapsed:.2f}s")
        print("\nSTDOUT:")
        print(result.stdout)
        print("\nSTDERR:")
        print(result.stderr)
        return False

def main():
    """Run all test suites."""
    # Change to backend directory
    backend_dir = Path(__file__).parent
    
    test_suites = [
        ("Unit Tests", ["python", "-m", "pytest", "tests/unit/test_intelligence_engine.py", "-v"]),
        ("Integration Tests", ["python", "-m", "pytest", "tests/integration/test_intelligence_engine_real_world.py", "-v"]),
        ("Security Tests", ["python", "-m", "pytest", "tests/security/test_intelligence_security.py", "-v"]),
        ("Performance Tests", ["python", "-m", "pytest", "tests/integration/test_intelligence_engine_real_world.py::TestIntelligenceEngineRealWorld::test_performance_benchmarks", "-v"]),
        ("Memory Tests", ["python", "-m", "pytest", "tests/integration/test_intelligence_engine_real_world.py::TestIntelligenceEngineRealWorld::test_memory_constraints", "-v"]),
        ("Concurrency Tests", ["python", "-m", "pytest", "tests/integration/test_intelligence_engine_real_world.py::TestIntelligenceEngineRealWorld::test_concurrent_processing", "-v"]),
    ]
    
    results = []
    total_start = time.time()
    
    print("🧪 Running Comprehensive Intelligence Engine Tests")
    print(f"Testing {len(test_suites)} test suites...")
    
    for name, command in test_suites:
        success = run_test_suite(name, command)
        results.append((name, success))
    
    total_elapsed = time.time() - total_start
    
    # Summary
    print(f"\n{'='*60}")
    print("TEST SUMMARY")
    print(f"{'='*60}")
    
    passed = sum(1 for _, success in results if success)
    failed = len(results) - passed
    
    for name, success in results:
        status = "✅ PASSED" if success else "❌ FAILED"
        print(f"{name:.<40} {status}")
    
    print(f"\nTotal: {passed}/{len(results)} passed, {failed} failed")
    print(f"Total time: {total_elapsed:.2f}s")
    
    if failed > 0:
        print("\n❌ Some tests failed. Please review the output above.")
        sys.exit(1)
    else:
        print("\n✅ All tests passed! The Intelligence Engine is robust, secure, and performant.")
        sys.exit(0)

if __name__ == "__main__":
    main()