#!/usr/bin/env python3
"""Test the validate_advanced_params function directly."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

# Import the validation logic
exec(open('backend/app/core/conversion/sandboxed_convert.py').read().split('def main')[0])

# Test the validation function
test_cases = [
    ("jpeg", {"progressive": True}, {"progressive": True}),
    ("jpeg", {"__class__": "evil"}, {}),
    ("jpeg", {"subsampling": 99}, {}),
    ("jpeg", {"subsampling": 2}, {"subsampling": 2}),
    ("webp", {"method": 99}, {}),
    ("webp", {"method": 4}, {"method": 4}),
    ("png", {"compress_level": 999}, {}),
    ("png", {"compress_level": 9}, {"compress_level": 9}),
]

print("Testing validate_advanced_params function:\n")

for format_name, input_params, expected_output in test_cases:
    result = validate_advanced_params(input_params, format_name)
    status = "✓" if result == expected_output else "✗"
    print(f"{status} Format: {format_name}")
    print(f"  Input:    {input_params}")
    print(f"  Expected: {expected_output}")
    print(f"  Got:      {result}")
    print()