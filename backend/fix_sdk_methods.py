#!/usr/bin/env python3
"""Fix SDK method names in CLI commands"""

import re
from pathlib import Path

def fix_sdk_methods(file_path):
    """Fix SDK method names to match actual SDK"""
    
    with open(file_path, 'r') as f:
        content = f.read()
    
    changed = False
    
    # Fix convert -> convert_image
    if 'client.convert(' in content:
        content = content.replace('client.convert(', 'client.convert_image(')
        changed = True
    
    # Fix analyze -> analyze_image
    if 'client.analyze(' in content:
        content = content.replace('client.analyze(', 'client.analyze_image(')
        changed = True
    
    # Fix get_formats -> get_supported_formats
    if 'client.get_formats(' in content:
        content = content.replace('client.get_formats(', 'client.get_supported_formats(')
        changed = True
    
    # Fix optimize -> convert_image (with optimize settings)
    if 'client.optimize(' in content:
        content = content.replace('client.optimize(', 'client.convert_image(')
        changed = True
    
    if changed:
        with open(file_path, 'w') as f:
            f.write(content)
    
    return changed

def main():
    cli_path = Path('app/cli')
    
    # Find all Python files
    files = list(cli_path.glob('**/*.py'))
    
    fixed_files = []
    for file_path in files:
        if fix_sdk_methods(file_path):
            fixed_files.append(file_path)
    
    if fixed_files:
        print(f"Fixed {len(fixed_files)} files:")
        for f in fixed_files:
            print(f"  - {f}")
    else:
        print("No files needed fixing")

if __name__ == '__main__':
    main()