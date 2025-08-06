#!/usr/bin/env python3
"""Fix SDK client initialization parameters in CLI commands"""

import re
from pathlib import Path

def fix_sdk_initialization(file_path):
    """Fix SDK client initialization to use host/port instead of base_url"""
    
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Check if file needs fixing
    if 'base_url=config.api_url' not in content:
        return False
    
    # Fix sync client
    content = re.sub(
        r'ImageConverterClient\(\s*base_url=config\.api_url,',
        'ImageConverterClient(\n            host=config.api_host,\n            port=config.api_port,',
        content,
        flags=re.MULTILINE
    )
    
    # Fix async client
    content = re.sub(
        r'AsyncImageConverterClient\(\s*base_url=config\.api_url,',
        'AsyncImageConverterClient(\n        host=config.api_host,\n        port=config.api_port,',
        content,
        flags=re.MULTILINE
    )
    
    # Ensure we have the right config attributes imported
    if 'config.api_host' in content and 'from app.cli.config import get_config' in content:
        # Add a note that config needs api_host and api_port
        pass
    
    with open(file_path, 'w') as f:
        f.write(content)
    
    return True

def main():
    cli_path = Path('app/cli')
    
    # Find all Python files
    files = list(cli_path.glob('**/*.py'))
    
    fixed_files = []
    for file_path in files:
        if fix_sdk_initialization(file_path):
            fixed_files.append(file_path)
    
    if fixed_files:
        print(f"Fixed {len(fixed_files)} files:")
        for f in fixed_files:
            print(f"  - {f}")
    else:
        print("No files needed fixing")
    
    # Now check config.py
    config_file = cli_path / 'config.py'
    with open(config_file, 'r') as f:
        config_content = f.read()
    
    if 'api_host' not in config_content:
        print("\nNeed to add api_host and api_port to CLIConfig")
        # Add the fields
        config_content = config_content.replace(
            'api_url: str = Field(default="http://localhost:8080", description="Backend API URL")',
            'api_url: str = Field(default="http://localhost:8080", description="Backend API URL")\n    api_host: str = Field(default="localhost", description="Backend API host")\n    api_port: int = Field(default=8080, description="Backend API port")'
        )
        
        with open(config_file, 'w') as f:
            f.write(config_content)
        print("Added api_host and api_port to CLIConfig")

if __name__ == '__main__':
    main()