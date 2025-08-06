#!/usr/bin/env python3
"""Fix CLI to use SDK correctly with temp files"""

import re
from pathlib import Path

def fix_convert_command(file_path):
    """Fix convert.py to use temp files for SDK"""
    
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Replace the convert_image call to use temp file
    new_convert_code = '''        # Show enhanced progress with interruption support
        import tempfile
        import os
        
        with InterruptableProgress(
            description="Converting image",
            total=100,
            show_emoji=should_use_emoji(),
            console=console,
            show_speed=True
        ) as progress:
            task = progress.add_task("Converting...", total=100)
            
            # Create temp file for SDK (it expects file path)
            with tempfile.NamedTemporaryFile(suffix=input_path.suffix, delete=False) as tmp_input:
                tmp_input.write(image_data)
                tmp_input_path = tmp_input.name
            
            try:
                # Perform conversion (SDK expects file path)
                output_data, result = client.convert_image(
                    image_path=tmp_input_path,
                    output_format=format.lower(),
                    quality=quality,
                    strip_metadata=not keep_metadata,
                    preset_id=preset
                )
                
                progress.update(task, advance=50, description="Processing...")
                
                # Write output file
                with open(output_path, 'wb') as f:
                    f.write(output_data)
                
                progress.update(task, advance=50, description="Saving...")
            finally:
                # Clean up temp file
                if os.path.exists(tmp_input_path):
                    os.unlink(tmp_input_path)'''
    
    # Find and replace the progress block
    pattern = r'        # Show enhanced progress.*?progress\.update\(task, advance=50, description="Saving\.\.\."\)'
    content = re.sub(pattern, new_convert_code, content, flags=re.DOTALL)
    
    # Also fix the stdin conversion
    stdin_fix = '''        # Create temp file for SDK
        import tempfile
        import os
        
        with tempfile.NamedTemporaryFile(suffix='.tmp', delete=False) as tmp_input:
            tmp_input.write(image_data)
            tmp_input_path = tmp_input.name
        
        try:
            # Perform conversion (SDK expects file path)
            output_data, result = client.convert_image(
                image_path=tmp_input_path,
                output_format=format.lower(),
                quality=quality,
                strip_metadata=True
            )
        finally:
            # Clean up temp file
            if os.path.exists(tmp_input_path):
                os.unlink(tmp_input_path)'''
    
    # Replace stdin conversion
    pattern2 = r'        # Perform conversion\s+result = client\.convert_image\([^)]+\)'
    content = re.sub(pattern2, stdin_fix, content)
    
    # Fix result references
    content = content.replace('result.output_data', 'output_data')
    
    with open(file_path, 'w') as f:
        f.write(content)
    
    return True

def main():
    convert_file = Path('app/cli/commands/convert.py')
    
    if fix_convert_command(convert_file):
        print(f"Fixed {convert_file}")
    else:
        print("Failed to fix convert.py")
    
    # Similar fixes needed for optimize.py and chain.py
    # But let's test this first

if __name__ == '__main__':
    main()