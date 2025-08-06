#!/usr/bin/env python3
"""Example: Convert a single image using the Image Converter SDK."""

import sys
from pathlib import Path
from image_converter import ImageConverterClient


def main():
    """Demonstrate single image conversion."""
    
    # Initialize client (localhost only for security)
    client = ImageConverterClient(
        host="localhost",
        port=8080,
        api_key=None,  # Will try to get from env or secure storage
    )
    
    # Example image path
    if len(sys.argv) < 2:
        print("Usage: python convert_single.py <image_path> [output_format]")
        print("Example: python convert_single.py photo.jpg webp")
        sys.exit(1)
    
    image_path = Path(sys.argv[1])
    output_format = sys.argv[2] if len(sys.argv) > 2 else "webp"
    
    if not image_path.exists():
        print(f"Error: Image file not found: {image_path}")
        sys.exit(1)
    
    try:
        # Convert the image
        print(f"Converting {image_path.name} to {output_format}...")
        
        converted_data, metadata = client.convert_image(
            image_path=image_path,
            output_format=output_format,
            quality=85,
            strip_metadata=True,  # Privacy-first: remove metadata by default
        )
        
        # Save the converted image
        output_path = image_path.with_suffix(f".converted.{output_format}")
        output_path.write_bytes(converted_data)
        
        # Display conversion results
        print(f"\n✅ Conversion successful!")
        print(f"📁 Output saved to: {output_path}")
        print(f"📊 Conversion Details:")
        print(f"   - Processing time: {metadata.processing_time:.3f}s")
        print(f"   - Input format: {metadata.input_format}")
        print(f"   - Output format: {metadata.output_format}")
        print(f"   - Input size: {metadata.input_size:,} bytes")
        print(f"   - Output size: {metadata.output_size:,} bytes")
        print(f"   - Compression ratio: {metadata.compression_ratio:.1%}")
        print(f"   - Quality used: {metadata.quality_used}")
        print(f"   - Metadata removed: {metadata.metadata_removed}")
        
    except Exception as e:
        print(f"❌ Conversion failed: {e}")
        sys.exit(1)
    finally:
        # Clean up
        client.close()


if __name__ == "__main__":
    main()