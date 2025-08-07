#!/usr/bin/env python3
"""Example: Batch convert multiple images using the Image Converter SDK."""

import sys
import time
from pathlib import Path
from image_converter import ImageConverterClient


def main():
    """Demonstrate batch image conversion with progress tracking."""

    # Initialize client (localhost only for security)
    client = ImageConverterClient(
        host="localhost",
        port=8000,
        api_key=None,  # Will try to get from env or secure storage
    )

    # Get directory or list of images
    if len(sys.argv) < 2:
        print("Usage: python batch_convert.py <directory_or_images...> [output_format]")
        print("Example: python batch_convert.py ./photos webp")
        print("Example: python batch_convert.py photo1.jpg photo2.png photo3.heic avif")
        sys.exit(1)

    # Determine if first arg is directory or file
    first_arg = Path(sys.argv[1])
    output_format = "webp"  # Default

    if first_arg.is_dir():
        # Directory mode
        image_paths = (
            list(first_arg.glob("*.jpg"))
            + list(first_arg.glob("*.jpeg"))
            + list(first_arg.glob("*.png"))
            + list(first_arg.glob("*.heic"))
            + list(first_arg.glob("*.heif"))
        )

        if len(sys.argv) > 2:
            output_format = sys.argv[2]
    else:
        # File list mode
        image_paths = []
        for arg in sys.argv[1:]:
            path = Path(arg)
            if path.suffix.lower() in [".jpg", ".jpeg", ".png", ".heic", ".heif", ".bmp", ".tiff"]:
                image_paths.append(path)
            else:
                # Assume it's the output format
                output_format = arg

    if not image_paths:
        print("Error: No valid image files found")
        sys.exit(1)

    print(f"Found {len(image_paths)} images to convert to {output_format}")

    try:
        # Create batch job
        print("\n📦 Creating batch conversion job...")

        batch_status = client.create_batch(
            image_paths=image_paths,
            output_format=output_format,
            quality=85,
            strip_metadata=True,  # Privacy-first
            max_concurrent=5,
        )

        print(f"✅ Batch job created: {batch_status.job_id}")
        print(f"📊 Total files: {batch_status.total_files}")

        # Poll for status
        print("\n⏳ Processing...")
        prev_progress = -1

        while batch_status.status not in ["completed", "failed", "cancelled"]:
            time.sleep(2)  # Poll every 2 seconds

            batch_status = client.get_batch_status(batch_status.job_id)

            # Show progress bar
            if batch_status.progress_percentage != prev_progress:
                prev_progress = batch_status.progress_percentage
                completed = int(batch_status.progress_percentage / 2)  # 50 chars wide
                remaining = 50 - completed
                progress_bar = "█" * completed + "░" * remaining

                print(
                    f"\r[{progress_bar}] {batch_status.progress_percentage:.0f}% "
                    f"({batch_status.completed_files}/{batch_status.total_files} files)",
                    end="",
                    flush=True,
                )

        print()  # New line after progress

        # Show results
        if batch_status.status == "completed":
            print(f"\n✅ Batch conversion completed successfully!")
            print(f"📊 Final Statistics:")
            print(f"   - Completed: {batch_status.completed_files} files")
            print(f"   - Failed: {batch_status.failed_files} files")

            if batch_status.estimated_completion:
                print(f"   - Completion time: {batch_status.estimated_completion}")
        else:
            print(f"\n❌ Batch conversion {batch_status.status}")
            if batch_status.errors:
                print("Errors:")
                for error in batch_status.errors[:5]:  # Show first 5 errors
                    print(f"   - {error.get('message', 'Unknown error')}")

    except Exception as e:
        print(f"❌ Batch conversion failed: {e}")
        sys.exit(1)
    finally:
        # Clean up
        client.close()


if __name__ == "__main__":
    main()
