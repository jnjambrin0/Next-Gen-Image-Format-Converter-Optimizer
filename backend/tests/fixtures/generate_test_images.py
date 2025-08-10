#!/usr/bin/env python3
"""Generate test images for the image converter test suite."""

import os
from PIL import Image, ImageDraw, ImageFont, ImageOps
from PIL.ExifTags import TAGS, GPSTAGS
import piexif
import numpy as np
from datetime import datetime
import json


def create_sample_photo():
    """Create a realistic landscape photo with EXIF data."""
    # Create a gradient background simulating a sunset
    width, height = 1920, 1080
    img = Image.new("RGB", (width, height))
    draw = ImageDraw.Draw(img)

    # Create sunset gradient
    for y in range(height):
        r = int(255 - (y / height) * 100)
        g = int(150 - (y / height) * 50)
        b = int(100 + (y / height) * 155)
        draw.rectangle([(0, y), (width, y + 1)], fill=(r, g, b))

    # Add some "mountains" silhouette
    points = [(0, height), (0, height * 0.7)]
    for x in range(0, width + 200, 200):
        peak_height = height * (0.6 + np.random.random() * 0.2)
        points.append((x, peak_height))
    points.extend([(width, height * 0.7), (width, height)])
    draw.polygon(points, fill=(30, 30, 50))

    # Add EXIF data
    exif_dict = {
        "0th": {
            piexif.ImageIFD.Make: b"Canon",
            piexif.ImageIFD.Model: b"EOS 5D Mark IV",
            piexif.ImageIFD.DateTime: datetime.now()
            .strftime("%Y:%m:%d %H:%M:%S")
            .encode(),
            piexif.ImageIFD.Artist: b"Test Photographer",
            piexif.ImageIFD.Copyright: b"Test Copyright 2025",
        },
        "Exif": {
            piexif.ExifIFD.DateTimeOriginal: datetime.now()
            .strftime("%Y:%m:%d %H:%M:%S")
            .encode(),
            piexif.ExifIFD.LensMake: b"Canon",
            piexif.ExifIFD.LensModel: b"EF 24-70mm f/2.8L II USM",
            piexif.ExifIFD.ExposureTime: (1, 125),
            piexif.ExifIFD.FNumber: (28, 10),
            piexif.ExifIFD.ISOSpeedRatings: 200,
            piexif.ExifIFD.FocalLength: (50, 1),
        },
        "GPS": {
            piexif.GPSIFD.GPSLatitudeRef: b"N",
            piexif.GPSIFD.GPSLatitude: ((37, 1), (46, 1), (30, 1)),
            piexif.GPSIFD.GPSLongitudeRef: b"W",
            piexif.GPSIFD.GPSLongitude: ((122, 1), (25, 1), (0, 1)),
            piexif.GPSIFD.GPSAltitudeRef: 0,
            piexif.GPSIFD.GPSAltitude: (10, 1),
        },
    }

    exif_bytes = piexif.dump(exif_dict)
    img.save("images/sample_photo.jpg", "JPEG", quality=85, exif=exif_bytes)
    print("Created sample_photo.jpg")


def create_portrait_photo():
    """Create a portrait orientation photo with GPS metadata."""
    width, height = 1080, 1920
    img = Image.new("RGB", (width, height))
    draw = ImageDraw.Draw(img)

    # Create a blurred background effect
    for i in range(50):
        x = np.random.randint(0, width)
        y = np.random.randint(0, height)
        r = np.random.randint(50, 200)
        color = (
            np.random.randint(100, 255),
            np.random.randint(100, 255),
            np.random.randint(100, 255),
        )
        # Draw soft circles
        for offset in range(r, 0, -2):
            alpha = int(255 * (1 - offset / r))
            overlay = Image.new("RGBA", (width, height), (0, 0, 0, 0))
            overlay_draw = ImageDraw.Draw(overlay)
            overlay_draw.ellipse(
                [(x - offset, y - offset), (x + offset, y + offset)],
                fill=(*color, alpha // 4),
            )
            img = Image.alpha_composite(img.convert("RGBA"), overlay).convert("RGB")

    # Add silhouette
    draw.ellipse(
        [(width * 0.3, height * 0.2), (width * 0.7, height * 0.6)], fill=(50, 50, 50)
    )

    # Add EXIF with GPS
    exif_dict = {
        "0th": {
            piexif.ImageIFD.Make: b"Apple",
            piexif.ImageIFD.Model: b"iPhone 14 Pro",
            piexif.ImageIFD.Orientation: 1,
            piexif.ImageIFD.DateTime: datetime.now()
            .strftime("%Y:%m:%d %H:%M:%S")
            .encode(),
        },
        "Exif": {
            piexif.ExifIFD.DateTimeOriginal: datetime.now()
            .strftime("%Y:%m:%d %H:%M:%S")
            .encode(),
            piexif.ExifIFD.ExposureTime: (1, 60),
            piexif.ExifIFD.FNumber: (18, 10),
            piexif.ExifIFD.ISOSpeedRatings: 100,
        },
        "GPS": {
            piexif.GPSIFD.GPSLatitudeRef: b"N",
            piexif.GPSIFD.GPSLatitude: ((40, 1), (42, 1), (46, 1)),
            piexif.GPSIFD.GPSLongitudeRef: b"W",
            piexif.GPSIFD.GPSLongitude: ((74, 1), (0, 1), (23, 1)),
        },
    }

    exif_bytes = piexif.dump(exif_dict)
    img.save("images/portrait_photo.jpg", "JPEG", quality=90, exif=exif_bytes)
    print("Created portrait_photo.jpg")


def create_screenshot():
    """Create a realistic desktop screenshot."""
    width, height = 1440, 900
    img = Image.new("RGB", (width, height), color=(245, 245, 245))
    draw = ImageDraw.Draw(img)

    # Draw window chrome
    draw.rectangle([(0, 0), (width, 30)], fill=(60, 60, 60))
    # Traffic lights
    for i, color in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        draw.ellipse([(10 + i * 20, 10), (20 + i * 20, 20)], fill=color)

    # Draw sidebar
    draw.rectangle([(0, 30), (200, height)], fill=(240, 240, 240))

    # Draw some menu items
    menu_items = ["File Explorer", "Documents", "Downloads", "Desktop", "Pictures"]
    for i, item in enumerate(menu_items):
        y = 50 + i * 40
        draw.rectangle([(10, y), (190, y + 30)], fill=(230, 230, 230))
        draw.text((20, y + 8), item, fill=(50, 50, 50))

    # Draw main content area with grid
    for x in range(220, width - 20, 150):
        for y in range(50, height - 50, 150):
            draw.rectangle(
                [(x, y), (x + 130, y + 130)],
                fill=(255, 255, 255),
                outline=(220, 220, 220),
            )
            # Add icon placeholder
            draw.rectangle([(x + 40, y + 20), (x + 90, y + 70)], fill=(100, 150, 255))
            draw.text((x + 20, y + 90), "Document.pdf", fill=(100, 100, 100))

    img.save("images/screenshot.png", "PNG")
    print("Created screenshot.png")


def create_document_scan():
    """Create a document scan (A4 size)."""
    # A4 at 300 DPI
    width, height = 2480, 3508
    img = Image.new("RGB", (width, height), color=(250, 250, 245))
    draw = ImageDraw.Draw(img)

    # Add slight paper texture
    pixels = np.array(img)
    noise = np.random.normal(0, 3, pixels.shape)
    pixels = np.clip(pixels + noise, 0, 255).astype(np.uint8)
    img = Image.fromarray(pixels)
    draw = ImageDraw.Draw(img)

    # Add header
    draw.rectangle([(200, 200), (width - 200, 400)], fill=(50, 50, 150))
    draw.text((width // 2 - 200, 270), "CONFIDENTIAL DOCUMENT", fill=(255, 255, 255))

    # Add text lines
    line_height = 60
    margin = 300
    y = 600

    for i in range(40):
        line_width = np.random.randint(width - 2 * margin - 200, width - 2 * margin)
        draw.rectangle([(margin, y), (margin + line_width, y + 30)], fill=(30, 30, 30))
        y += line_height

        # Add paragraph break
        if i % 5 == 4:
            y += line_height

    # Add signature area
    draw.rectangle(
        [(margin, height - 600), (width - margin, height - 500)],
        outline=(100, 100, 100),
        width=2,
    )
    draw.text(
        (margin + 50, height - 450), "Signature: _________________", fill=(50, 50, 50)
    )
    draw.text(
        (margin + 50, height - 350), "Date: _____________________", fill=(50, 50, 50)
    )

    img.save("images/document_scan.png", "PNG")
    print("Created document_scan.png")


def create_illustration():
    """Create a digital illustration with transparency."""
    width, height = 800, 800
    img = Image.new("RGBA", (width, height), color=(0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Draw abstract shapes with transparency
    for _ in range(20):
        x = np.random.randint(0, width)
        y = np.random.randint(0, height)
        r = np.random.randint(50, 200)
        color = (
            np.random.randint(0, 255),
            np.random.randint(0, 255),
            np.random.randint(0, 255),
            np.random.randint(100, 200),
        )

        shape = np.random.choice(["circle", "rectangle", "polygon"])
        if shape == "circle":
            draw.ellipse([(x - r, y - r), (x + r, y + r)], fill=color)
        elif shape == "rectangle":
            draw.rectangle([(x - r, y - r), (x + r, y + r)], fill=color)
        else:
            # Triangle
            points = [(x, y - r), (x - r, y + r), (x + r, y + r)]
            draw.polygon(points, fill=color)

    # Add border design
    border_width = 50
    border_color = (255, 100, 100, 255)
    draw.rectangle([(0, 0), (width, border_width)], fill=border_color)
    draw.rectangle([(0, height - border_width), (width, height)], fill=border_color)
    draw.rectangle([(0, 0), (border_width, height)], fill=border_color)
    draw.rectangle([(width - border_width, 0), (width, height)], fill=border_color)

    img.save("images/illustration.png", "PNG")
    print("Created illustration.png")


def create_animated_gif():
    """Create a simple animated GIF."""
    width, height = 500, 500
    frames = []

    for frame in range(3):
        img = Image.new("RGB", (width, height), color=(255, 255, 255))
        draw = ImageDraw.Draw(img)

        # Draw moving circle
        x = width // 2 + int(150 * np.cos(frame * 2 * np.pi / 3))
        y = height // 2 + int(150 * np.sin(frame * 2 * np.pi / 3))

        draw.ellipse([(x - 50, y - 50), (x + 50, y + 50)], fill=(255, 100, 100))

        # Add frame number
        draw.text((10, 10), f"Frame {frame + 1}", fill=(0, 0, 0))

        frames.append(img)

    frames[0].save(
        "images/animated.gif",
        save_all=True,
        append_images=frames[1:],
        duration=500,
        loop=0,
    )
    print("Created animated.gif")


def create_large_photo():
    """Create a large photo for performance testing."""
    width, height = 4000, 3000
    img = Image.new("RGB", (width, height))

    # Create a complex pattern that compresses poorly
    pixels = np.zeros((height, width, 3), dtype=np.uint8)

    # Add gradients and patterns
    for y in range(height):
        for x in range(width):
            pixels[y, x] = [
                int(255 * (x / width)),
                int(255 * (y / height)),
                int(255 * ((x + y) / (width + height))),
            ]

    # Add some noise to prevent good compression
    noise = np.random.randint(-20, 20, pixels.shape)
    pixels = np.clip(pixels + noise, 0, 255).astype(np.uint8)

    img = Image.fromarray(pixels)
    img.save("images/large_photo.jpg", "JPEG", quality=95)
    print("Created large_photo.jpg")


def create_tiny_icon():
    """Create a tiny icon for edge case testing."""
    width, height = 16, 16
    img = Image.new("RGBA", (width, height), color=(0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Draw a simple icon
    draw.ellipse([(2, 2), (14, 14)], fill=(100, 200, 100, 255))
    draw.rectangle([(6, 6), (10, 10)], fill=(255, 255, 255, 255))

    img.save("images/tiny_icon.png", "PNG")
    print("Created tiny_icon.png")


def create_corrupted_image():
    """Create an intentionally corrupted JPEG file."""
    # Start with a valid small image
    img = Image.new("RGB", (100, 100), color=(255, 0, 0))
    img.save("images/corrupted.jpg", "JPEG")

    # Corrupt it by truncating the file
    with open("images/corrupted.jpg", "rb") as f:
        data = f.read()

    # Write back only first 60% of the file
    with open("images/corrupted.jpg", "wb") as f:
        f.write(data[: int(len(data) * 0.6)])

    print("Created corrupted.jpg")


def create_empty_file():
    """Create an empty file for validation testing."""
    open("images/empty.png", "wb").close()
    print("Created empty.png")


def create_all_test_images():
    """Generate all test images."""
    # Create images directory if it doesn't exist
    os.makedirs("images", exist_ok=True)

    print("Generating test images...")
    create_sample_photo()
    create_portrait_photo()
    create_screenshot()
    create_document_scan()
    create_illustration()
    create_animated_gif()
    create_large_photo()
    create_tiny_icon()
    create_corrupted_image()
    create_empty_file()
    print("\nAll test images created successfully!")


if __name__ == "__main__":
    create_all_test_images()
