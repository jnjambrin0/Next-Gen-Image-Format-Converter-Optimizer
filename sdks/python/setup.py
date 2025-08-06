"""Setup script for Image Converter Python SDK."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="image-converter-sdk",
    version="1.0.0",
    author="Image Converter Team",
    author_email="support@imageconverter.local",
    description="Python SDK for local Image Converter API - privacy-focused image conversion",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/jnjambrin0/Next-Gen-Image-Format-Converter-Optimizer",
    packages=find_packages(exclude=["tests", "tests.*", "examples", "examples.*"]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.8",
    install_requires=[
        "httpx>=0.24.0",
        "pydantic>=2.0.0",
        "keyring>=24.0.0",
        "python-dotenv>=1.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "pytest-httpx>=0.21.0",
            "black>=23.0.0",
            "mypy>=1.0.0",
            "ruff>=0.1.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "image-converter=image_converter.cli:main",
        ],
    },
)
