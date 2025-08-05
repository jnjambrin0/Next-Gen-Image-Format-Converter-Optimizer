# Image Converter

A privacy-focused, high-performance image conversion tool that runs entirely on your local machine. No uploads, no cloud services, no tracking - just fast, secure image processing.

## Features

- **100% Local Processing**: All image conversions happen on your machine
- **Privacy First**: No data leaves your device, no analytics, no tracking
- **Multiple Format Support**: Convert between JPEG, PNG, WebP, AVIF, HEIF/HEIC, and more
- **Batch Processing**: Convert multiple images simultaneously
- **Smart Optimization**: AI-powered quality optimization for smaller file sizes
- **Security Focused**: Sandboxed processing, EXIF stripping, and malware detection
- **Cross-Platform**: Works on Windows, macOS, and Linux

## Quick Start

1. Clone the repository:

   ```bash
   git clone https://github.com/jnjambrin0/Next-Gen-Image-Format-Converter-Optimizer.git
   cd next-gen-image-format-converter-optimazer
   ```

2. Set up the development environment:

   ```bash
   # Backend setup
   cd backend
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt

   # Frontend setup
   cd ../frontend
   npm install
   ```

3. Run the application:

   ```bash
   # Start backend (from backend directory)
   uvicorn app.main:app --reload

   # Start frontend (from frontend directory)
   npm run dev
   ```

4. Open http://localhost:5173 in your browser

## Development

For detailed development setup and contribution guidelines, see [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md).

## Architecture

This project uses a modern, secure architecture:

- **Backend**: Python 3.11+ with FastAPI
- **Frontend**: Vanilla JavaScript with Vite and Tailwind CSS
- **Image Processing**: Pillow and libvips for high-performance operations
- **Security**: Sandboxed processes, content validation, and privacy-preserving logging

For detailed architecture documentation, see [docs/architecture/](docs/architecture/).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Security

Security is our top priority. If you discover a security vulnerability, please see [docs/SECURITY.md](docs/SECURITY.md) for reporting instructions.

## Status

[![CI Status](https://github.com/jnjambrin0/Next-Gen-Image-Format-Converter-Optimizer/workflows/CI/badge.svg)](https://github.com/jnjambrin0/Next-Gen-Image-Format-Converter-Optimizer/actions)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
