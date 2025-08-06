#!/bin/bash
# Create offline installation bundles for all SDKs

set -e

VERSION="${1:-1.2.0}"
BASE_DIR="$(dirname "$0")/.."
OUTPUT_DIR="${BASE_DIR}/offline-bundles"

echo "Creating offline bundles for SDK version ${VERSION}"
mkdir -p "${OUTPUT_DIR}"

# Python SDK offline bundle
create_python_bundle() {
    echo "Creating Python SDK offline bundle..."
    
    BUNDLE_NAME="python-sdk-offline-${VERSION}"
    BUNDLE_DIR="${OUTPUT_DIR}/${BUNDLE_NAME}"
    
    rm -rf "${BUNDLE_DIR}"
    mkdir -p "${BUNDLE_DIR}/wheels"
    
    # Download SDK and all dependencies
    pip download \
        "${BASE_DIR}/python" \
        --dest "${BUNDLE_DIR}/wheels" \
        --no-deps
    
    # Download dependencies
    pip download \
        httpx pydantic keyring \
        --dest "${BUNDLE_DIR}/wheels"
    
    # Create install script
    cat > "${BUNDLE_DIR}/install.sh" << 'EOF'
#!/bin/bash
set -e

echo "Installing Image Converter Python SDK (offline)"

# Check Python version
PYTHON_VERSION=$(python3 --version 2>&1 | grep -oE '[0-9]+\.[0-9]+')
REQUIRED_VERSION="3.9"

if ! python3 -c "import sys; exit(0 if sys.version_info >= (3, 9) else 1)" 2>/dev/null; then
    echo "Error: Python 3.9+ is required"
    exit 1
fi

# Install from wheels
echo "Installing SDK and dependencies..."
pip install --no-index --find-links ./wheels image-converter-sdk

echo "Installation complete!"
echo "Test with: python -c 'from image_converter import ImageConverterClient; print(\"SDK installed successfully\")'"
EOF
    
    chmod +x "${BUNDLE_DIR}/install.sh"
    
    # Create PowerShell install script for Windows
    cat > "${BUNDLE_DIR}/install.ps1" << 'EOF'
# PowerShell installation script for Windows

Write-Host "Installing Image Converter Python SDK (offline)" -ForegroundColor Green

# Check Python version
$pythonVersion = python --version 2>&1
if ($pythonVersion -notmatch "Python 3\.(9|1[0-9])") {
    Write-Host "Error: Python 3.9+ is required" -ForegroundColor Red
    exit 1
}

# Install from wheels
Write-Host "Installing SDK and dependencies..." -ForegroundColor Yellow
pip install --no-index --find-links .\wheels image-converter-sdk

if ($LASTEXITCODE -eq 0) {
    Write-Host "Installation complete!" -ForegroundColor Green
    Write-Host "Test with: python -c 'from image_converter import ImageConverterClient; print(\"SDK installed successfully\")'"
} else {
    Write-Host "Installation failed!" -ForegroundColor Red
    exit 1
}
EOF
    
    # Create README
    cat > "${BUNDLE_DIR}/README.md" << EOF
# Python SDK Offline Installation Bundle

Version: ${VERSION}

## Requirements

- Python 3.9 or higher
- pip package manager

## Installation

### Linux/macOS
\`\`\`bash
./install.sh
\`\`\`

### Windows
\`\`\`powershell
.\install.ps1
\`\`\`

### Manual Installation
\`\`\`bash
pip install --no-index --find-links ./wheels image-converter-sdk
\`\`\`

## Verification

\`\`\`python
from image_converter import ImageConverterClient
client = ImageConverterClient()
print(client.base_url)
\`\`\`

## Contents

- \`wheels/\` - Python wheel files for SDK and dependencies
- \`install.sh\` - Bash installation script
- \`install.ps1\` - PowerShell installation script
- \`README.md\` - This file
EOF
    
    # Create archive
    cd "${OUTPUT_DIR}"
    tar -czf "${BUNDLE_NAME}.tar.gz" "${BUNDLE_NAME}"
    zip -qr "${BUNDLE_NAME}.zip" "${BUNDLE_NAME}"
    
    echo "✓ Python SDK offline bundle created: ${BUNDLE_NAME}.tar.gz and ${BUNDLE_NAME}.zip"
}

# JavaScript SDK offline bundle
create_javascript_bundle() {
    echo "Creating JavaScript SDK offline bundle..."
    
    BUNDLE_NAME="javascript-sdk-offline-${VERSION}"
    BUNDLE_DIR="${OUTPUT_DIR}/${BUNDLE_NAME}"
    
    rm -rf "${BUNDLE_DIR}"
    mkdir -p "${BUNDLE_DIR}/packages"
    
    # Build and pack SDK
    cd "${BASE_DIR}/javascript"
    npm run build 2>/dev/null || echo "Build step skipped"
    npm pack --pack-destination "${BUNDLE_DIR}/packages"
    
    # Pack dependencies
    cd "${BUNDLE_DIR}/packages"
    npm pack form-data
    npm pack node-fetch
    
    # Create package.json for offline install
    cat > "${BUNDLE_DIR}/package.json" << EOF
{
  "name": "image-converter-sdk-offline",
  "version": "${VERSION}",
  "private": true,
  "dependencies": {
    "@image-converter/sdk": "file:./packages/image-converter-sdk-${VERSION}.tgz",
    "form-data": "file:./packages/form-data-4.0.0.tgz",
    "node-fetch": "file:./packages/node-fetch-3.3.2.tgz"
  }
}
EOF
    
    # Create install script
    cat > "${BUNDLE_DIR}/install.sh" << 'EOF'
#!/bin/bash
set -e

echo "Installing Image Converter JavaScript SDK (offline)"

# Check Node.js version
if ! command -v node &> /dev/null; then
    echo "Error: Node.js is not installed"
    exit 1
fi

NODE_VERSION=$(node --version | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 16 ]; then
    echo "Error: Node.js 16+ is required"
    exit 1
fi

# Install from local packages
echo "Installing SDK and dependencies..."
npm install --offline --prefer-offline

echo "Installation complete!"
echo "Test with: node -e 'const sdk = require(\"@image-converter/sdk\"); console.log(\"SDK installed successfully\")'"
EOF
    
    chmod +x "${BUNDLE_DIR}/install.sh"
    
    # Create PowerShell install script
    cat > "${BUNDLE_DIR}/install.ps1" << 'EOF'
# PowerShell installation script for Windows

Write-Host "Installing Image Converter JavaScript SDK (offline)" -ForegroundColor Green

# Check Node.js
if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    Write-Host "Error: Node.js is not installed" -ForegroundColor Red
    exit 1
}

$nodeVersion = node --version
if ($nodeVersion -notmatch "v(1[6-9]|[2-9][0-9])") {
    Write-Host "Error: Node.js 16+ is required" -ForegroundColor Red
    exit 1
}

# Install from local packages
Write-Host "Installing SDK and dependencies..." -ForegroundColor Yellow
npm install --offline --prefer-offline

if ($LASTEXITCODE -eq 0) {
    Write-Host "Installation complete!" -ForegroundColor Green
    Write-Host "Test with: node -e 'const sdk = require(\"@image-converter/sdk\"); console.log(\"SDK installed\")'"
} else {
    Write-Host "Installation failed!" -ForegroundColor Red
    exit 1
}
EOF
    
    # Create README
    cat > "${BUNDLE_DIR}/README.md" << EOF
# JavaScript SDK Offline Installation Bundle

Version: ${VERSION}

## Requirements

- Node.js 16 or higher
- npm package manager

## Installation

### Linux/macOS
\`\`\`bash
./install.sh
\`\`\`

### Windows
\`\`\`powershell
.\install.ps1
\`\`\`

### Manual Installation
\`\`\`bash
npm install --offline --prefer-offline
\`\`\`

## Verification

\`\`\`javascript
const { ImageConverterClient } = require('@image-converter/sdk');
const client = new ImageConverterClient();
console.log('SDK installed successfully');
\`\`\`

## Contents

- \`packages/\` - npm package tarballs
- \`package.json\` - Package manifest for offline install
- \`install.sh\` - Bash installation script
- \`install.ps1\` - PowerShell installation script
- \`README.md\` - This file
EOF
    
    # Create archive
    cd "${OUTPUT_DIR}"
    tar -czf "${BUNDLE_NAME}.tar.gz" "${BUNDLE_NAME}"
    zip -qr "${BUNDLE_NAME}.zip" "${BUNDLE_NAME}"
    
    echo "✓ JavaScript SDK offline bundle created: ${BUNDLE_NAME}.tar.gz and ${BUNDLE_NAME}.zip"
}

# Go SDK offline bundle
create_go_bundle() {
    echo "Creating Go SDK offline bundle..."
    
    BUNDLE_NAME="go-sdk-offline-${VERSION}"
    BUNDLE_DIR="${OUTPUT_DIR}/${BUNDLE_NAME}"
    
    rm -rf "${BUNDLE_DIR}"
    mkdir -p "${BUNDLE_DIR}"
    
    # Copy Go SDK with vendored dependencies
    cp -r "${BASE_DIR}/go" "${BUNDLE_DIR}/image-converter-sdk-go"
    
    # Vendor dependencies
    cd "${BUNDLE_DIR}/image-converter-sdk-go"
    go mod vendor 2>/dev/null || echo "Vendor step skipped"
    
    # Create install script
    cat > "${BUNDLE_DIR}/install.sh" << 'EOF'
#!/bin/bash
set -e

echo "Installing Image Converter Go SDK (offline)"

# Check Go version
if ! command -v go &> /dev/null; then
    echo "Error: Go is not installed"
    exit 1
fi

GO_VERSION=$(go version | grep -oE 'go[0-9]+\.[0-9]+' | cut -c3-)
REQUIRED_VERSION="1.20"

if ! printf '%s\n' "$REQUIRED_VERSION" "$GO_VERSION" | sort -V | head -n1 | grep -q "$REQUIRED_VERSION"; then
    echo "Error: Go 1.20+ is required"
    exit 1
fi

# Install SDK
echo "Installing SDK..."
cd image-converter-sdk-go
go install -mod=vendor ./...

echo "Installation complete!"
echo "Import with: import \"github.com/image-converter/image-converter-sdk-go\""
EOF
    
    chmod +x "${BUNDLE_DIR}/install.sh"
    
    # Create PowerShell install script
    cat > "${BUNDLE_DIR}/install.ps1" << 'EOF'
# PowerShell installation script for Windows

Write-Host "Installing Image Converter Go SDK (offline)" -ForegroundColor Green

# Check Go
if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    Write-Host "Error: Go is not installed" -ForegroundColor Red
    exit 1
}

$goVersion = go version
if ($goVersion -notmatch "go1\.(2[0-9]|[3-9][0-9])") {
    Write-Host "Error: Go 1.20+ is required" -ForegroundColor Red
    exit 1
}

# Install SDK
Write-Host "Installing SDK..." -ForegroundColor Yellow
Set-Location image-converter-sdk-go
go install -mod=vendor ./...

if ($LASTEXITCODE -eq 0) {
    Write-Host "Installation complete!" -ForegroundColor Green
    Write-Host "Import with: import \"github.com/image-converter/image-converter-sdk-go\""
} else {
    Write-Host "Installation failed!" -ForegroundColor Red
    exit 1
}
EOF
    
    # Create README
    cat > "${BUNDLE_DIR}/README.md" << EOF
# Go SDK Offline Installation Bundle

Version: ${VERSION}

## Requirements

- Go 1.20 or higher

## Installation

### Linux/macOS
\`\`\`bash
./install.sh
\`\`\`

### Windows
\`\`\`powershell
.\install.ps1
\`\`\`

### Manual Installation
\`\`\`bash
cd image-converter-sdk-go
go install -mod=vendor ./...
\`\`\`

## Usage

\`\`\`go
package main

import (
    ic "github.com/image-converter/image-converter-sdk-go"
)

func main() {
    client, _ := ic.NewClient(nil)
    // Use client...
}
\`\`\`

## Contents

- \`image-converter-sdk-go/\` - Go SDK with vendored dependencies
- \`install.sh\` - Bash installation script
- \`install.ps1\` - PowerShell installation script
- \`README.md\` - This file
EOF
    
    # Create archive
    cd "${OUTPUT_DIR}"
    tar -czf "${BUNDLE_NAME}.tar.gz" "${BUNDLE_NAME}"
    zip -qr "${BUNDLE_NAME}.zip" "${BUNDLE_NAME}"
    
    echo "✓ Go SDK offline bundle created: ${BUNDLE_NAME}.tar.gz and ${BUNDLE_NAME}.zip"
}

# Create all bundles
create_python_bundle
create_javascript_bundle
create_go_bundle

# Create master bundle with all SDKs
echo "Creating master offline bundle..."
MASTER_BUNDLE="all-sdks-offline-${VERSION}"
MASTER_DIR="${OUTPUT_DIR}/${MASTER_BUNDLE}"

rm -rf "${MASTER_DIR}"
mkdir -p "${MASTER_DIR}"

# Copy all individual bundles
cp -r "${OUTPUT_DIR}/python-sdk-offline-${VERSION}" "${MASTER_DIR}/"
cp -r "${OUTPUT_DIR}/javascript-sdk-offline-${VERSION}" "${MASTER_DIR}/"
cp -r "${OUTPUT_DIR}/go-sdk-offline-${VERSION}" "${MASTER_DIR}/"

# Create master install script
cat > "${MASTER_DIR}/install-all.sh" << 'EOF'
#!/bin/bash
set -e

echo "Installing all Image Converter SDKs (offline)"
echo "=========================================="

# Install Python SDK
if command -v python3 &> /dev/null; then
    echo "\nInstalling Python SDK..."
    cd python-sdk-offline-*/
    ./install.sh
    cd ..
else
    echo "\nSkipping Python SDK (Python not found)"
fi

# Install JavaScript SDK
if command -v node &> /dev/null; then
    echo "\nInstalling JavaScript SDK..."
    cd javascript-sdk-offline-*/
    ./install.sh
    cd ..
else
    echo "\nSkipping JavaScript SDK (Node.js not found)"
fi

# Install Go SDK
if command -v go &> /dev/null; then
    echo "\nInstalling Go SDK..."
    cd go-sdk-offline-*/
    ./install.sh
    cd ..
else
    echo "\nSkipping Go SDK (Go not found)"
fi

echo "\n=========================================="
echo "Installation complete!"
EOF

chmod +x "${MASTER_DIR}/install-all.sh"

# Create master archive
cd "${OUTPUT_DIR}"
tar -czf "${MASTER_BUNDLE}.tar.gz" "${MASTER_BUNDLE}"
zip -qr "${MASTER_BUNDLE}.zip" "${MASTER_BUNDLE}"

echo "✓ Master offline bundle created: ${MASTER_BUNDLE}.tar.gz and ${MASTER_BUNDLE}.zip"

# Create checksums
echo "Creating checksums..."
sha256sum *.tar.gz *.zip > checksums.txt

echo ""
echo "========================================"
echo "Offline bundles created successfully!"
echo "========================================"
echo "Output directory: ${OUTPUT_DIR}"
echo ""
ls -lh "${OUTPUT_DIR}"/*.{tar.gz,zip} 2>/dev/null
echo ""
echo "Checksums saved to: ${OUTPUT_DIR}/checksums.txt"