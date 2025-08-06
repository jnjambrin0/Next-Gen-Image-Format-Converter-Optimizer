# Distribution Guide

This guide covers how to install, distribute, and manage the Image Converter SDKs.

## Installation Methods

### Online Installation (Standard)

#### Python SDK
```bash
# From PyPI
pip install image-converter-sdk

# From GitHub
pip install git+https://github.com/image-converter/sdk-python.git

# Specific version
pip install image-converter-sdk==1.2.0
```

#### JavaScript SDK
```bash
# From npm
npm install @image-converter/sdk

# From GitHub
npm install github:image-converter/sdk-javascript

# Using yarn
yarn add @image-converter/sdk
```

#### Go SDK
```bash
# Latest version
go get github.com/image-converter/image-converter-sdk-go

# Specific version
go get github.com/image-converter/image-converter-sdk-go@v1.2.0
```

### Offline Installation (Air-Gapped Environments)

#### Python SDK - Offline

1. **Download wheel file**:
```bash
# On internet-connected machine
pip download image-converter-sdk --dest ./offline-packages
```

2. **Transfer and install**:
```bash
# On offline machine
pip install --no-index --find-links ./offline-packages image-converter-sdk
```

3. **Using setup script**:
```bash
# Download offline bundle
curl -O https://github.com/image-converter/releases/download/v1.2.0/python-sdk-offline.tar.gz
tar -xzf python-sdk-offline.tar.gz
cd python-sdk-offline
./install.sh
```

#### JavaScript SDK - Offline

1. **Create offline bundle**:
```bash
# On internet-connected machine
mkdir offline-npm
cd offline-npm
npm pack @image-converter/sdk
# Also download dependencies
npm pack form-data
npm pack node-fetch
```

2. **Install from bundle**:
```bash
# On offline machine
npm install ./offline-npm/image-converter-sdk-1.2.0.tgz
```

3. **Using offline script**:
```bash
# Download offline bundle
curl -O https://github.com/image-converter/releases/download/v1.2.0/js-sdk-offline.tar.gz
tar -xzf js-sdk-offline.tar.gz
cd js-sdk-offline
./install.sh
```

#### Go SDK - Offline

1. **Vendor dependencies**:
```bash
# On internet-connected machine
git clone https://github.com/image-converter/image-converter-sdk-go
cd image-converter-sdk-go
go mod vendor
tar -czf go-sdk-vendor.tar.gz .
```

2. **Use vendored version**:
```bash
# On offline machine
tar -xzf go-sdk-vendor.tar.gz
cd image-converter-sdk-go
go build -mod=vendor
```

## Distribution Channels

### Official Channels

| Channel | Python | JavaScript | Go | Notes |
|---------|---------|------------|-----|-------|
| Package Registry | PyPI | npm | pkg.go.dev | Primary distribution |
| GitHub Releases | ✓ | ✓ | ✓ | Tagged releases with binaries |
| Direct Download | ✓ | ✓ | ✓ | From project website |
| Docker Images | ✓ | ✓ | ✓ | Pre-configured containers |

### Self-Hosted Options

#### Private PyPI Server
```bash
# Using pypiserver
pip install pypiserver
pypi-server -p 8080 ./packages

# Upload SDK
twine upload --repository-url http://localhost:8080 dist/*

# Install from private server
pip install --index-url http://localhost:8080 image-converter-sdk
```

#### Private npm Registry
```bash
# Using Verdaccio
npm install -g verdaccio
verdaccio

# Publish SDK
npm publish --registry http://localhost:4873

# Install from private registry
npm install @image-converter/sdk --registry http://localhost:4873
```

#### Private Go Proxy
```bash
# Using Athens
docker run -p 3000:3000 gomods/athens

# Configure Go to use proxy
export GOPROXY=http://localhost:3000
go get github.com/image-converter/image-converter-sdk-go
```

## Verification and Security

### Checksum Verification

All releases include SHA-256 checksums:

```bash
# Python
curl -O https://github.com/image-converter/releases/download/v1.2.0/checksums.txt
sha256sum -c checksums.txt

# JavaScript
npm pack @image-converter/sdk
sha256sum image-converter-sdk-1.2.0.tgz

# Go
go mod download -json | jq -r .Sum
```

### GPG Signature Verification

```bash
# Import public key
curl https://keybase.io/imageconverter/pgp_keys.asc | gpg --import

# Verify signature
gpg --verify image-converter-sdk-1.2.0.tar.gz.sig image-converter-sdk-1.2.0.tar.gz
```

### Integrity Verification Script

```bash
#!/bin/bash
# verify-sdk.sh

SDK_VERSION="1.2.0"
BASE_URL="https://github.com/image-converter/releases/download/v${SDK_VERSION}"

# Download files
curl -O "${BASE_URL}/python-sdk-${SDK_VERSION}.tar.gz"
curl -O "${BASE_URL}/python-sdk-${SDK_VERSION}.tar.gz.sig"
curl -O "${BASE_URL}/checksums.txt"

# Verify checksum
grep "python-sdk" checksums.txt | sha256sum -c -

# Verify signature
gpg --verify "python-sdk-${SDK_VERSION}.tar.gz.sig" "python-sdk-${SDK_VERSION}.tar.gz"
```

## Version Management

### Version Alignment

| API Version | SDK Version | Compatibility |
|-------------|-------------|---------------|
| v1.0        | 1.0.x       | Full          |
| v1.1        | 1.1.x       | Full          |
| v1.2        | 1.2.x       | Full          |
| v2.0        | 2.0.x       | Breaking changes |

### Version Pinning

#### Python
```python
# requirements.txt
image-converter-sdk>=1.2.0,<2.0.0

# pyproject.toml
[tool.poetry.dependencies]
image-converter-sdk = "^1.2.0"
```

#### JavaScript
```json
// package.json
{
  "dependencies": {
    "@image-converter/sdk": "^1.2.0"
  }
}
```

#### Go
```go
// go.mod
require (
    github.com/image-converter/image-converter-sdk-go v1.2.0
)
```

## Building from Source

### Python SDK
```bash
git clone https://github.com/image-converter/sdk-python
cd sdk-python
python -m venv venv
source venv/bin/activate
pip install -e .
python setup.py bdist_wheel
```

### JavaScript SDK
```bash
git clone https://github.com/image-converter/sdk-javascript
cd sdk-javascript
npm install
npm run build
npm pack
```

### Go SDK
```bash
git clone https://github.com/image-converter/image-converter-sdk-go
cd image-converter-sdk-go
go build ./...
go test ./...
```

## Docker Distribution

### Pre-built Images

```bash
# Python SDK environment
docker pull imageconverter/python-sdk:1.2.0
docker run -it imageconverter/python-sdk:1.2.0 python

# Node.js SDK environment
docker pull imageconverter/node-sdk:1.2.0
docker run -it imageconverter/node-sdk:1.2.0 node

# Go SDK builder
docker pull imageconverter/go-sdk:1.2.0
docker run -v $(pwd):/app imageconverter/go-sdk:1.2.0 go build
```

### Custom Docker Images

```dockerfile
# Python SDK Dockerfile
FROM python:3.11-slim
RUN pip install image-converter-sdk==1.2.0
COPY . /app
WORKDIR /app
CMD ["python", "app.py"]
```

```dockerfile
# Node.js SDK Dockerfile
FROM node:18-alpine
RUN npm install -g @image-converter/sdk@1.2.0
COPY . /app
WORKDIR /app
CMD ["node", "app.js"]
```

## CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/sdk-test.yml
name: SDK Tests
on: [push, pull_request]

jobs:
  python:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - run: pip install image-converter-sdk
      - run: python -m pytest

  javascript:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '18'
      - run: npm install @image-converter/sdk
      - run: npm test

  go:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-go@v4
        with:
          go-version: '1.21'
      - run: go get github.com/image-converter/image-converter-sdk-go
      - run: go test ./...
```

### GitLab CI

```yaml
# .gitlab-ci.yml
stages:
  - test

test-python:
  image: python:3.11
  script:
    - pip install image-converter-sdk
    - pytest

test-javascript:
  image: node:18
  script:
    - npm install @image-converter/sdk
    - npm test

test-go:
  image: golang:1.21
  script:
    - go get github.com/image-converter/image-converter-sdk-go
    - go test ./...
```

## Offline Bundle Creation

### Python Offline Bundle Script

```bash
#!/bin/bash
# create-python-offline-bundle.sh

VERSION="1.2.0"
BUNDLE_DIR="python-sdk-offline-${VERSION}"

mkdir -p "${BUNDLE_DIR}/wheels"

# Download SDK and dependencies
pip download image-converter-sdk=="${VERSION}" \
    --dest "${BUNDLE_DIR}/wheels" \
    --platform manylinux2014_x86_64 \
    --platform macosx_10_9_x86_64 \
    --platform win_amd64 \
    --only-binary :all:

# Create install script
cat > "${BUNDLE_DIR}/install.sh" << 'EOF'
#!/bin/bash
pip install --no-index --find-links ./wheels image-converter-sdk
EOF

chmod +x "${BUNDLE_DIR}/install.sh"

# Create README
cat > "${BUNDLE_DIR}/README.md" << EOF
# Python SDK Offline Installation

Version: ${VERSION}

## Installation
Run: ./install.sh

## Manual Installation
pip install --no-index --find-links ./wheels image-converter-sdk
EOF

# Create archive
tar -czf "python-sdk-offline-${VERSION}.tar.gz" "${BUNDLE_DIR}"
echo "Created: python-sdk-offline-${VERSION}.tar.gz"
```

### JavaScript Offline Bundle Script

```bash
#!/bin/bash
# create-js-offline-bundle.sh

VERSION="1.2.0"
BUNDLE_DIR="js-sdk-offline-${VERSION}"

mkdir -p "${BUNDLE_DIR}/packages"
cd "${BUNDLE_DIR}/packages"

# Pack SDK and dependencies
npm pack @image-converter/sdk@"${VERSION}"
npm pack form-data
npm pack node-fetch

cd ../..

# Create install script
cat > "${BUNDLE_DIR}/install.sh" << 'EOF'
#!/bin/bash
for package in packages/*.tgz; do
    npm install "$package"
done
EOF

chmod +x "${BUNDLE_DIR}/install.sh"

# Create package.json for offline install
cat > "${BUNDLE_DIR}/package.json" << EOF
{
  "name": "offline-install",
  "version": "1.0.0",
  "dependencies": {
    "@image-converter/sdk": "file:./packages/image-converter-sdk-${VERSION}.tgz"
  }
}
EOF

# Create archive
tar -czf "js-sdk-offline-${VERSION}.tar.gz" "${BUNDLE_DIR}"
echo "Created: js-sdk-offline-${VERSION}.tar.gz"
```

## Mirror Setup Guide

### Creating a Complete Local Mirror

```bash
#!/bin/bash
# setup-local-mirror.sh

# Python mirror
mkdir -p mirrors/pypi
pip download image-converter-sdk --dest mirrors/pypi
pypi-server -p 8080 mirrors/pypi &

# JavaScript mirror
mkdir -p mirrors/npm
cd mirrors/npm
npm pack @image-converter/sdk
verdaccio --config ./config.yaml &

# Go mirror
export GOPATH=$HOME/mirrors/go
go get -d github.com/image-converter/image-converter-sdk-go

echo "Mirrors available at:"
echo "  Python: http://localhost:8080"
echo "  JavaScript: http://localhost:4873"
echo "  Go: file://$GOPATH"
```

## Troubleshooting

### Common Issues

#### Issue: "Package not found" in offline mode
**Solution**: Ensure all dependencies are included in offline bundle:
```bash
pip download --dest ./offline image-converter-sdk --no-deps
pip download --dest ./offline keyring httpx pydantic  # Add dependencies
```

#### Issue: "Checksum mismatch" error
**Solution**: Re-download with verification:
```bash
curl -O https://github.com/.../checksums.txt
sha256sum -c checksums.txt || echo "Checksum failed - redownload"
```

#### Issue: "Network error" in air-gapped environment
**Solution**: Ensure localhost is properly configured:
```bash
echo "127.0.0.1 localhost" >> /etc/hosts
```

## Support

- **Documentation**: See README files in each SDK
- **Issues**: GitHub Issues for each SDK repository
- **Security**: security@imageconverter.local
- **General**: support@imageconverter.local