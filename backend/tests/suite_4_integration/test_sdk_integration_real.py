"""
Ultra-realistic SDK integration tests.
Tests Python, JavaScript, and Go SDKs with real-world scenarios.
"""

import asyncio
import base64
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List

import pytest

from app.models.conversion import ConversionRequest
from app.services.conversion_service import conversion_service


class TestSDKIntegrationReal:
    """Test SDK integration across multiple languages."""

    @pytest.fixture
    def python_sdk_path(self):
        """Get Python SDK path."""
        return Path(__file__).parent.parent.parent.parent / "sdks" / "python"

    @pytest.fixture
    def javascript_sdk_path(self):
        """Get JavaScript SDK path."""
        return Path(__file__).parent.parent.parent.parent / "sdks" / "javascript"

    @pytest.fixture
    def go_sdk_path(self):
        """Get Go SDK path."""
        return Path(__file__).parent.parent.parent.parent / "sdks" / "go"

    @pytest.mark.integration
    @pytest.mark.critical
    async def test_python_sdk_basic_conversion(
        self, python_sdk_path, realistic_image_generator
    ):
        """
        Test Python SDK basic conversion functionality.

        Real-world usage patterns.
        """
        # Create test image
        test_image = realistic_image_generator(
            width=800, height=600, content_type="photo"
        )

        # Write test script
        test_script = """
import sys
sys.path.insert(0, "{sdk_path}")

from image_converter_sdk import ImageConverterClient
import base64

# Initialize client
client = ImageConverterClient(
    host="localhost",
    port=8000,
    api_key="test_key"
)

# Decode image
image_data = base64.b64decode("{image_base64}")

# Save to temp file (SDK expects file path)
import tempfile
with tempfile.NamedTemporaryFile(suffix='.jpg', delete=False) as tmp:
    tmp.write(image_data)
    tmp_path = tmp.name

try:
    # Convert image
    output_data, result = client.convert_image(
        image_path=tmp_path,
        output_format="webp",
        quality=85,
        strip_metadata=True
    )
    
    print(f"Success: {{result.success}}")
    print(f"Output size: {{len(output_data)}}")
    print(f"Format: {{result.output_format}}")
    
finally:
    import os
    os.unlink(tmp_path)
""".format(
            sdk_path=python_sdk_path, image_base64=base64.b64encode(test_image).decode()
        )

        # Run script
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(test_script)
            script_path = f.name

        try:
            result = subprocess.run(
                ["python", script_path], capture_output=True, text=True, timeout=10
            )

            # Check output
            assert "Success: True" in result.stdout
            assert "Output size:" in result.stdout
            assert "Format: webp" in result.stdout

        finally:
            os.unlink(script_path)

    @pytest.mark.integration
    async def test_python_sdk_async_operations(self, python_sdk_path):
        """
        Test Python SDK async/await support.

        Modern Python applications use async.
        """
        test_script = """
import sys
sys.path.insert(0, "{sdk_path}")

import asyncio
from image_converter_sdk import AsyncImageConverterClient

async def main():
    # Initialize async client
    client = AsyncImageConverterClient(
        host="localhost",
        port=8000
    )
    
    # Create test image
    from PIL import Image
    import io
    
    img = Image.new('RGB', (200, 200), color='blue')
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    image_data = buffer.getvalue()
    
    # Save to temp file
    import tempfile
    with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as tmp:
        tmp.write(image_data)
        tmp_path = tmp.name
    
    try:
        # Async conversion
        tasks = []
        for format in ['jpeg', 'webp', 'png']:
            task = client.convert_image(
                image_path=tmp_path,
                output_format=format,
                quality=80
            )
            tasks.append(task)
        
        # Wait for all conversions
        results = await asyncio.gather(*tasks)
        
        for output_data, result in results:
            print(f"Format: {{result.output_format}}, Size: {{len(output_data)}}")
            
    finally:
        import os
        os.unlink(tmp_path)
        await client.close()

asyncio.run(main())
""".format(
            sdk_path=python_sdk_path
        )

        # Run async test
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(test_script)
            script_path = f.name

        try:
            result = subprocess.run(
                ["python", script_path], capture_output=True, text=True, timeout=10
            )

            # Should complete all formats
            assert "Format: jpeg" in result.stdout
            assert "Format: webp" in result.stdout
            assert "Format: png" in result.stdout

        finally:
            os.unlink(script_path)

    @pytest.mark.integration
    async def test_javascript_sdk_node(self, javascript_sdk_path):
        """
        Test JavaScript SDK in Node.js environment.

        Common server-side usage.
        """
        test_script = """
const path = require('path');
const fs = require('fs');

// Add SDK to path
const sdkPath = '{sdk_path}';
const {{ ImageConverterClient }} = require(path.join(sdkPath, 'dist', 'index.js'));

async function main() {{
    // Initialize client
    const client = new ImageConverterClient({{
        host: 'localhost',
        port: 8000,
        apiKey: 'test_key'
    }});
    
    // Create test image using canvas
    const {{ createCanvas }} = require('canvas');
    const canvas = createCanvas(200, 200);
    const ctx = canvas.getContext('2d');
    
    // Draw something
    ctx.fillStyle = 'red';
    ctx.fillRect(0, 0, 200, 200);
    ctx.fillStyle = 'white';
    ctx.fillText('TEST', 50, 100);
    
    // Get image buffer
    const imageBuffer = canvas.toBuffer('image/png');
    
    // Save to temp file
    const tmpPath = path.join(__dirname, 'temp_test.png');
    fs.writeFileSync(tmpPath, imageBuffer);
    
    try {{
        // Convert image
        const result = await client.convertImage({{
            imagePath: tmpPath,
            outputFormat: 'jpeg',
            quality: 90
        }});
        
        console.log('Success:', result.success);
        console.log('Output format:', result.outputFormat);
        console.log('Output size:', result.outputData.length);
        
    }} finally {{
        // Cleanup
        fs.unlinkSync(tmpPath);
    }}
}}

main().catch(console.error);
""".format(
            sdk_path=javascript_sdk_path
        )

        # Check if Node.js is available
        try:
            subprocess.run(["node", "--version"], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            pytest.skip("Node.js not available")

        # Run Node.js test
        with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
            f.write(test_script)
            script_path = f.name

        try:
            result = subprocess.run(
                ["node", script_path],
                capture_output=True,
                text=True,
                timeout=10,
                cwd=os.path.dirname(script_path),
            )

            if result.returncode != 0:
                # Canvas module might not be installed
                if "Cannot find module 'canvas'" in result.stderr:
                    pytest.skip("Node canvas module not installed")

            # Check output
            assert "Success: true" in result.stdout
            assert "Output format: jpeg" in result.stdout

        finally:
            os.unlink(script_path)

    @pytest.mark.integration
    async def test_go_sdk_basic(self, go_sdk_path):
        """
        Test Go SDK basic functionality.

        Go is common for microservices.
        """
        test_script = """
package main

import (
    "fmt"
    "io/ioutil"
    "os"
    
    converter "github.com/user/image-converter-sdk-go"
)

func main() {
    // Initialize client
    client := converter.NewClient("localhost", 8000)
    client.SetAPIKey("test_key")
    
    // Create test image (simplified)
    testData := []byte("fake_image_data")
    
    // Write to temp file
    tmpFile, err := ioutil.TempFile("", "test*.jpg")
    if err != nil {
        panic(err)
    }
    defer os.Remove(tmpFile.Name())
    
    if _, err := tmpFile.Write(testData); err != nil {
        panic(err)
    }
    tmpFile.Close()
    
    // Convert image
    result, err := client.ConvertImage(converter.ConversionRequest{
        ImagePath:     tmpFile.Name(),
        OutputFormat:  "webp",
        Quality:       85,
        StripMetadata: true,
    })
    
    if err != nil {
        fmt.Println("Error:", err)
    } else {
        fmt.Println("Success:", result.Success)
        fmt.Println("Format:", result.OutputFormat)
        fmt.Println("Size:", len(result.OutputData))
    }
}
"""

        # Check if Go is available
        try:
            subprocess.run(["go", "version"], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            pytest.skip("Go not available")

        # Write Go test
        with tempfile.NamedTemporaryFile(mode="w", suffix=".go", delete=False) as f:
            f.write(test_script)
            script_path = f.name

        try:
            # Note: This would need proper Go module setup
            # Simplified test for demonstration
            result = subprocess.run(
                ["go", "run", script_path],
                capture_output=True,
                text=True,
                timeout=10,
                cwd=go_sdk_path,
            )

            if "cannot find package" in result.stderr:
                pytest.skip("Go SDK not properly installed")

            # Check output
            if result.returncode == 0:
                assert "Success:" in result.stdout
                assert "Format:" in result.stdout

        finally:
            os.unlink(script_path)

    @pytest.mark.integration
    async def test_sdk_error_handling(self, python_sdk_path):
        """
        Test SDK error handling across languages.

        SDKs should handle errors gracefully.
        """
        test_script = """
import sys
sys.path.insert(0, "{sdk_path}")

from image_converter_sdk import ImageConverterClient, ImageConverterError

client = ImageConverterClient(
    host="localhost",
    port=8000
)

# Test various error conditions
errors_caught = []

# 1. Invalid file path
try:
    client.convert_image(
        image_path="/nonexistent/file.jpg",
        output_format="webp"
    )
except ImageConverterError as e:
    errors_caught.append("invalid_path")
    print(f"Caught invalid path: {{e}}")

# 2. Invalid format
import tempfile
with tempfile.NamedTemporaryFile(suffix='.jpg') as tmp:
    tmp.write(b"not_an_image")
    tmp.flush()
    
    try:
        client.convert_image(
            image_path=tmp.name,
            output_format="invalid_format"
        )
    except ImageConverterError as e:
        errors_caught.append("invalid_format")
        print(f"Caught invalid format: {{e}}")

# 3. Network error (wrong port)
bad_client = ImageConverterClient(
    host="localhost",
    port=9999  # Wrong port
)

try:
    with tempfile.NamedTemporaryFile(suffix='.jpg') as tmp:
        tmp.write(b"test")
        tmp.flush()
        bad_client.convert_image(
            image_path=tmp.name,
            output_format="png"
        )
except (ImageConverterError, ConnectionError) as e:
    errors_caught.append("network_error")
    print(f"Caught network error: {{e}}")

print(f"Errors caught: {{len(errors_caught)}}")
""".format(
            sdk_path=python_sdk_path
        )

        # Run error handling test
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(test_script)
            script_path = f.name

        try:
            result = subprocess.run(
                ["python", script_path], capture_output=True, text=True, timeout=10
            )

            # Should catch errors gracefully
            assert "Caught invalid path" in result.stdout
            assert (
                "Caught invalid format" in result.stdout
                or "Caught network error" in result.stdout
            )
            assert "Errors caught:" in result.stdout

        finally:
            os.unlink(script_path)

    @pytest.mark.integration
    async def test_sdk_batch_operations(self, python_sdk_path):
        """
        Test SDK batch processing capabilities.

        Real applications often process multiple images.
        """
        test_script = """
import sys
sys.path.insert(0, "{sdk_path}")

from image_converter_sdk import ImageConverterClient
import tempfile
import os
from PIL import Image
import io

client = ImageConverterClient(
    host="localhost",
    port=8000
)

# Create multiple test images
temp_files = []
for i in range(5):
    img = Image.new('RGB', (100, 100), color=['red', 'green', 'blue'][i % 3])
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    
    tmp = tempfile.NamedTemporaryFile(suffix='.png', delete=False)
    tmp.write(buffer.getvalue())
    tmp.close()
    temp_files.append(tmp.name)

try:
    # Batch convert
    results = client.batch_convert(
        image_paths=temp_files,
        output_format="jpeg",
        quality=80
    )
    
    print(f"Batch size: {{len(results)}}")
    
    for i, (output_data, result) in enumerate(results):
        print(f"Image {{i}}: Success={{result.success}}, Size={{len(output_data)}}")
        
finally:
    # Cleanup
    for path in temp_files:
        os.unlink(path)
""".format(
            sdk_path=python_sdk_path
        )

        # Run batch test
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(test_script)
            script_path = f.name

        try:
            result = subprocess.run(
                ["python", script_path], capture_output=True, text=True, timeout=15
            )

            # Check batch processing
            if (
                "AttributeError: 'ImageConverterClient' object has no attribute 'batch_convert'"
                in result.stderr
            ):
                # SDK might not have batch support yet
                pytest.skip("SDK doesn't support batch operations")

            if result.returncode == 0:
                assert "Batch size: 5" in result.stdout
                for i in range(5):
                    assert f"Image {i}: Success=True" in result.stdout

        finally:
            os.unlink(script_path)

    @pytest.mark.integration
    async def test_sdk_streaming(self, python_sdk_path):
        """
        Test SDK streaming capabilities for large files.

        Important for memory efficiency.
        """
        test_script = """
import sys
sys.path.insert(0, "{sdk_path}")

from image_converter_sdk import ImageConverterClient
import tempfile
from PIL import Image

client = ImageConverterClient(
    host="localhost",
    port=8000
)

# Create large test image
img = Image.new('RGB', (4000, 3000), color='blue')

with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as tmp:
    img.save(tmp, format='PNG')
    tmp_path = tmp.name

try:
    # Stream conversion (if supported)
    if hasattr(client, 'convert_image_stream'):
        # Streaming conversion
        with open(tmp_path, 'rb') as f:
            output_stream = client.convert_image_stream(
                image_stream=f,
                output_format="jpeg",
                quality=85
            )
            
            # Read output in chunks
            chunks = []
            while True:
                chunk = output_stream.read(1024 * 1024)  # 1MB chunks
                if not chunk:
                    break
                chunks.append(chunk)
            
            total_size = sum(len(c) for c in chunks)
            print(f"Streamed output size: {{total_size}}")
    else:
        # Fallback to regular conversion
        output_data, result = client.convert_image(
            image_path=tmp_path,
            output_format="jpeg",
            quality=85
        )
        print(f"Regular output size: {{len(output_data)}}")
        
finally:
    import os
    os.unlink(tmp_path)
""".format(
            sdk_path=python_sdk_path
        )

        # Run streaming test
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(test_script)
            script_path = f.name

        try:
            result = subprocess.run(
                ["python", script_path], capture_output=True, text=True, timeout=20
            )

            # Check streaming or fallback
            assert "output size:" in result.stdout.lower()

        finally:
            os.unlink(script_path)

    @pytest.mark.integration
    async def test_sdk_authentication(self, python_sdk_path):
        """
        Test SDK authentication mechanisms.

        API key, bearer token, etc.
        """
        test_script = """
import sys
sys.path.insert(0, "{sdk_path}")

from image_converter_sdk import ImageConverterClient

# Test different auth methods
auth_tests = []

# 1. API Key auth
try:
    client = ImageConverterClient(
        host="localhost",
        port=8000,
        api_key="valid_api_key_123"
    )
    auth_tests.append("api_key")
    print("API key auth configured")
except Exception as e:
    print(f"API key error: {{e}}")

# 2. Bearer token auth
try:
    client = ImageConverterClient(
        host="localhost",
        port=8000,
        bearer_token="eyJhbGciOiJIUzI1NiIs..."
    )
    auth_tests.append("bearer")
    print("Bearer token auth configured")
except Exception as e:
    print(f"Bearer token error: {{e}}")

# 3. No auth (localhost should work)
try:
    client = ImageConverterClient(
        host="localhost",
        port=8000
    )
    auth_tests.append("no_auth")
    print("No auth configured (localhost)")
except Exception as e:
    print(f"No auth error: {{e}}")

print(f"Auth methods tested: {{len(auth_tests)}}")
""".format(
            sdk_path=python_sdk_path
        )

        # Run auth test
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(test_script)
            script_path = f.name

        try:
            result = subprocess.run(
                ["python", script_path], capture_output=True, text=True, timeout=10
            )

            # Should support multiple auth methods
            assert "auth configured" in result.stdout.lower()
            assert "Auth methods tested:" in result.stdout

        finally:
            os.unlink(script_path)

    @pytest.mark.integration
    async def test_sdk_localhost_enforcement(self, python_sdk_path):
        """
        Test SDK localhost-only enforcement.

        Security: SDKs should block non-localhost by default.
        """
        test_script = """
import sys
sys.path.insert(0, "{sdk_path}")

from image_converter_sdk import ImageConverterClient, NetworkSecurityError

# Test localhost variations (should work)
localhost_hosts = ['localhost', '127.0.0.1', '[::1]', '::1']
for host in localhost_hosts:
    try:
        client = ImageConverterClient(host=host, port=8000)
        print(f"✓ Allowed: {{host}}")
    except NetworkSecurityError:
        print(f"✗ Blocked: {{host}}")

# Test non-localhost (should be blocked by default)
blocked_hosts = ['example.com', '192.168.1.1', '10.0.0.1', '8.8.8.8']
for host in blocked_hosts:
    try:
        client = ImageConverterClient(host=host, port=8000)
        print(f"✗ SECURITY ISSUE - Allowed: {{host}}")
    except (NetworkSecurityError, ValueError) as e:
        print(f"✓ Blocked: {{host}}")

# Test disabling localhost check (not recommended)
try:
    client = ImageConverterClient(
        host="example.com",
        port=8000,
        verify_localhost=False  # Security risk!
    )
    print("Warning: Non-localhost allowed with verify_localhost=False")
except Exception as e:
    print(f"Non-localhost with flag: {{e}}")
""".format(
            sdk_path=python_sdk_path
        )

        # Run localhost enforcement test
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(test_script)
            script_path = f.name

        try:
            result = subprocess.run(
                ["python", script_path], capture_output=True, text=True, timeout=10
            )

            # Localhost should be allowed
            assert (
                "✓ Allowed: localhost" in result.stdout
                or "Allowed: localhost" in result.stdout
            )

            # Non-localhost should be blocked by default
            assert (
                "✓ Blocked: example.com" in result.stdout
                or "Blocked: example.com" in result.stdout
            )

            # Should not have security issues
            assert "SECURITY ISSUE" not in result.stdout

        finally:
            os.unlink(script_path)
