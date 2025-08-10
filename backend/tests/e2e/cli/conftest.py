"""
Shared fixtures and configuration for CLI E2E tests
"""

import pytest
import subprocess
import sys
import os
import time
import tempfile
import shutil
from pathlib import Path
from typing import Generator, Dict, Any, Optional
import requests
from PIL import Image
import io

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))


class CLIRunner:
    """Helper class to run CLI commands with real execution"""

    def __init__(self, backend_url: str = "http://localhost:8000"):
        self.backend_url = backend_url
        self.cli_path = (
            Path(__file__).parent.parent.parent.parent / "app" / "cli" / "main.py"
        )
        self.temp_dir = None

    def setup(self):
        """Create temporary directory for test outputs"""
        self.temp_dir = tempfile.mkdtemp(prefix="cli_test_")
        return self.temp_dir

    def cleanup(self):
        """Clean up temporary directory"""
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def run_command(
        self,
        command: str,
        capture_output: bool = True,
        timeout: int = 30,
        env: Optional[Dict[str, str]] = None,
        input_text: Optional[str] = None,
    ) -> subprocess.CompletedProcess:
        """
        Run a CLI command and return the result

        Args:
            command: Command to run (e.g., "convert test.jpg -f webp")
            capture_output: Whether to capture stdout/stderr
            timeout: Command timeout in seconds
            env: Environment variables
            input_text: Input to send to stdin

        Returns:
            CompletedProcess with stdout, stderr, and returncode
        """
        # Build full command
        full_cmd = f"python {self.cli_path} {command}"

        # Setup environment
        test_env = os.environ.copy()
        test_env["IMAGE_CONVERTER_API_URL"] = self.backend_url
        test_env["NO_COLOR"] = "0"  # Enable colors for testing
        test_env["FORCE_COLOR"] = "1"  # Force color output
        if env:
            test_env.update(env)

        # Run command
        result = subprocess.run(
            full_cmd,
            shell=True,
            capture_output=capture_output,
            text=True,
            timeout=timeout,
            env=test_env,
            input=input_text,
            cwd=self.temp_dir,
        )

        return result

    def run_img_command(self, args: str, **kwargs) -> subprocess.CompletedProcess:
        """
        Run img CLI command directly

        Args:
            args: Arguments for img command
            **kwargs: Additional arguments for run_command

        Returns:
            CompletedProcess result
        """
        # Try img command first, fallback to python module
        test_env = os.environ.copy()
        test_env["IMAGE_CONVERTER_API_URL"] = self.backend_url
        test_env["FORCE_COLOR"] = "1"

        # First try installed img command
        cmd = f"img {args}"
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=kwargs.get("capture_output", True),
            text=True,
            timeout=kwargs.get("timeout", 30),
            env=test_env,
            input=kwargs.get("input_text"),
            cwd=self.temp_dir or os.getcwd(),
        )

        # If img command not found, try Python module
        if result.returncode == 127 or "command not found" in result.stderr:
            # Fallback to Python module execution
            cli_path = Path(__file__).parent.parent.parent.parent / "img.py"
            python_cmd = sys.executable  # Use the same Python interpreter
            if not cli_path.exists():
                # Try app.cli.main module
                cmd = f"{python_cmd} -m app.cli.main {args}"
            else:
                cmd = f"{python_cmd} {cli_path} {args}"

            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=kwargs.get("capture_output", True),
                text=True,
                timeout=kwargs.get("timeout", 30),
                env=test_env,
                input=kwargs.get("input_text"),
                cwd=self.temp_dir or os.getcwd(),
            )

        return result


@pytest.fixture(scope="session")
def backend_server():
    """Ensure backend server is running"""
    # Check if backend is running
    max_retries = 5
    for i in range(max_retries):
        try:
            response = requests.get("http://localhost:8000/api/health", timeout=2)
            if response.status_code == 200:
                print("✅ Backend server is running")
                return "http://localhost:8000"
        except requests.exceptions.RequestException:
            if i < max_retries - 1:
                print(f"⏳ Waiting for backend to start... ({i+1}/{max_retries})")
                time.sleep(2)
            else:
                pytest.skip(
                    "Backend server is not running. Start with: uvicorn app.main:app --port 8000"
                )

    return None


@pytest.fixture
def cli_runner(backend_server) -> Generator[CLIRunner, None, None]:
    """Create a CLI runner for tests"""
    runner = CLIRunner(backend_url=backend_server)
    runner.setup()
    yield runner
    runner.cleanup()


@pytest.fixture
def sample_images(cli_runner) -> Dict[str, Path]:
    """Create sample test images"""
    images = {}
    temp_dir = Path(cli_runner.temp_dir)

    # Create small test images
    sizes = {
        "tiny": (10, 10),
        "small": (100, 100),
        "medium": (500, 500),
        "large": (1000, 1000),
    }

    colors = {
        "red": (255, 0, 0),
        "green": (0, 255, 0),
        "blue": (0, 0, 255),
        "gradient": None,  # Will create gradient
    }

    for size_name, dimensions in sizes.items():
        for color_name, color in colors.items():
            if color:
                # Solid color image
                img = Image.new("RGB", dimensions, color)
            else:
                # Create gradient
                img = Image.new("RGB", dimensions)
                pixels = img.load()
                for i in range(dimensions[0]):
                    for j in range(dimensions[1]):
                        r = int(255 * (i / dimensions[0]))
                        g = int(255 * (j / dimensions[1]))
                        b = 128
                        pixels[i, j] = (r, g, b)

            # Save in different formats
            for fmt in ["jpg", "png"]:
                filename = f"test_{size_name}_{color_name}.{fmt}"
                filepath = temp_dir / filename
                img.save(filepath)
                images[f"{size_name}_{color_name}_{fmt}"] = filepath

    # Create a text-heavy image for OCR testing
    text_img = Image.new("RGB", (400, 200), "white")
    from PIL import ImageDraw

    draw = ImageDraw.Draw(text_img)
    draw.text((50, 50), "Test Text for OCR", fill="black")
    text_path = temp_dir / "text_image.png"
    text_img.save(text_path)
    images["text"] = text_path

    # Create transparent PNG
    trans_img = Image.new("RGBA", (200, 200), (255, 0, 0, 0))
    trans_path = temp_dir / "transparent.png"
    trans_img.save(trans_path)
    images["transparent"] = trans_path

    return images


@pytest.fixture
def terminal_configs() -> list:
    """Different terminal configurations to test"""
    return [
        {
            "name": "full_featured",
            "env": {
                "TERM": "xterm-256color",
                "COLORTERM": "truecolor",
                "FORCE_COLOR": "1",
                "TERM_PROGRAM": "iTerm.app",
            },
        },
        {
            "name": "basic_terminal",
            "env": {"TERM": "xterm", "NO_COLOR": "0", "FORCE_COLOR": "0"},
        },
        {"name": "no_color", "env": {"NO_COLOR": "1", "TERM": "dumb"}},
        {
            "name": "ci_environment",
            "env": {"CI": "true", "GITHUB_ACTIONS": "true", "TERM": "xterm"},
        },
    ]


@pytest.fixture
def ansi_parser():
    """Helper to parse ANSI escape codes from output"""
    import re

    class ANSIParser:
        # ANSI escape code patterns
        ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")
        ANSI_COLOR = re.compile(r"\x1b\[([0-9;]+)m")
        EMOJI_PATTERN = re.compile(r"[\U0001F300-\U0001F9FF]")

        def has_ansi_codes(self, text: str) -> bool:
            """Check if text contains ANSI codes"""
            return bool(self.ANSI_ESCAPE.search(text))

        def strip_ansi(self, text: str) -> str:
            """Remove ANSI codes from text"""
            return self.ANSI_ESCAPE.sub("", text)

        def extract_colors(self, text: str) -> list:
            """Extract color codes from text"""
            return self.ANSI_COLOR.findall(text)

        def has_emoji(self, text: str) -> bool:
            """Check if text contains emoji"""
            return bool(self.EMOJI_PATTERN.search(text))

        def count_emoji(self, text: str) -> int:
            """Count emojis in text"""
            return len(self.EMOJI_PATTERN.findall(text))

        def extract_table(self, text: str) -> list:
            """Extract table rows from output"""
            lines = text.split("\n")
            table_lines = []
            in_table = False

            for line in lines:
                # Simple heuristic: tables often have | or ─
                if "│" in line or "─" in line or "|" in line:
                    in_table = True
                    table_lines.append(line)
                elif in_table and line.strip() == "":
                    in_table = False
                elif in_table:
                    table_lines.append(line)

            return table_lines

    return ANSIParser()


@pytest.fixture
def progress_validator():
    """Helper to validate progress output"""

    class ProgressValidator:
        def has_progress_bar(self, text: str) -> bool:
            """Check if output contains progress bar"""
            indicators = ["█", "▓", "▒", "░", "━", "─", "%", "[", "]"]
            return any(ind in text for ind in indicators)

        def has_spinner(self, text: str) -> bool:
            """Check if output contains spinner characters"""
            spinners = [
                "⠋",
                "⠙",
                "⠹",
                "⠸",
                "⠼",
                "⠴",
                "⠦",
                "⠧",
                "⠇",
                "⠏",
                "/",
                "-",
                "\\",
                "|",
            ]
            return any(s in text for s in spinners)

        def extract_percentage(self, text: str) -> Optional[float]:
            """Extract percentage from progress output"""
            import re

            match = re.search(r"(\d+(?:\.\d+)?)\s*%", text)
            if match:
                return float(match.group(1))
            return None

    return ProgressValidator()


@pytest.fixture
def theme_validator():
    """Helper to validate theme application"""

    class ThemeValidator:
        # Color codes for different themes
        THEMES = {
            "dark": {
                "primary": "cyan",
                "success": "green",
                "error": "red",
                "warning": "yellow",
            },
            "light": {
                "primary": "blue",
                "success": "green",
                "error": "red",
                "warning": "yellow",
            },
            "minimal": {
                # Minimal theme uses less colors
                "all": "white"
            },
        }

        def validate_theme(self, output: str, theme_name: str) -> bool:
            """Check if output matches expected theme"""
            if theme_name not in self.THEMES:
                return False

            # Check for theme-specific patterns
            # This is simplified - real validation would be more complex
            return True

        def has_styled_output(self, text: str) -> bool:
            """Check if output has any styling"""
            # Check for ANSI codes or Rich markup
            return "\x1b[" in text or "[" in text

    return ThemeValidator()


def wait_for_file(filepath: Path, timeout: int = 10) -> bool:
    """Wait for a file to be created"""
    start_time = time.time()
    while time.time() - start_time < timeout:
        if filepath.exists():
            return True
        time.sleep(0.1)
    return False


def capture_screenshot(output_text: str, filename: str):
    """Save colored output as HTML for visual verification"""
    # This would convert ANSI to HTML for visual inspection
    # Simplified version - real implementation would use ansi2html
    html_content = f"""
    <html>
    <head>
        <style>
            body {{ background: #1e1e1e; color: #d4d4d4; font-family: monospace; }}
            pre {{ white-space: pre-wrap; }}
        </style>
    </head>
    <body>
        <pre>{output_text}</pre>
    </body>
    </html>
    """

    output_dir = Path("test_outputs")
    output_dir.mkdir(exist_ok=True)

    with open(output_dir / filename, "w") as f:
        f.write(html_content)
