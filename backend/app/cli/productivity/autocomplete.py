"""
Intelligent Autocomplete Engine
Privacy-aware command learning and suggestion system
"""

import base64
import hashlib
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from app.cli.config import get_config_dir


class PrivacySanitizer:
    """Sanitize commands to remove PII before storage"""

    # Patterns that might contain PII
    PATH_PATTERNS = [
        r"[/\\][\w\-\.]+(?:[/\\][\w\-\.]+)*",  # Unix/Windows paths
        r"[A-Z]:[/\\][\w\-\.]+(?:[/\\][\w\-\.]+)*",  # Windows absolute paths
        r"\./[\w\-\.]+(?:[/\\][\w\-\.]+)*",  # Relative paths
        r"\.\.\/[\w\-\.]+(?:[/\\][\w\-\.]+)*",  # Parent relative paths
        r"~[/\\][\w\-\.]+(?:[/\\][\w\-\.]+)*",  # Home directory paths
    ]

    FILENAME_PATTERNS = [
        r"[\w\-]+\.\w{1,5}",  # Basic filename with extension
        r"[\w\-\.]+\.(jpg|jpeg|png|gif|bmp|webp|avif|heif|heic|tiff?|jxl)",  # Image files
    ]

    @classmethod
    def sanitize(cls, command: str) -> str:
        """
        Remove all PII from a command string

        Args:
            command: Original command string

        Returns:
            Sanitized command with PII removed
        """
        sanitized = command

        # Remove specific PII patterns first (before generic patterns)
        # Email addresses (do this before filename patterns)
        sanitized = re.sub(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "<EMAIL>", sanitized
        )

        # URLs (do this before path patterns)
        sanitized = re.sub(r"https?://[^\s]+", "<URL>", sanitized)

        # IP addresses
        sanitized = re.sub(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", "<IP>", sanitized)

        # Replace all paths with generic placeholder
        for pattern in cls.PATH_PATTERNS:
            sanitized = re.sub(pattern, "<PATH>", sanitized, flags=re.IGNORECASE)

        # Replace all filenames with generic placeholder
        for pattern in cls.FILENAME_PATTERNS:
            sanitized = re.sub(pattern, "<FILE>", sanitized, flags=re.IGNORECASE)

        # Any remaining quoted strings that might be user data
        sanitized = re.sub(r'"[^"]*"', '"<STRING>"', sanitized)
        sanitized = re.sub(r"'[^']*'", "'<STRING>'", sanitized)

        return sanitized.strip()


class CommandLearner:
    """Learn from command usage patterns"""

    def __init__(self, data_dir: Path):
        """
        Initialize command learner

        Args:
            data_dir: Directory to store learning data
        """
        self.data_dir = data_dir
        self.data_file = data_dir / "patterns.json"
        self.encryption_key = self._get_or_create_key()
        self.fernet = Fernet(self.encryption_key)
        self.patterns = self._load_patterns()

    def _get_or_create_key(self) -> bytes:
        """Get or create encryption key for learning data"""
        key_file = self.data_dir / ".key"

        if key_file.exists():
            # Load existing key
            with open(key_file, "rb") as f:
                return f.read()
        else:
            # Generate new key
            # Use a deterministic salt based on user's home directory
            salt = hashlib.sha256(str(Path.home()).encode()).digest()[:16]
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend(),
            )
            key = base64.urlsafe_b64encode(kdf.derive(b"image-converter-autocomplete"))

            # Save key with restricted permissions
            key_file.parent.mkdir(parents=True, exist_ok=True)
            with open(key_file, "wb") as f:
                f.write(key)

            # Ensure proper permissions after write
            import stat

            key_file.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0o600

            return key

    def _load_patterns(self) -> Dict:
        """Load encrypted learning patterns"""
        if not self.data_file.exists():
            return {
                "commands": Counter(),
                "parameters": defaultdict(Counter),
                "sequences": defaultdict(Counter),
                "contexts": defaultdict(Counter),
                "last_updated": datetime.now().isoformat(),
            }

        try:
            with open(self.data_file, "rb") as f:
                encrypted = f.read()
                decrypted = self.fernet.decrypt(encrypted)
                data = json.loads(decrypted.decode())

                # Convert back to Counter objects
                data["commands"] = Counter(data["commands"])
                data["parameters"] = defaultdict(
                    Counter, {k: Counter(v) for k, v in data["parameters"].items()}
                )
                data["sequences"] = defaultdict(
                    Counter, {k: Counter(v) for k, v in data["sequences"].items()}
                )
                data["contexts"] = defaultdict(
                    Counter, {k: Counter(v) for k, v in data["contexts"].items()}
                )

                return data
        except Exception:
            # If decryption fails, start fresh
            return {
                "commands": Counter(),
                "parameters": defaultdict(Counter),
                "sequences": defaultdict(Counter),
                "contexts": defaultdict(Counter),
                "last_updated": datetime.now().isoformat(),
            }

    def _save_patterns(self):
        """Save encrypted learning patterns"""
        # Convert Counter objects to dict for JSON serialization
        data = {
            "commands": dict(self.patterns["commands"]),
            "parameters": {k: dict(v) for k, v in self.patterns["parameters"].items()},
            "sequences": {k: dict(v) for k, v in self.patterns["sequences"].items()},
            "contexts": {k: dict(v) for k, v in self.patterns["contexts"].items()},
            "last_updated": datetime.now().isoformat(),
        }

        # Encrypt and save
        json_data = json.dumps(data).encode()
        encrypted = self.fernet.encrypt(json_data)

        self.data_file.parent.mkdir(parents=True, exist_ok=True)
        self.data_file.touch(mode=0o600)
        with open(self.data_file, "wb") as f:
            f.write(encrypted)

    def learn(
        self,
        command: str,
        context: Optional[str] = None,
        previous_command: Optional[str] = None,
    ):
        """
        Learn from a command execution

        Args:
            command: Sanitized command that was executed
            context: Optional context (e.g., current directory type)
            previous_command: Previous command for sequence learning
        """
        # Parse command and parameters
        parts = command.split()
        if not parts:
            return

        base_command = parts[0]
        params = parts[1:] if len(parts) > 1 else []

        # Update command frequency
        self.patterns["commands"][base_command] += 1

        # Track subcommands
        if len(parts) > 1:
            subcommand = parts[1]
            if not subcommand.startswith("-"):
                self.patterns["commands"][subcommand] += 1

        # Update parameter patterns
        if params:
            param_key = f"{base_command}_params"
            for param in params:
                if param.startswith("-"):
                    self.patterns["parameters"][param_key][param] += 1

        # Update command sequences
        if previous_command:
            sequence_key = f"{previous_command} -> {base_command}"
            self.patterns["sequences"]["_sequences"][sequence_key] += 1

        # Update context patterns
        if context:
            self.patterns["contexts"][context][base_command] += 1

        # Save periodically (every 10 updates)
        total_commands = sum(self.patterns["commands"].values())
        if total_commands % 10 == 0:
            self._save_patterns()

    def get_suggestions(
        self, partial: str, context: Optional[str] = None, limit: int = 5
    ) -> List[str]:
        """
        Get command suggestions based on learned patterns

        Args:
            partial: Partial command entered by user
            context: Optional context for context-aware suggestions
            limit: Maximum number of suggestions

        Returns:
            List of suggested commands
        """
        suggestions = []

        # Get base suggestions from command frequency
        for command, count in self.patterns["commands"].most_common():
            if command.startswith(partial):
                suggestions.append((command, count))

        # Boost context-aware suggestions
        if context and context in self.patterns["contexts"]:
            for command, count in self.patterns["contexts"][context].most_common():
                if command.startswith(partial):
                    # Boost score for context matches
                    for i, (cmd, score) in enumerate(suggestions):
                        if cmd == command:
                            suggestions[i] = (cmd, score + count * 2)
                            break
                    else:
                        suggestions.append((command, count * 2))

        # Sort by score and return top suggestions
        suggestions.sort(key=lambda x: x[1], reverse=True)
        return [cmd for cmd, _ in suggestions[:limit]]

    def cleanup_old_data(self, days: int = 7):
        """
        Remove learning data older than specified days

        Args:
            days: Number of days to retain data
        """
        if "last_updated" in self.patterns:
            last_updated = datetime.fromisoformat(self.patterns["last_updated"])
            if datetime.now() - last_updated > timedelta(days=days):
                # Reset patterns
                self.patterns = {
                    "commands": Counter(),
                    "parameters": defaultdict(Counter),
                    "sequences": defaultdict(Counter),
                    "contexts": defaultdict(Counter),
                    "last_updated": datetime.now().isoformat(),
                }
                self._save_patterns()


class AutocompleteEngine:
    """Main autocomplete engine with privacy-aware learning"""

    def __init__(self):
        """Initialize autocomplete engine"""
        self.config_dir = get_config_dir()
        self.autocomplete_dir = self.config_dir / "autocomplete"
        self.autocomplete_dir.mkdir(parents=True, exist_ok=True)

        self.sanitizer = PrivacySanitizer()
        self.learner = CommandLearner(self.autocomplete_dir)

        # Command registry for context-aware suggestions
        self.command_registry = self._build_command_registry()

        # Track previous command for sequence learning
        self.previous_command = None

    def _build_command_registry(self) -> Dict[str, Dict]:
        """Build registry of available commands and their parameters"""
        return {
            "convert": {
                "params": [
                    "-f",
                    "--format",
                    "-o",
                    "--output",
                    "-q",
                    "--quality",
                    "--preset",
                    "--preserve-metadata",
                    "--strip-metadata",
                ],
                "requires_file": True,
                "description": "Convert image to different format",
            },
            "batch": {
                "params": [
                    "-f",
                    "--format",
                    "-q",
                    "--quality",
                    "--preset",
                    "--workers",
                    "--progress",
                ],
                "requires_file": True,
                "description": "Batch convert multiple images",
            },
            "optimize": {
                "params": [
                    "--preset",
                    "--target-size",
                    "--max-width",
                    "--max-height",
                    "--quality",
                    "--lossless",
                ],
                "requires_file": True,
                "description": "Optimize image for specific use case",
            },
            "analyze": {
                "params": ["--format", "--metadata", "--content", "--all"],
                "requires_file": True,
                "description": "Analyze image properties",
            },
            "formats": {
                "params": ["--input", "--output", "--all", "--details"],
                "requires_file": False,
                "description": "List supported formats",
            },
            "presets": {
                "params": [
                    "--list",
                    "--create",
                    "--edit",
                    "--delete",
                    "--export",
                    "--import",
                ],
                "requires_file": False,
                "description": "Manage optimization presets",
            },
            "profile": {
                "params": ["--list", "--create", "--switch", "--delete", "--show"],
                "requires_file": False,
                "description": "Manage configuration profiles",
            },
            "watch": {
                "params": [
                    "--filter",
                    "--exclude",
                    "--format",
                    "--preset",
                    "--workers",
                ],
                "requires_file": False,
                "description": "Watch directory for changes",
            },
            "macro": {
                "params": ["--record", "--play", "--list", "--edit", "--delete"],
                "requires_file": False,
                "description": "Manage command macros",
            },
        }

    def record_command(self, command: str, context: Optional[str] = None):
        """
        Record a command execution for learning

        Args:
            command: Full command string entered by user
            context: Optional context information
        """
        # Sanitize command to remove PII
        sanitized = self.sanitizer.sanitize(command)

        # Learn from the sanitized command
        self.learner.learn(sanitized, context, self.previous_command)

        # Update previous command for sequence learning
        self.previous_command = sanitized.split()[0] if sanitized else None

    def get_suggestions(
        self, partial_input: str, context: Optional[str] = None
    ) -> List[Tuple[str, str]]:
        """
        Get autocomplete suggestions for partial input

        Args:
            partial_input: Partial command or parameter entered
            context: Optional context for suggestions

        Returns:
            List of (suggestion, description) tuples
        """
        suggestions = []
        parts = partial_input.split()

        if not parts:
            # Suggest all commands
            for cmd, info in self.command_registry.items():
                suggestions.append((cmd, info["description"]))
        elif len(parts) == 1:
            # Suggest matching commands
            partial = parts[0].lower()

            # Get learned suggestions first
            learned = self.learner.get_suggestions(partial, context)
            for cmd in learned:
                if cmd in self.command_registry:
                    suggestions.append((cmd, self.command_registry[cmd]["description"]))

            # Add registry commands that weren't in learned suggestions
            for cmd, info in self.command_registry.items():
                if cmd.startswith(partial) and cmd not in learned:
                    suggestions.append((cmd, info["description"]))
        else:
            # Suggest parameters for the command
            command = parts[0]
            if command in self.command_registry:
                last_part = parts[-1]

                # Check if we're in the middle of typing a parameter
                if last_part.startswith("-"):
                    for param in self.command_registry[command]["params"]:
                        if param.startswith(last_part):
                            suggestions.append((param, f"Parameter for {command}"))
                else:
                    # Suggest next parameter
                    used_params = set(p for p in parts[1:] if p.startswith("-"))
                    for param in self.command_registry[command]["params"]:
                        if param not in used_params:
                            suggestions.append((param, f"Parameter for {command}"))

        return suggestions[:10]  # Limit to 10 suggestions

    def get_parameter_values(self, command: str, parameter: str) -> List[str]:
        """
        Get suggested values for a specific parameter

        Args:
            command: The command being used
            parameter: The parameter to get values for

        Returns:
            List of suggested values
        """
        # Parameter-specific value suggestions
        value_suggestions = {
            ("-f", "--format"): ["webp", "avif", "jpeg", "png", "jxl", "heif"],
            ("-q", "--quality"): ["85", "90", "95", "100", "75", "60"],
            ("--preset",): ["web", "print", "archive", "thumbnail", "fast"],
            ("--workers",): ["2", "4", "8", "auto"],
        }

        for params, values in value_suggestions.items():
            if parameter in params:
                return values

        return []

    def cleanup(self):
        """Cleanup old learning data"""
        self.learner.cleanup_old_data(days=7)

    def export_learning_data(self, output_file: Path) -> bool:
        """
        Export learning data with PII removed

        Args:
            output_file: Path to export file

        Returns:
            True if export successful
        """
        try:
            # Get raw patterns without decryption details
            export_data = {
                "commands": dict(self.learner.patterns["commands"].most_common(50)),
                "exported_at": datetime.now().isoformat(),
                "total_commands": sum(self.learner.patterns["commands"].values()),
            }

            with open(output_file, "w") as f:
                json.dump(export_data, f, indent=2)

            return True
        except Exception:
            return False

    def import_learning_data(self, input_file: Path) -> bool:
        """
        Import learning data (only command frequencies)

        Args:
            input_file: Path to import file

        Returns:
            True if import successful
        """
        try:
            with open(input_file, "r") as f:
                data = json.load(f)

            # Only import command frequencies, no PII
            if "commands" in data:
                for cmd, count in data["commands"].items():
                    # Verify command is in registry (additional safety check)
                    if cmd in self.command_registry:
                        self.learner.patterns["commands"][cmd] += count

                self.learner._save_patterns()
                return True

            return False
        except Exception:
            return False
