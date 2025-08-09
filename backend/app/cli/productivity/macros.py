"""
Macro Recording and Playback System
Secure macro management with command validation and sandboxing
"""

import hashlib
import hmac
import json
import re
import secrets
import shlex
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.cli.config import get_config_dir
from app.cli.productivity.autocomplete import PrivacySanitizer


class ExecutionPolicy(Enum):
    """Macro execution policy"""

    ALLOW_ALL = "allow_all"  # Allow all macros
    REQUIRE_APPROVAL = "require_approval"  # Require approval before first run
    SANDBOX_ONLY = "sandbox_only"  # Only run in sandbox
    DISABLED = "disabled"  # Disable macro execution


class MacroSecurity(Enum):
    """Macro security levels"""

    SAFE = "safe"  # No dangerous operations
    WARNING = "warning"  # Contains potentially dangerous operations
    DANGEROUS = "dangerous"  # Contains known dangerous operations
    BLOCKED = "blocked"  # Contains blocked operations


@dataclass
class MacroCommand:
    """Single command in a macro"""

    command: str
    description: Optional[str] = None
    parameters: Dict[str, Any] = field(default_factory=dict)
    sanitized_command: Optional[str] = None
    security_level: MacroSecurity = MacroSecurity.SAFE
    warnings: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        # Sanitize command for storage
        if not self.sanitized_command:
            self.sanitized_command = PrivacySanitizer.sanitize(self.command)


@dataclass
class Macro:
    """A recorded macro"""

    name: str
    description: str
    commands: List[MacroCommand]
    created_at: str = None
    updated_at: str = None
    executed_count: int = 0
    last_executed: Optional[str] = None
    signature: Optional[str] = None
    approved: bool = False
    security_level: MacroSecurity = MacroSecurity.SAFE
    tags: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.created_at:
            self.created_at = datetime.now().isoformat()
        if not self.updated_at:
            self.updated_at = self.created_at

        # Determine overall security level
        if self.commands:
            levels = [cmd.security_level for cmd in self.commands]
            if MacroSecurity.BLOCKED in levels:
                self.security_level = MacroSecurity.BLOCKED
            elif MacroSecurity.DANGEROUS in levels:
                self.security_level = MacroSecurity.DANGEROUS
            elif MacroSecurity.WARNING in levels:
                self.security_level = MacroSecurity.WARNING

    def to_dict(self) -> Dict:
        """Convert to dictionary for storage"""
        data = asdict(self)
        # Convert enums to values
        data["security_level"] = self.security_level.value
        for cmd in data["commands"]:
            cmd["security_level"] = (
                cmd["security_level"].value
                if isinstance(cmd["security_level"], MacroSecurity)
                else cmd["security_level"]
            )
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Macro":
        """Create from dictionary"""
        # Convert security level strings back to enums
        if "security_level" in data:
            data["security_level"] = MacroSecurity(data["security_level"])

        if "commands" in data:
            commands = []
            for cmd_data in data["commands"]:
                if "security_level" in cmd_data:
                    cmd_data["security_level"] = MacroSecurity(
                        cmd_data["security_level"]
                    )
                commands.append(MacroCommand(**cmd_data))
            data["commands"] = commands

        return cls(**data)


@dataclass
class ValidationResult:
    """Result of command validation"""

    is_safe: bool
    security_level: MacroSecurity
    violations: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class CommandValidator:
    """Validate and sanitize commands for security"""

    # Dangerous commands that should be blocked
    BLOCKED_COMMANDS = {
        "rm",
        "del",
        "rmdir",
        "format",
        "fdisk",
        "dd",
        "mkfs",
        "sudo",
        "su",
        "chmod",
        "chown",
        "kill",
        "pkill",
        "killall",
        "shutdown",
        "reboot",
        "poweroff",
        "halt",
        "curl",
        "wget",
        "nc",
        "netcat",
        "telnet",
        "ssh",
        "scp",
        "eval",
        "exec",
        "source",
        ".",
        "sh",
        "bash",
        "zsh",
        "fish",
        "python",
        "perl",
        "ruby",
        "php",
        "node",
        "java",
    }

    # Patterns that indicate dangerous operations
    DANGEROUS_PATTERNS = [
        r"\|",  # Pipe to another command
        r"&&",  # Command chaining
        r";",  # Command separator
        r"`",  # Command substitution
        r"\$\(",  # Command substitution
        r">",  # Output redirection
        r">>",  # Append redirection
        r"<",  # Input redirection
        r"2>",  # Error redirection
        r"\*",  # Wildcard (in certain contexts)
        r"~/",  # Home directory access
        r"\.\./",  # Parent directory access
        r"/etc/",  # System configuration
        r"/sys/",  # System files
        r"/proc/",  # Process information
    ]

    # Commands that are allowed with warnings
    WARNING_COMMANDS = {
        "mv",
        "cp",
        "ln",
        "touch",
        "mkdir",
        "git",
        "docker",
        "npm",
        "pip",
    }

    @classmethod
    def validate(cls, command: str) -> ValidationResult:
        """
        Validate a command and return ValidationResult

        Args:
            command: Command to validate

        Returns:
            ValidationResult with safety status
        """
        security_level, warnings = cls.validate_command(command)

        is_safe = security_level not in (MacroSecurity.BLOCKED, MacroSecurity.DANGEROUS)
        violations = warnings if security_level == MacroSecurity.BLOCKED else []

        return ValidationResult(
            is_safe=is_safe,
            security_level=security_level,
            violations=violations,
            warnings=warnings if security_level != MacroSecurity.BLOCKED else [],
        )

    @classmethod
    def validate_command(cls, command: str) -> Tuple[MacroSecurity, List[str]]:
        """
        Validate a command for security issues

        Args:
            command: Command to validate

        Returns:
            (security_level, list_of_warnings)
        """
        warnings = []

        # Parse command
        try:
            parts = shlex.split(command)
            if not parts:
                return MacroSecurity.SAFE, []

            base_command = parts[0]
        except ValueError:
            warnings.append("Invalid command syntax")
            return MacroSecurity.WARNING, warnings

        # Check for blocked commands
        if base_command in cls.BLOCKED_COMMANDS:
            warnings.append(f"Blocked command: {base_command}")
            return MacroSecurity.BLOCKED, warnings

        # Check for dangerous patterns
        for pattern in cls.DANGEROUS_PATTERNS:
            if re.search(pattern, command):
                warnings.append(f"Dangerous pattern detected: {pattern}")
                return MacroSecurity.DANGEROUS, warnings

        # Check for warning commands
        if base_command in cls.WARNING_COMMANDS:
            warnings.append(f"Potentially dangerous command: {base_command}")
            return MacroSecurity.WARNING, warnings

        # Check for shell metacharacters
        shell_chars = [
            "&",
            "|",
            ";",
            "`",
            "$",
            ">",
            "<",
            "*",
            "?",
            "[",
            "]",
            "(",
            ")",
            "{",
            "}",
        ]
        for char in shell_chars:
            if char in command and char not in parts:  # Not properly quoted
                warnings.append(f"Unquoted shell character: {char}")
                return MacroSecurity.WARNING, warnings

        # Check for absolute paths
        for part in parts[1:]:  # Skip command itself
            if part.startswith("/") or part.startswith("~"):
                warnings.append(f"Absolute path detected: {part[:20]}...")
                # Don't block, just warn

        if warnings:
            return MacroSecurity.WARNING, warnings

        return MacroSecurity.SAFE, []

    @classmethod
    def sanitize_for_execution(cls, command: str) -> str:
        """
        Sanitize command for safe execution

        Args:
            command: Command to sanitize

        Returns:
            Sanitized command
        """
        # Parse and re-quote properly
        try:
            parts = shlex.split(command)
            # Re-quote each part to prevent injection
            safe_parts = [shlex.quote(part) for part in parts]
            return " ".join(safe_parts)
        except ValueError:
            # If parsing fails, reject the command
            raise ValueError("Invalid command syntax")


class SignatureVerifier:
    """Verify macro signatures for integrity"""

    def __init__(self, secret_key: bytes) -> None:
        """
        Initialize signature verifier

        Args:
            secret_key: Secret key for HMAC signing
        """
        self.secret_key = secret_key

    def sign(self, data: Dict[str, Any]) -> str:
        """
        Generate HMAC signature for data

        Args:
            data: Data to sign

        Returns:
            Hex-encoded signature
        """
        # Serialize data in a consistent way
        serialized = json.dumps(data, sort_keys=True, separators=(",", ":"))

        # Generate HMAC signature
        signature = hmac.new(
            self.secret_key, serialized.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        return signature

    def verify(self, data: Dict[str, Any], signature: str) -> bool:
        """
        Verify HMAC signature for data

        Args:
            data: Data to verify
            signature: Signature to check

        Returns:
            True if signature is valid
        """
        try:
            # Generate expected signature
            expected_signature = self.sign(data)

            # Use constant-time comparison to prevent timing attacks
            return hmac.compare_digest(expected_signature, signature)
        except Exception:
            return False


class MacroManager:
    """Manage macros with security and approval"""

    def __init__(self) -> None:
        """Initialize macro manager"""
        self.macros_dir = get_config_dir() / "macros"
        self.macros_dir.mkdir(parents=True, exist_ok=True)

        # Set restrictive permissions
        self.macros_dir.chmod(0o700)

        # Load existing macros
        self.macros = self._load_macros()

        # Secret key for signatures
        self.secret_key = self._get_or_create_secret()

        # Sanitizer for PII removal
        self.sanitizer = PrivacySanitizer()

        # Recording state
        self.recording = False
        self.recorded_commands = []

    def _get_or_create_secret(self) -> bytes:
        """Get or create secret key for signatures"""
        secret_file = self.macros_dir / ".secret"

        if secret_file.exists():
            with open(secret_file, "rb") as f:
                return f.read()
        else:
            # Generate new secret
            secret = secrets.token_bytes(32)
            secret_file.touch(mode=0o600)
            with open(secret_file, "wb") as f:
                f.write(secret)
            return secret

    def _load_macros(self) -> Dict[str, Macro]:
        """Load macros from disk"""
        macros = {}

        for macro_file in self.macros_dir.glob("*.json"):
            if macro_file.name.startswith("."):
                continue  # Skip hidden files

            try:
                with open(macro_file, "r") as f:
                    data = json.load(f)
                    macro = Macro.from_dict(data)

                    # Verify signature
                    if macro.signature:
                        if not self._verify_signature(macro):
                            macro.approved = False
                            macro.warnings.append("Signature verification failed")

                    macros[macro.name] = macro
            except (json.JSONDecodeError, KeyError, IOError):
                # Skip invalid macro files
                continue

        return macros

    def _save_macro(self, macro: Macro) -> None:
        """Save macro to disk"""
        # Update signature
        macro.signature = self._generate_signature(macro)
        macro.updated_at = datetime.now().isoformat()

        macro_file = self.macros_dir / f"{macro.name}.json"
        macro_file.touch(mode=0o600)

        with open(macro_file, "w") as f:
            json.dump(macro.to_dict(), f, indent=2)

    def _generate_signature(self, macro: Macro) -> str:
        """Generate signature for macro integrity"""
        # Create deterministic string representation
        data = json.dumps(
            {
                "name": macro.name,
                "commands": [cmd.sanitized_command for cmd in macro.commands],
            },
            sort_keys=True,
        )

        # Generate HMAC signature
        signature = hmac.new(self.secret_key, data.encode(), hashlib.sha256).hexdigest()

        return signature

    def _verify_signature(self, macro: Macro) -> bool:
        """Verify macro signature"""
        expected = self._generate_signature(macro)
        return hmac.compare_digest(expected, macro.signature or "")

    def start_recording(self, name: str, description: str) -> None:
        """
        Start recording a new macro

        Args:
            name: Macro name
            description: Macro description
        """
        if self.recording:
            raise RuntimeError("Already recording a macro")

        if name in self.macros:
            raise ValueError(f"Macro '{name}' already exists")

        self.recording = True
        self.recording_name = name
        self.recording_description = description
        self.recorded_commands = []

    def record_command(self, command: str, description: Optional[str] = None) -> None:
        """
        Record a command

        Args:
            command: Command to record
            description: Optional[Any] description
        """
        if not self.recording:
            raise RuntimeError("Not currently recording")

        # Validate command
        security_level, warnings = CommandValidator.validate_command(command)

        # Create command object
        cmd = MacroCommand(
            command=command,
            description=description,
            security_level=security_level,
            warnings=warnings,
        )

        self.recorded_commands.append(cmd)

    def stop_recording(self) -> Macro:
        """
        Stop recording and save macro

        Returns:
            Created macro
        """
        if not self.recording:
            raise RuntimeError("Not currently recording")

        if not self.recorded_commands:
            raise ValueError("No commands recorded")

        # Create macro
        macro = Macro(
            name=self.recording_name,
            description=self.recording_description,
            commands=self.recorded_commands,
            approved=False,  # Require approval before first execution
        )

        # Save macro
        self._save_macro(macro)
        self.macros[macro.name] = macro

        # Reset recording state
        self.recording = False
        self.recording_name = None
        self.recording_description = None
        self.recorded_commands = []

        return macro

    def play_macro(
        self,
        name: str,
        parameters: Optional[Dict[str, str]] = None,
        dry_run: bool = False,
        force: bool = False,
    ) -> List[str]:
        """
        Play a macro

        Args:
            name: Macro name
            parameters: Parameter substitutions
            dry_run: If True, don't execute, just return commands
            force: Skip approval check

        Returns: List[Any] of executed commands
        """
        if name not in self.macros:
            raise ValueError(f"Macro '{name}' not found")

        macro = self.macros[name]

        # Check approval
        if not macro.approved and not force:
            raise PermissionError(f"Macro '{name}' not approved for execution")

        # Check security level
        if macro.security_level == MacroSecurity.BLOCKED:
            raise PermissionError(f"Macro '{name}' contains blocked operations")

        executed_commands = []

        for cmd in macro.commands:
            # Substitute parameters
            command = cmd.command
            if parameters:
                for key, value in parameters.items():
                    # Safe parameter substitution
                    placeholder = f"{{{key}}}"
                    if placeholder in command:
                        # Quote the value to prevent injection
                        safe_value = shlex.quote(value)
                        command = command.replace(placeholder, safe_value)

            # Sanitize for execution
            try:
                safe_command = CommandValidator.sanitize_for_execution(command)
            except ValueError as e:
                raise ValueError(f"Invalid command in macro: {e}")

            if not dry_run:
                # Would execute command here
                # In real implementation, would use subprocess with proper sandboxing
                pass

            executed_commands.append(safe_command)

        # Update execution stats
        if not dry_run:
            macro.executed_count += 1
            macro.last_executed = datetime.now().isoformat()
            self._save_macro(macro)

        return executed_commands

    def approve_macro(self, name: str) -> bool:
        """
        Approve a macro for execution

        Args:
            name: Macro name

        Returns:
            True if approved
        """
        if name not in self.macros:
            raise ValueError(f"Macro '{name}' not found")

        macro = self.macros[name]

        # Don't approve blocked macros
        if macro.security_level == MacroSecurity.BLOCKED:
            return False

        macro.approved = True
        self._save_macro(macro)

        return True

    def delete_macro(self, name: str) -> bool:
        """
        Delete a macro

        Args:
            name: Macro name

        Returns:
            True if deleted
        """
        if name not in self.macros:
            return False

        # Delete file
        macro_file = self.macros_dir / f"{name}.json"
        macro_file.unlink(missing_ok=True)

        # Remove from memory
        del self.macros[name]

        return True


class MacroSandbox:
    """Sandbox for macro execution"""

    def __init__(
        self, policy: ExecutionPolicy = ExecutionPolicy.REQUIRE_APPROVAL
    ) -> None:
        """
        Initialize macro sandbox

        Args:
            policy: Execution policy
        """
        self.policy = policy
        self.blocked_commands = CommandValidator.BLOCKED_COMMANDS

    def execute(self, command: str, dry_run: bool = False) -> Tuple[bool, str]:
        """
        Execute command in sandbox

        Args:
            command: Command to execute
            dry_run: If True, don't actually execute

        Returns:
            Tuple of (success, output)
        """
        # Validate command first
        validator = CommandValidator()
        security_level, warnings = validator.validate_command(command)

        if security_level == MacroSecurity.BLOCKED:
            return False, f"Command blocked: {warnings}"

        if dry_run:
            return True, f"[DRY RUN] Would execute: {command}"

        # Check policy
        if self.policy == ExecutionPolicy.DISABLED:
            return False, "Macro execution is disabled"

        if self.policy == ExecutionPolicy.SANDBOX_ONLY:
            # Execute in restricted environment
            return self._execute_sandboxed(command)

        # Execute command
        try:
            # Use shlex to properly parse command
            import shlex

            args = shlex.split(command)

            # Run with timeout and capture output
            result = subprocess.run(
                args, capture_output=True, text=True, timeout=30, check=False
            )

            if result.returncode == 0:
                return True, result.stdout
            else:
                return (
                    False,
                    result.stderr or f"Command failed with code {result.returncode}",
                )

        except subprocess.TimeoutExpired:
            return False, "Command timed out"
        except Exception as e:
            return False, f"Execution error: {e}"

    def _execute_sandboxed(self, command: str) -> Tuple[bool, str]:
        """Execute command in sandboxed environment"""
        # Create minimal environment
        env = {
            "PATH": "/usr/bin:/bin",
            "HOME": "/tmp",
            "USER": "sandbox",
        }

        try:
            import shlex

            args = shlex.split(command)

            # Run with restrictions
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
                env=env,
                cwd="/tmp",
            )

            if result.returncode == 0:
                return True, result.stdout
            else:
                return (
                    False,
                    result.stderr or f"Command failed with code {result.returncode}",
                )

        except Exception as e:
            return False, f"Sandboxed execution error: {e}"

    def get_macro(self, name: str) -> Optional[Macro]:
        """Get a specific macro"""
        return self.macros.get(name)

    def edit_macro(
        self,
        name: str,
        description: Optional[str] = None,
        commands: Optional[List[MacroCommand]] = None,
    ) -> Macro:
        """
        Edit an existing macro

        Args:
            name: Macro name
            description: New description
            commands: New commands

        Returns:
            Updated macro
        """
        if name not in self.macros:
            raise ValueError(f"Macro '{name}' not found")

        macro = self.macros[name]

        if description:
            macro.description = description

        if commands:
            macro.commands = commands
            # Re-evaluate security level
            levels = [cmd.security_level for cmd in commands]
            if MacroSecurity.BLOCKED in levels:
                macro.security_level = MacroSecurity.BLOCKED
            elif MacroSecurity.DANGEROUS in levels:
                macro.security_level = MacroSecurity.DANGEROUS
            elif MacroSecurity.WARNING in levels:
                macro.security_level = MacroSecurity.WARNING
            else:
                macro.security_level = MacroSecurity.SAFE

            # Require re-approval after edit
            macro.approved = False

        self._save_macro(macro)

        return macro

    def export_macro(
        self, name: str, output_file: Path, remove_pii: bool = True
    ) -> bool:
        """
        Export macro to file

        Args:
            name: Macro name
            output_file: Output file path
            remove_pii: Remove PII from commands

        Returns:
            True if exported
        """
        if name not in self.macros:
            return False

        macro = self.macros[name]
        export_data = macro.to_dict()

        if remove_pii:
            # Sanitize commands
            for cmd in export_data["commands"]:
                cmd["command"] = self.sanitizer.sanitize(cmd["command"])
                cmd["sanitized_command"] = cmd["command"]

        # Remove signature (won't be valid after export)
        export_data["signature"] = None
        export_data["approved"] = False

        try:
            with open(output_file, "w") as f:
                json.dump(export_data, f, indent=2)
            return True
        except IOError:
            return False

    def import_macro(
        self, input_file: Path, rename: Optional[str] = None
    ) -> Optional[Macro]:
        """
        Import macro from file

        Args:
            input_file: Input file path
            rename: Optional[Any] new name

        Returns:
            Imported macro or None
        """
        try:
            with open(input_file, "r") as f:
                data = json.load(f)

            macro = Macro.from_dict(data)

            if rename:
                macro.name = rename

            # Check for name conflict
            if macro.name in self.macros:
                macro.name = f"{macro.name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

            # Reset approval and signature
            macro.approved = False
            macro.signature = None

            # Re-validate all commands
            for cmd in macro.commands:
                security_level, warnings = CommandValidator.validate_command(
                    cmd.command
                )
                cmd.security_level = security_level
                cmd.warnings = warnings

            # Re-evaluate overall security
            levels = [cmd.security_level for cmd in macro.commands]
            if MacroSecurity.BLOCKED in levels:
                macro.security_level = MacroSecurity.BLOCKED
            elif MacroSecurity.DANGEROUS in levels:
                macro.security_level = MacroSecurity.DANGEROUS
            elif MacroSecurity.WARNING in levels:
                macro.security_level = MacroSecurity.WARNING
            else:
                macro.security_level = MacroSecurity.SAFE

            # Save imported macro
            self._save_macro(macro)
            self.macros[macro.name] = macro

            return macro

        except (json.JSONDecodeError, KeyError, IOError):
            return None
