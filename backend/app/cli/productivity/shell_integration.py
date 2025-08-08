"""
Shell Integration Module
Generate and manage shell completion scripts for various shells
"""

import os
import sys
from pathlib import Path
from typing import Optional, Dict
import subprocess
import shlex


class ShellIntegrator:
    """Generate shell-specific completion scripts"""

    @staticmethod
    def detect_shell() -> Optional[str]:
        """
        Detect the user's current shell

        Returns:
            Shell name (bash, zsh, fish, powershell) or None
        """
        # Check SHELL environment variable (Unix-like systems)
        shell_env = os.environ.get("SHELL", "")

        if "bash" in shell_env:
            return "bash"
        elif "zsh" in shell_env:
            return "zsh"
        elif "fish" in shell_env:
            return "fish"

        # Check for PowerShell on Windows
        if sys.platform == "win32":
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "$PSVersionTable.PSVersion"],
                    capture_output=True,
                    text=True,
                    timeout=2,
                )
                if result.returncode == 0:
                    return "powershell"
            except (subprocess.SubprocessError, FileNotFoundError):
                pass

            # Fallback to cmd on Windows
            return "cmd"

        # Try to detect from parent process
        try:
            parent = Path(f"/proc/{os.getppid()}/exe").resolve()
            parent_name = parent.name

            if "bash" in parent_name:
                return "bash"
            elif "zsh" in parent_name:
                return "zsh"
            elif "fish" in parent_name:
                return "fish"
        except (OSError, FileNotFoundError):
            pass

        # Default to bash if unable to detect
        return "bash"

    @staticmethod
    def generate_bash_completion() -> str:
        """Generate Bash completion script"""
        return """# Image Converter CLI - Bash Completion
# Add to ~/.bashrc or ~/.bash_profile

_img_completion() {
    local cur prev opts base_cmds
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    
    # Base commands
    base_cmds="convert batch optimize analyze formats presets profile watch macro --help --version"
    
    # Command-specific options
    case "${COMP_WORDS[1]}" in
        convert|c)
            local convert_opts="-f --format -o --output -q --quality --preset --preserve-metadata --strip-metadata --dry-run"
            case "$prev" in
                -f|--format)
                    COMPREPLY=( $(compgen -W "webp avif jpeg png jxl heif" -- ${cur}) )
                    return 0
                    ;;
                -q|--quality)
                    COMPREPLY=( $(compgen -W "60 75 85 90 95 100" -- ${cur}) )
                    return 0
                    ;;
                --preset)
                    COMPREPLY=( $(compgen -W "web print archive thumbnail fast" -- ${cur}) )
                    return 0
                    ;;
                *)
                    COMPREPLY=( $(compgen -W "${convert_opts}" -- ${cur}) )
                    return 0
                    ;;
            esac
            ;;
        batch|b)
            local batch_opts="-f --format -q --quality --preset --workers --progress --dry-run"
            case "$prev" in
                -f|--format)
                    COMPREPLY=( $(compgen -W "webp avif jpeg png jxl heif" -- ${cur}) )
                    return 0
                    ;;
                --workers)
                    COMPREPLY=( $(compgen -W "2 4 8 auto" -- ${cur}) )
                    return 0
                    ;;
                *)
                    COMPREPLY=( $(compgen -W "${batch_opts}" -- ${cur}) )
                    return 0
                    ;;
            esac
            ;;
        optimize|o)
            local optimize_opts="--preset --target-size --max-width --max-height --quality --lossless --dry-run"
            case "$prev" in
                --preset)
                    COMPREPLY=( $(compgen -W "web print archive thumbnail fast" -- ${cur}) )
                    return 0
                    ;;
                *)
                    COMPREPLY=( $(compgen -W "${optimize_opts}" -- ${cur}) )
                    return 0
                    ;;
            esac
            ;;
        analyze|a)
            local analyze_opts="--format --metadata --content --all"
            COMPREPLY=( $(compgen -W "${analyze_opts}" -- ${cur}) )
            return 0
            ;;
        formats)
            local formats_opts="--input --output --all --details"
            COMPREPLY=( $(compgen -W "${formats_opts}" -- ${cur}) )
            return 0
            ;;
        presets)
            local presets_opts="--list --create --edit --delete --export --import"
            COMPREPLY=( $(compgen -W "${presets_opts}" -- ${cur}) )
            return 0
            ;;
        profile)
            local profile_opts="--list --create --switch --delete --show"
            COMPREPLY=( $(compgen -W "${profile_opts}" -- ${cur}) )
            return 0
            ;;
        watch|w)
            local watch_opts="--filter --exclude --format --preset --workers"
            COMPREPLY=( $(compgen -W "${watch_opts}" -- ${cur}) )
            return 0
            ;;
        macro|m)
            local macro_opts="--record --play --list --edit --delete"
            COMPREPLY=( $(compgen -W "${macro_opts}" -- ${cur}) )
            return 0
            ;;
        *)
            # Complete base commands
            COMPREPLY=( $(compgen -W "${base_cmds}" -- ${cur}) )
            return 0
            ;;
    esac
}

complete -F _img_completion img

# Aliases
alias imgc='img convert'
alias imgb='img batch'
alias imgo='img optimize'
"""

    @staticmethod
    def generate_zsh_completion() -> str:
        """Generate Zsh completion script"""
        return """# Image Converter CLI - Zsh Completion
# Add to ~/.zshrc or ~/.zprofile

_img_completion() {
    local -a _commands
    _commands=(
        'convert:Convert image to different format'
        'batch:Batch convert multiple images'
        'optimize:Optimize image for specific use case'
        'analyze:Analyze image properties'
        'formats:List supported formats'
        'presets:Manage optimization presets'
        'profile:Manage configuration profiles'
        'watch:Watch directory for changes'
        'macro:Manage command macros'
    )
    
    local -a _global_opts
    _global_opts=(
        '--help[Show help message]'
        '--version[Show version]'
        '--verbose[Enable verbose output]'
        '--debug[Enable debug mode]'
        '--output[Output format]:format:(json table plain rich)'
    )
    
    if (( CURRENT == 2 )); then
        _describe -t commands 'img commands' _commands
        _arguments $_global_opts
    else
        case $words[2] in
            convert|c)
                _arguments \
                    '-f[Output format]:format:(webp avif jpeg png jxl heif)' \
                    '--format[Output format]:format:(webp avif jpeg png jxl heif)' \
                    '-o[Output file]:file:_files' \
                    '--output[Output file]:file:_files' \
                    '-q[Quality]:quality:(60 75 85 90 95 100)' \
                    '--quality[Quality]:quality:(60 75 85 90 95 100)' \
                    '--preset[Optimization preset]:preset:(web print archive thumbnail fast)' \
                    '--preserve-metadata[Preserve image metadata]' \
                    '--strip-metadata[Strip image metadata]' \
                    '--dry-run[Simulate operation without executing]' \
                    '*:file:_files -g "*.{jpg,jpeg,png,gif,bmp,webp,avif,heif,heic,tiff,tif}"'
                ;;
            batch|b)
                _arguments \
                    '-f[Output format]:format:(webp avif jpeg png jxl heif)' \
                    '--format[Output format]:format:(webp avif jpeg png jxl heif)' \
                    '-q[Quality]:quality:(60 75 85 90 95 100)' \
                    '--quality[Quality]:quality:(60 75 85 90 95 100)' \
                    '--preset[Optimization preset]:preset:(web print archive thumbnail fast)' \
                    '--workers[Number of workers]:workers:(2 4 8 auto)' \
                    '--progress[Show progress bar]' \
                    '--dry-run[Simulate operation without executing]' \
                    '*:pattern:_files'
                ;;
            optimize|o)
                _arguments \
                    '--preset[Optimization preset]:preset:(web print archive thumbnail fast)' \
                    '--target-size[Target file size]' \
                    '--max-width[Maximum width]' \
                    '--max-height[Maximum height]' \
                    '--quality[Quality]:quality:(60 75 85 90 95 100)' \
                    '--lossless[Use lossless compression]' \
                    '--dry-run[Simulate operation without executing]' \
                    '*:file:_files -g "*.{jpg,jpeg,png,gif,bmp,webp,avif,heif,heic,tiff,tif}"'
                ;;
            watch|w)
                _arguments \
                    '--filter[File filter pattern]' \
                    '--exclude[Exclude pattern]' \
                    '--format[Output format]:format:(webp avif jpeg png jxl heif)' \
                    '--preset[Optimization preset]:preset:(web print archive thumbnail fast)' \
                    '--workers[Number of workers]:workers:(2 4 8 auto)' \
                    '*:directory:_directories'
                ;;
            profile)
                _arguments \
                    '--list[List all profiles]' \
                    '--create[Create new profile]' \
                    '--switch[Switch to profile]' \
                    '--delete[Delete profile]' \
                    '--show[Show profile details]'
                ;;
            macro|m)
                _arguments \
                    '--record[Record new macro]' \
                    '--play[Play macro]' \
                    '--list[List all macros]' \
                    '--edit[Edit macro]' \
                    '--delete[Delete macro]'
                ;;
        esac
    fi
}

compdef _img_completion img

# Aliases
alias imgc='img convert'
alias imgb='img batch'
alias imgo='img optimize'
"""

    @staticmethod
    def generate_fish_completion() -> str:
        """Generate Fish completion script"""
        return """# Image Converter CLI - Fish Completion
# Save to ~/.config/fish/completions/img.fish

# Disable file completion by default
complete -c img -f

# Commands
complete -c img -n "__fish_use_subcommand" -a convert -d "Convert image to different format"
complete -c img -n "__fish_use_subcommand" -a batch -d "Batch convert multiple images"
complete -c img -n "__fish_use_subcommand" -a optimize -d "Optimize image for specific use case"
complete -c img -n "__fish_use_subcommand" -a analyze -d "Analyze image properties"
complete -c img -n "__fish_use_subcommand" -a formats -d "List supported formats"
complete -c img -n "__fish_use_subcommand" -a presets -d "Manage optimization presets"
complete -c img -n "__fish_use_subcommand" -a profile -d "Manage configuration profiles"
complete -c img -n "__fish_use_subcommand" -a watch -d "Watch directory for changes"
complete -c img -n "__fish_use_subcommand" -a macro -d "Manage command macros"

# Global options
complete -c img -l help -d "Show help message"
complete -c img -l version -d "Show version"
complete -c img -l verbose -d "Enable verbose output"
complete -c img -l debug -d "Enable debug mode"
complete -c img -l output -a "json table plain rich" -d "Output format"

# Convert command
complete -c img -n "__fish_seen_subcommand_from convert c" -s f -l format -a "webp avif jpeg png jxl heif" -d "Output format"
complete -c img -n "__fish_seen_subcommand_from convert c" -s o -l output -r -d "Output file"
complete -c img -n "__fish_seen_subcommand_from convert c" -s q -l quality -a "60 75 85 90 95 100" -d "Quality"
complete -c img -n "__fish_seen_subcommand_from convert c" -l preset -a "web print archive thumbnail fast" -d "Optimization preset"
complete -c img -n "__fish_seen_subcommand_from convert c" -l preserve-metadata -d "Preserve image metadata"
complete -c img -n "__fish_seen_subcommand_from convert c" -l strip-metadata -d "Strip image metadata"
complete -c img -n "__fish_seen_subcommand_from convert c" -l dry-run -d "Simulate operation"

# Batch command
complete -c img -n "__fish_seen_subcommand_from batch b" -s f -l format -a "webp avif jpeg png jxl heif" -d "Output format"
complete -c img -n "__fish_seen_subcommand_from batch b" -s q -l quality -a "60 75 85 90 95 100" -d "Quality"
complete -c img -n "__fish_seen_subcommand_from batch b" -l preset -a "web print archive thumbnail fast" -d "Optimization preset"
complete -c img -n "__fish_seen_subcommand_from batch b" -l workers -a "2 4 8 auto" -d "Number of workers"
complete -c img -n "__fish_seen_subcommand_from batch b" -l progress -d "Show progress bar"
complete -c img -n "__fish_seen_subcommand_from batch b" -l dry-run -d "Simulate operation"

# Optimize command
complete -c img -n "__fish_seen_subcommand_from optimize o" -l preset -a "web print archive thumbnail fast" -d "Optimization preset"
complete -c img -n "__fish_seen_subcommand_from optimize o" -l target-size -d "Target file size"
complete -c img -n "__fish_seen_subcommand_from optimize o" -l max-width -d "Maximum width"
complete -c img -n "__fish_seen_subcommand_from optimize o" -l max-height -d "Maximum height"
complete -c img -n "__fish_seen_subcommand_from optimize o" -l quality -a "60 75 85 90 95 100" -d "Quality"
complete -c img -n "__fish_seen_subcommand_from optimize o" -l lossless -d "Use lossless compression"
complete -c img -n "__fish_seen_subcommand_from optimize o" -l dry-run -d "Simulate operation"

# Watch command
complete -c img -n "__fish_seen_subcommand_from watch w" -l filter -d "File filter pattern"
complete -c img -n "__fish_seen_subcommand_from watch w" -l exclude -d "Exclude pattern"
complete -c img -n "__fish_seen_subcommand_from watch w" -l format -a "webp avif jpeg png jxl heif" -d "Output format"
complete -c img -n "__fish_seen_subcommand_from watch w" -l preset -a "web print archive thumbnail fast" -d "Optimization preset"
complete -c img -n "__fish_seen_subcommand_from watch w" -l workers -a "2 4 8 auto" -d "Number of workers"

# Profile command
complete -c img -n "__fish_seen_subcommand_from profile" -l list -d "List all profiles"
complete -c img -n "__fish_seen_subcommand_from profile" -l create -d "Create new profile"
complete -c img -n "__fish_seen_subcommand_from profile" -l switch -d "Switch to profile"
complete -c img -n "__fish_seen_subcommand_from profile" -l delete -d "Delete profile"
complete -c img -n "__fish_seen_subcommand_from profile" -l show -d "Show profile details"

# Macro command
complete -c img -n "__fish_seen_subcommand_from macro m" -l record -d "Record new macro"
complete -c img -n "__fish_seen_subcommand_from macro m" -l play -d "Play macro"
complete -c img -n "__fish_seen_subcommand_from macro m" -l list -d "List all macros"
complete -c img -n "__fish_seen_subcommand_from macro m" -l edit -d "Edit macro"
complete -c img -n "__fish_seen_subcommand_from macro m" -l delete -d "Delete macro"

# Aliases
abbr imgc 'img convert'
abbr imgb 'img batch'
abbr imgo 'img optimize'
"""

    @staticmethod
    def generate_powershell_completion() -> str:
        """Generate PowerShell completion script"""
        return """# Image Converter CLI - PowerShell Completion
# Add to $PROFILE (run: notepad $PROFILE)
#
# IMPORTANT: PowerShell Execution Policy
# ======================================
# If you encounter "script cannot be loaded" errors, you may need to adjust
# your PowerShell execution policy. Run PowerShell as Administrator and execute:
#
#   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
#
# This allows local scripts to run while maintaining security for remote scripts.
# For more restrictive environments, consult your system administrator.
#
# To check current policy: Get-ExecutionPolicy -List

Register-ArgumentCompleter -CommandName img -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    
    $commands = @{
        'convert' = 'Convert image to different format'
        'batch' = 'Batch convert multiple images'
        'optimize' = 'Optimize image for specific use case'
        'analyze' = 'Analyze image properties'
        'formats' = 'List supported formats'
        'presets' = 'Manage optimization presets'
        'profile' = 'Manage configuration profiles'
        'watch' = 'Watch directory for changes'
        'macro' = 'Manage command macros'
    }
    
    $formats = @('webp', 'avif', 'jpeg', 'png', 'jxl', 'heif')
    $qualities = @('60', '75', '85', '90', '95', '100')
    $presets = @('web', 'print', 'archive', 'thumbnail', 'fast')
    $workers = @('2', '4', '8', 'auto')
    
    # Get the current command context
    $cmdElements = $commandAst.CommandElements
    $subCommand = if ($cmdElements.Count -gt 1) { $cmdElements[1].Value } else { $null }
    
    # If no subcommand yet, suggest commands
    if (-not $subCommand -or $wordToComplete) {
        $commands.Keys | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_, $_, 'Command', $commands[$_])
        }
        return
    }
    
    # Suggest parameters based on subcommand
    switch ($subCommand) {
        'convert' {
            $params = @{
                '-f' = 'Output format'
                '--format' = 'Output format'
                '-o' = 'Output file'
                '--output' = 'Output file'
                '-q' = 'Quality'
                '--quality' = 'Quality'
                '--preset' = 'Optimization preset'
                '--preserve-metadata' = 'Preserve metadata'
                '--strip-metadata' = 'Strip metadata'
                '--dry-run' = 'Simulate operation'
            }
            
            # Check if we're completing a parameter value
            $lastParam = $cmdElements[-2].Value if ($cmdElements.Count -gt 2) else $null
            
            switch ($lastParam) {
                {$_ -in '-f', '--format'} {
                    $formats | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
                    }
                }
                {$_ -in '-q', '--quality'} {
                    $qualities | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
                    }
                }
                '--preset' {
                    $presets | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
                    }
                }
                default {
                    $params.Keys | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                        [System.Management.Automation.CompletionResult]::new($_, $_, 'Parameter', $params[$_])
                    }
                }
            }
        }
        'batch' {
            $params = @{
                '-f' = 'Output format'
                '--format' = 'Output format'
                '-q' = 'Quality'
                '--quality' = 'Quality'
                '--preset' = 'Optimization preset'
                '--workers' = 'Number of workers'
                '--progress' = 'Show progress'
                '--dry-run' = 'Simulate operation'
            }
            
            $lastParam = $cmdElements[-2].Value if ($cmdElements.Count -gt 2) else $null
            
            switch ($lastParam) {
                {$_ -in '-f', '--format'} {
                    $formats | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
                    }
                }
                '--workers' {
                    $workers | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
                    }
                }
                default {
                    $params.Keys | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                        [System.Management.Automation.CompletionResult]::new($_, $_, 'Parameter', $params[$_])
                    }
                }
            }
        }
    }
}

# Aliases
Set-Alias imgc 'img convert'
Set-Alias imgb 'img batch'
Set-Alias imgo 'img optimize'
"""

    @staticmethod
    def install_completion(shell: Optional[str] = None) -> bool:
        """
        Install completion script for the specified shell

        Args:
            shell: Target shell (auto-detect if None)

        Returns:
            True if installation successful
        """
        if not shell:
            shell = ShellIntegrator.detect_shell()

        if not shell:
            return False

        generators = {
            "bash": ShellIntegrator.generate_bash_completion,
            "zsh": ShellIntegrator.generate_zsh_completion,
            "fish": ShellIntegrator.generate_fish_completion,
            "powershell": ShellIntegrator.generate_powershell_completion,
        }

        if shell not in generators:
            return False

        script = generators[shell]()

        # Determine installation path
        install_paths = {
            "bash": Path.home() / ".img_completion.bash",
            "zsh": Path.home() / ".img_completion.zsh",
            "fish": Path.home() / ".config" / "fish" / "completions" / "img.fish",
            "powershell": None,  # Handled differently
        }

        if shell == "powershell":
            # For PowerShell, we need to add to the profile
            print("PowerShell Completion Script:")
            print(script)
            print("\nAdd the above script to your PowerShell profile.")
            print("Run: notepad $PROFILE")
            return True

        install_path = install_paths.get(shell)
        if not install_path:
            return False

        # Create parent directory if needed
        install_path.parent.mkdir(parents=True, exist_ok=True)

        # Write completion script
        install_path.write_text(script)
        install_path.chmod(0o644)

        # Provide sourcing instructions
        if shell == "bash":
            rc_file = Path.home() / ".bashrc"
            source_line = f"source {install_path}"
            print(f"Completion script installed to: {install_path}")
            print(f"Add this line to {rc_file}:")
            print(f"  {source_line}")
        elif shell == "zsh":
            rc_file = Path.home() / ".zshrc"
            source_line = f"source {install_path}"
            print(f"Completion script installed to: {install_path}")
            print(f"Add this line to {rc_file}:")
            print(f"  {source_line}")
        elif shell == "fish":
            print(f"Completion script installed to: {install_path}")
            print("Fish will load it automatically on next start.")

        return True

    @staticmethod
    def generate_helper_functions() -> Dict[str, str]:
        """
        Generate shell helper functions for common tasks

        Returns:
            Dictionary of shell -> helper functions script
        """
        return {
            "bash": """
# Image Converter Helper Functions

# Quick convert to WebP
img2webp() {
    img convert "$1" -f webp -o "${1%.*}.webp"
}

# Quick convert to AVIF
img2avif() {
    img convert "$1" -f avif -o "${1%.*}.avif"
}

# Optimize for web
imgweb() {
    img optimize "$1" --preset web
}

# Batch convert current directory
imgbatch() {
    img batch "*.{jpg,jpeg,png,gif}" -f "${1:-webp}" --quality "${2:-85}"
}

# Watch current directory
imgwatch() {
    img watch . --format "${1:-webp}" --preset "${2:-web}"
}
""",
            "zsh": """
# Image Converter Helper Functions

# Quick convert to WebP
img2webp() {
    img convert "$1" -f webp -o "${1:r}.webp"
}

# Quick convert to AVIF
img2avif() {
    img convert "$1" -f avif -o "${1:r}.avif"
}

# Optimize for web
imgweb() {
    img optimize "$1" --preset web
}

# Batch convert current directory
imgbatch() {
    img batch "*.{jpg,jpeg,png,gif}" -f "${1:-webp}" --quality "${2:-85}"
}

# Watch current directory
imgwatch() {
    img watch . --format "${1:-webp}" --preset "${2:-web}"
}
""",
            "fish": """
# Image Converter Helper Functions

# Quick convert to WebP
function img2webp
    img convert $argv[1] -f webp -o (string replace -r '\\.[^.]+$' '.webp' $argv[1])
end

# Quick convert to AVIF
function img2avif
    img convert $argv[1] -f avif -o (string replace -r '\\.[^.]+$' '.avif' $argv[1])
end

# Optimize for web
function imgweb
    img optimize $argv[1] --preset web
end

# Batch convert current directory
function imgbatch
    set -l format (test -n "$argv[1]"; and echo $argv[1]; or echo "webp")
    set -l quality (test -n "$argv[2]"; and echo $argv[2]; or echo "85")
    img batch "*.{jpg,jpeg,png,gif}" -f $format --quality $quality
end

# Watch current directory
function imgwatch
    set -l format (test -n "$argv[1]"; and echo $argv[1]; or echo "webp")
    set -l preset (test -n "$argv[2]"; and echo $argv[2]; or echo "web")
    img watch . --format $format --preset $preset
end
""",
            "powershell": """
# Image Converter Helper Functions

# Quick convert to WebP
function img2webp {
    param([string]$file)
    $output = [System.IO.Path]::ChangeExtension($file, "webp")
    img convert $file -f webp -o $output
}

# Quick convert to AVIF
function img2avif {
    param([string]$file)
    $output = [System.IO.Path]::ChangeExtension($file, "avif")
    img convert $file -f avif -o $output
}

# Optimize for web
function imgweb {
    param([string]$file)
    img optimize $file --preset web
}

# Batch convert current directory
function imgbatch {
    param(
        [string]$format = "webp",
        [int]$quality = 85
    )
    img batch "*.jpg,*.jpeg,*.png,*.gif" -f $format --quality $quality
}

# Watch current directory
function imgwatch {
    param(
        [string]$format = "webp",
        [string]$preset = "web"
    )
    img watch . --format $format --preset $preset
}
""",
        }
