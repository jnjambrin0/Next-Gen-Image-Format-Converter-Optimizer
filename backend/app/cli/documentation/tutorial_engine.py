"""
Tutorial Engine Framework
Interactive tutorial system with progress tracking
"""

import asyncio
import json
import re
import sys
import tempfile
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.syntax import Syntax


class TutorialStepType(str, Enum):
    """Types of tutorial steps"""

    INSTRUCTION = "instruction"
    COMMAND = "command"
    INTERACTIVE = "interactive"
    QUIZ = "quiz"
    SANDBOX = "sandbox"
    CHECKPOINT = "checkpoint"


@dataclass
class TutorialStep:
    """Represents a single tutorial step"""

    id: str
    type: TutorialStepType
    title: str
    content: str
    command: Optional[str] = None
    expected_output: Optional[str] = None
    hints: List[str] = field(default_factory=list)
    validation: Optional[Dict[str, Any]] = None
    sandbox_files: Optional[Dict[str, str]] = None  # For sandbox exercises
    quiz_options: Optional[List[str]] = None
    quiz_answer: Optional[int] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        return {
            "id": self.id,
            "type": self.type,
            "title": self.title,
            "content": self.content,
            "command": self.command,
            "expected_output": self.expected_output,
            "hints": self.hints,
            "validation": self.validation,
            "sandbox_files": self.sandbox_files,
            "quiz_options": self.quiz_options,
            "quiz_answer": self.quiz_answer,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TutorialStep":
        """Create from dictionary"""
        return cls(
            id=data["id"],
            type=TutorialStepType(data["type"]),
            title=data["title"],
            content=data["content"],
            command=data.get("command"),
            expected_output=data.get("expected_output"),
            hints=data.get("hints", []),
            validation=data.get("validation"),
            sandbox_files=data.get("sandbox_files"),
            quiz_options=data.get("quiz_options"),
            quiz_answer=data.get("quiz_answer"),
        )


@dataclass
class TutorialProgress:
    """Tracks tutorial progress"""

    tutorial_id: str
    current_step: int
    completed_steps: List[str] = field(default_factory=list)
    total_steps: int = 0
    started_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None
    achievements: List[str] = field(default_factory=list)
    score: int = 0

    def to_dict(self) -> Dict:
        """Convert to dictionary for storage"""
        return {
            "tutorial_id": self.tutorial_id,
            "current_step": self.current_step,
            "completed_steps": self.completed_steps,
            "total_steps": self.total_steps,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "achievements": self.achievements,
            "score": self.score,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TutorialProgress":
        """Create from dictionary"""
        return cls(
            tutorial_id=data["tutorial_id"],
            current_step=data["current_step"],
            completed_steps=data.get("completed_steps", []),
            total_steps=data.get("total_steps", 0),
            started_at=data.get("started_at", time.time()),
            completed_at=data.get("completed_at"),
            achievements=data.get("achievements", []),
            score=data.get("score", 0),
        )

    @property
    def completion_percentage(self) -> float:
        """Calculate completion percentage"""
        if self.total_steps == 0:
            return 0.0
        return (len(self.completed_steps) / self.total_steps) * 100


class TutorialEngine:
    """Manages tutorial execution and progress"""

    def __init__(self, console: Optional[Console] = None) -> None:
        self.console = console or Console()
        self.tutorials: Dict[str, List[TutorialStep]] = {}
        self.progress: Dict[str, TutorialProgress] = {}
        self.config_dir = Path.home() / ".image-converter"
        self.progress_file = self.config_dir / "tutorial_progress.json"
        self.sandbox_dir = Path(tempfile.gettempdir()) / "img-cli-tutorial"

        self._load_tutorials()
        self._load_progress()

    def _load_tutorials(self) -> None:
        """Load tutorial content from embedded data"""
        # Tutorial content is embedded for offline operation
        self.tutorials = {
            "basic_conversion": [
                TutorialStep(
                    id="intro",
                    type=TutorialStepType.INSTRUCTION,
                    title="Welcome to Image Converter CLI",
                    content="""
# Welcome to the Image Converter CLI Tutorial!

This interactive tutorial will teach you the basics of image conversion.
We'll cover:

1. **Converting single images** - Change formats with ease
2. **Quality settings** - Control output quality
3. **Using presets** - Apply optimized settings
4. **Viewing formats** - See what's supported

Let's get started! Press Enter to continue.
                    """.strip(),
                ),
                TutorialStep(
                    id="first_convert",
                    type=TutorialStepType.COMMAND,
                    title="Your First Conversion",
                    content="""
Let's convert a JPEG image to WebP format.

WebP provides better compression than JPEG while maintaining quality.
Try this command:
                    """.strip(),
                    command="img convert sample.jpg -f webp -o sample.webp",
                    expected_output="Conversion complete",
                    hints=[
                        "The -f flag specifies the output format",
                        "The -o flag specifies the output filename",
                    ],
                ),
                TutorialStep(
                    id="quality_quiz",
                    type=TutorialStepType.QUIZ,
                    title="Quick Check: Quality Settings",
                    content="What quality value provides the best balance between file size and visual quality?",
                    quiz_options=["100", "85", "50", "10"],
                    quiz_answer=1,  # 85 is correct
                ),
                TutorialStep(
                    id="quality_control",
                    type=TutorialStepType.SANDBOX,
                    title="Controlling Quality",
                    content="""
Now let's experiment with quality settings.

Try converting the same image with different quality values:
- High quality (95): Larger file, best visual quality
- Medium quality (85): Good balance
- Low quality (60): Smaller file, some quality loss

Run the command below with different --quality values:
                    """.strip(),
                    command="img convert sample.jpg -f webp --quality 85",
                    sandbox_files={
                        "sample.jpg": "tutorial_sample_image"  # Special marker for tutorial engine
                    },
                    validation={
                        "check_output_exists": "sample.webp",
                        "check_quality_range": [60, 95],
                    },
                ),
                TutorialStep(
                    id="using_presets",
                    type=TutorialStepType.INTERACTIVE,
                    title="Using Presets",
                    content="""
Presets are pre-configured settings for common use cases.

Let's use the 'web' preset which optimizes images for web use:
                    """.strip(),
                    command="img optimize sample.jpg --preset web",
                    hints=[
                        "Presets automatically choose format and quality",
                        "Use 'img presets list' to see all available presets",
                    ],
                ),
                TutorialStep(
                    id="checkpoint",
                    type=TutorialStepType.CHECKPOINT,
                    title="Checkpoint: Basic Conversion",
                    content="""
🎉 **Congratulations!** You've completed the basic conversion tutorial!

You've learned:
✅ How to convert images between formats
✅ How to control output quality
✅ How to use presets for common tasks

**Achievement Unlocked:** First Conversion! 🏆

Ready for the next tutorial? Try 'img tutorial batch' to learn batch processing!
                    """.strip(),
                ),
            ],
            "batch_processing": [
                TutorialStep(
                    id="batch_intro",
                    type=TutorialStepType.INSTRUCTION,
                    title="Batch Processing Introduction",
                    content="""
# Batch Processing Tutorial

When you have multiple images to convert, batch processing saves time.

You'll learn:
1. **Pattern matching** - Select files with wildcards
2. **Parallel processing** - Speed up with multiple workers
3. **Output management** - Organize converted files

Let's begin!
                    """.strip(),
                ),
                TutorialStep(
                    id="glob_patterns",
                    type=TutorialStepType.COMMAND,
                    title="Using Glob Patterns",
                    content="""
Glob patterns let you select multiple files at once:

- `*.jpg` - All JPEG files in current directory
- `photos/*.png` - All PNG files in photos directory
- `**/*.gif` - All GIF files recursively

Try converting all PNG files to WebP:
                    """.strip(),
                    command="img batch *.png -f webp",
                    hints=[
                        "The asterisk (*) matches any characters",
                        "Use quotes around patterns with spaces",
                    ],
                ),
                TutorialStep(
                    id="parallel_quiz",
                    type=TutorialStepType.QUIZ,
                    title="Quick Check: Parallel Processing",
                    content="How many worker threads should you use for optimal performance?",
                    quiz_options=[
                        "1 (sequential processing)",
                        "Number of CPU cores",
                        "2x number of CPU cores",
                        "As many as possible",
                    ],
                    quiz_answer=1,  # Number of CPU cores
                ),
                TutorialStep(
                    id="output_directory",
                    type=TutorialStepType.SANDBOX,
                    title="Organizing Output",
                    content="""
Keep your files organized by specifying an output directory.

This command converts all images and saves them in a 'converted' folder:
                    """.strip(),
                    command="img batch *.jpg -f avif --output-dir ./converted",
                    sandbox_files={
                        "photo1.jpg": "tutorial_sample_image",
                        "photo2.jpg": "tutorial_sample_image",
                        "photo3.jpg": "tutorial_sample_image",
                    },
                    validation={
                        "check_directory_exists": "converted",
                        "check_file_count": 3,
                    },
                ),
                TutorialStep(
                    id="batch_checkpoint",
                    type=TutorialStepType.CHECKPOINT,
                    title="Checkpoint: Batch Processing",
                    content="""
🎉 **Excellent work!** You've mastered batch processing!

You've learned:
✅ How to use glob patterns for file selection
✅ How to process multiple files efficiently
✅ How to organize output files

**Achievement Unlocked:** Batch Master! 🏆

Next steps:
- Try 'img tutorial optimization' for advanced optimization
- Use 'img watch' to auto-convert new files
                    """.strip(),
                ),
            ],
            "optimization": [
                TutorialStep(
                    id="opt_intro",
                    type=TutorialStepType.INSTRUCTION,
                    title="Image Optimization Mastery",
                    content="""
# Advanced Optimization Tutorial

Learn to optimize images intelligently using AI-powered features.

Topics covered:
1. **Content detection** - Automatic format selection
2. **Target size** - Achieve specific file sizes
3. **Lossless compression** - Reduce size without quality loss
4. **Smart presets** - Content-aware optimization

Ready to optimize like a pro?
                    """.strip(),
                ),
                # Add more optimization steps...
            ],
        }

    def _load_progress(self) -> None:
        """Load tutorial progress from disk with graceful error recovery"""
        if self.progress_file.exists():
            try:
                with open(self.progress_file, "r") as f:
                    data = json.load(f)
                    self.progress = {}

                    # Load each tutorial progress with individual error handling
                    for tid, p in data.items():
                        try:
                            self.progress[tid] = TutorialProgress.from_dict(p)
                        except (KeyError, TypeError, ValueError) as e:
                            # Skip corrupted individual progress entries
                            self.console.print(
                                f"[yellow]Warning: Skipping corrupted progress for tutorial '{tid}': {e}[/yellow]"
                            )
                            continue

            except json.JSONDecodeError as e:
                # Handle corrupted JSON file
                self.console.print(
                    f"[yellow]Warning: Tutorial progress file corrupted, starting fresh: {e}[/yellow]"
                )
                # Backup corrupted file for debugging
                backup_path = self.progress_file.with_suffix(".json.corrupt")
                try:
                    self.progress_file.rename(backup_path)
                    self.console.print(
                        f"[dim]Corrupted file backed up to: {backup_path}[/dim]"
                    )
                except:
                    pass
                self.progress = {}
            except Exception as e:
                # Catch-all for unexpected errors
                self.console.print(
                    f"[yellow]Warning: Could not load tutorial progress: {e}[/yellow]"
                )
                self.progress = {}
        else:
            self.progress = {}

    def _save_progress(self) -> None:
        """Save tutorial progress to disk"""
        self.config_dir.mkdir(parents=True, exist_ok=True)
        with open(self.progress_file, "w") as f:
            data = {tid: p.to_dict() for tid, p in self.progress.items()}
            json.dump(data, f, indent=2)

    def list_tutorials(self) -> List[Dict[str, Any]]:
        """List available tutorials with progress"""
        tutorials = []
        for tid, steps in self.tutorials.items():
            progress = self.progress.get(tid)
            tutorials.append(
                {
                    "id": tid,
                    "title": self._get_tutorial_title(tid),
                    "steps": len(steps),
                    "completed": progress.completion_percentage if progress else 0,
                    "status": self._get_tutorial_status(tid),
                }
            )
        return tutorials

    def _get_tutorial_title(self, tutorial_id: str) -> str:
        """Get human-readable tutorial title"""
        titles = {
            "basic_conversion": "Basic Image Conversion",
            "batch_processing": "Batch Processing",
            "optimization": "Advanced Optimization",
        }
        return titles.get(tutorial_id, tutorial_id.replace("_", " ").title())

    def _get_tutorial_status(self, tutorial_id: str) -> str:
        """Get tutorial status"""
        if tutorial_id not in self.progress:
            return "Not Started"

        progress = self.progress[tutorial_id]
        if progress.completed_at:
            return "Completed"
        elif progress.current_step > 0:
            return "In Progress"
        else:
            return "Started"

    async def run_tutorial(self, tutorial_id: str, resume: bool = True):
        """
        Run an interactive tutorial

        Args:
            tutorial_id: Tutorial to run
            resume: Resume from last position
        """
        if tutorial_id not in self.tutorials:
            self.console.print(f"[red]Tutorial '{tutorial_id}' not found[/red]")
            return

        steps = self.tutorials[tutorial_id]

        # Initialize or get progress
        if tutorial_id not in self.progress:
            self.progress[tutorial_id] = TutorialProgress(
                tutorial_id=tutorial_id, current_step=0, total_steps=len(steps)
            )

        progress = self.progress[tutorial_id]

        # Resume or restart
        if resume and progress.current_step > 0:
            start_step = progress.current_step
            self.console.print(
                f"[green]Resuming tutorial from step {start_step + 1}[/green]\n"
            )
        else:
            start_step = 0
            progress.current_step = 0
            progress.completed_steps = []

        # Create sandbox directory
        self.sandbox_dir.mkdir(parents=True, exist_ok=True)

        # Run tutorial steps
        for i in range(start_step, len(steps)):
            step = steps[i]
            progress.current_step = i

            # Display progress bar
            self._display_progress(progress)

            # Execute step based on type
            success = await self._execute_step(step, progress)

            if not success:
                # Step failed or user exited
                self._save_progress()
                return

            # Mark step as completed
            if step.id not in progress.completed_steps:
                progress.completed_steps.append(step.id)

            # Award points for quiz/interactive steps
            if step.type in [TutorialStepType.QUIZ, TutorialStepType.INTERACTIVE]:
                progress.score += 10

            # Save progress after each step
            self._save_progress()

            # Pause between steps
            if i < len(steps) - 1:
                self.console.print()
                if not Confirm.ask("[cyan]Continue to next step?[/cyan]", default=True):
                    self.console.print(
                        "[yellow]Tutorial paused. Resume anytime![/yellow]"
                    )
                    return

        # Tutorial completed
        progress.completed_at = time.time()
        progress.achievements.append(f"completed_{tutorial_id}")
        self._save_progress()

        self._display_completion(progress)

    def _display_progress(self, progress: TutorialProgress) -> None:
        """Display tutorial progress bar"""
        percentage = progress.completion_percentage
        filled = int(percentage / 5)  # 20 character bar
        bar = "█" * filled + "░" * (20 - filled)

        self.console.print(
            f"\n[cyan]Tutorial Progress:[/cyan] {bar} {percentage:.0f}%",
            f"[dim]Step {progress.current_step + 1}/{progress.total_steps}[/dim]\n",
        )

    async def _execute_step(
        self, step: TutorialStep, progress: TutorialProgress
    ) -> bool:
        """
        Execute a tutorial step

        Returns:
            True if step completed successfully
        """
        # Display step title
        panel = Panel(f"[bold]{step.title}[/bold]", style="cyan", padding=(0, 2))
        self.console.print(panel)

        # Display step content
        if step.content:
            self.console.print(Markdown(step.content))
            self.console.print()

        # Execute based on step type
        if step.type == TutorialStepType.INSTRUCTION:
            # Just display content and wait
            Prompt.ask("[dim]Press Enter to continue[/dim]", default="")
            return True

        elif step.type == TutorialStepType.COMMAND:
            return await self._execute_command_step(step)

        elif step.type == TutorialStepType.QUIZ:
            return self._execute_quiz_step(step)

        elif step.type == TutorialStepType.SANDBOX:
            return await self._execute_sandbox_step(step)

        elif step.type == TutorialStepType.INTERACTIVE:
            return await self._execute_interactive_step(step)

        elif step.type == TutorialStepType.CHECKPOINT:
            # Display achievement
            self.console.print(step.content)
            return True

        return True

    async def _execute_command_step(self, step: TutorialStep) -> bool:
        """Execute a command demonstration step"""
        if step.command:
            # Show the command
            syntax = Syntax(step.command, "bash", theme="monokai")
            self.console.print(syntax)
            self.console.print()

            # Ask user to try it
            if Confirm.ask(
                "[cyan]Would you like to run this command?[/cyan]", default=True
            ):
                # Run in sandbox
                try:
                    result = await self._run_sandboxed_command(step.command)
                    if step.expected_output and step.expected_output not in result:
                        self.console.print(
                            "[yellow]Output differs from expected.[/yellow]"
                        )
                        if step.hints:
                            self.console.print(f"[dim]Hint: {step.hints[0]}[/dim]")
                except Exception as e:
                    self.console.print(f"[red]Command failed:[/red] {e}")
                    return False

        return True

    def _execute_quiz_step(self, step: TutorialStep) -> bool:
        """Execute a quiz step"""
        if not step.quiz_options or step.quiz_answer is None:
            return True

        # Display options
        for i, option in enumerate(step.quiz_options, 1):
            self.console.print(f"  {i}. {option}")

        # Get answer
        answer = Prompt.ask(
            "\n[cyan]Your answer (enter number)[/cyan]",
            choices=[str(i) for i in range(1, len(step.quiz_options) + 1)],
        )

        # Check answer
        if int(answer) - 1 == step.quiz_answer:
            self.console.print("[green]✓ Correct![/green]")
            return True
        else:
            self.console.print(
                f"[yellow]Not quite. The correct answer is {step.quiz_answer + 1}.[/yellow]"
            )
            if step.hints:
                self.console.print(f"[dim]Explanation: {step.hints[0]}[/dim]")
            return True  # Still continue even if wrong

    async def _execute_sandbox_step(self, step: TutorialStep) -> bool:
        """Execute a sandbox exercise step"""
        # Setup sandbox files
        if step.sandbox_files:
            for filename, content_marker in step.sandbox_files.items():
                # Create sample files in sandbox
                filepath = self.sandbox_dir / filename
                if content_marker == "tutorial_sample_image":
                    # Create a tiny valid image
                    self._create_sample_image(filepath)

        # Show command if provided
        if step.command:
            syntax = Syntax(step.command, "bash", theme="monokai")
            self.console.print("[cyan]Try this command:[/cyan]")
            self.console.print(syntax)
            self.console.print()

        # Let user experiment
        self.console.print("[yellow]Sandbox mode:[/yellow] Try different variations!")
        self.console.print("[dim]Type 'done' when finished, 'hint' for help[/dim]\n")

        while True:
            user_input = Prompt.ask("[green]sandbox>[/green]")

            if user_input.lower() == "done":
                # Validate if criteria met
                if step.validation:
                    if self._validate_sandbox(step.validation):
                        self.console.print("[green]✓ Great job![/green]")
                        return True
                    else:
                        self.console.print(
                            "[yellow]Not quite there yet. Keep trying![/yellow]"
                        )
                else:
                    return True

            elif user_input.lower() == "hint":
                if step.hints:
                    self.console.print(f"[cyan]Hint:[/cyan] {step.hints[0]}")
                else:
                    self.console.print("[yellow]No hints available[/yellow]")

            elif user_input.lower() == "skip":
                return True

            else:
                # Execute command in sandbox
                try:
                    result = await self._run_sandboxed_command(user_input)
                    if result:
                        self.console.print(result)
                except Exception as e:
                    self.console.print(f"[red]Error:[/red] {e}")

    async def _execute_interactive_step(self, step: TutorialStep) -> bool:
        """Execute an interactive step"""
        # Similar to command but with more interaction
        return await self._execute_command_step(step)

    async def _run_sandboxed_command(self, command: str) -> str:
        """Run command in sandboxed environment with security restrictions"""
        # Security validation following CLAUDE.md sandbox patterns

        # Comprehensive blocked commands list
        blocked_commands = [
            # Destructive commands
            "rm",
            "del",
            "format",
            "fdisk",
            "dd",
            "mkfs",
            "shred",
            "wipe",
            # Network tools
            "curl",
            "wget",
            "nc",
            "netcat",
            "telnet",
            "ssh",
            "ftp",
            "sftp",
            "scp",
            "rsync",
            "ping",
            "traceroute",
            "nmap",
            "dig",
            "nslookup",
            # Programming languages and shells
            "python",
            "python3",
            "perl",
            "ruby",
            "php",
            "node",
            "nodejs",
            "bash",
            "sh",
            "zsh",
            "fish",
            "ksh",
            "csh",
            "tcsh",
            "powershell",
            "cmd",
            # System commands
            "sudo",
            "su",
            "chmod",
            "chown",
            "chgrp",
            "kill",
            "pkill",
            "killall",
            "ps",
            "top",
            "htop",
            "systemctl",
            "service",
            "mount",
            "umount",
            # Compilers and build tools
            "gcc",
            "g++",
            "clang",
            "make",
            "cmake",
            "cargo",
            "go",
            "javac",
            # Package managers
            "apt",
            "yum",
            "dnf",
            "pacman",
            "brew",
            "pip",
            "npm",
            "gem",
            "cargo",
            # Text editors (could be used to escape sandbox)
            "vi",
            "vim",
            "nano",
            "emacs",
            "ed",
            "sed",
            "awk",
        ]

        # Additional command injection patterns
        dangerous_patterns = [
            r";\s*[^i]",  # Command chaining (except for img)
            r"&&",  # Command chaining
            r"\|\|",  # Command chaining
            r"\|",  # Piping (could be used to escape)
            r"`",  # Command substitution
            r"\$\(",  # Command substitution
            r">\s*/",  # Redirect to root paths
            r"<\s*/",  # Read from root paths
        ]

        # Check for blocked commands
        cmd_lower = command.lower()
        cmd_parts = cmd_lower.split()

        for blocked in blocked_commands:
            if (
                blocked in cmd_parts
                or f"/{blocked}" in cmd_lower
                or cmd_lower.startswith(blocked)
            ):
                raise ValueError(f"Command '{blocked}' is not allowed in sandbox")

        # Check for dangerous patterns
        for pattern in dangerous_patterns:
            if re.search(pattern, command):
                raise ValueError(f"Command contains dangerous pattern: {pattern}")

        # Validate paths - no absolute paths or parent directory access
        if re.search(r"^/|^[A-Z]:|\\\\|\.\./|/\.\.", command):
            raise ValueError("Absolute paths and parent directory access not allowed")

        # Ensure command stays within sandbox
        if not command.startswith("img "):
            raise ValueError("Only 'img' commands are allowed in tutorial sandbox")

        # Validate img command structure to prevent malformed commands
        img_parts = command[4:].strip().split()  # Skip 'img ' prefix
        if not img_parts:
            raise ValueError("Invalid img command: missing subcommand")

        # List of valid img subcommands
        valid_subcommands = [
            "convert",
            "batch",
            "optimize",
            "analyze",
            "formats",
            "presets",
            "watch",
            "chain",
            "docs",
            "tutorial",
            "help",
            "config",
            "version",
            "--help",
            "-h",
        ]

        # Check if the first part after 'img' is a valid subcommand
        subcommand = img_parts[0].lower()
        if subcommand not in valid_subcommands:
            raise ValueError(
                f"Invalid img subcommand: '{subcommand}'. Use 'img --help' to see valid commands"
            )

        # Create safe environment variables with minimal PATH
        safe_env = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": str(self.sandbox_dir),
            "TMPDIR": str(self.sandbox_dir / "tmp"),
            "IMAGE_CONVERTER_ENABLE_SANDBOXING": "true",
            "IMAGE_CONVERTER_SANDBOX_STRICTNESS": "paranoid",
            # Disable network access through environment
            "http_proxy": "http://127.0.0.1:1",  # Invalid proxy to block HTTP
            "https_proxy": "http://127.0.0.1:1",  # Invalid proxy to block HTTPS
            "no_proxy": "*",  # Disable all proxies
        }

        # Prepare sandboxed command with working directory restriction
        sandbox_cmd = command.replace("img ", f"cd {self.sandbox_dir} && img ")

        try:
            # Create subprocess with strict limits
            process = await asyncio.create_subprocess_shell(
                sandbox_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(self.sandbox_dir),
                env=safe_env,
                # Limit resources on Unix systems
                preexec_fn=lambda: (
                    self._set_resource_limits() if sys.platform != "win32" else None
                ),
            )

            # Run with timeout and kill on timeout
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=10.0  # 10 second timeout
                )
            except asyncio.TimeoutError:
                # Kill process on timeout
                try:
                    process.terminate()
                    await asyncio.sleep(0.1)  # Give it time to terminate
                    if process.returncode is None:
                        process.kill()  # Force kill if still running
                except:
                    pass
                return "[red]Command timed out (10s limit)[/red]"

            if process.returncode != 0:
                error_msg = stderr.decode("utf-8", errors="replace")
                return f"[red]Command failed:[/red] {error_msg[:200]}"

            return stdout.decode("utf-8", errors="replace")[:1000]  # Limit output

        except asyncio.TimeoutError:
            return "[red]Command timed out (10s limit)[/red]"
        except Exception as e:
            # For tutorial mode, return simulated output as fallback
            return f"[dim]Simulated output for: {command}[/dim]\n[yellow]Note: Actual execution unavailable[/yellow]"

    def _set_resource_limits(self) -> None:
        """Set resource limits for sandboxed process (Unix only)"""
        try:
            import resource

            # Limit CPU time (5 seconds)
            resource.setrlimit(resource.RLIMIT_CPU, (5, 5))
            # Limit memory (128MB)
            resource.setrlimit(
                resource.RLIMIT_AS, (128 * 1024 * 1024, 128 * 1024 * 1024)
            )
            # Limit file size (10MB)
            resource.setrlimit(
                resource.RLIMIT_FSIZE, (10 * 1024 * 1024, 10 * 1024 * 1024)
            )
            # Limit number of processes (no subprocesses)
            resource.setrlimit(resource.RLIMIT_NPROC, (0, 0))
        except ImportError:
            pass  # resource module not available on Windows

    def _create_sample_image(self, filepath: Path) -> None:
        """Create a sample image for tutorial"""
        # Create a minimal valid PNG
        png_header = b"\x89PNG\r\n\x1a\n"
        # Add minimal chunks for valid PNG
        # This is a 1x1 transparent pixel
        png_data = (
            png_header
            + b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
            + b"\x00\x00\x00\rIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05\xd8\xdc\xcb\xd3"
            + b"\x00\x00\x00\x00IEND\xaeB`\x82"
        )
        filepath.write_bytes(png_data)

    def _validate_sandbox(self, validation: Dict[str, Any]) -> bool:
        """Validate sandbox exercise completion"""
        # Check various validation criteria
        for key, value in validation.items():
            if key == "check_output_exists":
                if not (self.sandbox_dir / value).exists():
                    return False
            elif key == "check_directory_exists":
                if not (self.sandbox_dir / value).is_dir():
                    return False
            # Add more validation types as needed

        return True

    def _display_completion(self, progress: TutorialProgress) -> None:
        """Display tutorial completion message"""
        duration = progress.completed_at - progress.started_at
        minutes = int(duration / 60)

        panel = Panel(
            f"""
[bold green]🎉 Tutorial Complete! 🎉[/bold green]

[yellow]Stats:[/yellow]
• Time: {minutes} minutes
• Score: {progress.score} points
• Steps: {len(progress.completed_steps)}/{progress.total_steps}

[cyan]Achievements:[/cyan]
{chr(10).join(f'• 🏆 {a}' for a in progress.achievements)}

Great work! Ready for the next challenge?
            """.strip(),
            title="[bold]Congratulations![/bold]",
            border_style="green",
            padding=(1, 2),
        )
        self.console.print(panel)

    def reset_progress(self, tutorial_id: Optional[str] = None) -> None:
        """Reset tutorial progress"""
        if tutorial_id:
            if tutorial_id in self.progress:
                del self.progress[tutorial_id]
                self._save_progress()
                self.console.print(
                    f"[green]✓[/green] Reset progress for '{tutorial_id}'"
                )
        else:
            self.progress = {}
            self._save_progress()
            self.console.print("[green]✓[/green] All tutorial progress reset")
