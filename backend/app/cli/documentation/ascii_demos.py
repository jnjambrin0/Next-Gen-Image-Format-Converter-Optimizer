"""
ASCII Demo Framework
Plays ASCII-based terminal demonstrations
"""

import time
import json
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Callable
from enum import Enum
import asyncio

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.prompt import Prompt
from rich.live import Live
from rich.layout import Layout
from rich.text import Text


class DemoSpeed(float, Enum):
    """Playback speed options"""

    SLOW = 0.5
    NORMAL = 1.0
    FAST = 1.5
    VERY_FAST = 2.0


@dataclass
class DemoFrame:
    """Represents a single frame in ASCII demo"""

    content: str
    delay: int  # milliseconds
    clear: bool = False
    highlight: Optional[List[tuple]] = None  # (start, end, style) for highlighting

    def to_dict(self) -> Dict:
        """Convert to dictionary for storage"""
        return {
            "content": self.content,
            "delay": self.delay,
            "clear": self.clear,
            "highlight": self.highlight,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "DemoFrame":
        """Create from dictionary"""
        return cls(
            content=data["content"],
            delay=data["delay"],
            clear=data.get("clear", False),
            highlight=data.get("highlight"),
        )


@dataclass
class AsciiDemo:
    """Represents a complete ASCII demo"""

    id: str
    title: str
    description: str
    frames: List[DemoFrame]
    category: str = "general"
    tags: List[str] = field(default_factory=list)
    loop: bool = False
    default_speed: DemoSpeed = DemoSpeed.NORMAL

    def to_dict(self) -> Dict:
        """Convert to dictionary for storage"""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "frames": [f.to_dict() for f in self.frames],
            "category": self.category,
            "tags": self.tags,
            "loop": self.loop,
            "default_speed": self.default_speed.value,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "AsciiDemo":
        """Create from dictionary"""
        return cls(
            id=data["id"],
            title=data["title"],
            description=data["description"],
            frames=[DemoFrame.from_dict(f) for f in data["frames"]],
            category=data.get("category", "general"),
            tags=data.get("tags", []),
            loop=data.get("loop", False),
            default_speed=DemoSpeed(data.get("default_speed", 1.0)),
        )

    @property
    def duration(self) -> float:
        """Calculate total duration in seconds"""
        return sum(f.delay for f in self.frames) / 1000.0


class AsciiDemoPlayer:
    """Plays ASCII demonstrations in terminal"""

    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()
        self.demos: Dict[str, AsciiDemo] = {}
        self.current_demo: Optional[AsciiDemo] = None
        self.is_playing = False
        self.is_paused = False
        self.current_frame = 0
        self.speed = DemoSpeed.NORMAL
        self._load_demos()

    def _load_demos(self):
        """Load demo library"""
        # Demos are embedded for offline operation
        demos_data = [
            AsciiDemo(
                id="basic_conversion",
                title="Basic Image Conversion",
                description="Converting a JPEG image to WebP format",
                frames=[
                    DemoFrame(content="$ img convert photo.jpg -f webp", delay=1000),
                    DemoFrame(
                        content="$ img convert photo.jpg -f webp\n[dim]Analyzing image...[/dim]",
                        delay=500,
                    ),
                    DemoFrame(
                        content="$ img convert photo.jpg -f webp\n[dim]Analyzing image...[/dim]\n✓ Format detected: JPEG",
                        delay=500,
                    ),
                    DemoFrame(
                        content="$ img convert photo.jpg -f webp\n[dim]Analyzing image...[/dim]\n✓ Format detected: JPEG\n[yellow]Converting to WebP...[/yellow]",
                        delay=1000,
                    ),
                    DemoFrame(
                        content="$ img convert photo.jpg -f webp\n[dim]Analyzing image...[/dim]\n✓ Format detected: JPEG\n[yellow]Converting to WebP...[/yellow]\n[green]✓ Conversion complete![/green]",
                        delay=500,
                    ),
                    DemoFrame(
                        content="$ img convert photo.jpg -f webp\n[dim]Analyzing image...[/dim]\n✓ Format detected: JPEG\n[yellow]Converting to WebP...[/yellow]\n[green]✓ Conversion complete![/green]\n\nOutput: photo.webp (reduced size by 42%)",
                        delay=2000,
                    ),
                ],
                category="conversion",
                tags=["basic", "convert", "webp"],
            ),
            AsciiDemo(
                id="batch_processing",
                title="Batch Processing with Progress",
                description="Converting multiple files with progress display",
                frames=[
                    DemoFrame(
                        content="$ img batch *.png -f avif --progress", delay=1000
                    ),
                    DemoFrame(
                        content="$ img batch *.png -f avif --progress\n[cyan]Found 12 files to process[/cyan]",
                        delay=500,
                    ),
                    DemoFrame(
                        content="$ img batch *.png -f avif --progress\n[cyan]Found 12 files to process[/cyan]\n\n[▱▱▱▱▱▱▱▱▱▱] 0% (0/12)",
                        delay=500,
                    ),
                    DemoFrame(
                        content="$ img batch *.png -f avif --progress\n[cyan]Found 12 files to process[/cyan]\n\n[████▱▱▱▱▱▱] 33% (4/12) - photo1.png ✓",
                        delay=1000,
                    ),
                    DemoFrame(
                        content="$ img batch *.png -f avif --progress\n[cyan]Found 12 files to process[/cyan]\n\n[███████▱▱▱] 67% (8/12) - photo5.png ✓",
                        delay=1000,
                    ),
                    DemoFrame(
                        content="$ img batch *.png -f avif --progress\n[cyan]Found 12 files to process[/cyan]\n\n[██████████] 100% (12/12) - Complete!",
                        delay=500,
                    ),
                    DemoFrame(
                        content="$ img batch *.png -f avif --progress\n[cyan]Found 12 files to process[/cyan]\n\n[██████████] 100% (12/12) - Complete!\n\n[green]✓ Successfully converted 12 files[/green]\n[dim]Total time: 3.2 seconds[/dim]",
                        delay=2000,
                    ),
                ],
                category="batch",
                tags=["batch", "progress", "avif"],
            ),
            AsciiDemo(
                id="optimization",
                title="Smart Image Optimization",
                description="Using AI to optimize images intelligently",
                frames=[
                    DemoFrame(
                        content="$ img optimize photo.jpg --preset web", delay=1000
                    ),
                    DemoFrame(
                        content="$ img optimize photo.jpg --preset web\n[cyan]🤖 Analyzing content...[/cyan]",
                        delay=800,
                    ),
                    DemoFrame(
                        content="$ img optimize photo.jpg --preset web\n[cyan]🤖 Analyzing content...[/cyan]\n  • Detected: Photo\n  • Faces found: 2\n  • Quality score: 92",
                        delay=1000,
                    ),
                    DemoFrame(
                        content="$ img optimize photo.jpg --preset web\n[cyan]🤖 Analyzing content...[/cyan]\n  • Detected: Photo\n  • Faces found: 2\n  • Quality score: 92\n\n[yellow]Optimizing for web...[/yellow]",
                        delay=1000,
                    ),
                    DemoFrame(
                        content="$ img optimize photo.jpg --preset web\n[cyan]🤖 Analyzing content...[/cyan]\n  • Detected: Photo\n  • Faces found: 2\n  • Quality score: 92\n\n[yellow]Optimizing for web...[/yellow]\n  • Format: WebP (best for photos)\n  • Quality: 85 (balanced)\n  • Size: 1200x800 (responsive)",
                        delay=1500,
                    ),
                    DemoFrame(
                        content="$ img optimize photo.jpg --preset web\n[cyan]🤖 Analyzing content...[/cyan]\n  • Detected: Photo\n  • Faces found: 2\n  • Quality score: 92\n\n[yellow]Optimizing for web...[/yellow]\n  • Format: WebP (best for photos)\n  • Quality: 85 (balanced)\n  • Size: 1200x800 (responsive)\n\n[green]✓ Optimization complete![/green]\n  Original: 2.4 MB → Optimized: 285 KB (88% smaller)",
                        delay=2000,
                    ),
                ],
                category="optimization",
                tags=["optimize", "ai", "web"],
            ),
            AsciiDemo(
                id="watch_mode",
                title="Watch Mode Auto-Conversion",
                description="Monitoring directory for automatic conversion",
                frames=[
                    DemoFrame(
                        content="$ img watch ./uploads -f webp --output-dir ./processed",
                        delay=1000,
                    ),
                    DemoFrame(
                        content="$ img watch ./uploads -f webp --output-dir ./processed\n[yellow]👁 Watching ./uploads for changes...[/yellow]\n[dim]Press Ctrl+C to stop[/dim]",
                        delay=2000,
                    ),
                    DemoFrame(
                        content="$ img watch ./uploads -f webp --output-dir ./processed\n[yellow]👁 Watching ./uploads for changes...[/yellow]\n[dim]Press Ctrl+C to stop[/dim]\n\n[green]→[/green] New file: photo1.jpg",
                        delay=500,
                    ),
                    DemoFrame(
                        content="$ img watch ./uploads -f webp --output-dir ./processed\n[yellow]👁 Watching ./uploads for changes...[/yellow]\n[dim]Press Ctrl+C to stop[/dim]\n\n[green]→[/green] New file: photo1.jpg\n  Converting... ✓ → ./processed/photo1.webp",
                        delay=1500,
                    ),
                    DemoFrame(
                        content="$ img watch ./uploads -f webp --output-dir ./processed\n[yellow]👁 Watching ./uploads for changes...[/yellow]\n[dim]Press Ctrl+C to stop[/dim]\n\n[green]→[/green] New file: photo1.jpg\n  Converting... ✓ → ./processed/photo1.webp\n\n[green]→[/green] New file: photo2.jpg",
                        delay=500,
                    ),
                    DemoFrame(
                        content="$ img watch ./uploads -f webp --output-dir ./processed\n[yellow]👁 Watching ./uploads for changes...[/yellow]\n[dim]Press Ctrl+C to stop[/dim]\n\n[green]→[/green] New file: photo1.jpg\n  Converting... ✓ → ./processed/photo1.webp\n\n[green]→[/green] New file: photo2.jpg\n  Converting... ✓ → ./processed/photo2.webp\n\n[dim]Processed: 2 files | Watching...[/dim]",
                        delay=2000,
                    ),
                ],
                category="advanced",
                tags=["watch", "auto", "monitor"],
                loop=True,
            ),
        ]

        # Index demos
        for demo in demos_data:
            self.demos[demo.id] = demo

    def list_demos(self) -> List[Dict[str, Any]]:
        """List available demos"""
        demos = []
        for demo in self.demos.values():
            demos.append(
                {
                    "id": demo.id,
                    "title": demo.title,
                    "description": demo.description,
                    "duration": f"{demo.duration:.1f}s",
                    "frames": len(demo.frames),
                    "category": demo.category,
                    "tags": demo.tags,
                }
            )
        return demos

    async def play(self, demo_id: str, speed: Optional[DemoSpeed] = None):
        """
        Play an ASCII demo

        Args:
            demo_id: Demo to play
            speed: Playback speed
        """
        if demo_id not in self.demos:
            self.console.print(f"[red]Demo '{demo_id}' not found[/red]")
            return

        demo = self.demos[demo_id]
        self.current_demo = demo
        self.speed = speed or demo.default_speed
        self.current_frame = 0
        self.is_playing = True
        self.is_paused = False

        # Display demo info
        panel = Panel(
            f"[bold]{demo.title}[/bold]\n{demo.description}\n\n[dim]Duration: {demo.duration:.1f}s | Frames: {len(demo.frames)}[/dim]",
            title="[cyan]ASCII Demo[/cyan]",
            border_style="cyan",
        )
        self.console.print(panel)
        self.console.print("\n[dim]Press Ctrl+C to stop, Space to pause/resume[/dim]\n")

        # Play frames
        try:
            await self._play_frames(demo)
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Demo stopped[/yellow]")
        finally:
            self.is_playing = False

            if demo.loop and self.current_frame >= len(demo.frames):
                # Ask to replay
                replay = Prompt.ask(
                    "\n[cyan]Replay demo?[/cyan]", choices=["y", "n"], default="n"
                )
                if replay == "y":
                    await self.play(demo_id, self.speed)

    async def _play_frames(self, demo: AsciiDemo):
        """Play demo frames"""
        while self.current_frame < len(demo.frames):
            if self.is_paused:
                await asyncio.sleep(0.1)
                continue

            frame = demo.frames[self.current_frame]

            # Clear screen if requested
            if frame.clear:
                self.console.clear()

            # Display frame content
            if frame.highlight:
                # Apply highlighting
                text = Text(frame.content)
                for start, end, style in frame.highlight:
                    text.stylize(style, start, end)
                self.console.print(text)
            else:
                self.console.print(frame.content)

            # Wait for delay (adjusted by speed)
            delay_seconds = (frame.delay / 1000.0) / self.speed.value
            await asyncio.sleep(delay_seconds)

            self.current_frame += 1

        # Loop if enabled
        if demo.loop:
            self.current_frame = 0
            await self._play_frames(demo)

    def pause(self):
        """Pause playback"""
        self.is_paused = True
        self.console.print("[yellow]⏸ Paused[/yellow]")

    def resume(self):
        """Resume playback"""
        self.is_paused = False
        self.console.print("[green]▶ Resumed[/green]")

    def stop(self):
        """Stop playback"""
        self.is_playing = False
        self.current_frame = 0
        self.console.print("[red]■ Stopped[/red]")

    def set_speed(self, speed: DemoSpeed):
        """Change playback speed"""
        self.speed = speed
        self.console.print(f"[cyan]Speed: {speed.name}[/cyan]")

    def search_demos(self, query: str) -> List[AsciiDemo]:
        """Search demos by query"""
        results = []
        query_lower = query.lower()

        for demo in self.demos.values():
            score = 0

            # Check title
            if query_lower in demo.title.lower():
                score += 10

            # Check description
            if query_lower in demo.description.lower():
                score += 5

            # Check tags
            for tag in demo.tags:
                if query_lower in tag.lower():
                    score += 3
                    break

            # Check category
            if query_lower in demo.category.lower():
                score += 2

            if score > 0:
                results.append((score, demo))

        # Sort by score
        results.sort(key=lambda x: x[0], reverse=True)
        return [demo for _, demo in results]

    def record_demo(self, title: str, description: str) -> "DemoRecorder":
        """Start recording a new demo"""
        return DemoRecorder(title, description, self)

    def save_demo(self, demo: AsciiDemo):
        """Save a demo to library"""
        self.demos[demo.id] = demo

        # Save to file for persistence
        demo_file = Path.home() / ".image-converter" / "demos" / f"{demo.id}.json"
        demo_file.parent.mkdir(parents=True, exist_ok=True)

        with open(demo_file, "w") as f:
            json.dump(demo.to_dict(), f, indent=2)

        self.console.print(f"[green]✓[/green] Saved demo: {demo.id}")


class DemoRecorder:
    """Records terminal sessions as ASCII demos"""

    def __init__(self, title: str, description: str, player: AsciiDemoPlayer):
        self.title = title
        self.description = description
        self.player = player
        self.frames: List[DemoFrame] = []
        self.start_time = time.time()
        self.last_frame_time = self.start_time

    def add_frame(self, content: str, clear: bool = False):
        """Add a frame to the recording"""
        current_time = time.time()
        delay = int((current_time - self.last_frame_time) * 1000)

        frame = DemoFrame(content=content, delay=delay, clear=clear)
        self.frames.append(frame)
        self.last_frame_time = current_time

    def finish(
        self, demo_id: str, category: str = "custom", tags: Optional[List[str]] = None
    ) -> AsciiDemo:
        """Finish recording and create demo"""
        demo = AsciiDemo(
            id=demo_id,
            title=self.title,
            description=self.description,
            frames=self.frames,
            category=category,
            tags=tags or [],
        )

        self.player.save_demo(demo)
        return demo
