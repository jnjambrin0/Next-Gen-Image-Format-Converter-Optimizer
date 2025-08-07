"""
Tutorial Command
Interactive tutorial launcher and manager
"""

import asyncio
from typing import Optional, Annotated
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm

from app.cli.documentation.tutorial_engine import TutorialEngine
from app.cli.ui.themes import get_theme_manager

# Initialize theme manager and console
theme_manager = get_theme_manager()
console = Console(theme=theme_manager.get_theme())

# Create tutorial command app
app = typer.Typer(
    name="tutorial",
    help="📚 Interactive tutorials to master the CLI",
    no_args_is_help=False,
    rich_markup_mode="rich"
)

# Initialize tutorial engine
tutorial_engine = TutorialEngine(console)


@app.callback(invoke_without_command=True)
def tutorial_command(
    ctx: typer.Context,
    tutorial: Annotated[
        Optional[str],
        typer.Argument(help="Tutorial to run (e.g., 'basic', 'batch', 'optimization')")
    ] = None,
    list_tutorials: Annotated[
        bool,
        typer.Option("--list", "-l", help="List all available tutorials")
    ] = False,
    resume: Annotated[
        bool,
        typer.Option("--resume", "-r", help="Resume from last position")
    ] = True,
    reset: Annotated[
        Optional[str],
        typer.Option("--reset", help="Reset progress for a tutorial (or 'all')")
    ] = None,
    status: Annotated[
        bool,
        typer.Option("--status", "-s", help="Show tutorial progress status")
    ] = False,
):
    """
    Launch interactive tutorials to learn CLI features step by step.
    
    [bold green]Available Tutorials:[/bold green]
    • basic - Learn fundamental image conversion
    • batch - Master batch processing techniques
    • optimization - Advanced optimization strategies
    
    [bold yellow]Features:[/bold yellow]
    • Interactive step-by-step guidance
    • Progress tracking and achievements
    • Sandbox environment for safe practice
    • Quiz questions to test knowledge
    
    [bold cyan]Examples:[/bold cyan]
    
    Start your first tutorial:
      [cyan]img tutorial basic[/cyan]
    
    Resume where you left off:
      [cyan]img tutorial --resume[/cyan]
    
    See your progress:
      [cyan]img tutorial --status[/cyan]
    """
    
    if reset:
        _reset_progress(reset)
        return
    
    if list_tutorials or status:
        _show_tutorial_list(show_progress=status)
        return
    
    if tutorial:
        # Map short names to full IDs
        tutorial_map = {
            "basic": "basic_conversion",
            "batch": "batch_processing",
            "optimization": "optimization",
            "opt": "optimization"
        }
        tutorial_id = tutorial_map.get(tutorial, tutorial)
        
        # Run the tutorial
        asyncio.run(tutorial_engine.run_tutorial(tutorial_id, resume=resume))
    else:
        # Interactive selection
        _interactive_tutorial_selection()


def _show_tutorial_list(show_progress: bool = False):
    """Display list of available tutorials"""
    tutorials = tutorial_engine.list_tutorials()
    
    if not tutorials:
        console.print("[yellow]No tutorials available[/yellow]")
        return
    
    # Create table
    table = Table(
        title="📚 Available Tutorials" if not show_progress else "📊 Tutorial Progress",
        box=None,
        padding=(0, 2)
    )
    
    table.add_column("ID", style="cyan")
    table.add_column("Tutorial", style="bold")
    table.add_column("Steps", justify="center")
    
    if show_progress:
        table.add_column("Progress", justify="center")
        table.add_column("Status", style="green")
    
    for tutorial in tutorials:
        row = [
            tutorial["id"].replace("_", "-"),
            tutorial["title"],
            str(tutorial["steps"])
        ]
        
        if show_progress:
            # Progress bar
            percentage = tutorial["completed"]
            filled = int(percentage / 10)  # 10 character bar
            progress_bar = "█" * filled + "░" * (10 - filled)
            row.append(f"{progress_bar} {percentage:.0f}%")
            
            # Status with color
            status = tutorial["status"]
            if status == "Completed":
                status = f"[green]{status}[/green]"
            elif status == "In Progress":
                status = f"[yellow]{status}[/yellow]"
            else:
                status = f"[dim]{status}[/dim]"
            row.append(status)
        
        table.add_row(*row)
    
    console.print(table)
    
    if not show_progress:
        console.print("\n[yellow]💡 Tip:[/yellow] Use 'img tutorial ID' to start a tutorial")
    else:
        # Show achievements summary
        all_achievements = []
        for tid in tutorial_engine.progress.values():
            all_achievements.extend(tid.achievements)
        
        if all_achievements:
            console.print(f"\n[green]🏆 Achievements:[/green] {len(all_achievements)} earned")


def _interactive_tutorial_selection():
    """Interactive tutorial selection menu"""
    tutorials = tutorial_engine.list_tutorials()
    
    if not tutorials:
        console.print("[yellow]No tutorials available[/yellow]")
        return
    
    # Display welcome message
    panel = Panel(
        """
[bold]Welcome to Interactive Tutorials![/bold]

Choose a tutorial to begin your learning journey.
Each tutorial includes:

• Step-by-step instructions
• Hands-on exercises
• Progress tracking
• Achievements to unlock

[yellow]Recommended path:[/yellow]
1. Start with 'basic' for fundamentals
2. Move to 'batch' for efficiency
3. Master 'optimization' for advanced techniques
        """.strip(),
        title="[bold cyan]📚 Tutorial Center[/bold cyan]",
        border_style="cyan",
        padding=(1, 2)
    )
    console.print(panel)
    
    # Show tutorial options
    console.print("\n[bold]Available Tutorials:[/bold]\n")
    
    for i, tutorial in enumerate(tutorials, 1):
        status_icon = "✅" if tutorial["status"] == "Completed" else "📝" if tutorial["status"] == "In Progress" else "📘"
        console.print(
            f"  {i}. {status_icon} [cyan]{tutorial['title']}[/cyan]",
            f"[dim]({tutorial['steps']} steps, {tutorial['completed']:.0f}% complete)[/dim]"
        )
    
    console.print("\n  0. [dim]Exit[/dim]")
    
    # Get selection
    choice = Prompt.ask(
        "\n[cyan]Select tutorial (enter number)[/cyan]",
        choices=[str(i) for i in range(len(tutorials) + 1)],
        default="0"
    )
    
    if choice == "0":
        console.print("[yellow]Tutorial center closed[/yellow]")
        return
    
    selected = tutorials[int(choice) - 1]
    tutorial_id = selected["id"]
    
    # Check if resuming or starting fresh
    if selected["status"] == "In Progress":
        resume = Confirm.ask(
            f"[cyan]Resume '{selected['title']}' from where you left off?[/cyan]",
            default=True
        )
    else:
        resume = False
    
    # Launch tutorial
    console.print(f"\n[green]Starting:[/green] {selected['title']}\n")
    asyncio.run(tutorial_engine.run_tutorial(tutorial_id, resume=resume))


def _reset_progress(target: str):
    """Reset tutorial progress"""
    if target.lower() == "all":
        if Confirm.ask("[red]Reset ALL tutorial progress?[/red]", default=False):
            tutorial_engine.reset_progress()
            console.print("[green]✓[/green] All tutorial progress has been reset")
    else:
        # Map short name to full ID
        tutorial_map = {
            "basic": "basic_conversion",
            "batch": "batch_processing",
            "optimization": "optimization"
        }
        tutorial_id = tutorial_map.get(target, target)
        
        if Confirm.ask(f"[yellow]Reset progress for '{tutorial_id}'?[/yellow]", default=True):
            tutorial_engine.reset_progress(tutorial_id)


# Export app for main CLI
__all__ = ["app"]