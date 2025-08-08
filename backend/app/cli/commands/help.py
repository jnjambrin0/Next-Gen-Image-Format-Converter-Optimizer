"""
Enhanced Help Command
Context-aware help with examples and search functionality
"""

from typing import Optional, Annotated
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.columns import Columns
from rich.markdown import Markdown

from app.cli.documentation.help_context import HelpContextAnalyzer
from app.cli.ui.themes import get_theme_manager

# Initialize theme manager and console
theme_manager = get_theme_manager()
console = Console(theme=theme_manager.get_theme())

# Create help command app
app = typer.Typer(
    name="help",
    help="🔍 Get context-aware help and search documentation",
    no_args_is_help=False,
    rich_markup_mode="rich",
)

# Initialize help analyzer
help_analyzer = HelpContextAnalyzer(console)


@app.callback(invoke_without_command=True)
def help_command(
    ctx: typer.Context,
    query: Annotated[
        Optional[str], typer.Argument(help="Search query or command name")
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Show detailed help with all examples"),
    ] = False,
    examples: Annotated[
        bool, typer.Option("--examples", "-e", help="Show only examples")
    ] = False,
    errors: Annotated[
        bool, typer.Option("--errors", help="Show common errors and solutions")
    ] = False,
    search: Annotated[
        bool, typer.Option("--search", "-s", help="Search all help topics")
    ] = False,
    clear_cache: Annotated[
        bool, typer.Option("--clear-cache", help="Clear help cache", hidden=True)
    ] = False,
):
    """
    Get intelligent, context-aware help for any command.

    [bold green]Features:[/bold green]
    • Smart context detection based on recent commands
    • Relevant examples for your current task
    • Error-specific troubleshooting
    • Fuzzy search across all documentation

    [bold yellow]Examples:[/bold yellow]

    Get help for a command:
      [cyan]img help convert[/cyan]

    Search documentation:
      [cyan]img help --search "batch processing"[/cyan]

    Show examples only:
      [cyan]img help optimize --examples[/cyan]

    Get error solutions:
      [cyan]img help --errors[/cyan]
    """

    if clear_cache:
        help_analyzer.clear_cache()
        console.print("[green]✓[/green] Help cache cleared")
        return

    if query and search:
        # Search mode
        _search_help(query)
    elif query:
        # Direct command help
        _show_command_help(query, verbose, examples, errors)
    elif errors:
        # Show all error codes
        _show_all_errors()
    else:
        # Context-aware help
        context = help_analyzer.get_context(ctx)
        help_analyzer.display_context_help(context, verbose)


def _search_help(query: str):
    """Search all help topics"""
    results = help_analyzer.search_help(query)

    if not results:
        console.print(f"[yellow]No results found for:[/yellow] {query}")
        console.print(
            "\n[dim]Try different keywords or use 'img help' to browse commands[/dim]"
        )
        return

    console.print(f"\n[bold cyan]Search Results for '{query}':[/bold cyan]\n")

    for i, result in enumerate(results, 1):
        command = result["command"]
        topic = result["topic"]
        score = result["score"]

        # Display result
        console.print(f"[bold]{i}. {command}[/bold] [dim](relevance: {score})[/dim]")
        console.print(f"   {topic.get('brief', '')}")

        # Show matching example if any
        for example in topic.get("examples", []):
            if query.lower() in example.lower():
                console.print(f"   [green]Example:[/green] {example}")
                break

        console.print()

    console.print("[yellow]💡 Tip:[/yellow] Use 'img help COMMAND' for detailed help")


def _show_command_help(
    command: str, verbose: bool, examples_only: bool, errors_only: bool
):
    """Show help for a specific command"""
    # Resolve alias
    resolved = help_analyzer._resolve_alias(command)

    if resolved not in help_analyzer.help_topics:
        # Try fuzzy search
        suggestions = help_analyzer._get_command_suggestions(command)
        if suggestions:
            console.print(f"[red]Command '{command}' not found[/red]\n")
            console.print("[yellow]Did you mean:[/yellow]")
            for suggestion in suggestions:
                console.print(f"  • {suggestion}")
        else:
            console.print(f"[red]Command '{command}' not found[/red]")
            console.print("[yellow]Use 'img help' to see available commands[/yellow]")
        return

    topic = help_analyzer.help_topics[resolved]

    if examples_only:
        # Show only examples
        console.print(f"\n[bold cyan]Examples for '{resolved}':[/bold cyan]\n")
        for example in topic.get("examples", []):
            console.print(f"  [green]$[/green] {example}")
        return

    if errors_only:
        # Show only errors
        errors = topic.get("common_errors", {})
        if errors:
            console.print(f"\n[bold cyan]Common Errors for '{resolved}':[/bold cyan]\n")
            table = Table(box=None)
            table.add_column("Error Code", style="red")
            table.add_column("Solution")

            for code, solution in errors.items():
                table.add_row(code, solution)

            console.print(table)
        else:
            console.print(
                f"[yellow]No common errors documented for '{resolved}'[/yellow]"
            )
        return

    # Full help display
    title = f"{resolved} - {topic.get('brief', '')}"

    # Build help content sections
    sections = []

    # Description
    sections.append(
        f"[bold yellow]Description:[/bold yellow]\n{topic.get('description', '')}"
    )

    # Usage (if available)
    if "usage" in topic:
        sections.append(f"[bold yellow]Usage:[/bold yellow]\n{topic['usage']}")

    # Examples
    if topic.get("examples"):
        examples_text = "[bold yellow]Examples:[/bold yellow]\n"
        example_limit = None if verbose else 3
        for example in topic["examples"][:example_limit]:
            examples_text += f"  [green]$[/green] {example}\n"
        if not verbose and len(topic["examples"]) > 3:
            examples_text += f"\n  [dim]... and {len(topic['examples']) - 3} more examples. Use --verbose to see all.[/dim]"
        sections.append(examples_text.rstrip())

    # Common Errors
    if topic.get("common_errors"):
        errors_text = "[bold yellow]Common Errors:[/bold yellow]\n"
        for code, solution in list(topic["common_errors"].items())[
            : None if verbose else 2
        ]:
            errors_text += f"  [red]{code}:[/red] {solution}\n"
        if not verbose and len(topic["common_errors"]) > 2:
            errors_text += f"\n  [dim]... and {len(topic['common_errors']) - 2} more. Use --verbose to see all.[/dim]"
        sections.append(errors_text.rstrip())

    # Related Commands
    if topic.get("related"):
        related = ", ".join([f"[cyan]{r}[/cyan]" for r in topic["related"]])
        sections.append(f"[bold yellow]Related Commands:[/bold yellow] {related}")

    # Options (if verbose)
    if verbose and "options" in topic:
        sections.append(f"[bold yellow]Options:[/bold yellow]\n{topic['options']}")

    # Tips (if verbose)
    if verbose and "tips" in topic:
        tips_text = "[bold yellow]Tips:[/bold yellow]\n"
        for tip in topic["tips"]:
            tips_text += f"  💡 {tip}\n"
        sections.append(tips_text.rstrip())

    # Create panel
    panel = Panel(
        "\n\n".join(sections),
        title=f"[bold cyan]{title}[/bold cyan]",
        border_style="cyan",
        padding=(1, 2),
    )
    console.print(panel)

    # Footer hints
    if not verbose:
        console.print(
            "\n[dim]Use --verbose for more details, --examples for examples only[/dim]"
        )


def _show_all_errors():
    """Show all documented error codes"""
    console.print("\n[bold cyan]All Documented Error Codes:[/bold cyan]\n")

    table = Table(title="Error Reference", box=None)
    table.add_column("Command", style="cyan")
    table.add_column("Error Code", style="red")
    table.add_column("Description")

    for command, topic in sorted(help_analyzer.help_topics.items()):
        errors = topic.get("common_errors", {})
        for code, description in errors.items():
            table.add_row(command, code, description)

    console.print(table)
    console.print(
        "\n[yellow]💡 Tip:[/yellow] Use 'img help COMMAND --errors' for command-specific errors"
    )


# Export app for main CLI
__all__ = ["app"]
