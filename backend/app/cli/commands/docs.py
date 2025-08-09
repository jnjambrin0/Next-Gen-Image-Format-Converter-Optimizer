"""
Documentation Browser Command
Browse and search offline documentation
"""

import asyncio
from typing import Annotated, Any, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from app.cli.documentation.ascii_demos import AsciiDemoPlayer, DemoSpeed
from app.cli.documentation.doc_browser import DocumentationBrowser
from app.cli.documentation.examples import ExampleCategory, ExampleDatabase
from app.cli.documentation.knowledge_base import KnowledgeBase, QuestionCategory
from app.cli.documentation.man_generator import ManPageGenerator
from app.cli.documentation.reference_cards import ReferenceCardGenerator
from app.cli.ui.themes import get_theme_manager

# Initialize theme manager and console
theme_manager = get_theme_manager()
console = Console(theme=theme_manager.get_theme())

# Create docs command app
app = typer.Typer(
    name="docs",
    help="📖 Browse documentation, examples, and knowledge base",
    no_args_is_help=False,
    rich_markup_mode="rich",
)

# Initialize documentation components
doc_browser = DocumentationBrowser(console)
example_db = ExampleDatabase(console)
knowledge_base = KnowledgeBase(console)
reference_cards = ReferenceCardGenerator(console)
demo_player = AsciiDemoPlayer(console)
man_generator = ManPageGenerator(console)


@app.callback(invoke_without_command=True)
def docs_command(
    ctx: typer.Context,
    section: Annotated[
        Optional[str], typer.Argument(help="Documentation section to view")
    ] = None,
    browse: Annotated[
        bool, typer.Option("--browse", "-b", help="Start interactive browser")
    ] = False,
    examples: Annotated[
        bool, typer.Option("--examples", "-e", help="Browse command examples")
    ] = False,
    qa: Annotated[
        bool, typer.Option("--qa", "-q", help="Search Q&A knowledge base")
    ] = False,
    reference: Annotated[
        Optional[str],
        typer.Option(
            "--reference", "-r", help="Generate reference card (basic/advanced/presets)"
        ),
    ] = None,
    demo: Annotated[
        Optional[str], typer.Option("--demo", "-d", help="Play ASCII demo")
    ] = None,
    man: Annotated[
        Optional[str], typer.Option("--man", "-m", help="Generate man page for command")
    ] = None,
    search: Annotated[
        Optional[str], typer.Option("--search", "-s", help="Search all documentation")
    ] = None,
):
    """
    Browse comprehensive offline documentation.

    [bold green]Features:[/bold green]
    • Interactive documentation browser
    • Command examples with safe execution
    • Q&A knowledge base with troubleshooting
    • Quick reference cards (PDF/Markdown)
    • ASCII demos for visual learning
    • Man page generation
    • Full-text search across all docs

    [bold yellow]Examples:[/bold yellow]

    Browse documentation interactively:
      [cyan]img docs --browse[/cyan]

    Search for specific topic:
      [cyan]img docs --search "batch processing"[/cyan]

    View command examples:
      [cyan]img docs --examples[/cyan]

    Generate reference card:
      [cyan]img docs --reference basic[/cyan]

    Play demo:
      [cyan]img docs --demo optimization[/cyan]
    """

    if browse or (
        not any([examples, qa, reference, demo, man, search]) and not section
    ):
        # Start interactive browser
        doc_browser.browse(section if section else "root")

    elif examples:
        _browse_examples()

    elif qa:
        _browse_knowledge_base()

    elif reference:
        _generate_reference(reference)

    elif demo:
        asyncio.run(_play_demo(demo))

    elif man:
        _generate_man_page(man)

    elif search:
        _search_documentation(search)

    elif section:
        # Display specific section
        _view_section(section)
    else:
        # Show documentation overview
        _show_overview()


def _show_overview() -> None:
    """Show documentation overview"""
    panel = Panel(
        """
[bold]Documentation Center[/bold]

Available resources:

[cyan]📚 Documentation Browser[/cyan]
  Interactive navigation through all documentation
  Use: img docs --browse

[cyan]💡 Command Examples[/cyan]
  Runnable examples for every command
  Use: img docs --examples

[cyan]❓ Q&A Knowledge Base[/cyan]
  Troubleshooting and common questions
  Use: img docs --qa

[cyan]📋 Reference Cards[/cyan]
  Quick reference in PDF/Markdown
  Use: img docs --reference basic

[cyan]🎬 ASCII Demos[/cyan]
  Visual demonstrations of features
  Use: img docs --demo basic_conversion

[cyan]📖 Man Pages[/cyan]
  Generate system man pages
  Use: img docs --man img
        """.strip(),
        title="[bold cyan]📖 Documentation Center[/bold cyan]",
        border_style="cyan",
        padding=(1, 2),
    )
    console.print(panel)

    # Show quick stats
    console.print("\n[bold]Documentation Stats:[/bold]")
    console.print(f"  • Sections: {len(doc_browser.sections)}")
    console.print(f"  • Examples: {len(example_db.examples)}")
    console.print(f"  • Q&A Entries: {len(knowledge_base.search('', limit=1000))}")
    console.print(f"  • Demos: {len(demo_player.demos)}")

    console.print(
        "\n[yellow]💡 Tip:[/yellow] Use 'img docs --browse' for interactive mode"
    )


def _view_section(section_id: str) -> None:
    """View specific documentation section"""
    section = doc_browser.sections.get(section_id)

    if not section:
        # Try to find by title
        for sid, sec in doc_browser.sections.items():
            if sec.title.lower() == section_id.lower():
                section = sec
                break

    if section:
        doc_browser.display_section(section)
    else:
        console.print(f"[red]Section not found:[/red] {section_id}")
        console.print(
            "[yellow]Use 'img docs --browse' to explore available sections[/yellow]"
        )


def _browse_examples() -> None:
    """Browse command examples"""
    console.print("\n[bold cyan]Command Examples[/bold cyan]\n")

    # Show categories
    categories = list(ExampleCategory)
    console.print("[bold]Categories:[/bold]")
    for i, cat in enumerate(categories, 1):
        examples = example_db.get_by_category(cat)
        console.print(f"  {i}. {cat.value.title()} ({len(examples)} examples)")

    # Get selection
    choice = Prompt.ask(
        "\n[cyan]Select category (number) or 'search' to search[/cyan]", default="1"
    )

    if choice.lower() == "search":
        query = Prompt.ask("[cyan]Search for[/cyan]")
        examples = example_db.search(query)
    else:
        try:
            index = int(choice) - 1
            if 0 <= index < len(categories):
                examples = example_db.get_by_category(categories[index])
            else:
                examples = []
        except ValueError:
            examples = []

    if not examples:
        console.print("[yellow]No examples found[/yellow]")
        return

    # Display examples
    for i, example in enumerate(examples, 1):
        console.print(f"\n[bold]{i}. {example.description}[/bold]")
        example_db.display_example(example, show_variations=True)

        # Ask for action
        action = Prompt.ask(
            "\n[cyan]Action[/cyan]",
            choices=["next", "copy", "run", "quit"],
            default="next",
        )

        if action == "copy":
            example_db.copy_to_clipboard(example)
        elif action == "run":
            asyncio.run(example_db.run_example(example, dry_run=True))
        elif action == "quit":
            break


def _browse_knowledge_base() -> None:
    """Browse Q&A knowledge base"""
    console.print("\n[bold cyan]Q&A Knowledge Base[/bold cyan]\n")

    # Show options
    console.print("[bold]Options:[/bold]")
    console.print("  1. Search Q&A")
    console.print("  2. Browse by category")
    console.print("  3. Error code lookup")
    console.print("  4. Troubleshooting tree")

    choice = Prompt.ask(
        "\n[cyan]Select option[/cyan]", choices=["1", "2", "3", "4"], default="1"
    )

    if choice == "1":
        # Search
        query = Prompt.ask("[cyan]Search for[/cyan]")
        questions = knowledge_base.search(query)

    elif choice == "2":
        # Browse by category
        categories = list(QuestionCategory)
        console.print("\n[bold]Categories:[/bold]")
        for i, cat in enumerate(categories, 1):
            console.print(f"  {i}. {cat.value.title()}")

        cat_choice = Prompt.ask("[cyan]Select category[/cyan]", default="1")
        try:
            index = int(cat_choice) - 1
            if 0 <= index < len(categories):
                questions = knowledge_base.get_by_category(categories[index])
            else:
                questions = []
        except ValueError:
            questions = []

    elif choice == "3":
        # Error code lookup
        error_code = Prompt.ask("[cyan]Enter error code[/cyan]")
        question = knowledge_base.get_by_error_code(error_code.upper())
        if question:
            questions = [question]
        else:
            console.print(f"[yellow]No Q&A found for error code: {error_code}[/yellow]")
            questions = []

    else:
        # Troubleshooting tree
        tree = knowledge_base.get_troubleshooting_tree()
        console.print("\n[bold]Troubleshooting Decision Tree:[/bold]\n")
        for category, items in tree.items():
            console.print(f"[cyan]{category}:[/cyan]")
            for item in items:
                console.print(f"  • {item}")
        return

    # Display questions
    for question in questions:
        knowledge_base.display_question(question)

        if not Confirm.ask("\n[cyan]Continue?[/cyan]", default=True):
            break


def _generate_reference(card_type: str) -> None:
    """Generate reference card"""
    try:
        # Display in console
        reference_cards.display_card(card_type)

        # Ask for export
        if Confirm.ask("\n[cyan]Export reference card?[/cyan]", default=False):
            format_choice = Prompt.ask(
                "[cyan]Format[/cyan]",
                choices=["markdown", "pdf", "text"],
                default="markdown",
            )

            if format_choice == "markdown":
                content = reference_cards.generate_markdown(card_type)
                path = reference_cards.output_dir / f"reference_{card_type}.md"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
                console.print(f"[green]✓[/green] Saved to {path}")

            elif format_choice == "pdf":
                path = reference_cards.generate_pdf(card_type)
                if path:
                    console.print(f"[green]✓[/green] Saved to {path}")

            else:
                content = reference_cards.generate_text(card_type)
                path = reference_cards.output_dir / f"reference_{card_type}.txt"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
                console.print(f"[green]✓[/green] Saved to {path}")

    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        console.print(
            "[yellow]Available cards: basic, advanced, presets, troubleshooting[/yellow]"
        )


async def _play_demo(demo_id: str):
    """Play ASCII demo"""
    if demo_id == "list":
        # List available demos
        demos = demo_player.list_demos()

        table = Table(title="Available Demos", box=None)
        table.add_column("ID", style="cyan")
        table.add_column("Title")
        table.add_column("Duration")
        table.add_column("Category")

        for demo in demos:
            table.add_row(demo["id"], demo["title"], demo["duration"], demo["category"])

        console.print(table)
    else:
        # Play demo
        speed = DemoSpeed.NORMAL
        if "/" in demo_id:
            demo_id, speed_str = demo_id.split("/")
            speed_map = {
                "slow": DemoSpeed.SLOW,
                "normal": DemoSpeed.NORMAL,
                "fast": DemoSpeed.FAST,
                "veryfast": DemoSpeed.VERY_FAST,
            }
            speed = speed_map.get(speed_str, DemoSpeed.NORMAL)

        await demo_player.play(demo_id, speed)


def _generate_man_page(command: str) -> None:
    """Generate man page"""
    try:
        content = man_generator.generate(command)

        # Display preview
        console.print(f"\n[bold cyan]Man Page Preview: {command}[/bold cyan]\n")
        console.print(content[:500] + "...\n")

        # Ask to install
        if Confirm.ask("[cyan]Install man page?[/cyan]", default=False):
            if man_generator.install(command):
                console.print(f"[green]✓[/green] Man page installed")
                console.print(f"[dim]View with: man {command}[/dim]")
            else:
                console.print("[yellow]Could not install to system location[/yellow]")

    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        console.print(
            "[yellow]Available: img, img-convert, img-batch, img-formats[/yellow]"
        )


def _search_documentation(query: str) -> None:
    """Search all documentation"""
    console.print(f"\n[bold cyan]Searching for: '{query}'[/bold cyan]\n")

    all_results = []

    # Search documentation sections
    doc_results = doc_browser.search(query)
    for section in doc_results[:3]:
        all_results.append(
            {
                "type": "Documentation",
                "title": section.title,
                "preview": section.content[:100],
                "action": lambda s=section: doc_browser.display_section(s),
            }
        )

    # Search examples
    example_results = example_db.search(query)
    for example in example_results[:3]:
        all_results.append(
            {
                "type": "Example",
                "title": example.description,
                "preview": example.command,
                "action": lambda e=example: example_db.display_example(e),
            }
        )

    # Search Q&A
    qa_results = knowledge_base.search(query, limit=3)
    for question in qa_results:
        all_results.append(
            {
                "type": "Q&A",
                "title": question.question,
                "preview": question.answer[:100],
                "action": lambda q=question: knowledge_base.display_question(q),
            }
        )

    if not all_results:
        console.print("[yellow]No results found[/yellow]")
        return

    # Display results
    for i, result in enumerate(all_results, 1):
        console.print(f"{i}. [{result['type']}] [cyan]{result['title']}[/cyan]")
        console.print(f"   [dim]{result['preview']}...[/dim]\n")

    # Select result
    choice = Prompt.ask(
        "[cyan]View result (number) or press Enter to cancel[/cyan]", default=""
    )

    if choice.isdigit():
        index = int(choice) - 1
        if 0 <= index < len(all_results):
            all_results[index]["action"]()


# Export app for main CLI
__all__ = ["app"]
