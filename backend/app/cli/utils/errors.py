"""
Error Handling Utilities
Smart error handling with suggestions
"""

from typing import Optional, List
from difflib import get_close_matches
from rich.console import Console
from rich.panel import Panel
from rich.text import Text


class ErrorHandler:
    """Handles errors with helpful suggestions"""

    def __init__(self):
        self.known_commands = [
            "convert",
            "batch",
            "optimize",
            "analyze",
            "formats",
            "presets",
            "config",
            "aliases",
            "plugins",
            "history",
        ]

        self.known_formats = [
            "jpeg",
            "jpg",
            "png",
            "webp",
            "avif",
            "heif",
            "heic",
            "bmp",
            "tiff",
            "gif",
            "jxl",
            "webp2",
        ]

    def suggest_command(self, incorrect: str) -> Optional[str]:
        """Suggest a similar command"""
        matches = get_close_matches(incorrect, self.known_commands, n=1, cutoff=0.6)
        return matches[0] if matches else None

    def suggest_format(self, incorrect: str) -> Optional[str]:
        """Suggest a similar format"""
        matches = get_close_matches(
            incorrect.lower(), self.known_formats, n=1, cutoff=0.6
        )
        return matches[0] if matches else None

    def handle(self, error: Exception, console: Console):
        """Handle an error with helpful output"""
        error_type = type(error).__name__
        error_msg = str(error)

        # Create error panel
        error_text = Text()
        error_text.append("Error: ", style="bold red")
        error_text.append(error_msg)

        # Add suggestions based on error type
        suggestions = []

        if "command not found" in error_msg.lower():
            # Try to extract the command and suggest alternatives
            words = error_msg.split()
            for word in words:
                suggestion = self.suggest_command(word)
                if suggestion:
                    suggestions.append(f"Did you mean: [cyan]{suggestion}[/cyan]?")

        elif (
            "invalid format" in error_msg.lower()
            or "unsupported format" in error_msg.lower()
        ):
            # Try to extract format and suggest alternatives
            words = error_msg.split()
            for word in words:
                suggestion = self.suggest_format(word)
                if suggestion:
                    suggestions.append(
                        f"Did you mean format: [cyan]{suggestion}[/cyan]?"
                    )

        elif "connection" in error_msg.lower() or "api" in error_msg.lower():
            suggestions.append(
                "Check if the API server is running: [cyan]cd backend && uvicorn app.main:app --port 8000[/cyan]"
            )
            suggestions.append("Verify API URL: [cyan]img config get api_url[/cyan]")

        elif "permission" in error_msg.lower():
            suggestions.append("Check file permissions and ownership")
            suggestions.append("Try running with appropriate permissions")

        elif "not found" in error_msg.lower():
            suggestions.append("Check if the file or directory exists")
            suggestions.append("Verify the path is correct")

        # Build panel content
        panel_content = error_text

        if suggestions:
            panel_content.append("\n\n")
            panel_content.append("Suggestions:", style="bold yellow")
            for suggestion in suggestions:
                panel_content.append(f"\n  • {suggestion}")

        # Add generic help
        panel_content.append("\n\n")
        panel_content.append("For more help: [dim]img --help[/dim]")

        # Display error panel
        console.print(
            Panel(
                panel_content,
                title=f"[bold red]{error_type}[/bold red]",
                border_style="red",
                padding=(1, 2),
            )
        )


def handle_api_error(error: Exception, console: Console):
    """Handle API-specific errors"""
    if hasattr(error, "response"):
        # HTTP error with response
        status = getattr(error.response, "status_code", "Unknown")

        if status == 404:
            console.print(
                "[red]Error: API endpoint not found. Is the server running?[/red]"
            )
            console.print(
                "[dim]Start server: cd backend && uvicorn app.main:app --port 8000[/dim]"
            )
        elif status == 401:
            console.print(
                "[red]Error: Authentication failed. Check your API key.[/red]"
            )
            console.print("[dim]Set API key: img config set api_key YOUR_KEY[/dim]")
        elif status == 413:
            console.print("[red]Error: File too large for conversion.[/red]")
        elif status == 415:
            console.print("[red]Error: Unsupported file type.[/red]")
        elif status == 429:
            console.print(
                "[red]Error: Rate limit exceeded. Please wait before retrying.[/red]"
            )
        elif status == 500:
            console.print("[red]Error: Server error during conversion.[/red]")
        else:
            console.print(f"[red]Error: API returned status {status}[/red]")
    else:
        # Generic error
        console.print(f"[red]Error: {str(error)}[/red]")

        if "connection" in str(error).lower():
            console.print(
                "[dim]Is the API server running? Check with: img config get api_url[/dim]"
            )
