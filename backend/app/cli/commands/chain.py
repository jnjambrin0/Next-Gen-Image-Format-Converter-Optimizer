"""
Chain Command
Command chaining and piping support
"""

import sys
import io
from pathlib import Path
from typing import List, Optional, Annotated
import asyncio

import typer
from rich.console import Console

from app.cli.config import get_config
from app.cli.utils.errors import handle_api_error

# Import SDK client
from app.cli.utils import setup_sdk_path

setup_sdk_path()
from image_converter.client import ImageConverterClient
from image_converter.models import ConversionRequest, OutputFormat as SDKOutputFormat

app = typer.Typer(no_args_is_help=True)
console = Console()


@app.command()
def chain(
    operations: Annotated[
        List[str],
        typer.Argument(
            help="Operations to chain (format:quality, resize:WxH, optimize, etc.)"
        ),
    ],
    input_file: Annotated[
        Optional[Path],
        typer.Option("-i", "--input", help="Input file (or read from stdin)"),
    ] = None,
    output_file: Annotated[
        Optional[Path],
        typer.Option("-o", "--output", help="Output file (or write to stdout)"),
    ] = None,
):
    """
    Chain multiple operations on an image

    Examples:
      img chain "format:webp" "resize:1920x1080" "optimize" -i photo.jpg -o result.webp
      cat image.png | img chain "format:jpeg" "quality:85" > output.jpg
      img chain "format:avif" "quality:90" "resize:800x" < input.png > output.avif
    """
    # Read input
    if input_file:
        with open(input_file, "rb") as f:
            image_data = f.read()
    else:
        # Read from stdin
        if sys.stdin.isatty():
            console.print("[red]Error: No input file specified and no stdin data[/red]")
            raise typer.Exit(1)
        image_data = sys.stdin.buffer.read()

    # Process operations
    config = get_config()
    client = ImageConverterClient(
        host=config.api_host,
        port=config.api_port,
        api_key=config.api_key,
        timeout=config.api_timeout,
    )

    # Parse operations
    output_format = None
    quality = None
    width = None
    height = None
    optimize_level = None

    for op in operations:
        if ":" in op:
            cmd, arg = op.split(":", 1)

            if cmd == "format":
                output_format = arg
            elif cmd == "quality":
                quality = int(arg)
            elif cmd == "resize":
                if "x" in arg:
                    w, h = arg.split("x")
                    width = int(w) if w else None
                    height = int(h) if h else None
            elif cmd == "optimize":
                optimize_level = 2
        else:
            # Single word operations
            if op == "optimize":
                optimize_level = 2

    # Apply operations
    if output_format:
        request = ConversionRequest(
            output_format=SDKOutputFormat(output_format.lower()),
            quality=quality,
            width=width,
            height=height,
            optimize_level=optimize_level,
        )

        result = client.convert_image(image_data=image_data, request=request)

        image_data = result.output_data

    # Write output
    if output_file:
        with open(output_file, "wb") as f:
            f.write(image_data)
        console.print(
            f"[green]✓[/green] Output saved to: [cyan]{output_file}[/cyan]",
            file=sys.stderr,
        )
    else:
        # Write to stdout
        sys.stdout.buffer.write(image_data)


@app.command()
def pipe(
    format: Annotated[str, typer.Option("-f", "--format", help="Output format")],
    quality: Annotated[
        Optional[int], typer.Option("-q", "--quality", help="Quality (1-100)")
    ] = None,
):
    """
    Process image from stdin to stdout (for Unix pipes)

    Examples:
      cat image.jpg | img pipe -f webp | another-command
      img convert file photo.png -f jpeg | img pipe -f avif > final.avif
    """
    # Check for stdin data
    if sys.stdin.isatty():
        console.print(
            "[red]Error: No input data. This command is for piping.[/red]",
            file=sys.stderr,
        )
        console.print(
            "[dim]Usage: cat image.jpg | img pipe -f webp > output.webp[/dim]",
            file=sys.stderr,
        )
        raise typer.Exit(1)

    # Read from stdin
    image_data = sys.stdin.buffer.read()

    # Process
    config = get_config()
    client = ImageConverterClient(
        host=config.api_host,
        port=config.api_port,
        api_key=config.api_key,
        timeout=config.api_timeout,
    )

    request = ConversionRequest(
        output_format=SDKOutputFormat(format.lower()),
        quality=quality or config.default_quality,
    )

    result = client.convert_image(image_data=image_data, request=request)

    # Write to stdout (binary mode)
    sys.stdout.buffer.write(result.output_data)


@app.callback()
def chain_callback():
    """Command chaining and piping"""
    pass
