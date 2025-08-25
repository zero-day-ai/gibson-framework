#!/usr/bin/env python3
"""Gibson CLI main entry point with Typer framework."""

import sys
from pathlib import Path
from typing import Optional

import typer
from loguru import logger
from rich.console import Console

from gibson import __version__
from gibson.cli.commands import chain, config, console as console_cmd, credentials, database, llm, module, payloads, report, scan, schema, target
from gibson.core.config import ConfigManager
from gibson.core.context import Context
from gibson.utils.lazy_loader import LazyLoader

# Lazy load heavy dependencies
np = LazyLoader("numpy")
torch = LazyLoader("torch")
transformers = LazyLoader("transformers")

# Initialize Rich console
console = Console()

# Create main Typer app
app = typer.Typer(
    name="gibson",
    help="AI/ML Security Testing Framework - Developer-first CLI for comprehensive AI security testing",
    no_args_is_help=True,
    pretty_exceptions_enable=False,
    rich_markup_mode="rich",
    context_settings={"help_option_names": ["-h", "--help"]},
    add_completion=True,
)

# Add subcommands
app.add_typer(scan.app, name="scan", help="Security scanning operations")
app.add_typer(module.app, name="module", help="Module management")
app.add_typer(target.app, name="target", help="Target management")
app.add_typer(payloads.app, name="payloads", help="Payload registry management")
app.add_typer(chain.app, name="chain", help="Attack chain management")
app.add_typer(console_cmd.app, name="console", help="Interactive console mode")
app.add_typer(report.app, name="report", help="Report generation")
app.add_typer(config.app, name="config", help="Configuration management")
app.add_typer(credentials.app, name="credentials", help="API credential management")
app.add_typer(llm.app, name="llm", help="LLM provider management and configuration")
app.add_typer(schema.app, name="schema", help="Schema management and validation")
app.add_typer(database.app, name="database", help="Database migration and management")


def version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        console.print(f"Gibson CLI v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    ctx: typer.Context,
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        help="Show version and exit",
        callback=version_callback,
        is_eager=True,
    ),
    config_file: Optional[Path] = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to configuration file",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        help="Enable verbose output",
    ),
    debug: bool = typer.Option(
        False,
        "--debug",
        help="Enable debug mode",
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Suppress non-error output",
    ),
    no_color: bool = typer.Option(
        False,
        "--no-color",
        help="Disable colored output",
        envvar="NO_COLOR",
    ),
    output_format: Optional[str] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output format: json, yaml, csv, sarif, markdown",
        metavar="FORMAT",
    ),
) -> None:
    """
    Gibson CLI - AI/ML Security Testing Framework.
    
    A developer-first CLI for comprehensive AI security testing, combining
    cutting-edge attack techniques with an AI research assistant.
    
    Examples:
        # Quick scan of an API endpoint
        gibson scan quick https://api.example.com
        
        # Interactive console mode
        gibson console
        
        # Search for modules
        gibson module search prompt-injection
        
        # Run attack chain
        gibson chain run owasp-top-10
    """
    # Configure logging
    log_level = "DEBUG" if debug else "INFO" if verbose else "WARNING"
    if quiet:
        log_level = "ERROR"
    
    logger.remove()  # Remove default handler
    logger.add(
        sys.stderr,
        level=log_level,
        format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
        colorize=not no_color,
    )
    
    # Initialize global context
    config_manager = ConfigManager(config_file=config_file)
    context = Context(
        config=config_manager.config,
        console=console,
        verbose=verbose,
        debug=debug,
        quiet=quiet,
        no_color=no_color,
        output_format=output_format,
    )
    
    # Store context in Typer context
    ctx.obj = context
    
    logger.debug(f"Gibson CLI v{__version__} initialized")
    logger.debug(f"Config loaded from: {config_manager.config_file}")


def main() -> None:
    """Main entry point for the Gibson CLI."""
    app()


if __name__ == "__main__":
    main()