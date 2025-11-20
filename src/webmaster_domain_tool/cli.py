"""Command-line interface for webmaster-domain-tool.

This is the main CLI entry point using the modular analyzer system.
All analyzers are auto-discovered via the registry.
"""

import logging
import re
import sys
from pathlib import Path
from typing import Annotated

import rich.panel
import typer
from rich import box
from rich.console import Console

# Remove borders from CLI help output by monkey-patching Panel
_original_panel_init = rich.panel.Panel.__init__


def _no_border_panel_init(self, *args, **kwargs):
    kwargs["box"] = box.HORIZONTALS
    return _original_panel_init(self, *args, **kwargs)


rich.panel.Panel.__init__ = _no_border_panel_init

# Import modular system components
# Import all analyzers so they register themselves
from .analyzers import dns_analyzer  # noqa: F401, E402
from .analyzers.protocol import VerbosityLevel  # noqa: E402
from .core.config_manager import ConfigManager  # noqa: E402
from .core.registry import registry  # noqa: E402
from .renderers import CLIRenderer, JSONRenderer  # noqa: E402

logger = logging.getLogger(__name__)

app = typer.Typer(
    name="webmaster-domain-tool",
    help="Comprehensive domain analysis tool for webmasters",
    add_completion=False,
    no_args_is_help=True,
)

console = Console()


# ============================================================================
# Validation Functions
# ============================================================================


def validate_domain(domain: str) -> str:
    """
    Validate domain name format.

    Args:
        domain: Domain to validate

    Returns:
        Validated domain

    Raises:
        typer.BadParameter: If domain format is invalid
    """
    # Remove protocol and trailing slash if present
    domain = domain.replace("http://", "").replace("https://", "").rstrip("/")

    # Basic domain validation regex
    domain_pattern = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )

    if not domain_pattern.match(domain):
        raise typer.BadParameter(f"Invalid domain format: {domain}. Expected format: example.com")

    return domain


def validate_verbosity(value: str) -> str:
    """
    Validate verbosity level.

    Args:
        value: Verbosity level string

    Returns:
        Validated verbosity level

    Raises:
        typer.BadParameter: If verbosity is invalid
    """
    valid_levels = ["quiet", "normal", "verbose", "debug"]
    if value.lower() not in valid_levels:
        raise typer.BadParameter(
            f"Invalid verbosity: {value}. Must be one of: {', '.join(valid_levels)}"
        )
    return value.lower()


# ============================================================================
# CLI Commands
# ============================================================================


@app.command()
def analyze(
    domain: Annotated[
        str,
        typer.Argument(
            help="Domain to analyze (e.g., example.com)",
            callback=validate_domain,
        ),
    ],
    skip: Annotated[
        list[str] | None,
        typer.Option(help="Analyzers to skip (e.g., --skip dns --skip whois)"),
    ] = None,
    verbosity: Annotated[
        str,
        typer.Option(
            "--verbosity",
            "-v",
            help="Output verbosity: quiet, normal, verbose, debug",
            callback=validate_verbosity,
        ),
    ] = "normal",
    output_format: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Output format: cli, json",
        ),
    ] = "cli",
    config_file: Annotated[
        Path | None,
        typer.Option(
            "--config",
            "-c",
            help="Path to configuration file",
            exists=True,
            dir_okay=False,
        ),
    ] = None,
):
    """
    Analyze a domain.

    Runs all enabled analyzers on the specified domain. Use --skip to disable
    specific analyzers.

    Example:
        wdt analyze example.com
        wdt analyze example.com --skip dns --skip whois
        wdt analyze example.com --verbosity verbose --format json
    """
    # Setup logging
    log_level = {
        "quiet": logging.ERROR,
        "normal": logging.WARNING,
        "verbose": logging.INFO,
        "debug": logging.DEBUG,
    }.get(verbosity, logging.INFO)

    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Validate skip analyzers
    skip_set = set(skip or [])
    if skip_set:
        valid, unknown = registry.validate_skip_list(list(skip_set))
        if not valid:
            console.print(f"[red]Error: Unknown analyzer(s): {', '.join(unknown)}[/red]")
            console.print(f"\nAvailable analyzers: {', '.join(registry.get_all_ids())}")
            raise typer.Exit(1)

    # Load configuration
    config_manager = ConfigManager()
    try:
        if config_file:
            config_manager.load_from_files(extra_paths=[config_file])
        else:
            config_manager.load_from_files()
    except Exception as e:
        logger.warning(f"Failed to load configuration: {e}")
        # Continue with defaults

    # Get enabled analyzers
    enabled_analyzers = [
        aid
        for aid in registry.get_all_ids()
        if aid not in skip_set and config_manager.get_analyzer_config(aid).enabled
    ]

    # Resolve dependencies
    try:
        execution_order = registry.resolve_dependencies(enabled_analyzers, skip_set)
    except ValueError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)

    if not execution_order:
        console.print("[yellow]No analyzers to run![/yellow]")
        raise typer.Exit(0)

    # Create renderer
    verbosity_level = VerbosityLevel[verbosity.upper()]

    if output_format == "cli":
        renderer = CLIRenderer(
            verbosity=verbosity_level,
            color=config_manager.global_config.color,
        )
    elif output_format == "json":
        renderer = JSONRenderer(verbosity=verbosity_level)
    else:
        console.print(f"[red]Error: Unknown output format: {output_format}[/red]")
        console.print("Available formats: cli, json")
        raise typer.Exit(1)

    # Display header (CLI only)
    if output_format == "cli" and verbosity != "quiet":
        console.print(f"[bold blue]Analyzing domain: {domain}[/bold blue]")
        console.print(f"[dim]Running {len(execution_order)} analyzer(s)[/dim]")

    # Execute analyzers
    results: dict[str, tuple[object, object]] = {}  # analyzer_id -> (descriptor, result)
    analysis_context: dict[str, object] = {}  # Shared data between analyzers

    for analyzer_id in execution_order:
        metadata = registry.get(analyzer_id)
        if not metadata:
            logger.error(f"Analyzer not found: {analyzer_id}")
            continue

        config = config_manager.get_analyzer_config(analyzer_id)

        try:
            # Instantiate analyzer
            analyzer = metadata.plugin_class()

            # Run analysis
            result = analyzer.analyze(domain, config)

            # Store in context for dependent analyzers
            analysis_context[analyzer_id] = result

            # Describe output
            descriptor = analyzer.describe_output(result)

            # Render
            renderer.render(descriptor, result, analyzer_id)

            # Store for summary
            results[analyzer_id] = (descriptor, result)

        except Exception as e:
            logger.error(f"Analyzer '{analyzer_id}' failed: {e}", exc_info=True)
            console.print(f"[red]✗ Analyzer '{analyzer_id}' failed: {e}[/red]")
            continue

    # Render summary
    renderer.render_summary()

    # Exit code based on errors
    if hasattr(renderer, "all_errors") and renderer.all_errors:
        raise typer.Exit(1)


@app.command()
def list_analyzers():
    """
    List all available analyzers.

    Shows analyzer ID, name, category, and dependencies.
    """
    console.print("[bold blue]Available Analyzers[/bold blue]\n")

    # Group by category
    by_category: dict[str, list] = {}
    for analyzer_id, metadata in registry.get_all().items():
        category = metadata.category
        if category not in by_category:
            by_category[category] = []
        by_category[category].append((analyzer_id, metadata))

    # Display by category
    for category in sorted(by_category.keys()):
        console.print(f"[cyan]{category.upper()}[/cyan]")
        for analyzer_id, metadata in sorted(by_category[category]):
            deps = f" (depends on: {', '.join(metadata.depends_on)})" if metadata.depends_on else ""
            console.print(f"  • {analyzer_id:15} - {metadata.name}{deps}")
        console.print()


@app.command()
def create_config(
    output: Annotated[
        Path,
        typer.Option(
            "--output",
            "-o",
            help="Output file path",
        ),
    ] = Path(".webmaster-domain-tool.toml"),
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            "-f",
            help="Overwrite existing file",
        ),
    ] = False,
):
    """
    Create a default configuration file.

    Generates a TOML configuration file with all analyzer settings.

    Example:
        wdt create-config
        wdt create-config --output ~/.config/webmaster-domain-tool/config.toml
    """
    if output.exists() and not force:
        console.print(f"[yellow]File already exists: {output}[/yellow]")
        console.print("Use --force to overwrite")
        raise typer.Exit(1)

    # Create config manager and generate defaults
    config_manager = ConfigManager()

    try:
        config_manager.create_default_config_file(output)
        console.print(f"[green]✓ Created configuration file: {output}[/green]")
    except Exception as e:
        console.print(f"[red]✗ Failed to create config: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def version():
    """Show version information."""
    try:
        import importlib.metadata

        version = importlib.metadata.version("webmaster-domain-tool")
        console.print(f"webmaster-domain-tool version {version}")
    except Exception:
        console.print("webmaster-domain-tool (version unknown)")


# ============================================================================
# Entry Point
# ============================================================================


def main():
    """Main entry point for CLI."""
    try:
        app()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        console.print(f"[red]Unexpected error: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
