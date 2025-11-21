"""Command-line interface for webmaster-domain-tool.

This is the main CLI entry point using the modular analyzer system.
All analyzers are auto-discovered via the registry.
"""

import inspect
import logging
import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Annotated

if TYPE_CHECKING:
    from .renderers.base import BaseRenderer

import rich.panel
import typer
from rich import box
from rich.console import Console

# Remove borders from CLI help output by monkey-patching Panel
_original_panel_init = rich.panel.Panel.__init__


def _no_border_panel_init(self, *args, **kwargs) -> None:
    kwargs["box"] = box.HORIZONTALS
    return _original_panel_init(self, *args, **kwargs)


rich.panel.Panel.__init__ = _no_border_panel_init

# Import modular system components
# Import analyzers package which auto-imports all analyzer modules
from . import analyzers  # noqa: F401, E402  # Triggers analyzer registration
from .analyzers.protocol import VerbosityLevel  # noqa: E402
from .core.config_manager import ConfigManager  # noqa: E402
from .core.registry import registry  # noqa: E402
from .renderers import BulkJSONLinesRenderer, CLIRenderer, JSONRenderer  # noqa: E402
from .utils.debug_stats import get_stats_tracker  # noqa: E402

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
# Helper Functions
# ============================================================================


def _analyze_single_domain(
    domain: str,
    execution_order: list[str],
    config_manager: ConfigManager,
    renderer: "BaseRenderer",
) -> None:
    """
    Analyze a single domain.

    Args:
        domain: Domain to analyze
        execution_order: List of analyzer IDs in execution order
        config_manager: Configuration manager
        renderer: Output renderer
    """
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

            # Run analysis - pass context if analyzer supports it
            analyze_signature = inspect.signature(analyzer.analyze)
            if "context" in analyze_signature.parameters:
                result = analyzer.analyze(domain, config, context=analysis_context)
            else:
                result = analyzer.analyze(domain, config)

            # Store in context for dependent analyzers
            analysis_context[analyzer_id] = result

            # Describe output
            descriptor = analyzer.describe_output(result)

            # Render
            renderer.render(descriptor, result, analyzer_id)

        except Exception as e:
            logger.error(f"Analyzer '{analyzer_id}' failed: {e}", exc_info=True)
            # Don't print error in bulk mode - just log it
            if not hasattr(renderer, "set_current_domain"):
                console.print(f"[red]✗ Analyzer '{analyzer_id}' failed: {e}[/red]")


def _process_bulk_domains(
    domain_file: str,
    execution_order: list[str],
    config_manager: ConfigManager,
    renderer: "BaseRenderer",
) -> None:
    """
    Process multiple domains from file or stdin.

    Args:
        domain_file: Path to file or '-' for stdin
        execution_order: List of analyzer IDs in execution order
        config_manager: Configuration manager
        renderer: Output renderer
    """
    # Read domains
    try:
        if domain_file == "-":
            domains = [line.strip() for line in sys.stdin if line.strip()]
        else:
            with open(domain_file) as f:
                domains = [line.strip() for line in f if line.strip()]
    except Exception as e:
        console.print(f"[red]Error reading domain file: {e}[/red]")
        raise typer.Exit(1)

    if not domains:
        console.print("[yellow]No domains found in input[/yellow]")
        raise typer.Exit(0)

    # Process each domain
    for domain_line in domains:
        # Validate domain
        try:
            domain = validate_domain(domain_line)
        except typer.BadParameter as e:
            logger.warning(f"Skipping invalid domain: {domain_line} - {e}")
            continue

        # Set current domain (for bulk renderer)
        if hasattr(renderer, "set_current_domain"):
            renderer.set_current_domain(domain)

        # Analyze domain
        _analyze_single_domain(domain, execution_order, config_manager, renderer)

        # Render summary for this domain
        renderer.render_summary()


# ============================================================================
# CLI Commands
# ============================================================================


@app.command()
def analyze(
    domain: Annotated[
        str | None,
        typer.Argument(
            help="Domain to analyze (e.g., example.com). Optional if --domain-file is used.",
        ),
    ] = None,
    domain_file: Annotated[
        str | None,
        typer.Option(
            "--domain-file",
            help="File with list of domains (one per line). Use '-' for stdin.",
        ),
    ] = None,
    skip: Annotated[
        list[str] | None,
        typer.Option(help="Analyzers to skip (e.g., --skip dns --skip whois)"),
    ] = None,
    only: Annotated[
        str | None,
        typer.Option(
            help="Run only these analyzers (e.g., --only html or --only html,dns,ssl). Cannot be used with --skip."
        ),
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
            help="Output format: cli, json, jsonlines",
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
    Analyze a domain or multiple domains from a file.

    Runs all enabled analyzers on the specified domain(s). Use --skip to disable
    specific analyzers, or --only to run just specific analyzers.

    Single domain analysis:
        wdt analyze example.com
        wdt analyze example.com --skip dns --skip whois
        wdt analyze example.com --only html
        wdt analyze example.com --verbosity verbose --format json

    Bulk domain analysis:
        wdt analyze --domain-file domains.txt --format jsonlines
        cat domains.txt | wdt analyze --domain-file - --format jsonlines
        wdt analyze --domain-file domains.txt --config custom.toml
    """
    # Validate domain or domain_file is provided
    if not domain and not domain_file:
        console.print("[red]Error: Either DOMAIN or --domain-file must be provided[/red]")
        raise typer.Exit(1)

    if domain and domain_file:
        console.print("[red]Error: Cannot use both DOMAIN and --domain-file together[/red]")
        console.print("Use either a single domain or --domain-file for bulk analysis")
        raise typer.Exit(1)

    # Validate --only and --skip are mutually exclusive
    if only and skip:
        console.print("[red]Error: Cannot use --only and --skip together[/red]")
        console.print("Use either --only to run one analyzer, or --skip to exclude specific ones")
        raise typer.Exit(1)

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

    # Enable debug statistics tracking if in debug mode
    stats_tracker = get_stats_tracker()
    if verbosity == "debug":
        stats_tracker.enable()
        stats_tracker.reset()
        logger.debug("Debug statistics tracking enabled")

    # Handle --only option
    if only:
        # Parse comma-separated list
        only_list = [a.strip() for a in only.split(",") if a.strip()]

        # Validate all analyzers exist
        all_analyzer_ids = registry.get_all_ids()
        unknown = [a for a in only_list if a not in all_analyzer_ids]
        if unknown:
            console.print(f"[red]Error: Unknown analyzer(s): {', '.join(unknown)}[/red]")
            console.print(f"\nAvailable analyzers: {', '.join(sorted(all_analyzer_ids))}")
            raise typer.Exit(1)

        # Set skip to all analyzers except the ones specified
        skip_set = set(all_analyzer_ids) - set(only_list)
    else:
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
    elif output_format == "jsonlines":
        renderer = BulkJSONLinesRenderer(verbosity=verbosity_level)
    else:
        console.print(f"[red]Error: Unknown output format: {output_format}[/red]")
        console.print("Available formats: cli, json, jsonlines")
        raise typer.Exit(1)

    # Branch: Bulk processing or single domain
    if domain_file:
        # Bulk domain processing
        _process_bulk_domains(domain_file, execution_order, config_manager, renderer)
    else:
        # Single domain processing
        # Validate domain (should not be None at this point)
        assert domain is not None
        domain = validate_domain(domain)

        # Display header (CLI only)
        if output_format == "cli" and verbosity != "quiet":
            console.print(f"[bold blue]Analyzing domain: {domain}[/bold blue]")
            console.print(f"[dim]Running {len(execution_order)} analyzer(s)[/dim]")

        # Analyze domain
        _analyze_single_domain(domain, execution_order, config_manager, renderer)

        # Render summary
        renderer.render_summary()

    # Print debug statistics if in debug mode
    if verbosity == "debug" and stats_tracker.is_enabled():
        # Print to stderr (where logging goes) so it doesn't interfere with JSON output
        sys.stderr.write(stats_tracker.get_summary() + "\n")

    # Exit code based on errors
    if hasattr(renderer, "all_errors") and renderer.all_errors:
        raise typer.Exit(1)


@app.command()
def list_analyzers() -> None:
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
def version() -> None:
    """Show version information."""
    try:
        import importlib.metadata

        version = importlib.metadata.version("webmaster-domain-tool")
        console.print(f"webmaster-domain-tool version {version}")
    except Exception:
        console.print("webmaster-domain-tool (version unknown)")


@app.command()
def create_validator_profile(
    output: Annotated[
        str,
        typer.Option("--output", "-o", help="Output config file path"),
    ] = "~/.webmaster-domain-tool.toml",
) -> None:
    """
    Interactive wizard to create a domain validation profile.

    Creates a profile with step-by-step guidance.

    Example:
        wdt create-validator-profile
        wdt create-validator-profile --output ./my-config.toml
    """
    import tomli
    import tomli_w

    console.print("[bold blue]Domain Validator Profile Wizard[/bold blue]\n")

    # Step 1: Profile ID
    console.print("[cyan]Step 1: Profile Identity[/cyan]")
    profile_id = typer.prompt("Profile ID (e.g., my-server, cloudflare-prod)", default="my-server")
    profile_name = typer.prompt("Profile name (human-readable)", default="My Server")
    description = typer.prompt("Description (optional)", default="", show_default=False)

    # Step 2: Infrastructure type
    console.print("\n[cyan]Step 2: Infrastructure Type[/cyan]")
    console.print("1. Direct hosting (static IP addresses)")
    console.print("2. CDN-based (Cloudflare, Fastly, etc.)")
    console.print("3. Email-only validation (no web validation)")
    infra_type = typer.prompt("Choose type", type=int, default=1)

    profile: dict = {
        "name": profile_name,
    }
    if description:
        profile["description"] = description

    # Step 3: Based on type, ask relevant questions
    if infra_type == 1:
        # Direct hosting
        console.print("\n[cyan]Step 3: Server Configuration[/cyan]")
        ipv4 = typer.prompt("IPv4 address(es) (comma-separated)", default="")
        if ipv4:
            profile["expected_ips"] = [ip.strip() for ip in ipv4.split(",")]

        ipv6 = typer.prompt(
            "IPv6 address(es) (optional, comma-separated)", default="", show_default=False
        )
        if ipv6:
            profile["expected_ipv6"] = [ip.strip() for ip in ipv6.split(",")]

        match_mode = typer.prompt(
            "IP match mode (any=at least one matches, all=all must match)", default="any"
        )
        profile["ip_match_mode"] = match_mode

    elif infra_type == 2:
        # CDN
        console.print("\n[cyan]Step 3: CDN Configuration[/cyan]")
        console.print("Common CDN providers: cloudflare, fastly, akamai, cloudfront")
        cdn = typer.prompt("Expected CDN provider", default="cloudflare")
        profile["expected_cdn"] = cdn

    # Step 4: Verification file (optional)
    console.print("\n[cyan]Step 4: Verification File (Optional)[/cyan]")
    add_verification = typer.confirm("Add verification file check?", default=False)
    if add_verification:
        verify_path = typer.prompt(
            "Verification file path", default="/.well-known/verification.txt"
        )
        profile["verification_path"] = verify_path

        verify_content = typer.prompt("Expected content (optional)", default="", show_default=False)
        if verify_content:
            profile["verification_content"] = verify_content

    # Step 5: Email security (optional)
    if infra_type != 3:
        console.print("\n[cyan]Step 5: Email Security (Optional)[/cyan]")
        add_email = typer.confirm("Add email security validation?", default=False)
    else:
        add_email = True

    if add_email:
        spf = typer.prompt(
            "SPF includes (comma-separated, e.g., include:_spf.google.com)",
            default="",
            show_default=False,
        )
        if spf:
            profile["spf_includes"] = [s.strip() for s in spf.split(",")]

        dkim = typer.prompt(
            "DKIM selectors (comma-separated, e.g., default,google)", default="", show_default=False
        )
        if dkim:
            profile["dkim_selectors"] = [s.strip() for s in dkim.split(",")]

        dmarc = typer.prompt(
            "DMARC policy (none/quarantine/reject)", default="", show_default=False
        )
        if dmarc:
            profile["dmarc_policy"] = dmarc

    # Step 6: Save
    console.print("\n[cyan]Step 6: Saving Profile[/cyan]")

    # Build config structure
    config_data: dict = {
        "domain-validator": {
            "enabled": True,
            "active_profile": profile_id,
            "strict_mode": True,
            "hide_expected_values": True,
            "profiles": {profile_id: profile},
        }
    }

    # Expand ~ in output path
    output_path = Path(output).expanduser()

    # If file exists, merge; otherwise create new
    if output_path.exists():
        with open(output_path, "rb") as f:
            existing = tomli.load(f)

        # Merge profiles
        if "domain-validator" in existing:
            if "profiles" not in existing["domain-validator"]:
                existing["domain-validator"]["profiles"] = {}
            existing["domain-validator"]["profiles"][profile_id] = profile
            existing["domain-validator"]["active_profile"] = profile_id
        else:
            existing["domain-validator"] = config_data["domain-validator"]

        config_data = existing

    # Write config
    with open(output_path, "wb") as f:
        tomli_w.dump(config_data, f)

    console.print(f"\n[green]✓[/green] Profile '{profile_id}' created in {output_path}")
    console.print("\n[bold]Next steps:[/bold]")
    console.print(f"1. Review the profile: cat {output_path}")
    console.print("2. Test it: wdt analyze example.com")
    console.print(f"3. Edit if needed: wdt config  (or manually edit {output_path})")


@app.command()
def test_validator_profile(
    domain: Annotated[str, typer.Argument(help="Domain to test against")],
    profile: Annotated[str, typer.Option("--profile", "-p", help="Profile ID to test")],
    config_file: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Config file path"),
    ] = None,
) -> None:
    """
    Test a validation profile without activating it.

    This runs validation checks without setting the profile as active,
    allowing you to test configurations before deployment.

    Example:
        wdt test-validator-profile example.com --profile my-server
        wdt test-validator-profile example.com -p prod-config -c ./test.toml
    """
    console.print(f"[bold blue]Testing profile '{profile}' against {domain}[/bold blue]\n")

    # Validate domain
    domain = validate_domain(domain)

    # Load config
    config_manager = ConfigManager()
    try:
        if config_file:
            config_manager.load_from_files(extra_paths=[config_file])
        else:
            config_manager.load_from_files()
    except Exception as e:
        console.print(f"[red]Error loading config: {e}[/red]")
        raise typer.Exit(1)

    # Get validator config
    validator_config = config_manager.get_analyzer_config("domain-validator")

    # Check profile exists
    if profile not in validator_config.profiles:
        console.print(f"[red]Error: Profile '{profile}' not found[/red]")
        console.print(f"\nAvailable profiles: {', '.join(validator_config.profiles.keys())}")
        raise typer.Exit(1)

    # Temporarily set active profile
    original_active = validator_config.active_profile
    validator_config.active_profile = profile

    # Run dependencies first
    console.print("[dim]Running dependency analyzers...[/dim]")

    context: dict[str, object] = {}

    # Run DNS
    try:
        from .analyzers.dns_analyzer import DNSAnalyzer

        dns_analyzer = DNSAnalyzer()
        dns_config = config_manager.get_analyzer_config("dns")
        dns_result = dns_analyzer.analyze(domain, dns_config)
        context["dns"] = dns_result
        console.print("  [green]✓[/green] DNS analysis complete")
    except Exception as e:
        console.print(f"  [red]✗[/red] DNS analysis failed: {e}")

    # Run HTTP (if needed)
    profile_obj = validator_config.profiles[profile]
    if profile_obj.verification_path:
        try:
            from .analyzers.http_analyzer import HTTPAnalyzer

            http_analyzer = HTTPAnalyzer()
            http_config = config_manager.get_analyzer_config("http")
            http_result = http_analyzer.analyze(domain, http_config)
            context["http"] = http_result
            console.print("  [green]✓[/green] HTTP analysis complete")
        except Exception as e:
            console.print(f"  [red]✗[/red] HTTP analysis failed: {e}")

    # Run Email (if needed)
    if profile_obj.spf_includes or profile_obj.dkim_selectors or profile_obj.dmarc_policy:
        try:
            from .analyzers.email_security import EmailSecurityAnalyzer

            email_analyzer = EmailSecurityAnalyzer()
            email_config = config_manager.get_analyzer_config("email")
            email_result = email_analyzer.analyze(domain, email_config)
            context["email"] = email_result
            console.print("  [green]✓[/green] Email analysis complete")
        except Exception as e:
            console.print(f"  [red]✗[/red] Email analysis failed: {e}")

    # Run CDN (if needed)
    if profile_obj.expected_cdn:
        try:
            from .analyzers.cdn_detector import CDNDetector

            cdn_analyzer = CDNDetector()
            cdn_config = config_manager.get_analyzer_config("cdn")
            cdn_result = cdn_analyzer.analyze(domain, cdn_config, context=context)
            context["cdn"] = cdn_result
            console.print("  [green]✓[/green] CDN analysis complete")
        except Exception as e:
            console.print(f"  [red]✗[/red] CDN analysis failed: {e}")

    # Run validation
    console.print(f"\n[bold]Testing profile: {profile_obj.name}[/bold]")

    from .analyzers.domain_config_validator import DomainConfigValidator

    validator = DomainConfigValidator()
    result = validator.analyze(domain, validator_config, context)

    # Display results
    console.print("\n[bold]Results:[/bold]")

    if result.profile_active:
        passed = sum(1 for c in result.checks if c.passed)
        failed = sum(1 for c in result.checks if not c.passed)
        total = len(result.checks)

        console.print(f"Checks: {passed} passed, {failed} failed (total: {total})")

        # Show each check
        for check in result.checks:
            if check.passed:
                console.print(f"  [green]✓[/green] {check.check_name}")
            else:
                console.print(f"  [red]✗[/red] {check.check_name}")
                if check.details:
                    console.print(f"      {check.details}")

        # Overall
        if result.overall_passed:
            console.print("\n[green]✓ All checks passed![/green]")
        else:
            console.print(f"\n[red]✗ {failed} check(s) failed[/red]")
            console.print(
                f"\n[yellow]Tip:[/yellow] Run 'wdt analyze {domain} --verbosity verbose' for more details"
            )
    else:
        console.print("[yellow]Profile not active or validation skipped[/yellow]")

    # Restore original active profile
    validator_config.active_profile = original_active


# ============================================================================
# Entry Point
# ============================================================================


def main() -> None:
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
