"""Configuration management commands with domain-specific settings."""

from pathlib import Path
from typing import Any, Optional, Dict, List
import typer
from rich.console import Console
from rich.syntax import Syntax
from rich.table import Table
from rich.tree import Tree
import yaml
from loguru import logger

from gibson.core.context import Context
from gibson.core.config import ConfigManager
from gibson.core.modules.base import ModuleCategory
from gibson.core.llm.environment import EnvironmentManager

app = typer.Typer(help="Configuration management with domain settings")
console = Console()


@app.command()
def show(
    ctx: typer.Context,
    key: Optional[str] = typer.Argument(None, help="Configuration key to show"),
) -> None:
    """
    Show current configuration.

    Examples:
        gibson config show              # Show all config
        gibson config show api          # Show API config
        gibson config show api.timeout  # Show specific value
    """
    context: Context = ctx.obj

    if key:
        # Show specific key
        value = _get_nested_value(context.config.model_dump(), key.split("."))
        if value is not None:
            console.print(yaml.dump({key: value}, default_flow_style=False))
        else:
            console.print(f"[red]Key '{key}' not found[/red]")
    else:
        # Show all config
        config_yaml = yaml.dump(context.config.model_dump(), default_flow_style=False)
        syntax = Syntax(config_yaml, "yaml", theme="monokai")
        console.print(syntax)


@app.command()
def set(
    ctx: typer.Context,
    key: str = typer.Argument(help="Configuration key"),
    value: str = typer.Argument(help="Value to set"),
) -> None:
    """
    Set a configuration value.

    Examples:
        gibson config set api.timeout 60
        gibson config set output.format json
        gibson config set safety.dry_run true
    """
    context: Context = ctx.obj

    try:
        # Parse the value to appropriate type
        parsed_value = _parse_value(value)

        # Update the configuration
        config_dict = context.config.model_dump()
        _set_nested_value(config_dict, key.split("."), parsed_value)

        # Recreate config object
        from gibson.core.config import Config

        updated_config = Config(**config_dict)
        context.config = updated_config

        # Save to file
        config_manager = ConfigManager()
        config_manager.config = updated_config
        config_manager.save()

        console.print(f"[green]✓[/green] Set {key} = {value}")
        console.print(f"[dim]Configuration saved to ~/.config/gibson/config.yaml[/dim]")

    except Exception as e:
        console.print(f"[red]Failed to set configuration: {e}[/red]")


@app.command()
def edit(
    ctx: typer.Context,
    editor: Optional[str] = typer.Option(None, "--editor", "-e", help="Editor to use"),
) -> None:
    """Open configuration file in editor."""
    context: Context = ctx.obj
    import subprocess
    import os

    config_file = Path.home() / ".config" / "gibson" / "config.yaml"
    editor = editor or os.environ.get("EDITOR", "nano")

    subprocess.run([editor, str(config_file)])
    console.print("[green]✓[/green] Configuration updated")


@app.command()
def init(
    ctx: typer.Context,
    path: Optional[Path] = typer.Option(None, "--path", "-p", help="Config path"),
    with_domains: bool = typer.Option(
        True, "--domains/--no-domains", help="Include domain settings"
    ),
) -> None:
    """Initialize configuration file with domain settings."""
    context: Context = ctx.obj

    path = path or Path.cwd() / ".gibson" / "config.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)

    manager = ConfigManager()

    # Add domain-specific defaults if requested
    if with_domains:
        _initialize_domain_config(manager)

    manager.save(path)

    console.print(f"[green]✓[/green] Configuration initialized at: {path}")
    if with_domains:
        console.print("[dim]Domain settings included - use 'gibson config domains' to view[/dim]")


@app.command()
def domains(
    ctx: typer.Context,
    action: str = typer.Argument("list", help="Action: list, enable, disable, configure"),
    domain: Optional[str] = typer.Option(None, "--domain", "-d", help="Domain name"),
    format: str = typer.Option("table", "--format", "-f", help="Output format"),
) -> None:
    """
    Manage domain-specific configuration settings.

    Examples:
        gibson config domains list                    # List all domains
        gibson config domains enable --domain llm-prompt-injection
        gibson config domains configure --domain llm-model-theft
    """
    context: Context = ctx.obj

    if action == "list":
        _list_domain_config(context, format)
    elif action == "enable":
        if not domain:
            console.print("[red]Domain name required for enable action[/red]")
            raise typer.Exit(1)
        _enable_disable_domain(context, domain, True)
    elif action == "disable":
        if not domain:
            console.print("[red]Domain name required for disable action[/red]")
            raise typer.Exit(1)
        _enable_disable_domain(context, domain, False)
    elif action == "configure":
        if not domain:
            console.print("[red]Domain name required for configure action[/red]")
            raise typer.Exit(1)
        _configure_domain(context, domain)
    else:
        console.print(f"[red]Unknown action: {action}[/red]")
        console.print("[dim]Valid actions: list, enable, disable, configure[/dim]")
        raise typer.Exit(1)


@app.command()
def thresholds(
    ctx: typer.Context,
    action: str = typer.Argument("show", help="Action: show, set, reset"),
    domain: Optional[str] = typer.Option(None, "--domain", "-d", help="Domain name"),
    severity: Optional[str] = typer.Option(None, "--severity", "-s", help="Severity threshold"),
    confidence: Optional[int] = typer.Option(
        None, "--confidence", "-c", help="Confidence threshold"
    ),
) -> None:
    """
    Manage domain-specific security thresholds.

    Examples:
        gibson config thresholds show
        gibson config thresholds set --domain llm-prompt-injection --severity high
        gibson config thresholds set --domain llm-model-theft --confidence 80
    """
    context: Context = ctx.obj

    if action == "show":
        _show_thresholds(context, domain)
    elif action == "set":
        if not domain:
            console.print("[red]Domain name required for set action[/red]")
            raise typer.Exit(1)
        _set_threshold(context, domain, severity, confidence)
    elif action == "reset":
        _reset_thresholds(context, domain)
    else:
        console.print(f"[red]Unknown action: {action}[/red]")
        console.print("[dim]Valid actions: show, set, reset[/dim]")
        raise typer.Exit(1)


@app.command()
def modules(
    ctx: typer.Context,
    action: str = typer.Argument("show", help="Action: show, enable, disable"),
    module: Optional[str] = typer.Option(None, "--module", "-m", help="Module name"),
    domain: Optional[str] = typer.Option(None, "--domain", "-d", help="Domain filter"),
) -> None:
    """
    Manage module-specific configuration.

    Examples:
        gibson config modules show
        gibson config modules show --domain llm-prompt-injection
        gibson config modules enable --module prompt_injection
        gibson config modules disable --module model_theft
    """
    context: Context = ctx.obj

    if action == "show":
        _show_module_config(context, domain)
    elif action == "enable":
        if not module:
            console.print("[red]Module name required for enable action[/red]")
            raise typer.Exit(1)
        _enable_disable_module(context, module, True)
    elif action == "disable":
        if not module:
            console.print("[red]Module name required for disable action[/red]")
            raise typer.Exit(1)
        _enable_disable_module(context, module, False)
    else:
        console.print(f"[red]Unknown action: {action}[/red]")
        console.print("[dim]Valid actions: show, enable, disable[/dim]")
        raise typer.Exit(1)


@app.command()
def export(
    ctx: typer.Context,
    output: Path = typer.Option("gibson-config-export.yaml", "--output", "-o", help="Output file"),
    domain: Optional[str] = typer.Option(
        None, "--domain", "-d", help="Export specific domain only"
    ),
    include_secrets: bool = typer.Option(
        False, "--include-secrets", help="Include API keys and secrets"
    ),
) -> None:
    """Export configuration to file."""
    context: Context = ctx.obj

    try:
        config_dict = context.config.model_dump()

        # Filter by domain if specified
        if domain:
            domain_config = _extract_domain_config(config_dict, domain)
            if not domain_config:
                console.print(f"[red]No configuration found for domain: {domain}[/red]")
                raise typer.Exit(1)
            config_dict = {"domains": {domain: domain_config}}

        # Remove secrets unless explicitly requested
        if not include_secrets:
            config_dict = _remove_secrets(config_dict)

        # Write to file
        with open(output, "w") as f:
            yaml.dump(config_dict, f, default_flow_style=False, sort_keys=True)

        console.print(f"[green]✓[/green] Configuration exported to: {output}")

        if not include_secrets:
            console.print("[dim]Secrets excluded - use --include-secrets to include them[/dim]")

    except Exception as e:
        logger.error(f"Export failed: {e}")
        console.print(f"[red]Export failed:[/red] {e}")
        raise typer.Exit(1)


@app.command(name="import")
def import_config(
    ctx: typer.Context,
    config_file: Path = typer.Argument(help="Configuration file to import"),
    merge: bool = typer.Option(
        True, "--merge/--replace", help="Merge with existing config or replace"
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show changes without applying"),
) -> None:
    """Import configuration from file."""
    context: Context = ctx.obj

    if not config_file.exists():
        console.print(f"[red]Configuration file not found: {config_file}[/red]")
        raise typer.Exit(1)

    try:
        # Load import config
        with open(config_file, "r") as f:
            import_config = yaml.safe_load(f)

        if dry_run:
            _show_config_diff(context.config.model_dump(), import_config, merge)
            return

        # Apply configuration
        if merge:
            current_config = context.config.model_dump()
            merged_config = _merge_configs(current_config, import_config)
        else:
            merged_config = import_config

        # Update and save
        from gibson.core.config import Config

        updated_config = Config(**merged_config)
        context.config = updated_config

        config_manager = ConfigManager()
        config_manager.config = updated_config
        config_manager.save()

        console.print(f"[green]✓[/green] Configuration imported from: {config_file}")

    except Exception as e:
        logger.error(f"Import failed: {e}")
        console.print(f"[red]Import failed:[/red] {e}")
        raise typer.Exit(1)


@app.command()
def llm(
    ctx: typer.Context,
) -> None:
    """
    Show LLM provider configuration status.

    Examples:
        gibson config llm        # Check current LLM setup
    """
    context: Context = ctx.obj

    import asyncio

    async def run_llm_command():
        await _show_llm_status()

    try:
        asyncio.run(run_llm_command())
    except Exception as e:
        logger.error(f"LLM command failed: {e}")
        console.print(f"[red]Command failed:[/red] {e}")
        raise typer.Exit(1)


async def _show_llm_status() -> None:
    """Show current LLM provider status."""
    console.print("[bold cyan]LLM Provider Status[/bold cyan]\n")

    try:
        # Check current environment setup
        discovery = await discover_llm_providers()

        if discovery.has_any_provider:
            console.print(f"[green]Current Environment Setup:[/green]")
            console.print(f"  Configured providers: {discovery.configured_providers}")
            console.print(f"  Partially configured: {discovery.partially_configured}")
            console.print(f"  Configuration score: {discovery.configuration_score:.1%}\n")

            # Show provider details
            table = Table(title="Provider Status")
            table.add_column("Provider", style="cyan")
            table.add_column("Status", style="green")
            table.add_column("Completion", style="blue")
            table.add_column("Missing Variables", style="yellow")

            for provider, config in discovery.provider_configs.items():
                status_icon = "✓" if config.is_available else "✗"
                completion = f"{config.completion_percentage:.0%}"
                missing = ", ".join(config.missing_variables[:3])  # Show first 3
                if len(config.missing_variables) > 3:
                    missing += "..."

                table.add_row(
                    provider.value,
                    f"{status_icon} {config.status.value}",
                    completion,
                    missing or "None",
                )

            console.print(table)
        else:
            console.print("[red]No LLM providers configured[/red]")
            console.print("[dim]Set up environment variables for LLM providers[/dim]")

        # Show recommendations
        if discovery.recommendations:
            console.print("\n[bold yellow]Recommendations:[/bold yellow]")
            for rec in discovery.recommendations[:3]:  # Show first 3
                console.print(f"  • {rec}")

    except Exception as e:
        console.print(f"[red]Failed to check LLM status:[/red] {e}")


# Migration functions removed - using environment variables only


def _get_nested_value(data: dict, keys: list[str]) -> Any:
    """Get nested dictionary value."""
    for key in keys:
        if isinstance(data, dict) and key in data:
            data = data[key]
        else:
            return None
    return data


def _set_nested_value(data: dict, keys: list[str], value: Any) -> None:
    """Set nested dictionary value."""
    for key in keys[:-1]:
        if key not in data:
            data[key] = {}
        elif not isinstance(data[key], dict):
            raise ValueError(f"Cannot set nested value: {key} is not a dictionary")
        data = data[key]

    # Set the final value
    data[keys[-1]] = value


def _parse_value(value_str: str) -> Any:
    """Parse string value to appropriate Python type."""
    # Handle booleans
    if value_str.lower() in ["true", "yes", "1", "on"]:
        return True
    elif value_str.lower() in ["false", "no", "0", "off"]:
        return False

    # Handle None/null
    if value_str.lower() in ["null", "none", ""]:
        return None

    # Try to parse as integer
    try:
        return int(value_str)
    except ValueError:
        pass

    # Try to parse as float
    try:
        return float(value_str)
    except ValueError:
        pass

    # Try to parse as JSON (for lists/dicts)
    try:
        import json

        return json.loads(value_str)
    except (json.JSONDecodeError, ValueError):
        pass

    # Return as string
    return value_str


# Domain-specific configuration functions


def _initialize_domain_config(manager: ConfigManager) -> None:
    """Initialize domain-specific configuration."""
    domain_defaults = {
        "domains": {
            "enabled": list(ModuleCategory),
            "settings": {
                domain.value: {
                    "enabled": True,
                    "severity_threshold": "medium",
                    "confidence_threshold": 70,
                    "timeout": 300,
                    "max_retries": 3,
                    "parallel_execution": False,
                }
                for domain in ModuleCategory
            },
            "thresholds": {
                "global": {
                    "min_severity": "medium",
                    "min_confidence": 50,
                    "max_findings_per_module": 100,
                },
                "critical_domains": ["llm-prompt-injection", "llm-model-theft"],
                "auto_escalation": True,
            },
        }
    }

    # Update manager config
    current_config = manager.config.model_dump()
    current_config.update(domain_defaults)

    from gibson.core.config import Config

    manager.config = Config(**current_config)


def _list_domain_config(context: Context, format: str) -> None:
    """List domain configuration."""
    config = context.config.model_dump()
    domain_config = config.get("domains", {})

    if not domain_config:
        console.print("[yellow]No domain configuration found[/yellow]")
        console.print("[dim]Initialize with:[/dim] [cyan]gibson config init --domains[/cyan]")
        return

    if format == "table":
        table = Table(title="Domain Configuration")
        table.add_column("Domain", style="cyan")
        table.add_column("Enabled", style="green")
        table.add_column("Severity Threshold", style="yellow")
        table.add_column("Confidence Threshold", style="blue")
        table.add_column("Timeout", style="magenta")

        settings = domain_config.get("settings", {})
        for domain, config in settings.items():
            table.add_row(
                domain,
                "✓" if config.get("enabled", True) else "✗",
                config.get("severity_threshold", "medium"),
                str(config.get("confidence_threshold", 70)),
                f"{config.get('timeout', 300)}s",
            )

        console.print(table)

    # Show global thresholds
    thresholds = domain_config.get("thresholds", {})
    if thresholds:
        console.print("\n[bold]Global Thresholds:[/bold]")
        for key, value in thresholds.get("global", {}).items():
            console.print(f"  {key}: {value}")


def _enable_disable_domain(context: Context, domain: str, enable: bool) -> None:
    """Enable or disable a domain."""
    try:
        config_dict = context.config.model_dump()

        if "domains" not in config_dict:
            config_dict["domains"] = {"settings": {}}

        if domain not in config_dict["domains"]["settings"]:
            config_dict["domains"]["settings"][domain] = {}

        config_dict["domains"]["settings"][domain]["enabled"] = enable

        # Update context and save
        from gibson.core.config import Config

        updated_config = Config(**config_dict)
        context.config = updated_config

        config_manager = ConfigManager()
        config_manager.config = updated_config
        config_manager.save()

        status = "enabled" if enable else "disabled"
        console.print(f"[green]✓[/green] Domain '{domain}' {status}")

    except Exception as e:
        logger.error(f"Failed to {enable and 'enable' or 'disable'} domain: {e}")
        console.print(f"[red]Failed to update domain configuration: {e}[/red]")


def _configure_domain(context: Context, domain: str) -> None:
    """Interactive domain configuration."""
    console.print(f"[cyan]Configuring domain:[/cyan] {domain}")

    # Get current settings
    config_dict = context.config.model_dump()
    domain_settings = config_dict.get("domains", {}).get("settings", {}).get(domain, {})

    # Interactive configuration
    console.print("\n[dim]Current settings (press Enter to keep current value):[/dim]")

    enabled = typer.confirm(
        f"Enable domain? (current: {domain_settings.get('enabled', True)})",
        default=domain_settings.get("enabled", True),
    )

    severity = typer.prompt(
        "Severity threshold (low/medium/high/critical)",
        default=domain_settings.get("severity_threshold", "medium"),
    )

    confidence = typer.prompt(
        "Confidence threshold (0-100)",
        type=int,
        default=domain_settings.get("confidence_threshold", 70),
    )

    timeout = typer.prompt(
        "Timeout in seconds", type=int, default=domain_settings.get("timeout", 300)
    )

    # Update configuration
    if "domains" not in config_dict:
        config_dict["domains"] = {"settings": {}}

    config_dict["domains"]["settings"][domain] = {
        "enabled": enabled,
        "severity_threshold": severity,
        "confidence_threshold": confidence,
        "timeout": timeout,
        "max_retries": domain_settings.get("max_retries", 3),
        "parallel_execution": domain_settings.get("parallel_execution", False),
    }

    # Save changes
    try:
        from gibson.core.config import Config

        updated_config = Config(**config_dict)
        context.config = updated_config

        config_manager = ConfigManager()
        config_manager.config = updated_config
        config_manager.save()

        console.print(f"[green]✓[/green] Domain '{domain}' configured successfully")

    except Exception as e:
        logger.error(f"Failed to save domain configuration: {e}")
        console.print(f"[red]Failed to save configuration: {e}[/red]")


def _show_thresholds(context: Context, domain: Optional[str] = None) -> None:
    """Show threshold configuration."""
    config = context.config.model_dump()
    thresholds = config.get("domains", {}).get("thresholds", {})

    if not thresholds:
        console.print("[yellow]No threshold configuration found[/yellow]")
        return

    if domain:
        # Show domain-specific thresholds
        domain_settings = config.get("domains", {}).get("settings", {}).get(domain, {})
        if domain_settings:
            console.print(f"[bold cyan]Thresholds for {domain}:[/bold cyan]")
            console.print(f"  Severity: {domain_settings.get('severity_threshold', 'medium')}")
            console.print(f"  Confidence: {domain_settings.get('confidence_threshold', 70)}")
        else:
            console.print(f"[red]No configuration found for domain: {domain}[/red]")
    else:
        # Show global thresholds
        console.print("[bold cyan]Global Thresholds:[/bold cyan]")
        global_thresh = thresholds.get("global", {})
        for key, value in global_thresh.items():
            console.print(f"  {key}: {value}")

        # Show critical domains
        critical = thresholds.get("critical_domains", [])
        if critical:
            console.print(f"\n[bold]Critical Domains:[/bold] {', '.join(critical)}")


def _set_threshold(
    context: Context, domain: str, severity: Optional[str], confidence: Optional[int]
) -> None:
    """Set threshold for domain."""
    try:
        config_dict = context.config.model_dump()

        if "domains" not in config_dict:
            config_dict["domains"] = {"settings": {}}

        if domain not in config_dict["domains"]["settings"]:
            config_dict["domains"]["settings"][domain] = {}

        if severity:
            config_dict["domains"]["settings"][domain]["severity_threshold"] = severity
            console.print(f"[green]✓[/green] Set severity threshold for '{domain}' to '{severity}'")

        if confidence is not None:
            config_dict["domains"]["settings"][domain]["confidence_threshold"] = confidence
            console.print(
                f"[green]✓[/green] Set confidence threshold for '{domain}' to {confidence}"
            )

        # Save changes
        from gibson.core.config import Config

        updated_config = Config(**config_dict)
        context.config = updated_config

        config_manager = ConfigManager()
        config_manager.config = updated_config
        config_manager.save()

    except Exception as e:
        logger.error(f"Failed to set threshold: {e}")
        console.print(f"[red]Failed to set threshold: {e}[/red]")


def _reset_thresholds(context: Context, domain: Optional[str] = None) -> None:
    """Reset thresholds to defaults."""
    # Implementation for resetting thresholds
    console.print("[yellow]Threshold reset functionality not yet implemented[/yellow]")


def _show_module_config(context: Context, domain_filter: Optional[str] = None) -> None:
    """Show module configuration."""
    console.print("[cyan]Module Configuration:[/cyan]")

    # This would show modules filtered by domain
    # For now, show placeholder
    console.print("[yellow]Module configuration display not yet implemented[/yellow]")
    console.print("[dim]Use 'gibson module list' to see available modules[/dim]")


def _enable_disable_module(context: Context, module: str, enable: bool) -> None:
    """Enable/disable module."""
    status = "enabled" if enable else "disabled"
    console.print(f"[yellow]Module {status} functionality not yet implemented[/yellow]")
    console.print(f"[dim]Would {status} module: {module}[/dim]")


def _extract_domain_config(config: Dict[str, Any], domain: str) -> Optional[Dict[str, Any]]:
    """Extract configuration for specific domain."""
    return config.get("domains", {}).get("settings", {}).get(domain)


def _remove_secrets(config: Dict[str, Any]) -> Dict[str, Any]:
    """Remove sensitive information from config."""
    # Implementation to remove API keys, tokens, etc.
    import copy

    clean_config = copy.deepcopy(config)

    # Remove known secret keys
    secret_keys = ["api_key", "token", "password", "secret", "auth"]

    def clean_dict(d):
        if isinstance(d, dict):
            for key in list(d.keys()):
                if any(secret in key.lower() for secret in secret_keys):
                    d[key] = "[REDACTED]"
                else:
                    clean_dict(d[key])
        elif isinstance(d, list):
            for item in d:
                clean_dict(item)

    clean_dict(clean_config)
    return clean_config


def _show_config_diff(current: Dict[str, Any], import_config: Dict[str, Any], merge: bool) -> None:
    """Show configuration differences."""
    console.print("[cyan]Configuration Changes Preview:[/cyan]")
    console.print("[yellow]Diff functionality not yet implemented[/yellow]")
    console.print(f"[dim]Would {'merge' if merge else 'replace'} current configuration[/dim]")


def _merge_configs(base: Dict[str, Any], overlay: Dict[str, Any]) -> Dict[str, Any]:
    """Merge two configuration dictionaries."""
    import copy

    result = copy.deepcopy(base)

    def merge_dict(target, source):
        for key, value in source.items():
            if key in target and isinstance(target[key], dict) and isinstance(value, dict):
                merge_dict(target[key], value)
            else:
                target[key] = value

    merge_dict(result, overlay)
    return result
