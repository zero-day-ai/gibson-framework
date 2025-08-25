"""Target management commands with full database integration."""

import asyncio
import json
from typing import Optional, List, Union
from uuid import UUID
from pathlib import Path
from datetime import datetime

import typer
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn

from gibson.core.context import Context
from gibson.db.manager import DatabaseManager
from gibson.core.targets import (
    TargetManager,
    TargetManagerError,
    TargetValidationError,
    TargetNotFoundError,
    TargetAlreadyExistsError,
)
from gibson.models.target import TargetModel, TargetType, TargetStatus, LLMProvider
from gibson.models.auth import ApiKeyFormat
from gibson.models.domain import AttackDomain

app = typer.Typer(help="Target management")
console = Console()


@app.command()
def add(
    ctx: typer.Context,
    base_url: str = typer.Argument(help="Target base URL"),
    name: Optional[str] = typer.Option(None, "--name", "-n", help="Target name (defaults to URL)"),
    target_type: str = typer.Option(
        "api", "--type", "-t", help="Target type (api, web_application, chatbot, etc.)"
    ),
    description: Optional[str] = typer.Option(None, "--description", help="Target description"),
    api_key: Optional[str] = typer.Option(None, "--api-key", help="API key for authentication"),
    auth_format: str = typer.Option("bearer_token", "--auth-format", help="Authentication format"),
    provider: Optional[str] = typer.Option(
        None, "--provider", help="LLM provider hint (openai, anthropic, etc.)"
    ),
    environment: str = typer.Option("production", "--environment", "-e", help="Environment type"),
    tags: List[str] = typer.Option([], "--tag", help="Target tags"),
    validate: bool = typer.Option(
        True, "--validate/--no-validate", help="Validate target after creation"
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Show what would be created without saving"
    ),
) -> None:
    """
    Add a new target to the Gibson Framework.

    Creates a target with automatic provider detection, credential storage,
    and optional validation.

    Examples:
        gibson target add https://api.openai.com/v1 --name "OpenAI API" --api-key sk-xxx
        gibson target add https://api.anthropic.com --provider anthropic --tag production
        gibson target add http://localhost:8080 --type chatbot --environment development
    """
    context: Context = ctx.obj

    async def _add_target():
        # Initialize database
        db_manager = DatabaseManager("sqlite:///gibson.db")
        await db_manager.initialize()

        async with db_manager.get_session() as session:
            target_manager = TargetManager(session)

            try:
                # Validate target type
                try:
                    target_type_enum = TargetType(target_type)
                except ValueError:
                    valid_types = [t.value for t in TargetType]
                    console.print(f"[red]Invalid target type: {target_type}[/red]")
                    console.print(f"Valid types: {', '.join(valid_types)}")
                    raise typer.Exit(1)

                # Parse authentication format
                try:
                    key_format = ApiKeyFormat(auth_format)
                except ValueError:
                    valid_formats = [f.value for f in ApiKeyFormat]
                    console.print(f"[red]Invalid auth format: {auth_format}[/red]")
                    console.print(f"Valid formats: {', '.join(valid_formats)}")
                    raise typer.Exit(1)

                # Parse provider hint if provided
                provider_hint = None
                if provider:
                    try:
                        provider_hint = LLMProvider(provider)
                    except ValueError:
                        valid_providers = [p.value for p in LLMProvider]
                        console.print(f"[red]Invalid provider: {provider}[/red]")
                        console.print(f"Valid providers: {', '.join(valid_providers)}")
                        raise typer.Exit(1)

                # Prepare target configuration
                target_name = name or base_url.split("/")[-1] or "unnamed_target"

                if dry_run:
                    console.print("[cyan]Dry run mode - showing what would be created:[/cyan]")
                    console.print(f"  Name: {target_name}")
                    console.print(f"  Base URL: {base_url}")
                    console.print(f"  Type: {target_type}")
                    console.print(f"  Environment: {environment}")
                    console.print(f"  Tags: {', '.join(tags) if tags else 'None'}")
                    console.print(f"  Has API Key: {'Yes' if api_key else 'No'}")
                    if provider_hint:
                        console.print(f"  Provider: {provider_hint.value}")
                    return

                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    console=console,
                ) as progress:
                    task = progress.add_task("Creating target...", total=None)

                    # Create target
                    created_target = await target_manager.create_target(
                        name=target_name,
                        base_url=base_url,
                        target_type=target_type_enum,
                        description=description,
                        api_key=api_key,
                        key_format=key_format,
                        provider_hint=provider_hint,
                        environment=environment,
                        tags=tags,
                    )

                    progress.update(task, description="Target created successfully")

                # Display results
                console.print(f"[green]✓[/green] Created target: {created_target.name}")
                console.print(f"  ID: {created_target.id}")
                console.print(f"  Type: {created_target.target_type.value}")
                console.print(f"  URL: {created_target.base_url}")
                console.print(
                    f"  Provider: {created_target.provider.value if created_target.provider else 'Auto-detected'}"
                )
                console.print(f"  Status: {created_target.status.value}")

                if description:
                    console.print(f"  Description: {description}")
                if tags:
                    console.print(f"  Tags: {', '.join(tags)}")

                if api_key:
                    console.print(f"[green]✓[/green] Stored API credential")
                    console.print(f"  Format: {key_format.value}")

                # Validate if requested
                if validate and not dry_run:
                    if Confirm.ask("Validate target configuration now?", default=True):
                        console.print("[cyan]Validating target...[/cyan]")
                        try:
                            validation_result = await target_manager.validate_target(
                                created_target.id,
                                test_connection=True,
                                validate_credentials=api_key is not None,
                            )

                            if validation_result["overall_valid"]:
                                console.print(f"[green]✓[/green] Target validation successful")
                            else:
                                console.print(f"[yellow]⚠[/yellow] Target validation had issues:")
                                for error in validation_result.get("config_errors", []):
                                    console.print(f"  [red]Config:[/red] {error}")
                                for error in validation_result.get("connectivity_errors", []):
                                    console.print(f"  [red]Connectivity:[/red] {error}")
                                for error in validation_result.get("credentials_errors", []):
                                    console.print(f"  [red]Credentials:[/red] {error}")

                        except Exception as e:
                            console.print(f"[red]Validation failed: {e}[/red]")

            except TargetAlreadyExistsError as e:
                console.print(f"[red]Error: {e}[/red]")
                raise typer.Exit(1)

            except TargetValidationError as e:
                console.print(f"[red]Validation error: {e}[/red]")
                raise typer.Exit(1)

            except TargetManagerError as e:
                console.print(f"[red]Target creation failed: {e}[/red]")
                raise typer.Exit(1)

    # Run the async operation
    try:
        asyncio.run(_add_target())
    except KeyboardInterrupt:
        console.print("\n[yellow]Operation cancelled by user[/yellow]")
        raise typer.Exit(1)


@app.command(name="list")
def list_targets(
    ctx: typer.Context,
    status: Optional[str] = typer.Option(
        None, "--status", "-s", help="Filter by status (active, inactive, etc.)"
    ),
    target_type: Optional[str] = typer.Option(None, "--type", "-t", help="Filter by target type"),
    environment: Optional[str] = typer.Option(
        None, "--environment", "-e", help="Filter by environment"
    ),
    provider: Optional[str] = typer.Option(None, "--provider", "-p", help="Filter by provider"),
    tag: Optional[str] = typer.Option(None, "--tag", help="Filter by tag"),
    enabled_only: bool = typer.Option(False, "--enabled-only", help="Show only enabled targets"),
    with_credentials: bool = typer.Option(
        False, "--with-credentials", help="Include credential status"
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed information"),
    limit: Optional[int] = typer.Option(None, "--limit", help="Maximum number of results"),
) -> None:
    """
    List targets with optional filtering and sorting.

    Examples:
        gibson target list
        gibson target list --status active --with-credentials
        gibson target list --provider openai --verbose
        gibson target list --environment production --enabled-only
    """
    context: Context = ctx.obj

    async def _list_targets():
        # Initialize database
        db_manager = DatabaseManager("sqlite:///gibson.db")
        await db_manager.initialize()

        async with db_manager.get_session() as session:
            target_manager = TargetManager(session)

            try:
                # Parse filter enums
                status_filter = None
                if status:
                    try:
                        status_filter = TargetStatus(status)
                    except ValueError:
                        valid_statuses = [s.value for s in TargetStatus]
                        console.print(f"[red]Invalid status: {status}[/red]")
                        console.print(f"Valid statuses: {', '.join(valid_statuses)}")
                        raise typer.Exit(1)

                type_filter = None
                if target_type:
                    try:
                        type_filter = TargetType(target_type)
                    except ValueError:
                        valid_types = [t.value for t in TargetType]
                        console.print(f"[red]Invalid type: {target_type}[/red]")
                        console.print(f"Valid types: {', '.join(valid_types)}")
                        raise typer.Exit(1)

                # Get targets
                targets = await target_manager.list_targets(
                    status=status_filter,
                    target_type=type_filter,
                    environment=environment,
                    enabled_only=enabled_only,
                    with_credentials=with_credentials,
                    limit=limit,
                )

                # Additional filtering
                if provider:
                    targets = [t for t in targets if t.provider and t.provider.value == provider]

                if tag:
                    targets = [t for t in targets if tag in (t.tags or [])]

                if not targets:
                    console.print(
                        "[yellow]No targets found matching the specified criteria[/yellow]"
                    )
                    return

                # Create table
                table_title = "Targets"
                if any([status, target_type, environment, provider, tag]):
                    filters = []
                    if status:
                        filters.append(f"status={status}")
                    if target_type:
                        filters.append(f"type={target_type}")
                    if environment:
                        filters.append(f"env={environment}")
                    if provider:
                        filters.append(f"provider={provider}")
                    if tag:
                        filters.append(f"tag={tag}")
                    table_title = f"Targets ({', '.join(filters)})"

                table = Table(title=table_title)
                table.add_column("Name", style="cyan")
                table.add_column("Type", style="blue")
                table.add_column("URL")
                table.add_column("Provider", style="green")
                table.add_column("Status")

                if with_credentials:
                    table.add_column("Auth", style="yellow")

                if verbose:
                    table.add_column("Environment", style="dim")
                    table.add_column("Last Scan", style="dim")
                    table.add_column("Findings", style="red")

                for target in targets:
                    # Format status with color
                    status_color = {
                        "active": "green",
                        "inactive": "dim",
                        "pending_verification": "yellow",
                        "verification_failed": "red",
                        "archived": "dim",
                    }.get(target.status.value, "white")
                    status_str = f"[{status_color}]{target.status.value}[/{status_color}]"

                    # Format provider
                    provider_str = target.provider.value if target.provider else "auto"

                    row = [
                        target.name,
                        target.target_type.value,
                        target.base_url,
                        provider_str,
                        status_str,
                    ]

                    if with_credentials:
                        auth_status = "Yes" if target.requires_auth else "No"
                        if hasattr(target, "metadata") and "credential_status" in target.metadata:
                            cred_status = target.metadata["credential_status"]
                            if cred_status == "valid":
                                auth_status = "[green]Valid[/green]"
                            elif cred_status == "invalid":
                                auth_status = "[red]Invalid[/red]"
                            elif cred_status == "untested":
                                auth_status = "[yellow]Untested[/yellow]"
                        row.append(auth_status)

                    if verbose:
                        row.extend(
                            [
                                target.environment,
                                target.last_scanned.strftime("%Y-%m-%d")
                                if target.last_scanned
                                else "Never",
                                str(target.finding_count) if target.finding_count > 0 else "-",
                            ]
                        )

                    table.add_row(*row)

                console.print(table)
                console.print(f"\n[dim]Total: {len(targets)} targets[/dim]")

                if verbose:
                    # Show statistics
                    stats = await target_manager.get_statistics()
                    console.print(
                        f"[dim]Active: {stats.get('active_targets', 0)} | "
                        f"Inactive: {stats.get('inactive_targets', 0)} | "
                        f"Total: {stats.get('total_targets', 0)}[/dim]"
                    )

            except TargetManagerError as e:
                console.print(f"[red]Failed to list targets: {e}[/red]")
                raise typer.Exit(1)

    # Run the async operation
    try:
        asyncio.run(_list_targets())
    except KeyboardInterrupt:
        console.print("\n[yellow]Operation cancelled by user[/yellow]")
        raise typer.Exit(1)


@app.command()
def search(
    ctx: typer.Context,
    query: str = typer.Argument(help="Search query (name, URL, or description)"),
    limit: Optional[int] = typer.Option(20, "--limit", "-l", help="Maximum number of results"),
) -> None:
    """
    Search targets by name, URL, or description.

    Examples:
        gibson target search "production"
        gibson target search "api.openai.com"
        gibson target search "chat" --limit 10
    """
    context: Context = ctx.obj

    async def _search_targets():
        db_manager = DatabaseManager("sqlite:///gibson.db")
        await db_manager.initialize()

        async with db_manager.get_session() as session:
            target_manager = TargetManager(session)

            try:
                results = await target_manager.search_targets(query, limit)

                if not results:
                    console.print(f"[yellow]No targets found matching '{query}'[/yellow]")
                    return

                table = Table(title=f"Search Results for '{query}'")
                table.add_column("Name", style="cyan")
                table.add_column("Type", style="blue")
                table.add_column("URL")
                table.add_column("Provider", style="green")
                table.add_column("Status")

                for target in results:
                    status_color = {
                        "active": "green",
                        "inactive": "dim",
                        "pending_verification": "yellow",
                        "verification_failed": "red",
                    }.get(target.status.value, "white")

                    table.add_row(
                        target.name,
                        target.target_type.value,
                        target.base_url,
                        target.provider.value if target.provider else "auto",
                        f"[{status_color}]{target.status.value}[/{status_color}]",
                    )

                console.print(table)
                console.print(f"\n[dim]Found {len(results)} targets[/dim]")

            except TargetManagerError as e:
                console.print(f"[red]Search failed: {e}[/red]")
                raise typer.Exit(1)

    try:
        asyncio.run(_search_targets())
    except KeyboardInterrupt:
        console.print("\n[yellow]Search cancelled by user[/yellow]")
        raise typer.Exit(1)


@app.command()
def info(
    ctx: typer.Context,
    identifier: str = typer.Argument(help="Target name or ID"),
    show_config: bool = typer.Option(False, "--config", help="Show detailed configuration"),
    show_credentials: bool = typer.Option(False, "--credentials", help="Show credential status"),
) -> None:
    """
    Show detailed information about a target.

    Examples:
        gibson target info "Production API"
        gibson target info abc-123-def --config
        gibson target info openai-api --credentials
    """
    context: Context = ctx.obj

    async def _show_info():
        db_manager = DatabaseManager("sqlite:///gibson.db")
        await db_manager.initialize()

        async with db_manager.get_session() as session:
            target_manager = TargetManager(session)

            try:
                target = await target_manager.get_target(identifier)
                if not target:
                    console.print(f"[red]Target not found: {identifier}[/red]")
                    raise typer.Exit(1)

                # Basic information
                console.print(f"\n[bold cyan]{target.name}[/bold cyan]")
                console.print(f"ID: {target.id}")
                console.print(f"Type: {target.target_type.value}")
                console.print(f"URL: {target.base_url}")
                console.print(
                    f"Provider: {target.provider.value if target.provider else 'Auto-detected'}"
                )

                # Status with color
                status_color = {
                    "active": "green",
                    "inactive": "dim",
                    "pending_verification": "yellow",
                    "verification_failed": "red",
                }.get(target.status.value, "white")
                console.print(f"Status: [{status_color}]{target.status.value}[/{status_color}]")
                console.print(f"Enabled: {'Yes' if target.enabled else 'No'}")

                if target.description:
                    console.print(f"Description: {target.description}")

                # Environment and organization
                console.print(f"Environment: {target.environment}")
                console.print(f"Priority: {target.priority}/5")
                if target.tags:
                    console.print(f"Tags: {', '.join(target.tags)}")
                if target.owner:
                    console.print(f"Owner: {target.owner}")
                if target.contact_email:
                    console.print(f"Contact: {target.contact_email}")

                # Statistics
                console.print(f"\n[bold]Statistics:[/bold]")
                console.print(f"  Scans: {target.scan_count}")
                console.print(f"  Findings: {target.finding_count}")
                console.print(
                    f"  Created: {target.created_at.strftime('%Y-%m-%d %H:%M:%S') if target.created_at else 'Unknown'}"
                )
                console.print(
                    f"  Last Scan: {target.last_scanned.strftime('%Y-%m-%d %H:%M:%S') if target.last_scanned else 'Never'}"
                )
                console.print(
                    f"  Last Verified: {target.last_verified.strftime('%Y-%m-%d %H:%M:%S') if target.last_verified else 'Never'}"
                )

                # Endpoints
                if target.endpoints:
                    console.print(f"\n[bold]Endpoints ({len(target.endpoints)}):[/bold]")
                    for endpoint in target.endpoints:
                        console.print(f"  • {endpoint.name}: {endpoint.method} {endpoint.url}")
                        if endpoint.description:
                            console.print(f"    {endpoint.description}")

                # Configuration details
                if show_config:
                    console.print(f"\n[bold]Configuration:[/bold]")
                    console.print(f"  Rate Limit: {target.global_rate_limit or 'None'}")
                    console.print(f"  Concurrent Limit: {target.concurrent_limit}")
                    console.print(f"  Request Delay: {target.request_delay}s")
                    console.print(f"  Scan Timeout: {target.scan_timeout}s")
                    console.print(f"  Verify SSL: {target.verify_ssl}")
                    console.print(f"  Follow Redirects: {target.follow_redirects}")

                    if target.allowed_domains:
                        domains = [d.value for d in target.allowed_domains]
                        console.print(f"  Allowed Domains: {', '.join(domains)}")

                    if target.blocked_modules:
                        console.print(f"  Blocked Modules: {', '.join(target.blocked_modules)}")

                # Credential status
                if show_credentials:
                    console.print(f"\n[bold]Authentication:[/bold]")
                    auth_status = target.get_authentication_status(
                        target_manager.credential_manager
                    )

                    if auth_status.get("has_credential"):
                        console.print(f"  Status: [green]Configured[/green]")
                        console.print(f"  Format: {auth_status.get('key_format', 'Unknown')}")
                        console.print(
                            f"  Validation: {auth_status.get('validation_status', 'Unknown')}"
                        )
                        if auth_status.get("last_validated"):
                            console.print(f"  Last Validated: {auth_status.get('last_validated')}")
                        if auth_status.get("usage_count"):
                            console.print(f"  Usage Count: {auth_status.get('usage_count')}")
                    else:
                        console.print(f"  Status: [yellow]No credentials configured[/yellow]")

            except TargetNotFoundError:
                console.print(f"[red]Target not found: {identifier}[/red]")
                raise typer.Exit(1)
            except TargetManagerError as e:
                console.print(f"[red]Failed to get target info: {e}[/red]")
                raise typer.Exit(1)

    try:
        asyncio.run(_show_info())
    except KeyboardInterrupt:
        console.print("\n[yellow]Operation cancelled by user[/yellow]")
        raise typer.Exit(1)


@app.command()
def validate(
    ctx: typer.Context,
    identifier: str = typer.Argument(help="Target name or ID"),
    test_connection: bool = typer.Option(
        True, "--test-connection/--no-test-connection", help="Test network connectivity"
    ),
    validate_credentials: bool = typer.Option(
        True, "--validate-credentials/--no-validate-credentials", help="Validate authentication"
    ),
) -> None:
    """
    Validate target configuration and connectivity.

    Examples:
        gibson target validate "Production API"
        gibson target validate abc-123-def --no-test-connection
        gibson target validate openai-api --validate-credentials
    """
    context: Context = ctx.obj

    async def _validate_target():
        db_manager = DatabaseManager("sqlite:///gibson.db")
        await db_manager.initialize()

        async with db_manager.get_session() as session:
            target_manager = TargetManager(session)

            try:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    console=console,
                ) as progress:
                    task = progress.add_task("Validating target...", total=None)

                    result = await target_manager.validate_target(
                        identifier,
                        test_connection=test_connection,
                        validate_credentials=validate_credentials,
                    )

                    progress.update(task, description="Validation complete")

                # Display results
                target_name = result.get("target_name", "Unknown")

                if result["overall_valid"]:
                    console.print(f"[green]✓[/green] Target '{target_name}' validation successful")
                else:
                    console.print(f"[red]✗[/red] Target '{target_name}' validation failed")

                # Configuration validation
                console.print(f"\n[bold]Configuration:[/bold]")
                if result["config_valid"]:
                    console.print(f"  [green]✓[/green] Valid configuration")
                else:
                    console.print(f"  [red]✗[/red] Configuration errors:")
                    for error in result.get("config_errors", []):
                        console.print(f"    • {error}")

                # Connectivity validation
                if test_connection:
                    console.print(f"\n[bold]Connectivity:[/bold]")
                    if result["connectivity_valid"]:
                        console.print(f"  [green]✓[/green] Network connectivity successful")
                    elif result["connectivity_valid"] is False:
                        console.print(f"  [red]✗[/red] Connectivity errors:")
                        for error in result.get("connectivity_errors", []):
                            console.print(f"    • {error}")
                    else:
                        console.print(f"  [dim]- Connectivity test skipped[/dim]")

                # Credential validation
                if validate_credentials:
                    console.print(f"\n[bold]Credentials:[/bold]")
                    if result["credentials_valid"]:
                        console.print(f"  [green]✓[/green] Authentication successful")
                    elif result["credentials_valid"] is False:
                        console.print(f"  [red]✗[/red] Credential errors:")
                        for error in result.get("credentials_errors", []):
                            console.print(f"    • {error}")
                    else:
                        console.print(f"  [dim]- No credentials to validate[/dim]")

                console.print(
                    f"\n[dim]Validation completed at {result['validation_timestamp']}[/dim]"
                )

            except TargetNotFoundError:
                console.print(f"[red]Target not found: {identifier}[/red]")
                raise typer.Exit(1)
            except TargetManagerError as e:
                console.print(f"[red]Validation failed: {e}[/red]")
                raise typer.Exit(1)

    try:
        asyncio.run(_validate_target())
    except KeyboardInterrupt:
        console.print("\n[yellow]Validation cancelled by user[/yellow]")
        raise typer.Exit(1)


@app.command()
def remove(
    ctx: typer.Context,
    identifier: str = typer.Argument(help="Target name or ID"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation prompt"),
) -> None:
    """
    Remove a target and its associated data.

    Examples:
        gibson target remove "Production API"
        gibson target remove abc-123-def --force
    """
    context: Context = ctx.obj

    async def _remove_target():
        db_manager = DatabaseManager("sqlite:///gibson.db")
        await db_manager.initialize()

        async with db_manager.get_session() as session:
            target_manager = TargetManager(session)

            try:
                # Get target info first
                target = await target_manager.get_target(identifier)
                if not target:
                    console.print(f"[red]Target not found: {identifier}[/red]")
                    raise typer.Exit(1)

                # Confirm deletion unless forced
                if not force:
                    console.print(f"[yellow]Remove target '[bold]{target.name}[/bold]'?[/yellow]")
                    console.print(f"  ID: {target.id}")
                    console.print(f"  URL: {target.base_url}")
                    console.print(f"  Scans: {target.scan_count}")
                    console.print(f"  Findings: {target.finding_count}")

                    if target.requires_auth:
                        console.print(
                            f"  [yellow]Warning: This will also remove stored credentials[/yellow]"
                        )

                    if not Confirm.ask("Are you sure?"):
                        console.print("[dim]Operation cancelled[/dim]")
                        return

                # Remove target
                success = await target_manager.delete_target(target.id)

                if success:
                    console.print(f"[green]✓[/green] Removed target: {target.name}")
                else:
                    console.print(f"[red]Failed to remove target: {identifier}[/red]")
                    raise typer.Exit(1)

            except TargetNotFoundError:
                console.print(f"[red]Target not found: {identifier}[/red]")
                raise typer.Exit(1)
            except TargetManagerError as e:
                console.print(f"[red]Failed to remove target: {e}[/red]")
                raise typer.Exit(1)

    try:
        asyncio.run(_remove_target())
    except KeyboardInterrupt:
        console.print("\n[yellow]Operation cancelled by user[/yellow]")
        raise typer.Exit(1)


@app.command()
def export(
    ctx: typer.Context,
    output_file: str = typer.Argument(help="Output JSON file path"),
    include_credentials: bool = typer.Option(
        False, "--include-credentials", help="Include credential metadata (not keys)"
    ),
    status: Optional[str] = typer.Option(None, "--status", help="Filter by status"),
    environment: Optional[str] = typer.Option(None, "--environment", help="Filter by environment"),
    format_output: bool = typer.Option(True, "--format/--no-format", help="Format JSON output"),
) -> None:
    """
    Export targets to JSON file for backup or transfer.

    Examples:
        gibson target export targets.json
        gibson target export prod-targets.json --environment production
        gibson target export backup.json --include-credentials --status active
    """
    context: Context = ctx.obj

    async def _export_targets():
        db_manager = DatabaseManager("sqlite:///gibson.db")
        await db_manager.initialize()

        async with db_manager.get_session() as session:
            target_manager = TargetManager(session)

            try:
                # Build filter criteria
                filter_kwargs = {}
                if status:
                    try:
                        filter_kwargs["status"] = TargetStatus(status)
                    except ValueError:
                        console.print(f"[red]Invalid status: {status}[/red]")
                        raise typer.Exit(1)

                if environment:
                    filter_kwargs["environment"] = environment

                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    console=console,
                ) as progress:
                    task = progress.add_task("Exporting targets...", total=None)

                    count = await target_manager.export_targets(
                        file_path=output_file,
                        include_credentials=include_credentials,
                        filter_kwargs=filter_kwargs,
                    )

                    progress.update(task, description=f"Exported {count} targets")

                console.print(f"[green]✓[/green] Exported {count} targets to {output_file}")

                # Show file info
                file_path = Path(output_file)
                if file_path.exists():
                    file_size = file_path.stat().st_size
                    console.print(f"[dim]File size: {file_size:,} bytes[/dim]")

            except TargetManagerError as e:
                console.print(f"[red]Export failed: {e}[/red]")
                raise typer.Exit(1)

    try:
        asyncio.run(_export_targets())
    except KeyboardInterrupt:
        console.print("\n[yellow]Export cancelled by user[/yellow]")
        raise typer.Exit(1)


@app.command()
def import_cmd(
    ctx: typer.Context,
    input_file: str = typer.Argument(help="Input JSON file path"),
    update_existing: bool = typer.Option(
        False, "--update-existing", help="Update existing targets"
    ),
    skip_credentials: bool = typer.Option(
        True, "--skip-credentials/--import-credentials", help="Skip credential information"
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Show what would be imported without saving"
    ),
) -> None:
    """
    Import targets from JSON file.

    Examples:
        gibson target import targets.json
        gibson target import backup.json --update-existing
        gibson target import new-targets.json --dry-run
    """
    context: Context = ctx.obj

    async def _import_targets():
        # Check if file exists
        input_path = Path(input_file)
        if not input_path.exists():
            console.print(f"[red]File not found: {input_file}[/red]")
            raise typer.Exit(1)

        db_manager = DatabaseManager("sqlite:///gibson.db")
        await db_manager.initialize()

        async with db_manager.get_session() as session:
            target_manager = TargetManager(session)

            try:
                if dry_run:
                    console.print("[cyan]Dry run mode - analyzing import file...[/cyan]")

                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    console=console,
                ) as progress:
                    task = progress.add_task("Importing targets...", total=None)

                    stats = await target_manager.import_targets(
                        file_path=input_file,
                        update_existing=update_existing,
                        skip_credentials=skip_credentials,
                    )

                    progress.update(task, description="Import complete")

                # Display results
                console.print(f"[green]✓[/green] Import completed")
                console.print(f"  Total: {stats['total']}")
                console.print(f"  Created: {stats['created']}")
                console.print(f"  Updated: {stats['updated']}")
                console.print(f"  Skipped: {stats['skipped']}")

                if stats["errors"] > 0:
                    console.print(f"  [red]Errors: {stats['errors']}[/red]")

            except FileNotFoundError:
                console.print(f"[red]Import file not found: {input_file}[/red]")
                raise typer.Exit(1)
            except TargetManagerError as e:
                console.print(f"[red]Import failed: {e}[/red]")
                raise typer.Exit(1)

    try:
        asyncio.run(_import_targets())
    except KeyboardInterrupt:
        console.print("\n[yellow]Import cancelled by user[/yellow]")
        raise typer.Exit(1)


# Fix the import command name issue
app.command(name="import")(import_cmd)


@app.command()
def set_credential(
    ctx: typer.Context,
    identifier: str = typer.Argument(help="Target name or ID"),
    api_key: Optional[str] = typer.Option(
        None, "--api-key", help="API key (will prompt if not provided)"
    ),
    key_format: str = typer.Option("bearer_token", "--format", help="Authentication format"),
    validate: bool = typer.Option(
        True, "--validate/--no-validate", help="Validate credential after setting"
    ),
) -> None:
    """
    Set or update API credential for a target.

    Examples:
        gibson target set-credential "OpenAI API" --api-key sk-xxx
        gibson target set-credential abc-123-def --format custom_header
        gibson target set-credential prod-api --no-validate
    """
    context: Context = ctx.obj

    async def _set_credential():
        # Get API key if not provided
        if not api_key:
            api_key_input = Prompt.ask("API Key", password=True)
        else:
            api_key_input = api_key

        if not api_key_input:
            console.print("[red]API key is required[/red]")
            raise typer.Exit(1)

        db_manager = DatabaseManager("sqlite:///gibson.db")
        await db_manager.initialize()

        async with db_manager.get_session() as session:
            target_manager = TargetManager(session)

            try:
                # Validate key format
                try:
                    format_enum = ApiKeyFormat(key_format)
                except ValueError:
                    valid_formats = [f.value for f in ApiKeyFormat]
                    console.print(f"[red]Invalid format: {key_format}[/red]")
                    console.print(f"Valid formats: {', '.join(valid_formats)}")
                    raise typer.Exit(1)

                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    console=console,
                ) as progress:
                    task = progress.add_task("Setting credential...", total=None)

                    success = await target_manager.set_target_credential(
                        identifier=identifier,
                        api_key=api_key_input,
                        key_format=format_enum,
                        validate=validate,
                    )

                    progress.update(task, description="Credential set")

                if success:
                    console.print(f"[green]✓[/green] API credential set for target: {identifier}")
                    console.print(f"  Format: {format_enum.value}")

                    if validate:
                        console.print("  [dim]Credential validation attempted[/dim]")
                else:
                    console.print(f"[red]Failed to set credential for target: {identifier}[/red]")
                    raise typer.Exit(1)

            except TargetNotFoundError:
                console.print(f"[red]Target not found: {identifier}[/red]")
                raise typer.Exit(1)
            except TargetManagerError as e:
                console.print(f"[red]Failed to set credential: {e}[/red]")
                raise typer.Exit(1)

    try:
        asyncio.run(_set_credential())
    except KeyboardInterrupt:
        console.print("\n[yellow]Operation cancelled by user[/yellow]")
        raise typer.Exit(1)


@app.command()
def remove_credential(
    ctx: typer.Context,
    identifier: str = typer.Argument(help="Target name or ID"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation prompt"),
) -> None:
    """
    Remove API credential for a target.

    Examples:
        gibson target remove-credential "OpenAI API"
        gibson target remove-credential abc-123-def --force
    """
    context: Context = ctx.obj

    async def _remove_credential():
        db_manager = DatabaseManager("sqlite:///gibson.db")
        await db_manager.initialize()

        async with db_manager.get_session() as session:
            target_manager = TargetManager(session)

            try:
                # Get target info
                target = await target_manager.get_target(identifier)
                if not target:
                    console.print(f"[red]Target not found: {identifier}[/red]")
                    raise typer.Exit(1)

                if not target.requires_auth:
                    console.print(
                        f"[yellow]No credential configured for target: {target.name}[/yellow]"
                    )
                    return

                # Confirm removal unless forced
                if not force:
                    console.print(
                        f"[yellow]Remove credential for target '[bold]{target.name}[/bold]'?[/yellow]"
                    )
                    if not Confirm.ask("Are you sure?"):
                        console.print("[dim]Operation cancelled[/dim]")
                        return

                success = await target_manager.remove_target_credential(identifier)

                if success:
                    console.print(f"[green]✓[/green] Removed credential for target: {target.name}")
                else:
                    console.print(
                        f"[red]Failed to remove credential for target: {identifier}[/red]"
                    )
                    raise typer.Exit(1)

            except TargetNotFoundError:
                console.print(f"[red]Target not found: {identifier}[/red]")
                raise typer.Exit(1)
            except TargetManagerError as e:
                console.print(f"[red]Failed to remove credential: {e}[/red]")
                raise typer.Exit(1)

    try:
        asyncio.run(_remove_credential())
    except KeyboardInterrupt:
        console.print("\n[yellow]Operation cancelled by user[/yellow]")
        raise typer.Exit(1)


@app.command()
def stats(
    ctx: typer.Context,
    detailed: bool = typer.Option(False, "--detailed", "-d", help="Show detailed statistics"),
) -> None:
    """
    Show target management statistics and summary.

    Examples:
        gibson target stats
        gibson target stats --detailed
    """
    context: Context = ctx.obj

    async def _show_stats():
        db_manager = DatabaseManager("sqlite:///gibson.db")
        await db_manager.initialize()

        async with db_manager.get_session() as session:
            target_manager = TargetManager(session)

            try:
                stats = await target_manager.get_statistics()

                console.print("\n[bold cyan]Target Management Statistics[/bold cyan]")

                # Basic statistics
                total = stats.get("total_targets", 0)
                active = stats.get("active_targets", 0)
                inactive = stats.get("inactive_targets", 0)

                console.print(f"\n[bold]Overview:[/bold]")
                console.print(f"  Total Targets: {total}")
                console.print(f"  Active: [green]{active}[/green]")
                console.print(f"  Inactive: [dim]{inactive}[/dim]")

                if total > 0:
                    active_percentage = (active / total) * 100
                    console.print(f"  Active Rate: {active_percentage:.1f}%")

                # Targets by type
                targets_by_type = stats.get("targets_by_type", {})
                if targets_by_type:
                    console.print(f"\n[bold]By Type:[/bold]")
                    for target_type, count in targets_by_type.items():
                        console.print(f"  {target_type}: {count}")

                # Targets by environment
                targets_by_env = stats.get("targets_by_environment", {})
                if targets_by_env:
                    console.print(f"\n[bold]By Environment:[/bold]")
                    for env, count in targets_by_env.items():
                        color = {
                            "production": "red",
                            "staging": "yellow",
                            "development": "green",
                        }.get(env, "white")
                        console.print(f"  [{color}]{env}[/{color}]: {count}")

                if detailed:
                    # Get recent targets for additional info
                    recent_targets = await target_manager.list_targets(limit=5)

                    if recent_targets:
                        console.print(f"\n[bold]Recent Targets:[/bold]")
                        for target in recent_targets:
                            status_color = {
                                "active": "green",
                                "inactive": "dim",
                                "pending_verification": "yellow",
                            }.get(target.status.value, "white")

                            console.print(
                                f"  • [{status_color}]{target.name}[/{status_color}] ({target.target_type.value})"
                            )
                            console.print(f"    {target.base_url}")
                            if target.last_scanned:
                                console.print(
                                    f"    Last scan: {target.last_scanned.strftime('%Y-%m-%d %H:%M')}"
                                )

            except TargetManagerError as e:
                console.print(f"[red]Failed to get statistics: {e}[/red]")
                raise typer.Exit(1)

    try:
        asyncio.run(_show_stats())
    except KeyboardInterrupt:
        console.print("\n[yellow]Operation cancelled by user[/yellow]")
        raise typer.Exit(1)


# Target management commands complete.
# All commands now use the new TargetManager with full database integration.
