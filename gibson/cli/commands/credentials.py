"""Credential management CLI commands."""

import asyncio
import getpass
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional
from uuid import UUID

import typer
import yaml
from rich.console import Console
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

from gibson.core.auth.auth_service import AuthenticationService
from gibson.core.auth.config import AuthenticationConfig as AuthConfig
from gibson.core.auth.credential_manager import CredentialManager
from gibson.core.auth.crypto import CredentialEncryption
from gibson.core.auth.providers import (
    ProviderRegistry,
    detect_provider_from_key,
    detect_provider_from_url,
)
from gibson.core.config import ConfigManager
from gibson.core.context import Context
from gibson.models.auth import ApiKeyCredentialModel, ApiKeyFormat, ValidationStatus
from gibson.models.target import TargetModel

app = typer.Typer(help="Manage API credentials for targets")
console = Console()


@app.command()
def add(
    target_name: str = typer.Argument(..., help="Target name to add credentials for"),
    api_key: Optional[str] = typer.Option(
        None, "--api-key", "-k", help="API key (will prompt if not provided)"
    ),
    key_format: Optional[str] = typer.Option(
        None, "--format", "-f", help="Key format: bearer, custom_header, query_param"
    ),
    provider: Optional[str] = typer.Option(
        None, "--provider", "-p", help="API provider: openai, anthropic, google, etc."
    ),
    environment: Optional[str] = typer.Option(
        "production", "--environment", "-e", help="Environment: production, staging, development"
    ),
    validate: bool = typer.Option(
        True, "--validate/--no-validate", help="Validate credentials after adding"
    ),
):
    """Add API credentials for a target."""
    asyncio.run(
        _add_credential_async(target_name, api_key, key_format, provider, environment, validate)
    )


async def _add_credential_async(
    target_name: str,
    api_key: Optional[str],
    key_format: Optional[str],
    provider: Optional[str],
    environment: str,
    validate: bool,
):
    """Async implementation of add credential."""
    try:
        # Initialize services
        config_manager = ConfigManager()
        config = config_manager.config
        context = Context(config=config, console=console)
        auth_config = AuthConfig()
        encryption = CredentialEncryption()
        credential_manager = CredentialManager()
        auth_service = AuthenticationService()

        # Find target
        # TODO: Implement target lookup from database
        # For now, create a mock target
        from gibson.models.target import TargetType

        target = TargetModel(
            name=target_name,
            display_name=target_name,
            target_type=TargetType.AI_SERVICE if provider else TargetType.API,
            base_url=f"https://api.{provider or 'example'}.com",
            description=f"Target for {target_name}",
        )

        # Get API key if not provided
        if not api_key:
            api_key = getpass.getpass("Enter API key (hidden): ")
            if not api_key.strip():
                console.print("[red]Error: API key cannot be empty[/red]")
                raise typer.Exit(1)

        # Auto-detect provider if not specified
        if not provider:
            provider = detect_provider_from_key(api_key) or detect_provider_from_url(target.url)
            if provider:
                console.print(f"[blue]Auto-detected provider: {provider}[/blue]")

        # Auto-detect key format if not specified
        if not key_format:
            if provider in ["openai"]:
                key_format = "bearer"
            elif provider in ["anthropic"]:
                key_format = "custom_header"
            elif provider in ["google"]:
                key_format = "query_param"
            else:
                key_format = "bearer"  # Default
            console.print(f"[blue]Auto-detected key format: {key_format}[/blue]")

        # Convert string to enum
        format_mapping = {
            "bearer": ApiKeyFormat.BEARER_TOKEN,
            "bearer_token": ApiKeyFormat.BEARER_TOKEN,
            "custom_header": ApiKeyFormat.CUSTOM_HEADER,
            "query_param": ApiKeyFormat.QUERY_PARAMETER,
            "query_parameter": ApiKeyFormat.QUERY_PARAMETER,
        }

        format_enum = format_mapping.get(key_format.lower())
        if not format_enum:
            # Try provider-specific formats
            if provider == "anthropic":
                format_enum = ApiKeyFormat.ANTHROPIC_FORMAT
            elif provider == "openai":
                format_enum = ApiKeyFormat.OPENAI_FORMAT
            elif provider == "google":
                format_enum = ApiKeyFormat.GOOGLE_FORMAT
            else:
                console.print(
                    f"[red]Error: Invalid key format '{key_format}'. Valid options: bearer, custom_header, query_param[/red]"
                )
                raise typer.Exit(1)

        # Create credential model
        from gibson.models.target import AuthenticationType

        credential = ApiKeyCredentialModel(
            auth_type=AuthenticationType.API_KEY,
            token=api_key,
            key_format=format_enum,
            provider_name=provider,
            environment=environment,
            validation_status=ValidationStatus.UNTESTED,
        )

        # Validate credential if requested
        if validate:
            console.print("[yellow]Validating credentials...[/yellow]")
            try:
                result = await auth_service.validate_credential(target, credential)
                if result.is_valid:
                    console.print("[green]✓ Credentials validated successfully[/green]")
                    credential.validation_status = ValidationStatus.VALID
                else:
                    console.print(f"[yellow]⚠ Validation failed: {result.error_message}[/yellow]")
                    credential.validation_status = ValidationStatus.INVALID
                    if not Confirm.ask("Continue with invalid credentials?"):
                        raise typer.Exit(1)
            except Exception as e:
                console.print(f"[yellow]⚠ Validation error: {e}[/yellow]")
                if not Confirm.ask("Continue without validation?"):
                    raise typer.Exit(1)

        # Store credential
        credential_manager.store_credential(target.id, credential)

        console.print(f"[green]✓ Credentials added successfully for target '{target_name}'[/green]")

        # Show summary
        table = Table(title="Added Credential")
        table.add_column("Field", style="cyan")
        table.add_column("Value")

        table.add_row("Target", target_name)
        table.add_row("Provider", provider or "Unknown")
        table.add_row("Format", key_format)
        table.add_row("Environment", environment)
        table.add_row("Status", credential.validation_status.value)
        table.add_row("API Key", f"{api_key[:8]}...{api_key[-4:]}" if len(api_key) > 12 else "***")

        console.print(table)

    except Exception as e:
        console.print(f"[red]Error adding credentials: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def list(
    target: Optional[str] = typer.Option(None, "--target", "-t", help="Filter by target name"),
    provider: Optional[str] = typer.Option(None, "--provider", "-p", help="Filter by provider"),
    environment: Optional[str] = typer.Option(
        None, "--environment", "-e", help="Filter by environment"
    ),
    show_keys: bool = typer.Option(False, "--show-keys", help="Show masked API keys"),
):
    """List stored credentials."""
    asyncio.run(_list_credentials_async(target, provider, environment, show_keys))


async def _list_credentials_async(
    target_filter: Optional[str],
    provider_filter: Optional[str],
    environment_filter: Optional[str],
    show_keys: bool,
):
    """Async implementation of list credentials."""
    try:
        # Initialize services
        auth_config = AuthConfig()
        encryption = CredentialEncryption()
        credential_manager = CredentialManager()

        # List all credentials
        credentials = credential_manager.list_credentials()

        # Apply filters
        if target_filter:
            credentials = [c for c in credentials if target_filter.lower() in c.target_name.lower()]
        if provider_filter:
            credentials = [c for c in credentials if c.provider_name == provider_filter]
        if environment_filter:
            credentials = [c for c in credentials if c.environment == environment_filter]

        if not credentials:
            console.print("[yellow]No credentials found matching the criteria.[/yellow]")
            return

        # Create table
        table = Table(title="Stored Credentials")
        table.add_column("Target", style="cyan")
        table.add_column("Provider")
        table.add_column("Format")
        table.add_column("Environment")
        table.add_column("Status")
        table.add_column("Last Used")
        if show_keys:
            table.add_column("API Key (Masked)")

        for cred in credentials:
            status_color = {
                "validated": "green",
                "pending": "yellow",
                "failed": "red",
                "expired": "red",
            }.get(cred.validation_status, "white")

            last_used = (
                cred.last_used_at.strftime("%Y-%m-%d %H:%M") if cred.last_used_at else "Never"
            )

            row = [
                cred.target_name,
                cred.provider_name or "Unknown",
                cred.key_format,
                cred.environment or "Unknown",
                f"[{status_color}]{cred.validation_status}[/{status_color}]",
                last_used,
            ]

            if show_keys:
                row.append(cred.masked_preview or "***")

            table.add_row(*row)

        console.print(table)
        console.print(f"\nTotal: {len(credentials)} credential(s)")

    except Exception as e:
        console.print(f"[red]Error listing credentials: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def update(
    target_name: str = typer.Argument(..., help="Target name to update credentials for"),
    api_key: Optional[str] = typer.Option(None, "--api-key", "-k", help="New API key"),
    validate: bool = typer.Option(
        True, "--validate/--no-validate", help="Validate new credentials"
    ),
):
    """Update API credentials for a target."""
    asyncio.run(_update_credential_async(target_name, api_key, validate))


async def _update_credential_async(target_name: str, api_key: Optional[str], validate: bool):
    """Async implementation of update credential."""
    try:
        # Initialize services
        auth_config = AuthConfig()
        encryption = CredentialEncryption()
        credential_manager = CredentialManager()
        auth_service = AuthenticationService()

        # Find existing credential
        credentials = credential_manager.list_credentials()
        existing = next((c for c in credentials if c.target_name == target_name), None)

        if not existing:
            console.print(f"[red]No credentials found for target '{target_name}'[/red]")
            raise typer.Exit(1)

        # Get new API key if not provided
        if not api_key:
            api_key = getpass.getpass("Enter new API key (hidden): ")
            if not api_key.strip():
                console.print("[red]Error: API key cannot be empty[/red]")
                raise typer.Exit(1)

        # Retrieve existing credential to update it
        target_uuid = existing.target_id
        old_credential = credential_manager.retrieve_credential(target_uuid)

        if not old_credential:
            console.print(
                f"[red]Failed to retrieve existing credential for target '{target_name}'[/red]"
            )
            raise typer.Exit(1)

        # Update the credential
        updated_credential = ApiKeyCredentialModel(
            auth_type=AuthenticationType.API_KEY,
            token=api_key,
            key_format=old_credential.key_format,
            provider_name=old_credential.provider_name,
            environment=old_credential.environment,
            validation_status=ValidationStatus.UNTESTED,
        )

        # Validate if requested
        if validate:
            console.print("[yellow]Validating new credentials...[/yellow]")
            try:
                # Create mock target for validation
                target = TargetModel(
                    id=target_uuid,
                    name=target_name,
                    display_name=target_name,
                    target_type=TargetType.AI_SERVICE,
                    base_url=f"https://api.{old_credential.provider_name or 'example'}.com",
                )

                result = await auth_service.validate_credential(target, updated_credential)
                if result.is_valid:
                    console.print("[green]✓ New credentials validated successfully[/green]")
                    updated_credential.validation_status = ValidationStatus.VALID
                else:
                    console.print(f"[yellow]⚠ Validation failed: {result.error_message}[/yellow]")
                    updated_credential.validation_status = ValidationStatus.INVALID
                    if not Confirm.ask("Continue with invalid credentials?"):
                        raise typer.Exit(1)
            except Exception as e:
                console.print(f"[yellow]⚠ Validation error: {e}[/yellow]")
                if not Confirm.ask("Continue without validation?"):
                    raise typer.Exit(1)

        # Store updated credential
        credential_manager.store_credential(target_uuid, updated_credential)

        console.print(
            f"[green]✓ Credentials updated successfully for target '{target_name}'[/green]"
        )

    except Exception as e:
        console.print(f"[red]Error updating credentials: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def remove(
    target_name: str = typer.Argument(..., help="Target name to remove credentials for"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation prompt"),
):
    """Remove API credentials for a target."""
    asyncio.run(_remove_credential_async(target_name, force))


async def _remove_credential_async(target_name: str, force: bool):
    """Async implementation of remove credential."""
    try:
        # Initialize services
        auth_config = AuthConfig()
        encryption = CredentialEncryption()
        credential_manager = CredentialManager()

        # Find credential
        credentials = credential_manager.list_credentials()
        existing = next((c for c in credentials if c.target_name == target_name), None)

        if not existing:
            console.print(f"[red]No credentials found for target '{target_name}'[/red]")
            raise typer.Exit(1)

        # Confirm deletion
        if not force:
            if not Confirm.ask(f"Remove credentials for target '{target_name}'?"):
                console.print("Cancelled.")
                return

        # Delete credential
        success = credential_manager.delete_credential(existing.target_id)

        if success:
            console.print(f"[green]✓ Credentials removed for target '{target_name}'[/green]")
        else:
            console.print(f"[red]Failed to remove credentials for target '{target_name}'[/red]")
            raise typer.Exit(1)

    except Exception as e:
        console.print(f"[red]Error removing credentials: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def validate(
    target_name: str = typer.Argument(..., help="Target name to validate credentials for"),
):
    """Validate stored credentials for a target."""
    asyncio.run(_validate_credential_async(target_name))


async def _validate_credential_async(target_name: str):
    """Async implementation of validate credential."""
    try:
        # Initialize services
        auth_config = AuthConfig()
        encryption = CredentialEncryption()
        credential_manager = CredentialManager()
        auth_service = AuthenticationService()

        # Find credential
        credentials = credential_manager.list_credentials()
        existing = next((c for c in credentials if c.target_name == target_name), None)

        if not existing:
            console.print(f"[red]No credentials found for target '{target_name}'[/red]")
            raise typer.Exit(1)

        # Retrieve credential
        credential = credential_manager.retrieve_credential(existing.target_id)
        if not credential:
            console.print(f"[red]Failed to retrieve credential for target '{target_name}'[/red]")
            raise typer.Exit(1)

        console.print("[yellow]Validating credentials...[/yellow]")

        # Create target for validation
        target = TargetModel(
            id=existing.target_id,
            name=target_name,
            display_name=target_name,
            target_type=TargetType.AI_SERVICE,
            base_url=f"https://api.{credential.provider_name or 'example'}.com",
        )

        # Validate
        result = await auth_service.validate_credential(target, credential)

        if result.is_valid:
            console.print("[green]✓ Credentials are valid[/green]")

            # Update validation status
            credential.validation_status = ValidationStatus.VALID
            credential_manager.store_credential(existing.target_id, credential)

        else:
            console.print(f"[red]✗ Credentials are invalid: {result.error_message}[/red]")

            # Update validation status
            credential.validation_status = ValidationStatus.INVALID
            credential_manager.store_credential(existing.target_id, credential)

        # Show validation details
        table = Table(title="Validation Results")
        table.add_column("Field", style="cyan")
        table.add_column("Value")

        table.add_row("Target", target_name)
        table.add_row("Valid", "✓ Yes" if result.is_valid else "✗ No")
        table.add_row("Status Code", str(result.status_code) if result.status_code else "N/A")
        table.add_row("Error", result.error_message or "None")
        table.add_row("Timestamp", result.validation_timestamp.strftime("%Y-%m-%d %H:%M:%S"))

        console.print(table)

    except Exception as e:
        console.print(f"[red]Error validating credentials: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def export(
    output_file: str = typer.Argument(..., help="Output file path"),
    format: str = typer.Option("yaml", "--format", "-f", help="Export format: yaml, json"),
    include_keys: bool = typer.Option(
        False, "--include-keys", help="Include encrypted API keys (use with caution)"
    ),
):
    """Export credentials to a file."""
    asyncio.run(_export_credentials_async(output_file, format, include_keys))


async def _export_credentials_async(output_file: str, format: str, include_keys: bool):
    """Async implementation of export credentials."""
    try:
        # Initialize services
        auth_config = AuthConfig()
        encryption = CredentialEncryption()
        credential_manager = CredentialManager()

        # Get all credentials
        credentials = credential_manager.list_credentials()

        if not credentials:
            console.print("[yellow]No credentials found to export.[/yellow]")
            return

        # Prepare export data
        export_data = {"version": "1.0", "exported_at": "2025-08-21T13:40:00Z", "credentials": []}

        for cred_meta in credentials:
            cred_data = {
                "target_name": cred_meta.target_name,
                "provider_name": cred_meta.provider_name,
                "key_format": cred_meta.key_format,
                "environment": cred_meta.environment,
                "validation_status": cred_meta.validation_status,
                "created_at": cred_meta.created_at.isoformat() if cred_meta.created_at else None,
            }

            if include_keys:
                # Retrieve full credential
                full_cred = credential_manager.retrieve_credential(cred_meta.target_id)
                if full_cred:
                    cred_data["api_key"] = full_cred.api_key
                    console.print(
                        f"[yellow]⚠ Including API key for {cred_meta.target_name}[/yellow]"
                    )

            export_data["credentials"].append(cred_data)

        # Write to file
        output_path = Path(output_file)

        if format.lower() == "json":
            with open(output_path, "w") as f:
                json.dump(export_data, f, indent=2)
        elif format.lower() == "yaml":
            with open(output_path, "w") as f:
                yaml.dump(export_data, f, indent=2, default_flow_style=False)
        else:
            console.print(f"[red]Unsupported format: {format}. Use 'json' or 'yaml'.[/red]")
            raise typer.Exit(1)

        console.print(
            f"[green]✓ Exported {len(credentials)} credential(s) to {output_file}[/green]"
        )

        if include_keys:
            console.print(
                "[red]⚠ WARNING: Exported file contains sensitive API keys. Secure it properly![/red]"
            )

    except Exception as e:
        console.print(f"[red]Error exporting credentials: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def import_credentials(
    input_file: str = typer.Argument(..., help="Input file path"),
    format: str = typer.Option("yaml", "--format", "-f", help="Import format: yaml, json"),
    validate: bool = typer.Option(
        True, "--validate/--no-validate", help="Validate imported credentials"
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Show what would be imported without actually doing it"
    ),
):
    """Import credentials from a file."""
    asyncio.run(_import_credentials_async(input_file, format, validate, dry_run))


async def _import_credentials_async(input_file: str, format: str, validate: bool, dry_run: bool):
    """Async implementation of import credentials."""
    try:
        # Initialize services
        auth_config = AuthConfig()
        encryption = CredentialEncryption()
        credential_manager = CredentialManager()
        auth_service = AuthenticationService()

        # Read file
        input_path = Path(input_file)
        if not input_path.exists():
            console.print(f"[red]File not found: {input_file}[/red]")
            raise typer.Exit(1)

        with open(input_path, "r") as f:
            if format.lower() == "json":
                data = json.load(f)
            elif format.lower() == "yaml":
                data = yaml.safe_load(f)
            else:
                console.print(f"[red]Unsupported format: {format}. Use 'json' or 'yaml'.[/red]")
                raise typer.Exit(1)

        # Validate file structure
        if "credentials" not in data:
            console.print("[red]Invalid file format: missing 'credentials' section[/red]")
            raise typer.Exit(1)

        credentials_to_import = data["credentials"]
        console.print(f"[blue]Found {len(credentials_to_import)} credential(s) to import[/blue]")

        if dry_run:
            console.print("[yellow]DRY RUN - No changes will be made[/yellow]")

        imported_count = 0

        for cred_data in credentials_to_import:
            target_name = cred_data.get("target_name")
            api_key = cred_data.get("api_key")

            if not target_name:
                console.print("[yellow]Skipping credential with missing target_name[/yellow]")
                continue

            if not api_key:
                console.print(f"[yellow]Skipping {target_name}: missing api_key[/yellow]")
                continue

            if dry_run:
                console.print(
                    f"[blue]Would import: {target_name} ({cred_data.get('provider_name', 'unknown')})[/blue]"
                )
                continue

            # Create credential
            try:
                key_format = ApiKeyFormat(cred_data.get("key_format", "bearer"))
            except ValueError:
                key_format = ApiKeyFormat.BEARER

            credential = ApiKeyCredentialModel(
                auth_type=AuthenticationType.API_KEY,
                token=api_key,
                key_format=key_format,
                provider_name=cred_data.get("provider_name"),
                environment=cred_data.get("environment", "production"),
                validation_status=ValidationStatus.UNTESTED,
            )

            # Create mock target
            target = TargetModel(
                name=target_name,
                display_name=target_name,
                target_type=TargetType.AI_SERVICE,
                base_url=f"https://api.{credential.provider_name or 'example'}.com",
            )

            # Validate if requested
            if validate:
                try:
                    result = await auth_service.validate_credential(target, credential)
                    if result.is_valid:
                        credential.validation_status = ValidationStatus.VALID
                        console.print(f"[green]✓ {target_name}: validated[/green]")
                    else:
                        credential.validation_status = ValidationStatus.INVALID
                        console.print(f"[yellow]⚠ {target_name}: validation failed[/yellow]")
                except Exception as e:
                    console.print(f"[yellow]⚠ {target_name}: validation error - {e}[/yellow]")

            # Store credential
            credential_manager.store_credential(target.id, credential)
            imported_count += 1

            console.print(f"[green]✓ Imported: {target_name}[/green]")

        if not dry_run:
            console.print(f"[green]✓ Successfully imported {imported_count} credential(s)[/green]")

    except Exception as e:
        console.print(f"[red]Error importing credentials: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def import_env(
    ctx: typer.Context,
    env_file: Optional[Path] = typer.Option(None, "--file", "-f", help="Environment file to load"),
    auto_inject: bool = typer.Option(
        True, "--auto-inject", help="Automatically inject discovered credentials"
    ),
    validate: bool = typer.Option(False, "--validate", help="Validate credentials after injection"),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Show what would be imported without doing it"
    ),
) -> None:
    """Import credentials from environment variables."""
    context: Context = ctx.obj

    try:
        from gibson.core.auth.env_injector import EnvironmentCredentialInjector

        console.print("🌍 [cyan]Scanning environment for credentials...[/cyan]")

        # Load environment file if specified
        if env_file:
            if not env_file.exists():
                console.print(f"[red]Environment file not found: {env_file}[/red]")
                raise typer.Exit(1)

            # Load the env file
            import os

            with open(env_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        key, value = line.split("=", 1)
                        key = key.strip()
                        value = value.strip().strip("\"'")
                        os.environ[key] = value

            console.print(f"[cyan]Loaded environment from: {env_file}[/cyan]")

        # Create injector
        injector = EnvironmentCredentialInjector(
            auto_inject=False, validate_on_inject=validate  # We'll control injection manually
        )

        # Discover credentials
        discovered = injector.discover_environment_credentials()

        if not discovered:
            console.print("[yellow]No API credentials found in environment variables[/yellow]")
            console.print("\n[dim]Expected variables:[/dim]")
            console.print("[dim]  • GIBSON_TARGET_<UUID>_API_KEY=key[/dim]")
            console.print("[dim]  • OPENAI_API_KEY=sk-...[/dim]")
            console.print("[dim]  • ANTHROPIC_API_KEY=sk-ant-...[/dim]")
            console.print("[dim]  • GOOGLE_API_KEY=...[/dim]")
            console.print("[dim]  • AZURE_API_KEY=...[/dim]")
            return

        # Show discovered credentials
        table = Table(title="Discovered Environment Credentials")
        table.add_column("Target ID", style="cyan")
        table.add_column("Provider", style="green")
        table.add_column("Source", style="yellow")
        table.add_column("API Key Preview", style="dim")

        for target_id, cred_info in discovered.items():
            provider = cred_info.get("provider", "unknown")
            source = cred_info.get("source", "unknown")
            api_key = cred_info.get("api_key", "")

            # Mask API key for display
            if len(api_key) > 8:
                masked_key = f"{api_key[:4]}...{api_key[-4:]}"
            else:
                masked_key = "*" * len(api_key)

            table.add_row(target_id, provider, source, masked_key)

        console.print(table)

        if dry_run:
            console.print("\n[dim]Dry run mode - no credentials were imported[/dim]")
            return

        if auto_inject:
            console.print(f"\n[cyan]Injecting {len(discovered)} credentials...[/cyan]")

            # Inject credentials
            results = {}
            for target_id, cred_info in discovered.items():
                try:
                    success = injector.inject_credential(cred_info)
                    results[target_id] = success
                except Exception as e:
                    console.print(f"[red]Failed to inject {target_id}: {e}[/red]")
                    results[target_id] = False

            success_count = sum(1 for success in results.values() if success)
            console.print(
                f"\n[green]✓[/green] Successfully imported {success_count}/{len(discovered)} credentials"
            )

            # Show any failures
            failures = [tid for tid, success in results.items() if not success]
            if failures:
                console.print(f"[yellow]Failed to import: {', '.join(failures)}[/yellow]")
        else:
            console.print(
                "\n[dim]Auto-injection disabled - use 'gibson credentials add' to import manually[/dim]"
            )

    except Exception as e:
        console.print(f"[red]Failed to import environment credentials: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def env_template(
    ctx: typer.Context,
    output_file: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Output file path (defaults to .env.template)"
    ),
    target_ids: Optional[List[str]] = typer.Option(
        None, "--target-id", "-t", help="Include specific target IDs in template"
    ),
) -> None:
    """Generate environment variable template for credentials."""
    context: Context = ctx.obj

    try:
        from gibson.core.auth.env_injector import EnvironmentCredentialInjector

        # Create injector
        injector = EnvironmentCredentialInjector()

        # Generate template
        template = injector.generate_env_template(target_ids or [])

        # Determine output path
        if not output_file:
            output_file = Path.cwd() / ".env.template"

        # Write template
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(template)

        console.print(f"[green]✓[/green] Environment template created: {output_file}")
        console.print(f"[dim]Copy to .env and fill in your API keys[/dim]")

        # Show preview
        console.print(f"\n[bold]Template preview:[/bold]")
        lines = template.split("\n")[:15]  # Show first 15 lines
        for line in lines:
            if line.startswith("#"):
                console.print(f"[dim]{line}[/dim]")
            else:
                console.print(line)

        if len(template.split("\n")) > 15:
            console.print("[dim]...[/dim]")

    except Exception as e:
        console.print(f"[red]Failed to generate environment template: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def env_status(
    ctx: typer.Context,
) -> None:
    """Show environment credential injection status."""
    context: Context = ctx.obj

    try:
        from gibson.core.auth.env_injector import (
            EnvironmentCredentialInjector,
            detect_ci_environment,
        )

        # Create injector
        injector = EnvironmentCredentialInjector()

        # Get injection status
        status = injector.get_injection_status()

        # Get CI environment info
        ci_info = detect_ci_environment()

        # Show status
        console.print("[bold cyan]Environment Credential Status[/bold cyan]\n")

        # Basic stats
        table = Table(title="Injection Statistics")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")

        table.add_row("Discovered Credentials", str(status["discovered_count"]))
        table.add_row("Injected Credentials", str(status["injected_count"]))
        table.add_row("Injection Rate", f"{status['injection_rate']:.1%}")
        table.add_row("Auto-inject Enabled", "✓" if status["auto_inject_enabled"] else "✗")
        table.add_row("Validate on Inject", "✓" if status["validate_on_inject"] else "✗")

        console.print(table)

        # Environment detection
        console.print(f"\n[bold]Environment Detection:[/bold]")
        console.print(f"  CI Environment: {'✓' if ci_info['is_ci'] else '✗'}")
        console.print(f"  Container: {'✓' if ci_info['in_container'] else '✗'}")
        console.print(f"  Kubernetes: {'✓' if ci_info['kubernetes'] else '✗'}")

        if ci_info["detected_ci"]:
            console.print(f"  Detected CI: {', '.join(ci_info['detected_ci'])}")

        # List discovered environment variables
        env_vars = injector.list_environment_variables()
        if env_vars:
            console.print(f"\n[bold]Found Environment Variables:[/bold]")
            for var in env_vars:
                console.print(f"  [green]{var}[/green]")
        else:
            console.print(f"\n[yellow]No credential environment variables found[/yellow]")

    except Exception as e:
        console.print(f"[red]Failed to get environment status: {e}[/red]")
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
