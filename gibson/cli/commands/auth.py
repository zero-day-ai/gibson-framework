"""Authentication credential management commands."""

import asyncio
from pathlib import Path
from typing import Optional, List
from uuid import UUID

import typer
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.panel import Panel
from loguru import logger

from gibson.core.context import Context
from gibson.core.auth import (
    CredentialManager,
    AuthenticationService,
    EnvironmentCredentialInjector,
    detect_ci_environment,
    auto_inject_from_environment,
    resolve_credentials_path,
    load_environment_credentials
)
from gibson.models.auth import (
    ApiKeyCredentialModel,
    ApiKeyFormat,
    ValidationStatus,
    AuthErrorType
)
from gibson.models.target import TargetModel

app = typer.Typer(help="Credential and authentication management")
console = Console()


@app.command()
def add(
    ctx: typer.Context,
    target_id: str = typer.Argument(help="Target ID to associate with credential"),
    api_key: Optional[str] = typer.Option(None, "--api-key", "-k", help="API key value"),
    format: str = typer.Option("bearer", "--format", "-f", help="API key format"),
    header_name: Optional[str] = typer.Option(None, "--header", "-h", help="Custom header name"),
    token_prefix: Optional[str] = typer.Option(None, "--prefix", "-p", help="Token prefix"),
    provider: Optional[str] = typer.Option(None, "--provider", help="API provider name"),
    description: Optional[str] = typer.Option(None, "--description", "-d", help="Credential description"),
    interactive: bool = typer.Option(False, "--interactive", "-i", help="Interactive credential setup"),
) -> None:
    """
    Add API credentials for a target.
    
    Examples:
        gibson auth add target-123 --api-key sk-abc123 --format bearer
        gibson auth add target-456 --format custom --header "X-API-Key" 
        gibson auth add target-789 --interactive
    """
    context: Context = ctx.obj
    
    try:
        # Parse target ID
        try:
            parsed_target_id = UUID(target_id)
        except ValueError:
            console.print(f"[red]Invalid target ID format: {target_id}[/red]")
            console.print("[dim]Target ID must be a valid UUID[/dim]")
            raise typer.Exit(1)
        
        if interactive or not api_key:
            credential = _interactive_credential_setup(parsed_target_id, provider)
        else:
            # Parse format
            try:
                key_format = ApiKeyFormat(format.upper().replace('-', '_'))
            except ValueError:
                console.print(f"[red]Invalid format: {format}[/red]")
                console.print(f"[dim]Valid formats: {', '.join([f.value.lower().replace('_', '-') for f in ApiKeyFormat])}[/dim]")
                raise typer.Exit(1)
            
            credential = ApiKeyCredentialModel(
                target_id=parsed_target_id,
                token=api_key,
                key_format=key_format,
                header_name=header_name,
                token_prefix=token_prefix,
                provider=provider,
                description=description
            )
        
        # Store credential
        credential_manager = CredentialManager()
        credential_manager.store_credential(credential)
        
        console.print(f"[green]✓[/green] Credential stored for target: {target_id}")
        console.print(f"[dim]Format: {credential.key_format.value}[/dim]")
        
        if credential.provider:
            console.print(f"[dim]Provider: {credential.provider}[/dim]")
        
        # Optionally validate credential
        if Confirm.ask("Validate credential now?", default=True):
            asyncio.run(_validate_credential(credential))
        
    except Exception as e:
        logger.error(f"Failed to store credential: {e}")
        console.print(f"[red]Failed to store credential: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def list(
    ctx: typer.Context,
    show_tokens: bool = typer.Option(False, "--show-tokens", help="Show actual token values"),
    format: str = typer.Option("table", "--format", "-f", help="Output format (table, json)"),
) -> None:
    """List stored credentials."""
    context: Context = ctx.obj
    
    try:
        credential_manager = CredentialManager()
        credentials = credential_manager.list_credentials()
        
        if not credentials:
            console.print("[yellow]No credentials stored[/yellow]")
            console.print("[dim]Use 'gibson auth add' to store credentials[/dim]")
            return
        
        if format == "table":
            table = Table(title="Stored Credentials")
            table.add_column("Target ID", style="cyan")
            table.add_column("Format", style="yellow")
            table.add_column("Provider", style="green")
            table.add_column("Status", style="blue")
            table.add_column("Token", style="red" if show_tokens else "dim")
            table.add_column("Description", style="dim")
            
            for cred in credentials:
                token_display = cred.token if show_tokens else _mask_token(cred.token)
                status = _get_credential_status(cred)
                
                table.add_row(
                    str(cred.target_id),
                    cred.key_format.value,
                    cred.provider or "-",
                    status,
                    token_display,
                    cred.description or "-"
                )
            
            console.print(table)
        
        elif format == "json":
            import json
            cred_data = []
            for cred in credentials:
                data = cred.model_dump()
                if not show_tokens:
                    data["token"] = _mask_token(data["token"])
                cred_data.append(data)
            
            console.print(json.dumps(cred_data, indent=2, default=str))
        
        console.print(f"\n[dim]Total credentials: {len(credentials)}[/dim]")
        
        if not show_tokens:
            console.print("[dim]Use --show-tokens to reveal token values[/dim]")
    
    except Exception as e:
        logger.error(f"Failed to list credentials: {e}")
        console.print(f"[red]Failed to list credentials: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def show(
    ctx: typer.Context,
    target_id: str = typer.Argument(help="Target ID"),
    show_token: bool = typer.Option(False, "--show-token", help="Show actual token value"),
) -> None:
    """Show credential details for a target."""
    context: Context = ctx.obj
    
    try:
        # Parse target ID
        try:
            parsed_target_id = UUID(target_id)
        except ValueError:
            console.print(f"[red]Invalid target ID format: {target_id}[/red]")
            raise typer.Exit(1)
        
        credential_manager = CredentialManager()
        credential = credential_manager.retrieve_credential(parsed_target_id)
        
        if not credential:
            console.print(f"[yellow]No credential found for target: {target_id}[/yellow]")
            return
        
        # Create info panel
        info_lines = [
            f"[bold]Target ID:[/bold] {credential.target_id}",
            f"[bold]Format:[/bold] {credential.key_format.value}",
            f"[bold]Provider:[/bold] {credential.provider or 'Not specified'}",
            f"[bold]Token:[/bold] {credential.token if show_token else _mask_token(credential.token)}",
        ]
        
        if credential.header_name:
            info_lines.append(f"[bold]Header Name:[/bold] {credential.header_name}")
        
        if credential.token_prefix:
            info_lines.append(f"[bold]Token Prefix:[/bold] {credential.token_prefix}")
        
        if credential.description:
            info_lines.append(f"[bold]Description:[/bold] {credential.description}")
        
        info_lines.extend([
            f"[bold]Created:[/bold] {credential.created_at}",
            f"[bold]Last Used:[/bold] {credential.last_used_at or 'Never'}",
        ])
        
        panel = Panel("\n".join(info_lines), title="Credential Details", border_style="blue")
        console.print(panel)
        
        # Show validation status
        status = _get_credential_status(credential)
        console.print(f"\n[bold]Status:[/bold] {status}")
        
    except Exception as e:
        logger.error(f"Failed to show credential: {e}")
        console.print(f"[red]Failed to show credential: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def remove(
    ctx: typer.Context,
    target_id: str = typer.Argument(help="Target ID"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation"),
) -> None:
    """Remove credential for a target."""
    context: Context = ctx.obj
    
    try:
        # Parse target ID
        try:
            parsed_target_id = UUID(target_id)
        except ValueError:
            console.print(f"[red]Invalid target ID format: {target_id}[/red]")
            raise typer.Exit(1)
        
        credential_manager = CredentialManager()
        
        # Check if credential exists
        credential = credential_manager.retrieve_credential(parsed_target_id)
        if not credential:
            console.print(f"[yellow]No credential found for target: {target_id}[/yellow]")
            return
        
        # Confirm removal
        if not force:
            console.print(f"[yellow]This will remove the credential for target: {target_id}[/yellow]")
            console.print(f"[dim]Provider: {credential.provider or 'Unknown'}[/dim]")
            console.print(f"[dim]Format: {credential.key_format.value}[/dim]")
            
            if not Confirm.ask("Are you sure?"):
                console.print("[dim]Operation cancelled[/dim]")
                return
        
        # Remove credential
        success = credential_manager.delete_credential(parsed_target_id)
        
        if success:
            console.print(f"[green]✓[/green] Credential removed for target: {target_id}")
        else:
            console.print(f"[red]Failed to remove credential for target: {target_id}[/red]")
            raise typer.Exit(1)
        
    except Exception as e:
        logger.error(f"Failed to remove credential: {e}")
        console.print(f"[red]Failed to remove credential: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def validate(
    ctx: typer.Context,
    target_id: Optional[str] = typer.Argument(None, help="Target ID (validate all if not specified)"),
    fix_issues: bool = typer.Option(False, "--fix", help="Attempt to fix validation issues"),
) -> None:
    """Validate stored credentials."""
    context: Context = ctx.obj
    
    try:
        credential_manager = CredentialManager()
        
        if target_id:
            # Validate specific credential
            try:
                parsed_target_id = UUID(target_id)
            except ValueError:
                console.print(f"[red]Invalid target ID format: {target_id}[/red]")
                raise typer.Exit(1)
            
            credential = credential_manager.retrieve_credential(parsed_target_id)
            if not credential:
                console.print(f"[yellow]No credential found for target: {target_id}[/yellow]")
                return
            
            console.print(f"[cyan]Validating credential for target: {target_id}[/cyan]")
            asyncio.run(_validate_credential(credential, fix_issues))
        
        else:
            # Validate all credentials
            credentials = credential_manager.list_credentials()
            if not credentials:
                console.print("[yellow]No credentials to validate[/yellow]")
                return
            
            console.print(f"[cyan]Validating {len(credentials)} credentials...[/cyan]")
            
            valid_count = 0
            invalid_count = 0
            
            for credential in credentials:
                console.print(f"\n[dim]Validating {credential.target_id}...[/dim]")
                result = asyncio.run(_validate_credential(credential, fix_issues, quiet=True))
                
                if result:
                    valid_count += 1
                else:
                    invalid_count += 1
            
            console.print(f"\n[bold]Validation Summary:[/bold]")
            console.print(f"[green]Valid:[/green] {valid_count}")
            console.print(f"[red]Invalid:[/red] {invalid_count}")
    
    except Exception as e:
        logger.error(f"Failed to validate credentials: {e}")
        console.print(f"[red]Failed to validate credentials: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def status(
    ctx: typer.Context,
) -> None:
    """Show authentication system status."""
    context: Context = ctx.obj
    
    try:
        # Check credential storage
        creds_path = resolve_credentials_path()
        console.print(f"[cyan]Credential Storage:[/cyan] {creds_path}")
        console.print(f"[dim]Exists: {creds_path.exists()}[/dim]")
        
        if creds_path.exists():
            # Check permissions
            stat = creds_path.stat()
            perms = oct(stat.st_mode)[-3:]
            console.print(f"[dim]Permissions: {perms}[/dim]")
            
            if perms != "700":
                console.print("[yellow]⚠ Warning: Directory permissions should be 700[/yellow]")
        
        # Count stored credentials
        credential_manager = CredentialManager()
        credentials = credential_manager.list_credentials()
        console.print(f"[cyan]Stored Credentials:[/cyan] {len(credentials)}")
        
        # Check environment variables
        env_creds = load_environment_credentials()
        if env_creds:
            console.print(f"[cyan]Environment Credentials:[/cyan] {len(env_creds)} found")
        else:
            console.print("[cyan]Environment Credentials:[/cyan] None")
        
        # Check authentication service
        console.print(f"[cyan]Authentication Service:[/cyan] Available")
        
        # Show provider support
        console.print(f"\n[cyan]Supported Providers:[/cyan]")
        providers = ["OpenAI", "Anthropic", "Google", "Azure", "Custom"]
        for provider in providers:
            console.print(f"  • {provider}")
        
        # Show format support  
        console.print(f"\n[cyan]Supported Formats:[/cyan]")
        for fmt in ApiKeyFormat:
            console.print(f"  • {fmt.value}")
    
    except Exception as e:
        logger.error(f"Failed to get auth status: {e}")
        console.print(f"[red]Failed to get authentication status: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def inject_env(
    ctx: typer.Context,
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be injected"),
    validate: bool = typer.Option(False, "--validate", help="Validate credentials after injection"),
) -> None:
    """Inject credentials from environment variables using advanced detection."""
    context: Context = ctx.obj
    
    try:
        injector = EnvironmentCredentialInjector(
            auto_inject=False,
            validate_on_inject=validate
        )
        
        discovered = injector.discover_environment_credentials()
        
        if not discovered:
            console.print("[yellow]No environment credentials found[/yellow]")
            console.print("[dim]Set environment variables like:[/dim]")
            console.print("[dim]  GIBSON_TARGET_<UUID>_API_KEY=your_key[/dim]")
            console.print("[dim]  OPENAI_API_KEY=sk-...[/dim]")
            console.print("[dim]  ANTHROPIC_API_KEY=sk-ant-...[/dim]")
            return
        
        console.print(f"[cyan]Found {len(discovered)} credential sets from environment[/cyan]")
        
        if dry_run:
            table = Table(title="Environment Credentials Discovery")
            table.add_column("Target/Provider", style="cyan")
            table.add_column("Source", style="yellow")
            table.add_column("Provider", style="green")
            table.add_column("Format", style="blue")
            
            for target_id, creds in discovered.items():
                table.add_row(
                    target_id[:8] + "..." if len(target_id) > 12 else target_id,
                    creds.get("source", "unknown"),
                    creds.get("provider", "unknown"),
                    creds.get("format", "bearer")
                )
            
            console.print(table)
            console.print(f"[dim]Use 'gibson auth inject-env' to perform actual injection[/dim]")
            return
        
        # Perform injection
        console.print("[cyan]Injecting credentials...[/cyan]")
        results = injector.discover_and_inject()
        
        success_count = sum(1 for success in results.values() if success)
        failed_count = len(results) - success_count
        
        console.print(f"\n[green]✓ Injected {success_count} credentials[/green]")
        if failed_count > 0:
            console.print(f"[red]✗ Failed to inject {failed_count} credentials[/red]")
        
        # Show status
        status = injector.get_injection_status()
        console.print(f"\n[dim]Injection rate: {status['injection_rate']:.1%}[/dim]")
    
    except Exception as e:
        logger.error(f"Failed to inject environment credentials: {e}")
        console.print(f"[red]Failed to inject credentials: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def env_status(
    ctx: typer.Context,
) -> None:
    """Show environment credential injection status."""
    context: Context = ctx.obj
    
    try:
        # Detect environment
        ci_info = detect_ci_environment()
        
        console.print("[cyan]Environment Information:[/cyan]")
        console.print(f"  CI Environment: {'Yes' if ci_info['is_ci'] else 'No'}")
        if ci_info['detected_ci']:
            console.print(f"  Detected CI: {', '.join(ci_info['detected_ci'])}")
        console.print(f"  Container: {'Yes' if ci_info['in_container'] else 'No'}")
        console.print(f"  Kubernetes: {'Yes' if ci_info['kubernetes'] else 'No'}")
        console.print(f"  Docker: {'Yes' if ci_info['docker'] else 'No'}")
        
        # Check injection status
        injector = EnvironmentCredentialInjector(auto_inject=False)
        status = injector.get_injection_status()
        
        console.print(f"\n[cyan]Credential Injection Status:[/cyan]")
        console.print(f"  Discovered: {status['discovered_count']} credential sets")
        console.print(f"  Injected: {status['injected_count']} credentials")
        console.print(f"  Success Rate: {status['injection_rate']:.1%}")
        console.print(f"  Auto Inject: {'Enabled' if status['auto_inject_enabled'] else 'Disabled'}")
        console.print(f"  Validate on Inject: {'Enabled' if status['validate_on_inject'] else 'Disabled'}")
        
        # List environment variables
        env_vars = injector.list_environment_variables()
        if env_vars:
            console.print(f"\n[cyan]Detected Environment Variables:[/cyan]")
            for var in env_vars:
                # Mask sensitive values
                value = os.environ.get(var, "")
                if "API_KEY" in var or "SECRET" in var or "TOKEN" in var:
                    masked_value = value[:4] + "..." + value[-4:] if len(value) > 8 else "***"
                else:
                    masked_value = value
                console.print(f"  {var}={masked_value}")
    
    except Exception as e:
        logger.error(f"Failed to get environment status: {e}")
        console.print(f"[red]Failed to get environment status: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def env_template(
    ctx: typer.Context,
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path"),
    target_ids: List[str] = typer.Option(None, "--target-id", help="Target IDs to include in template"),
) -> None:
    """Generate environment variable template for credential injection."""
    context: Context = ctx.obj
    
    try:
        injector = EnvironmentCredentialInjector(auto_inject=False)
        template = injector.generate_env_template(target_ids)
        
        if output:
            injector.export_env_file(output, target_ids, include_values=False)
            console.print(f"[green]✓[/green] Environment template exported to: {output}")
        else:
            console.print("[cyan]Environment Variable Template:[/cyan]")
            console.print(template)
    
    except Exception as e:
        logger.error(f"Failed to generate environment template: {e}")
        console.print(f"[red]Failed to generate template: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def auto_inject(
    ctx: typer.Context,
) -> None:
    """Automatically inject environment credentials if appropriate for the environment."""
    context: Context = ctx.obj
    
    try:
        console.print("[cyan]Attempting automatic credential injection...[/cyan]")
        
        success = auto_inject_from_environment()
        
        if success:
            console.print("[green]✓ Automatic credential injection completed[/green]")
        else:
            console.print("[yellow]No automatic injection performed[/yellow]")
            console.print("[dim]Set GIBSON_AUTO_INJECT=true to enable automatic injection[/dim]")
    
    except Exception as e:
        logger.error(f"Auto injection failed: {e}")
        console.print(f"[red]Auto injection failed: {e}[/red]")
        raise typer.Exit(1)


def _interactive_credential_setup(target_id: UUID, provider: Optional[str]) -> ApiKeyCredentialModel:
    """Interactive credential setup."""
    console.print(f"[cyan]Setting up credentials for target: {target_id}[/cyan]")
    
    # Get API key
    api_key = Prompt.ask("API Key", password=True)
    
    # Get provider if not specified
    if not provider:
        providers = ["openai", "anthropic", "google", "azure", "custom"]
        provider = Prompt.ask(
            "Provider",
            choices=providers + [""],
            default="",
            show_choices=True
        )
        if not provider:
            provider = None
    
    # Get format based on provider
    if provider:
        format_map = {
            "openai": ApiKeyFormat.OPENAI_FORMAT,
            "anthropic": ApiKeyFormat.ANTHROPIC_FORMAT, 
            "google": ApiKeyFormat.GOOGLE_FORMAT,
            "azure": ApiKeyFormat.AZURE_FORMAT,
        }
        key_format = format_map.get(provider.lower(), ApiKeyFormat.BEARER_TOKEN)
    else:
        format_choices = [f.value.lower().replace('_', '-') for f in ApiKeyFormat]
        format_str = Prompt.ask(
            "Format",
            choices=format_choices,
            default="bearer-token"
        )
        key_format = ApiKeyFormat(format_str.upper().replace('-', '_'))
    
    # Get additional fields based on format
    header_name = None
    token_prefix = None
    
    if key_format == ApiKeyFormat.CUSTOM_HEADER:
        header_name = Prompt.ask("Header Name", default="X-API-Key")
    elif key_format == ApiKeyFormat.QUERY_PARAMETER:
        header_name = Prompt.ask("Query Parameter Name", default="api_key")
    elif key_format == ApiKeyFormat.BEARER_TOKEN:
        token_prefix = Prompt.ask("Token Prefix", default="Bearer")
    
    # Get optional description
    description = Prompt.ask("Description (optional)", default="")
    
    return ApiKeyCredentialModel(
        target_id=target_id,
        token=api_key,
        key_format=key_format,
        provider=provider,
        header_name=header_name,
        token_prefix=token_prefix,
        description=description if description else None
    )


async def _validate_credential(
    credential: ApiKeyCredentialModel,
    fix_issues: bool = False,
    quiet: bool = False
) -> bool:
    """Validate a credential."""
    try:
        auth_service = AuthenticationService()
        result = await auth_service.validate_credential(credential)
        
        if not quiet:
            if result.status == ValidationStatus.VALID:
                console.print(f"[green]✓[/green] Credential is valid")
                if result.rate_limit_info:
                    console.print(f"[dim]Rate limit: {result.rate_limit_info.requests_remaining} requests remaining[/dim]")
            
            elif result.status == ValidationStatus.INVALID:
                console.print(f"[red]✗[/red] Credential is invalid")
                if result.error_type:
                    console.print(f"[dim]Error: {result.error_type.value}[/dim]")
                if result.error_message:
                    console.print(f"[dim]{result.error_message}[/dim]")
                
                if fix_issues and result.error_type == AuthErrorType.RATE_LIMITED:
                    console.print("[yellow]Credential is rate limited, consider waiting before retrying[/yellow]")
            
            elif result.status == ValidationStatus.UNKNOWN:
                console.print(f"[yellow]?[/yellow] Could not validate credential")
                if result.error_message:
                    console.print(f"[dim]{result.error_message}[/dim]")
        
        return result.status == ValidationStatus.VALID
    
    except Exception as e:
        if not quiet:
            console.print(f"[red]Validation error: {e}[/red]")
        return False


def _mask_token(token: str) -> str:
    """Mask token for display."""
    if len(token) <= 8:
        return "***"
    return token[:4] + "..." + token[-4:]


def _get_credential_status(credential: ApiKeyCredentialModel) -> str:
    """Get credential status for display."""
    if credential.last_used_at:
        return "[green]Active[/green]"
    else:
        return "[yellow]Unused[/yellow]"