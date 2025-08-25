"""Security scanning commands."""

import asyncio
from enum import Enum
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from gibson.core.context import Context
from gibson.core.base import Base
from gibson.models.scan import ScanResult
from gibson.core.auth.credential_manager import CredentialManager
from gibson.db.manager import DatabaseManager
from gibson.core.targets import TargetManager, TargetNotFoundError

# Define ScanType locally since we're removing ScanService dependency
class ScanType(str, Enum):
    """Scan type definitions."""
    QUICK = "quick"
    FULL = "full"
    CUSTOM = "custom"

app = typer.Typer(help="Security scanning operations")
console = Console()


async def _resolve_target(target_identifier: str) -> tuple[str, Optional[dict]]:
    """Resolve target identifier to URL and credentials.
    
    Args:
        target_identifier: Target name, ID, or URL
        
    Returns:
        Tuple of (resolved_url, credentials_dict)
    """
    # If it looks like a URL, use it directly
    if target_identifier.startswith(('http://', 'https://', 'ws://', 'wss://')):
        return target_identifier, None
    
    # If it looks like a file path, use it directly
    if '.' in target_identifier and ('/' in target_identifier or '\\' in target_identifier):
        return target_identifier, None
    
    # Try to resolve as target name or ID
    try:
        db_manager = DatabaseManager("sqlite:///gibson.db")
        await db_manager.initialize()
        
        async with db_manager.get_session() as session:
            target_manager = TargetManager(session)
            target = await target_manager.get_target(target_identifier)
            
            if target:
                console.print(f"[cyan]Resolved target:[/cyan] {target.name} -> {target.base_url}")
                
                # Get credentials if available
                credentials = None
                if target.requires_auth:
                    auth_status = target.get_authentication_status(target_manager.credential_manager)
                    if auth_status.get('has_credential'):
                        # Get actual credential for scanning
                        try:
                            credential = target_manager.credential_manager.retrieve_credential(target.id)
                            if credential and credential.token:
                                credentials = {
                                    'api_key': credential.token,
                                    'format': credential.key_format.value,
                                    'provider': credential.provider
                                }
                                console.print(f"[green]✓[/green] Using stored credentials")
                        except Exception as e:
                            console.print(f"[yellow]Warning: Could not load credentials: {e}[/yellow]")
                
                return target.base_url, credentials
            
        # Not found in database, use as-is
        return target_identifier, None
        
    except Exception as e:
        console.print(f"[yellow]Warning: Target resolution failed: {e}[/yellow]")
        return target_identifier, None


class ScanTypeChoice(str, Enum):
    """Scan type choices for CLI."""
    
    QUICK = "quick"
    FULL = "full"
    SPECIFIC = "specific"
    CUSTOM = "custom"


@app.command()
def quick(
    ctx: typer.Context,
    target: str = typer.Argument(help="Target name, URL, file, or model identifier"),
    modules: Optional[List[str]] = typer.Option(
        None,
        "--module",
        "-m",
        help="Specific modules to run (e.g., prompt-injection, data-poisoning)",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Perform dry run without executing attacks",
    ),
) -> None:
    """
    Perform a quick, non-intrusive security scan.
    
    This command runs a fast scan across all attack domains using lightweight modules.
    Target can be a registered target name, URL, or file path.
    
    Examples:
        gibson scan quick "OpenAI API"  # Use registered target
        gibson scan quick https://api.example.com  # Direct URL
        gibson scan quick model.pkl --module prompt-injection  # File
        gibson scan quick prod-api --output report.json --dry-run  # Named target with options
    """
    context: Context = ctx.obj
    
    async def _run_quick_scan():
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Resolving target...", total=None)
            
            # Resolve target (name/ID to URL + credentials)
            resolved_url, credentials = await _resolve_target(target)
            
            progress.update(task, description="Initializing scan...")
            
            # Initialize new Base orchestration system
            base = Base()
            
            progress.update(task, description="Initializing attack domains...")
            await base.initialize()
            
            progress.update(task, description="Fingerprinting target...")
            
            # Run scan using new Base orchestration with credentials
            result = await base.scan(
                target=resolved_url,
                scan_type=ScanType.QUICK,
                modules=modules,
                dry_run=dry_run,
                credentials=credentials,
            )
            
            progress.update(task, description="Scan complete", completed=True)
            
            return result
    
    try:
        # Run the async scan
        result = asyncio.run(_run_quick_scan())
        
        # Display results
        _display_results(result, output, context)
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan cancelled by user[/yellow]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Scan failed: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def full(
    ctx: typer.Context,
    target: str = typer.Argument(help="Target name, URL, file, or model identifier"),
    modules: Optional[List[str]] = typer.Option(
        None,
        "--module",
        "-m",
        help="Specific modules to run (e.g., prompt-injection, data-poisoning)",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Perform dry run without executing attacks",
    ),
    confirm: bool = typer.Option(
        False,
        "--confirm",
        help="Require confirmation for each test",
    ),
) -> None:
    """
    Perform a comprehensive security scan.
    
    This scan type runs all applicable modules across all attack domains and may take longer.
    Use with caution on production systems as it performs thorough testing.
    Target can be a registered target name, URL, or file path.
    
    Examples:
        gibson scan full "Production API"  # Use registered target
        gibson scan full https://api.example.com --confirm
        gibson scan full model.h5 --dry-run
        gibson scan full prod-api --output results.json
    """
    context: Context = ctx.obj
    
    async def _run_full_scan():
        # Warn about full scan
        if not dry_run and not confirm:
            console.print(
                "[yellow]Warning:[/yellow] Full scan may be intrusive and time-consuming.",
                style="bold",
            )
            if not typer.confirm("Do you want to continue?"):
                raise typer.Abort()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Resolving target...", total=None)
            
            # Resolve target (name/ID to URL + credentials)
            resolved_url, credentials = await _resolve_target(target)
            
            progress.update(task, description="Running comprehensive scan...")
            
            # Initialize new Base orchestration system
            base = Base()
            
            progress.update(task, description="Initializing attack domains...")
            await base.initialize()
            
            # Run scan using new Base orchestration with credentials
            result = await base.scan(
                target=resolved_url,
                scan_type=ScanType.FULL,
                modules=modules,
                dry_run=dry_run,
                require_confirmation=confirm,
                credentials=credentials,
            )
            
            progress.update(task, description="Scan complete", completed=True)
            return result
    
    try:
        # Run the async scan
        result = asyncio.run(_run_full_scan())
        
        # Display results
        _display_results(result, output, context)
        
    except typer.Abort:
        console.print("[yellow]Scan cancelled by user[/yellow]")
        raise typer.Exit(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan cancelled by user[/yellow]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Scan failed: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def custom(
    ctx: typer.Context,
    target: str = typer.Argument(help="Target name, URL, file, or model identifier"),
    domains: List[str] = typer.Option(
        None,
        "--domain",
        "-d",
        help="Specific attack domains to use (prompt, data, model, system, output)",
    ),
    modules: Optional[List[str]] = typer.Option(
        None,
        "--module",
        "-m",
        help="Specific modules to run (e.g., prompt-injection, data-poisoning)",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Perform dry run without executing attacks",
    ),
) -> None:
    """
    Perform a custom scan with selected attack domains.
    
    This command allows fine-grained control over which attack domains to include in the scan.
    Available domains: prompt, data, model, system, output
    Target can be a registered target name, URL, or file path.
    
    Examples:
        gibson scan custom "OpenAI API" --domain prompt --domain data
        gibson scan custom https://api.example.com --domain prompt --domain data
        gibson scan custom model.pkl --domain model --domain system
        gibson scan custom api.yaml --domain output --dry-run
        gibson scan custom prod-api --module specific-test --output custom-report.json
    """
    context: Context = ctx.obj
    
    async def _run_custom_scan():
        # Validate domains
        valid_domains = ["prompt", "data", "model", "system", "output"]
        if domains:
            invalid = [d for d in domains if d.lower() not in valid_domains]
            if invalid:
                console.print(
                    f"[red]Invalid domains: {', '.join(invalid)}[/red]",
                    style="bold",
                )
                console.print(f"Valid domains: {', '.join(valid_domains)}")
                raise typer.Exit(1)
        else:
            # Default to all domains if none specified
            domains_list = valid_domains
        
        domains_list = domains or valid_domains
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Resolving target...", total=None)
            
            # Resolve target (name/ID to URL + credentials)
            resolved_url, credentials = await _resolve_target(target)
            
            progress.update(task, description="Initializing custom scan...")
            
            # Initialize new Base orchestration system
            base = Base()
            
            progress.update(task, description=f"Initializing {len(domains_list)} attack domains...")
            await base.initialize()
            
            # Filter modules based on selected domains
            if not modules and domains_list:
                # Auto-select modules from specified domains
                progress.update(task, description="Selecting domain modules...")
                # Base will handle domain-based module selection internally
            
            # Run scan using new Base orchestration with custom configuration and credentials
            result = await base.scan(
                target=resolved_url,
                scan_type=ScanType.CUSTOM,
                modules=modules,
                domains=domains_list,  # Pass domains to Base for filtering
                dry_run=dry_run,
                credentials=credentials,
            )
            
            progress.update(task, description="Custom scan complete", completed=True)
            return result, domains_list
    
    try:
        # Run the async scan
        result, active_domains = asyncio.run(_run_custom_scan())
        
        # Display results with domain focus
        console.print(f"\n[bold]Custom Scan - Active Domains: {', '.join(active_domains)}[/bold]")
        _display_results(result, output, context)
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan cancelled by user[/yellow]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Scan failed: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def list(
    ctx: typer.Context,
    limit: int = typer.Option(10, "--limit", "-l", help="Number of scans to show"),
    status: Optional[str] = typer.Option(None, "--status", help="Filter by status"),
) -> None:
    """
    List recent scans.
    
    Examples:
        gibson scan list
        gibson scan list --limit 20
        gibson scan list --status completed
    """
    context: Context = ctx.obj
    
    # Use Base orchestration for listing scans
    base = Base()
    asyncio.run(base.initialize())
    
    # Get scans from database directly
    from gibson.db import ScanRecord
    from gibson.db.manager import DatabaseManager
    from sqlalchemy.future import select
    
    async def get_scans():
        from gibson.models.config import DatabaseConfigModel
        config = DatabaseConfigModel()
        db_url = config.url.replace("~", str(Path.home()))
        db_manager = DatabaseManager(db_url)
        async with db_manager.get_session() as session:
            query = select(ScanRecord).order_by(ScanRecord.created_at.desc()).limit(limit)
            if status:
                query = query.where(ScanRecord.status == status)
            result = await session.execute(query)
            return result.scalars().all()
    
    scans = asyncio.run(get_scans())
    
    if not scans:
        console.print("No scans found")
        return
    
    table = Table(title="Recent Scans")
    table.add_column("ID", style="cyan")
    table.add_column("Target")
    table.add_column("Type")
    table.add_column("Status")
    table.add_column("Findings")
    table.add_column("Duration")
    table.add_column("Date")
    
    for scan in scans:
        status_style = "green" if scan.status == "completed" else "yellow"
        findings_style = "red" if scan.findings_count > 0 else "green"
        
        table.add_row(
            str(scan.id),
            scan.target,
            scan.scan_type,
            f"[{status_style}]{scan.status}[/{status_style}]",
            f"[{findings_style}]{scan.findings_count}[/{findings_style}]",
            scan.duration,
            scan.date.strftime("%Y-%m-%d %H:%M"),
        )
    
    console.print(table)


@app.command()
def stop(
    ctx: typer.Context,
    scan_id: str = typer.Argument(help="Scan ID to stop"),
) -> None:
    """
    Stop a running scan.
    
    Examples:
        gibson scan stop abc123
    """
    context: Context = ctx.obj
    
    # Use Base to stop scan
    base = Base()
    asyncio.run(base.initialize())
    
    # Stop scan through Base (would need to implement stop method in Base)
    # For now, update scan status in database directly
    from gibson.db import ScanRecord
    from gibson.db.manager import DatabaseManager
    from sqlalchemy.future import select
    from datetime import datetime
    
    async def stop_scan_in_db():
        from gibson.models.config import DatabaseConfigModel
        config = DatabaseConfigModel()
        db_url = config.url.replace("~", str(Path.home()))
        db_manager = DatabaseManager(db_url)
        async with db_manager.get_session() as session:
            query = select(ScanRecord).where(ScanRecord.id == scan_id)
            result = await session.execute(query)
            scan = result.scalar_one_or_none()
            if scan and scan.status == "running":
                scan.status = "stopped"
                scan.ended_at = datetime.utcnow()
                await session.commit()
                return True
            return False
    
    if asyncio.run(stop_scan_in_db()):
        console.print(f"[green]✓[/green] Scan {scan_id} stopped")
    else:
        console.print(f"[red]✗[/red] Failed to stop scan {scan_id}")


def _display_results(result: ScanResult, output: Optional[Path], context: Context) -> None:
    """Display scan results organized by attack domain."""
    # Group findings by domain
    domain_findings = {}
    for finding in result.findings:
        # Extract domain from module path (e.g., "prompts.prompt_injection" -> "prompts")
        domain = finding.module.split('.')[0] if '.' in finding.module else "general"
        if domain not in domain_findings:
            domain_findings[domain] = []
        domain_findings[domain].append(finding)
    
    # Create results table with domain grouping
    table = Table(title="Scan Results by Domain")
    table.add_column("Domain", style="magenta")
    table.add_column("Module", style="cyan")
    table.add_column("Severity", style="bold")
    table.add_column("Finding")
    table.add_column("Confidence")
    
    # Display findings grouped by domain
    for domain in sorted(domain_findings.keys()):
        for finding in domain_findings[domain]:
            severity_color = {
                "CRITICAL": "red",
                "HIGH": "red",
                "MEDIUM": "yellow",
                "LOW": "blue",
                "INFO": "white",
            }.get(finding.severity, "white")
            
            table.add_row(
                domain.capitalize(),
                finding.module,
                f"[{severity_color}]{finding.severity}[/{severity_color}]",
                finding.title,
                f"{finding.confidence}%",
            )
    
    console.print(table)
    
    # Summary with domain statistics
    console.print(f"\n[bold]Summary:[/bold]")
    console.print(f"  Target: {result.target}")
    console.print(f"  Duration: {result.duration}")
    console.print(f"  Modules Run: {result.modules_run}")
    console.print(f"  Total Findings: {len(result.findings)}")
    
    # Domain statistics
    if domain_findings:
        console.print(f"\n[bold]Domain Statistics:[/bold]")
        for domain in sorted(domain_findings.keys()):
            count = len(domain_findings[domain])
            console.print(f"  {domain.capitalize()}: {count} findings")
    
    if result.findings:
        critical_count = sum(1 for f in result.findings if f.severity == "CRITICAL")
        high_count = sum(1 for f in result.findings if f.severity == "HIGH")
        
        if critical_count > 0:
            console.print(f"  [red]Critical: {critical_count}[/red]")
        if high_count > 0:
            console.print(f"  [red]High: {high_count}[/red]")
    
    # Save output if requested
    if output:
        result.save(output, format=context.output_format or "json")
        console.print(f"\n[green]✓[/green] Results saved to: {output}")