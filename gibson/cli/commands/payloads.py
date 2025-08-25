"""Payload management commands."""

import asyncio
from pathlib import Path
from typing import Optional, List

import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.tree import Tree

from gibson.core.base import Base
from gibson.core.payloads.manager import PayloadManager
from gibson.models.payload import PayloadModel
from gibson.models.domain import AttackDomain, ModuleCategory, Severity
from gibson.core.payloads.types import PayloadQuery
from gibson.core.payloads.validator import PayloadValidator
from gibson.cli.output import render_error, render_success, render_warning, render_info

app = typer.Typer(help="Payload management")
console = Console()


@app.command("list")
def list_payloads(
    domain: Optional[str] = typer.Option(None, "--domain", "-d", help="Filter by domain"),
    attack_type: Optional[str] = typer.Option(None, "--type", "-t", help="Filter by attack type"),
    severity: Optional[str] = typer.Option(None, "--severity", "-s", help="Filter by severity"),
    tags: Optional[str] = typer.Option(None, "--tags", help="Filter by tags (comma-separated)"),
    search: Optional[str] = typer.Option(None, "--search", "-q", help="Search payload content"),
    limit: int = typer.Option(50, "--limit", "-l", help="Maximum results to show"),
    offset: int = typer.Option(0, "--offset", help="Result offset for pagination"),
    format: str = typer.Option("table", "--format", "-f", help="Output format (table, json, csv)")
):
    """List payloads with filtering and search."""
    async def _list():
        try:
            # Initialize Base to set up database
            base = Base()
            await base.initialize()
            
            # Build query
            query = PayloadQuery(
                search=search,
                domain=domain,  # Will be converted in PayloadQuery
                attack_type=attack_type,
                severity=severity,  # Will be converted in PayloadQuery
                tags=tags.split(",") if tags else None,
                limit=limit,
                offset=offset
            )
            
            async with PayloadManager() as manager:
                payloads, total_count = await manager.query_payloads(query)
                
                if format == "table":
                    _render_payload_table(payloads, total_count, offset)
                elif format == "json":
                    _render_payload_json(payloads)
                elif format == "csv":
                    _render_payload_csv(payloads)
                else:
                    render_error(f"Unknown format: {format}")
                    
        except Exception as e:
            render_error(f"Failed to list payloads: {e}")
    
    asyncio.run(_list())


@app.command("show")
def show_payload(
    payload_id: Optional[int] = typer.Argument(None, help="Payload ID"),
    hash: Optional[str] = typer.Option(None, "--hash", help="Payload hash"),
    name: Optional[str] = typer.Option(None, "--name", help="Payload name (search)"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed information")
):
    """Show detailed payload information."""
    async def _show():
        try:
            # Initialize Base to set up database
            base = Base()
            await base.initialize()
            
            async with PayloadManager() as manager:
                payload = None
                
                if payload_id:
                    payload = await manager.get_payload_by_id(payload_id)
                elif hash:
                    payload = await manager.get_payload_by_hash(hash)
                elif name:
                    query = PayloadQuery(search=name, limit=1)
                    payloads, _ = await manager.query_payloads(query)
                    payload = payloads[0] if payloads else None
                else:
                    render_error("Must specify --id, --hash, or --name")
                    return
                
                if not payload:
                    render_error("Payload not found")
                    return
                
                _render_payload_details(payload, verbose)
                
        except Exception as e:
            render_error(f"Failed to show payload: {e}")
    
    asyncio.run(_show())


@app.command("import")
def import_payloads(
    source: str = typer.Argument(..., help="Source file or directory path"),
    format: str = typer.Option("auto", "--format", "-f", help="Source format (auto, json, yaml, text)"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be imported without importing"),
    force: bool = typer.Option(False, "--force", help="Force import even if payloads exist")
):
    """Import payloads from file or directory."""
    async def _import():
        try:
            # Initialize Base to set up database
            base = Base()
            await base.initialize()
            
            source_path = Path(source)
            if not source_path.exists():
                render_error(f"Source path does not exist: {source}")
                return
            
            async with PayloadManager() as manager:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    console=console
                ) as progress:
                    task = progress.add_task("Importing payloads...", total=None)
                    
                    result = await manager.import_payloads(source_path, format)
                    
                    progress.update(task, completed=True)
                
                # Display results
                _render_import_results(result)
                
        except Exception as e:
            render_error(f"Failed to import payloads: {e}")
    
    asyncio.run(_import())


@app.command("sync")
def sync_repository(
    repository_url: str = typer.Argument(..., help="Full Git repository URL (e.g., https://github.com/owner/repo.git or git@github.com:owner/repo.git)"),
    branch: str = typer.Option("main", "--branch", "-b", help="Git branch to sync"),
    domains: Optional[str] = typer.Option(None, "--domains", help="Domains to sync (comma-separated)"),
    force: bool = typer.Option(False, "--force", help="Force sync even if no changes")
):
    """Synchronize payloads from Git repository using native Git operations.
    
    Authentication is handled automatically:
    1. First tries public access (no authentication)
    2. Then tries SSH keys if available
    3. Finally prompts for token if needed
    
    Examples:
        gibson payloads sync https://github.com/owner/repo.git
        gibson payloads sync git@github.com:owner/repo.git --branch develop
        gibson payloads sync https://gitlab.com/owner/repo.git --force
    """
    async def _sync():
        try:
            # Initialize Base to set up database
            base = Base()
            await base.initialize()
            
            # Parse and validate URL
            from gibson.core.payloads.git_models import GitURL
            try:
                git_url = GitURL.from_url(repository_url)
            except ValueError as e:
                render_error(f"Invalid repository URL: {e}")
                render_info("Example URLs:")
                render_info("  • https://github.com/owner/repo.git")
                render_info("  • git@github.com:owner/repo.git")
                render_info("  • https://gitlab.com/owner/repo.git")
                render_info("  • git@gitlab.com:owner/repo.git")
                return
            
            target_domains = None
            if domains:
                target_domains = [PayloadDomain(d.strip()) for d in domains.split(",")]
            
            async with PayloadManager() as manager:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    console=console
                ) as progress:
                    task = progress.add_task(f"Syncing {git_url.repo} from {git_url.host}...", total=None)
                    
                    result = await manager.sync_repository(
                        repository_url, branch, target_domains, force
                    )
                    
                    progress.update(task, completed=True)
                    
                    # Show authentication method used
                    if result.auth_method:
                        auth_display = {
                            "public": "🌐 Public access",
                            "ssh_key": "🔑 SSH key",
                            "token": "🔐 Personal access token"
                        }.get(result.auth_method, result.auth_method)
                        render_info(f"Authentication: {auth_display}")
                
                # Display results
                _render_sync_results(result)
                
        except Exception as e:
            render_error(f"Failed to sync repository: {e}")
    
    asyncio.run(_sync())


@app.command("validate")
def validate_payloads(
    payload_id: Optional[int] = typer.Option(None, "--id", help="Validate specific payload ID"),
    domain: Optional[str] = typer.Option(None, "--domain", help="Validate payloads in domain"),
    all: bool = typer.Option(False, "--all", help="Validate all payloads"),
    fix: bool = typer.Option(False, "--fix", help="Attempt to fix validation issues"),
    report: bool = typer.Option(False, "--report", help="Generate detailed validation report")
):
    """Validate payloads for quality and correctness."""
    async def _validate():
        try:
            # Initialize Base to set up database
            base = Base()
            await base.initialize()
            
            validator = PayloadValidator()
            
            async with PayloadManager() as manager:
                payloads = []
                
                if payload_id:
                    payload = await manager.get_payload_by_id(payload_id)
                    if payload:
                        payloads = [payload]
                elif domain:
                    query = PayloadQuery(domain=PayloadDomain(domain), limit=None)
                    payloads, _ = await manager.query_payloads(query)
                elif all:
                    query = PayloadQuery(limit=None)
                    payloads, _ = await manager.query_payloads(query)
                else:
                    render_error("Must specify --id, --domain, or --all")
                    return
                
                if not payloads:
                    render_info("No payloads found to validate")
                    return
                
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    console=console
                ) as progress:
                    task = progress.add_task(f"Validating {len(payloads)} payloads...", total=len(payloads))
                    
                    results = {}
                    for payload in payloads:
                        result = validator.validate_payload(payload)
                        results[payload.name] = result
                        progress.advance(task)
                
                # Display results
                _render_validation_results(results, validator, report)
                
        except Exception as e:
            render_error(f"Failed to validate payloads: {e}")
    
    asyncio.run(_validate())


@app.command("metrics")
def show_metrics(
    detailed: bool = typer.Option(False, "--detailed", "-d", help="Show detailed metrics"),
    export: Optional[str] = typer.Option(None, "--export", help="Export metrics to file (json/csv)")
):
    """Show payload system metrics and statistics."""
    async def _metrics():
        try:
            # Initialize Base to set up database
            base = Base()
            await base.initialize()
            
            async with PayloadManager() as manager:
                metrics = await manager.get_metrics()
                
                if detailed:
                    _render_detailed_metrics(metrics)
                else:
                    _render_basic_metrics(metrics)
                
                if export:
                    _export_metrics(metrics, export)
                    
        except Exception as e:
            render_error(f"Failed to get metrics: {e}")
    
    asyncio.run(_metrics())


@app.command("cleanup")
def cleanup_system(
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be cleaned without cleaning"),
    aggressive: bool = typer.Option(False, "--aggressive", help="Perform aggressive cleanup")
):
    """Clean up payload system (orphaned records, expired cache, etc.)."""
    async def _cleanup():
        try:
            async with PayloadManager() as manager:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    console=console
                ) as progress:
                    task = progress.add_task("Cleaning up system...", total=None)
                    
                    if not dry_run:
                        results = await manager.cleanup_system()
                    else:
                        results = {"note": "Dry run - no actual cleanup performed"}
                    
                    progress.update(task, completed=True)
                
                _render_cleanup_results(results, dry_run)
                
        except Exception as e:
            render_error(f"Failed to cleanup system: {e}")
    
    asyncio.run(_cleanup())


@app.command("auth")
def manage_auth(
    setup: bool = typer.Option(False, "--setup", help="Setup GitHub authentication"),
    test: bool = typer.Option(False, "--test", help="Test GitHub authentication"),
    remove: bool = typer.Option(False, "--remove", help="Remove GitHub authentication"),
    status: bool = typer.Option(False, "--status", help="Show authentication status")
):
    """Manage GitHub authentication for payload repositories."""
    auth_manager = GitHubAuthManager()
    
    if setup:
        _setup_github_auth(auth_manager)
    elif test:
        _test_github_auth(auth_manager)
    elif remove:
        _remove_github_auth(auth_manager)
    elif status:
        _show_auth_status(auth_manager)
    else:
        render_info("Use --setup, --test, --remove, or --status")


# Helper functions for rendering output

def _render_payload_table(payloads, total_count, offset):
    """Render payloads in table format."""
    table = Table(title=f"Payloads ({len(payloads)} of {total_count})")
    
    table.add_column("ID", style="cyan")
    table.add_column("Name", style="white")
    table.add_column("Domain", style="green")
    table.add_column("Attack Type", style="yellow")
    table.add_column("Severity", style="red")
    table.add_column("Tags", style="blue")
    table.add_column("Success Rate", style="magenta")
    
    for payload in payloads:
        tags_str = ", ".join(payload.tags[:3]) + ("..." if len(payload.tags) > 3 else "")
        success_rate = f"{payload.success_rate:.1%}" if payload.success_rate else "N/A"
        
        table.add_row(
            str(payload.id),
            payload.name[:30] + ("..." if len(payload.name) > 30 else ""),
            payload.domain.value,
            payload.category.value,  # Use category instead of attack_type
            payload.severity.value,
            tags_str,
            success_rate
        )
    
    console.print(table)
    
    if offset + len(payloads) < total_count:
        render_info(f"Showing results {offset + 1}-{offset + len(payloads)} of {total_count}")


def _render_payload_details(payload, verbose):
    """Render detailed payload information."""
    panel_content = f"""
[bold]Name:[/bold] {payload.name}
[bold]ID:[/bold] {payload.id}
[bold]Hash:[/bold] {payload.hash}
[bold]Domain:[/bold] {payload.domain.value}
[bold]Category:[/bold] {payload.category.value}
[bold]Severity:[/bold] {payload.severity.value}
[bold]Status:[/bold] {'active'}
[bold]Author:[/bold] {payload.author or 'Unknown'}
[bold]Version:[/bold] {getattr(payload, 'version', '1.0.0')}
[bold]Created:[/bold] {payload.created_at.strftime('%Y-%m-%d %H:%M:%S') if payload.created_at else 'Unknown'}
[bold]Tags:[/bold] {', '.join(payload.tags) if payload.tags else 'None'}
"""
    
    if verbose:
        panel_content += f"""
[bold]Description:[/bold] {payload.description or 'None'}
[bold]Expected Indicators:[/bold] {', '.join(payload.expected_indicators) if payload.expected_indicators else 'None'}
[bold]Success Rate:[/bold] {f'{payload.success_rate:.1%}' if payload.success_rate else 'Unknown'}
[bold]Usage Count:[/bold] {payload.usage_count}
[bold]Last Used:[/bold] {payload.last_used.strftime('%Y-%m-%d %H:%M:%S') if payload.last_used else 'Never'}
[bold]File Path:[/bold] {payload.file_path or 'None'}
[bold]Source:[/bold] {payload.source_repo or 'Local'}
[bold]References:[/bold] {', '.join(str(ref) for ref in payload.references) if payload.references else 'None'}

[bold]Content:[/bold]
{payload.content[:500]}{'...' if len(payload.content) > 500 else ''}
"""
    
    panel = Panel(panel_content, title="Payload Details", border_style="blue")
    console.print(panel)


def _render_import_results(result):
    """Render import operation results."""
    if result.success:
        render_success(f"Import completed in {result.processing_time_ms}ms")
    else:
        render_error("Import failed")
    
    table = Table(title="Import Results")
    table.add_column("Metric", style="cyan")
    table.add_column("Count", style="white")
    
    table.add_row("Imported", str(result.imported_count))
    table.add_row("Updated", str(result.updated_count))
    table.add_row("Skipped", str(result.skipped_count))
    table.add_row("Errors", str(result.error_count))
    table.add_row("Total Processed", str(result.total_processed))
    table.add_row("Success Rate", f"{result.success_rate:.1%}")
    
    console.print(table)
    
    if result.errors:
        render_warning("Errors occurred during import:")
        for error in result.errors[:5]:  # Show first 5 errors
            console.print(f"  • {error}")
        if len(result.errors) > 5:
            console.print(f"  ... and {len(result.errors) - 5} more errors")


def _render_sync_results(result):
    """Render sync operation results."""
    if result.success:
        render_success(f"Repository synchronized successfully")
    else:
        render_error("Sync failed")
    
    table = Table(title=f"Sync Results: {result.repository}")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="white")
    
    table.add_row("Branch", result.branch)
    if result.auth_method:
        auth_display = {
            "public": "Public (no auth)",
            "ssh_key": "SSH Key",
            "token": "Access Token"
        }.get(result.auth_method, result.auth_method)
        table.add_row("Authentication", auth_display)
    if result.clone_method:
        table.add_row("Clone Method", result.clone_method.title())
    table.add_row("New Payloads", str(len(result.new_payloads) if result.new_payloads else 0))
    table.add_row("Updated Payloads", str(len(result.updated_payloads) if result.updated_payloads else 0))
    if result.total_processed:
        table.add_row("Total Processed", str(result.total_processed))
    if result.sync_duration_ms:
        table.add_row("Duration", f"{result.sync_duration_ms / 1000:.2f}s")
    if result.last_commit:
        table.add_row("Commit", result.last_commit[:8])
    
    console.print(table)
    
    if result.errors:
        render_warning("Errors occurred during sync:")
        for error in result.errors[:5]:
            console.print(f"  • {error}")


def _render_validation_results(results, validator, report):
    """Render validation results."""
    summary = validator.get_validation_summary(results)
    
    # Summary table
    table = Table(title="Validation Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="white")
    
    table.add_row("Total Payloads", str(summary["total_payloads"]))
    table.add_row("Valid", str(summary["valid_payloads"]))
    table.add_row("Invalid", str(summary["invalid_payloads"]))
    table.add_row("Validation Rate", f"{summary['validation_rate']:.1f}%")
    table.add_row("Average Quality", f"{summary['average_quality_score']}/100")
    table.add_row("Total Errors", str(summary["total_errors"]))
    table.add_row("Total Warnings", str(summary["total_warnings"]))
    
    console.print(table)
    
    # Quality distribution
    dist = summary["quality_distribution"]
    quality_table = Table(title="Quality Distribution")
    quality_table.add_column("Quality", style="cyan")
    quality_table.add_column("Count", style="white")
    
    quality_table.add_row("Excellent (80+)", str(dist["excellent"]))
    quality_table.add_row("Good (60-79)", str(dist["good"]))
    quality_table.add_row("Fair (40-59)", str(dist["fair"]))
    quality_table.add_row("Poor (<40)", str(dist["poor"]))
    
    console.print(quality_table)
    
    if report:
        _render_detailed_validation_report(results)


def _render_detailed_validation_report(results):
    """Render detailed validation report."""
    invalid_payloads = {name: result for name, result in results.items() if not result.is_valid}
    
    if invalid_payloads:
        console.print("\n[bold red]Invalid Payloads:[/bold red]")
        for name, result in invalid_payloads.items():
            console.print(f"\n[bold]{name}[/bold]")
            for error in result.errors:
                console.print(f"  ❌ {error}")
            for warning in result.warnings:
                console.print(f"  ⚠️  {warning}")


def _render_basic_metrics(metrics):
    """Render basic metrics."""
    table = Table(title="Payload System Metrics")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="white")
    
    table.add_row("Total Payloads", str(metrics.total_payloads))
    table.add_row("Active Payloads", str(metrics.active_payloads))
    table.add_row("Deprecated Payloads", str(metrics.deprecated_payloads))
    table.add_row("Experimental Payloads", str(metrics.experimental_payloads))
    
    if metrics.avg_success_rate:
        table.add_row("Average Success Rate", f"{metrics.avg_success_rate:.1%}")
    
    if metrics.cache_hit_rate:
        table.add_row("Cache Hit Rate", f"{metrics.cache_hit_rate:.1%}")
    
    table.add_row("Total Storage", f"{metrics.total_size_bytes / 1024 / 1024:.1f} MB")
    
    console.print(table)


def _render_detailed_metrics(metrics):
    """Render detailed metrics."""
    _render_basic_metrics(metrics)
    
    # Domain distribution
    if metrics.domain_counts:
        domain_table = Table(title="Domain Distribution")
        domain_table.add_column("Domain", style="cyan")
        domain_table.add_column("Count", style="white")
        domain_table.add_column("Percentage", style="yellow")
        
        for domain, count in metrics.domain_counts.items():
            percentage = (count / metrics.total_payloads * 100) if metrics.total_payloads > 0 else 0
            domain_table.add_row(domain.value, str(count), f"{percentage:.1f}%")
        
        console.print(domain_table)


def _render_cleanup_results(results, dry_run):
    """Render cleanup results."""
    if dry_run:
        render_info("Dry run completed - no actual cleanup performed")
    else:
        render_success(f"Cleanup completed in {results.get('total_cleanup_time_ms', 0)}ms")
    
    table = Table(title="Cleanup Results")
    table.add_column("Component", style="cyan")
    table.add_column("Items Cleaned", style="white")
    
    table.add_row("Orphaned Records", str(results.get("orphaned_records", 0)))
    table.add_row("Expired Cache Entries", str(results.get("expired_cache_entries", 0)))
    table.add_row("Empty Directories", str(results.get("empty_directories", 0)))
    
    console.print(table)


def _setup_github_auth(auth_manager):
    """Setup GitHub authentication."""
    console.print("[bold]GitHub Authentication Setup[/bold]")
    console.print("Please provide your GitHub credentials for payload repository access.")
    
    username = typer.prompt("GitHub username")
    token = typer.prompt("GitHub token (personal access token)", hide_input=True)
    
    if auth_manager.store_credentials(username, token):
        render_success("GitHub credentials stored successfully")
        
        # Test credentials
        success, error = auth_manager.test_credentials()
        if success:
            render_success("Credentials verified successfully")
        else:
            render_warning(f"Credentials stored but verification failed: {error}")
    else:
        render_error("Failed to store GitHub credentials")


def _test_github_auth(auth_manager):
    """Test GitHub authentication."""
    if not auth_manager.has_credentials():
        render_error("No GitHub credentials found. Use --setup first.")
        return
    
    success, error = auth_manager.test_credentials()
    if success:
        render_success("GitHub authentication is working")
        
        # Show rate limit info
        rate_info = auth_manager.get_rate_limit_info()
        if rate_info:
            remaining = rate_info.get("rate", {}).get("remaining", "Unknown")
            limit = rate_info.get("rate", {}).get("limit", "Unknown")
            render_info(f"Rate limit: {remaining}/{limit} requests remaining")
    else:
        render_error(f"GitHub authentication failed: {error}")


def _remove_github_auth(auth_manager):
    """Remove GitHub authentication."""
    if not auth_manager.has_credentials():
        render_info("No GitHub credentials found")
        return
    
    confirm = typer.confirm("Are you sure you want to remove GitHub credentials?")
    if confirm:
        if auth_manager.remove_credentials():
            render_success("GitHub credentials removed successfully")
        else:
            render_error("Failed to remove GitHub credentials")
    else:
        render_info("Operation cancelled")


def _show_auth_status(auth_manager):
    """Show GitHub authentication status."""
    security_info = auth_manager.get_security_info()
    
    table = Table(title="GitHub Authentication Status")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="white")
    
    table.add_row("Has Credentials", "✅ Yes" if security_info["has_credentials"] else "❌ No")
    table.add_row("Auth Method", security_info["auth_method"])
    table.add_row("Keyring Backend", security_info["keyring_backend"])
    table.add_row("Encryption", "✅ Enabled" if security_info["encryption_enabled"] else "❌ Disabled")
    
    if security_info["has_credentials"]:
        if "credentials_valid" in security_info:
            valid_status = "✅ Valid" if security_info["credentials_valid"] else "❌ Invalid"
            table.add_row("Credentials Valid", valid_status)
            
            if security_info.get("last_error"):
                table.add_row("Last Error", security_info["last_error"])
    
    console.print(table)


def _render_payload_json(payloads):
    """Render payloads in JSON format."""
    import json
    
    payload_data = [payload.model_dump() for payload in payloads]
    console.print(json.dumps(payload_data, indent=2, default=str))


def _render_payload_csv(payloads):
    """Render payloads in CSV format."""
    import csv
    import io
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Header
    writer.writerow([
        "ID", "Name", "Domain", "Category", 
        "Severity", "Tags", "Success Rate", "Created", "Author"
    ])
    
    # Data
    for payload in payloads:
        writer.writerow([
            payload.id,
            payload.name,
            payload.domain.value,
            payload.category.value,
            payload.severity.value,
            ",".join(payload.tags) if payload.tags else "",
            payload.success_rate or "",
            payload.created_at.isoformat() if payload.created_at else "",
            payload.author or ""
        ])
    
    console.print(output.getvalue())


def _export_metrics(metrics, export_path):
    """Export metrics to file."""
    import json
    
    metrics_data = {
        "total_payloads": metrics.total_payloads,
        "active_payloads": metrics.active_payloads,
        "deprecated_payloads": metrics.deprecated_payloads,
        "experimental_payloads": metrics.experimental_payloads,
        "domain_counts": {k.value: v for k, v in metrics.domain_counts.items()},
        "avg_success_rate": metrics.avg_success_rate,
        "cache_hit_rate": metrics.cache_hit_rate,
        "total_size_bytes": metrics.total_size_bytes,
        "export_timestamp": "2024-01-01T00:00:00Z"  # Would be current timestamp
    }
    
    try:
        with open(export_path, 'w') as f:
            if export_path.endswith('.json'):
                json.dump(metrics_data, f, indent=2)
            elif export_path.endswith('.csv'):
                import csv
                writer = csv.writer(f)
                writer.writerow(["Metric", "Value"])
                for key, value in metrics_data.items():
                    writer.writerow([key, value])
        
        render_success(f"Metrics exported to {export_path}")
    except Exception as e:
        render_error(f"Failed to export metrics: {e}")


if __name__ == "__main__":
    app()