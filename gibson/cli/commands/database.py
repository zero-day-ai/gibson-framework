"""Database management CLI commands."""

import asyncio
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from gibson.db.manager import DatabaseManager
from gibson.core.migrations import MigrationManager
from gibson.core.migrations.safety import MigrationSafety
from gibson.db.utils.health_check import DatabaseHealthChecker
from gibson.db.utils.schema_analyzer import SchemaAnalyzer, SeverityLevel

console = Console()
app = typer.Typer(help="Database management commands")


@app.command()
def init(
    force: bool = typer.Option(
        False, "--force", "-f", help="Force initialization even if database exists"
    )
) -> None:
    """Initialize the database."""

    async def run():
        try:
            import os
            database_url = os.getenv("GIBSON_DATABASE_URL", "sqlite:///./gibson.db")
            db_manager = DatabaseManager(database_url)
            await db_manager.initialize(auto_migrate=True)
            console.print("[green]✓[/green] Database initialized successfully")
        except Exception as e:
            console.print(f"[red]✗[/red] Failed to initialize database: {e}")
            raise typer.Exit(1)

    asyncio.run(run())


@app.command()
def migrate(
    message: Optional[str] = typer.Argument(None, help="Migration message"),
    auto: bool = typer.Option(
        True, "--auto/--no-auto", help="Auto-generate migration from model changes"
    ),
    sql: bool = typer.Option(False, "--sql", help="Generate SQL script only"),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Show what would be done without executing"
    ),
) -> None:
    """Create and apply database migrations."""

    async def run():
        try:
            manager = MigrationManager()

            if message:
                # Create new migration
                console.print(f"Creating migration: {message}")
                if not dry_run:
                    revision = await manager.create_migration(message, autogenerate=auto, sql=sql)
                    console.print(f"[green]✓[/green] Created migration: {revision}")
                else:
                    console.print("[yellow]Dry run - no migration created[/yellow]")
            else:
                # Apply pending migrations
                status = await manager.get_status()

                if status.needs_migration:
                    console.print(f"Found {len(status.pending_migrations)} pending migration(s)")

                    # Show pending migrations
                    table = Table(title="Pending Migrations")
                    table.add_column("Revision", style="cyan")
                    table.add_column("Description", style="white")

                    for migration in status.pending_migrations:
                        table.add_row(
                            migration.revision[:8], migration.description or "No description"
                        )

                    console.print(table)

                    if not dry_run:
                        # Run safety checks
                        safety = MigrationSafety()
                        passed, checks = safety.run_safety_checks()

                        if not passed:
                            console.print("[yellow]⚠ Safety checks failed[/yellow]")
                            for check in checks:
                                if not check.passed:
                                    console.print(
                                        f"  [red]✗[/red] {check.check_name}: {check.message}"
                                    )

                            if not typer.confirm("Continue anyway?"):
                                raise typer.Exit(1)

                        # Create backup
                        console.print("Creating database backup...")
                        backup = safety.create_backup(
                            migration_revision=status.head_revision,
                            description="Pre-migration backup",
                        )
                        console.print(f"[green]✓[/green] Backup created: {backup.backup_id}")

                        # Apply migrations
                        console.print("Applying migrations...")
                        await manager.upgrade()
                        console.print("[green]✓[/green] Migrations applied successfully")
                    else:
                        console.print("[yellow]Dry run - no migrations applied[/yellow]")
                else:
                    console.print("[green]✓[/green] Database is up to date")

        except Exception as e:
            console.print(f"[red]✗[/red] Migration failed: {e}")
            raise typer.Exit(1)

    asyncio.run(run())


@app.command()
def status() -> None:
    """Show database migration status."""

    async def run():
        try:
            manager = MigrationManager()
            status = await manager.get_status()

            # Status panel
            status_text = f"""
Current Revision: {status.current_revision or 'None'}
Head Revision: {status.head_revision or 'None'}
Status: {'[green]Up to date[/green]' if status.is_up_to_date else '[yellow]Migrations pending[/yellow]'}
"""
            console.print(Panel(status_text.strip(), title="Migration Status"))

            # Pending migrations
            if status.pending_migrations:
                table = Table(title="Pending Migrations")
                table.add_column("Revision", style="cyan")
                table.add_column("Description", style="white")
                table.add_column("Created", style="dim")

                for migration in status.pending_migrations:
                    table.add_row(
                        migration.revision[:8],
                        migration.description or "No description",
                        migration.create_date.strftime("%Y-%m-%d %H:%M")
                        if migration.create_date
                        else "Unknown",
                    )

                console.print(table)

            # Applied migrations
            if status.applied_migrations:
                table = Table(title="Applied Migrations")
                table.add_column("Revision", style="cyan")
                table.add_column("Description", style="white")
                table.add_column("Status", style="dim")

                for migration in status.applied_migrations[:5]:  # Show last 5
                    table.add_row(
                        migration.revision[:8],
                        migration.description or "No description",
                        "[green]✓[/green] Current" if migration.is_current else "",
                    )

                console.print(table)

                if len(status.applied_migrations) > 5:
                    console.print(f"[dim]... and {len(status.applied_migrations) - 5} more[/dim]")

        except Exception as e:
            console.print(f"[red]✗[/red] Failed to get status: {e}")
            raise typer.Exit(1)

    asyncio.run(run())


@app.command()
def rollback(
    steps: int = typer.Argument(1, help="Number of migrations to rollback"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation"),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Show what would be done without executing"
    ),
) -> None:
    """Rollback database migrations."""

    async def run():
        try:
            manager = MigrationManager()
            safety = MigrationSafety()

            # Get current status
            status = await manager.get_status()

            if not status.current_revision:
                console.print("[yellow]No migrations to rollback[/yellow]")
                return

            # Calculate target revision
            target = f"-{steps}"

            # Show rollback plan
            console.print(f"[yellow]⚠ Rollback Plan[/yellow]")
            console.print(f"  Current: {status.current_revision[:8]}")
            console.print(f"  Target: {steps} step(s) back")

            if not dry_run:
                if not force:
                    if not typer.confirm("Are you sure you want to rollback?"):
                        raise typer.Exit(0)

                # Create backup
                console.print("Creating database backup...")
                backup = safety.create_backup(
                    migration_revision=status.current_revision, description=f"Pre-rollback backup"
                )
                console.print(f"[green]✓[/green] Backup created: {backup.backup_id}")

                # Perform rollback
                console.print(f"Rolling back {steps} migration(s)...")
                await manager.downgrade(target)
                console.print("[green]✓[/green] Rollback completed successfully")
            else:
                console.print("[yellow]Dry run - no rollback performed[/yellow]")

        except Exception as e:
            console.print(f"[red]✗[/red] Rollback failed: {e}")
            raise typer.Exit(1)

    asyncio.run(run())


@app.command()
def history(
    limit: int = typer.Option(10, "--limit", "-n", help="Number of migrations to show")
) -> None:
    """Show migration history."""

    async def run():
        try:
            manager = MigrationManager()
            history = await manager.get_migration_history()

            if not history:
                console.print("[yellow]No migration history found[/yellow]")
                return

            table = Table(title="Migration History")
            table.add_column("Revision", style="cyan")
            table.add_column("Description", style="white")
            table.add_column("Created", style="dim")
            table.add_column("Status", style="green")

            for migration in history[:limit]:
                table.add_row(
                    migration.revision[:8],
                    migration.description or "No description",
                    migration.create_date.strftime("%Y-%m-%d %H:%M")
                    if migration.create_date
                    else "Unknown",
                    "[green]✓[/green] Current" if migration.is_current else "",
                )

            console.print(table)

            if len(history) > limit:
                console.print(f"[dim]Showing {limit} of {len(history)} total migrations[/dim]")

        except Exception as e:
            console.print(f"[red]✗[/red] Failed to get history: {e}")
            raise typer.Exit(1)

    asyncio.run(run())


@app.command()
def backup(description: Optional[str] = typer.Argument(None, help="Backup description")) -> None:
    """Create a database backup."""
    try:
        safety = MigrationSafety()

        console.print("Creating database backup...")
        backup = safety.create_backup(description=description)

        console.print(f"[green]✓[/green] Backup created successfully")
        console.print(f"  ID: {backup.backup_id}")
        console.print(f"  Path: {backup.backup_path}")
        console.print(f"  Size: {backup.size_bytes / 1024 / 1024:.2f} MB")

    except Exception as e:
        console.print(f"[red]✗[/red] Backup failed: {e}")
        raise typer.Exit(1)


@app.command(name="list-backups")
def list_backups() -> None:
    """List available database backups."""
    try:
        safety = MigrationSafety()
        backups = safety.list_backups()

        if not backups:
            console.print("[yellow]No backups found[/yellow]")
            return

        table = Table(title="Database Backups")
        table.add_column("ID", style="cyan")
        table.add_column("Created", style="white")
        table.add_column("Size", style="dim")
        table.add_column("Migration", style="yellow")

        for backup in backups:
            table.add_row(
                backup.backup_id,
                backup.created_at.strftime("%Y-%m-%d %H:%M"),
                f"{backup.size_bytes / 1024 / 1024:.2f} MB",
                backup.migration_revision[:8] if backup.migration_revision else "-",
            )

        console.print(table)

    except Exception as e:
        console.print(f"[red]✗[/red] Failed to list backups: {e}")
        raise typer.Exit(1)


@app.command()
def restore(
    backup_id: str = typer.Argument(..., help="Backup ID to restore"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation"),
) -> None:
    """Restore database from backup."""
    try:
        if not force:
            if not typer.confirm(f"Are you sure you want to restore backup {backup_id}?"):
                raise typer.Exit(0)

        safety = MigrationSafety()

        console.print(f"Restoring backup: {backup_id}")
        safety.restore_backup(backup_id)

        console.print(f"[green]✓[/green] Database restored successfully from backup: {backup_id}")

    except Exception as e:
        console.print(f"[red]✗[/red] Restore failed: {e}")
        raise typer.Exit(1)


@app.command()
def check() -> None:
    """Run database safety checks."""
    try:
        safety = MigrationSafety()
        passed, checks = safety.run_safety_checks()

        console.print(Panel("Database Safety Checks", style="bold"))

        for check in checks:
            icon = "[green]✓[/green]" if check.passed else "[red]✗[/red]"
            severity_color = {
                "info": "dim",
                "warning": "yellow",
                "error": "red",
                "critical": "bold red",
            }.get(check.severity, "white")

            console.print(
                f"{icon} {check.check_name}: [{severity_color}]{check.message}[/{severity_color}]"
            )

        if passed:
            console.print("\n[green]All safety checks passed[/green]")
        else:
            console.print("\n[red]Some safety checks failed[/red]")
            raise typer.Exit(1)

    except Exception as e:
        console.print(f"[red]✗[/red] Safety check failed: {e}")
        raise typer.Exit(1)


@app.command()
def health() -> None:
    """Run comprehensive database health checks."""
    
    async def run():
        try:
            # Get database session
            import os
            database_url = os.getenv("GIBSON_DATABASE_URL", "sqlite:///./gibson.db")
            db_manager = DatabaseManager(database_url)
            async with db_manager.get_session() as session:
                # Run health checks
                checker = DatabaseHealthChecker()
                report = await checker.check_health(session)
                
                # Display overall status
                status_color = {
                    "healthy": "green",
                    "degraded": "yellow", 
                    "unhealthy": "red"
                }.get(report.overall_status, "white")
                
                console.print(Panel(
                    f"[{status_color}]Database Health: {report.overall_status.upper()}[/{status_color}]",
                    style="bold"
                ))
                
                # Display individual checks
                table = Table(title="Health Check Results")
                table.add_column("Check", style="cyan")
                table.add_column("Status", style="white")
                table.add_column("Message", style="white")
                
                for check in report.checks:
                    status_icon = {
                        "pass": "[green]✓ PASS[/green]",
                        "warn": "[yellow]⚠ WARN[/yellow]",
                        "fail": "[red]✗ FAIL[/red]"
                    }.get(check.status, check.status)
                    
                    table.add_row(
                        check.name,
                        status_icon,
                        check.message
                    )
                    
                    # Show details for failed checks
                    if check.status == "fail" and check.details:
                        for key, value in check.details.items():
                            if isinstance(value, list) and value:
                                console.print(f"    [dim]{key}: {', '.join(map(str, value[:5]))}[/dim]")
                
                console.print(table)
                
                # Display recommendations
                if report.recommendations:
                    console.print("\n[yellow]Recommendations:[/yellow]")
                    for rec in report.recommendations:
                        console.print(f"  • {rec}")
                
                # Exit with error if unhealthy
                if report.overall_status == "unhealthy":
                    raise typer.Exit(1)
                    
        except Exception as e:
            console.print(f"[red]✗[/red] Health check failed: {e}")
            raise typer.Exit(1)
    
    asyncio.run(run())


@app.command()
def analyze_schema() -> None:
    """Analyze database schema for mismatches and issues."""
    
    async def run():
        try:
            # Get database session
            import os
            database_url = os.getenv("GIBSON_DATABASE_URL", "sqlite:///./gibson.db")
            db_manager = DatabaseManager(database_url)
            
            console.print("🔍 [bold cyan]Analyzing Database Schema...[/bold cyan]")
            
            async with db_manager.get_session() as session:
                # Run schema analysis
                analyzer = SchemaAnalyzer()
                report = await analyzer.analyze_schema(session)
                
                # Display overall status
                status_color = "green" if report.is_healthy else "red"
                health_icon = "✅" if report.is_healthy else "❌"
                
                console.print(Panel(
                    f"[{status_color}]{health_icon} Schema Health: {'HEALTHY' if report.is_healthy else 'ISSUES DETECTED'}[/{status_color}]",
                    style="bold"
                ))
                
                # Display summary statistics
                summary_table = Table(title="Schema Analysis Summary")
                summary_table.add_column("Metric", style="cyan")
                summary_table.add_column("Value", style="white")
                
                summary_table.add_row("Database Type", report.database_type.upper())
                summary_table.add_row("Expected Tables", str(report.total_tables_expected))
                summary_table.add_row("Actual Tables", str(report.total_tables_actual))
                summary_table.add_row("Total Issues", str(report.total_issues))
                summary_table.add_row("Critical Issues", str(len(report.critical_issues)))
                summary_table.add_row("Analysis Time", report.analysis_timestamp.strftime("%Y-%m-%d %H:%M:%S"))
                
                console.print(summary_table)
                
                # Display issues by severity
                for severity_name in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                    severity = severity_name.lower()
                    issues = report.get_issues_by_severity(severity)
                    
                    if issues:
                        severity_color = {
                            'CRITICAL': 'red',
                            'HIGH': 'orange3',
                            'MEDIUM': 'yellow',
                            'LOW': 'cyan'
                        }.get(severity_name, 'white')
                        
                        severity_icon = {
                            'CRITICAL': '🚨',
                            'HIGH': '⚠️',
                            'MEDIUM': '🔶',
                            'LOW': 'ℹ️'
                        }.get(severity_name, '•')
                        
                        console.print(f"\n{severity_icon} [{severity_color}]{severity_name} Issues ({len(issues)}):[/{severity_color}]")
                        
                        # Create table for this severity level
                        issues_table = Table()
                        issues_table.add_column("Table", style="cyan")
                        issues_table.add_column("Column", style="yellow")
                        issues_table.add_column("Issue", style="white")
                        issues_table.add_column("Fix Suggestion", style="green")
                        
                        # Show first 10 issues of each severity to avoid clutter
                        display_issues = issues[:10]
                        for issue in display_issues:
                            issues_table.add_row(
                                issue.table_name,
                                issue.column_name or "N/A",
                                issue.description,
                                issue.fix_suggestion or "No suggestion available"
                            )
                        
                        console.print(issues_table)
                        
                        if len(issues) > 10:
                            console.print(f"[dim]... and {len(issues) - 10} more {severity_name.lower()} issues[/dim]")
                
                # Special focus on targets table (as mentioned in task)
                targets_analysis = next((t for t in report.tables_analyzed if t.table_name == 'targets'), None)
                if targets_analysis:
                    console.print(f"\n🎯 [bold cyan]Targets Table Analysis:[/bold cyan]")
                    
                    targets_table = Table()
                    targets_table.add_column("Property", style="cyan")
                    targets_table.add_column("Value", style="white")
                    
                    targets_table.add_row("Exists in Database", "✅ Yes" if targets_analysis.exists_in_db else "❌ No")
                    targets_table.add_row("Expected Columns", str(targets_analysis.column_count_expected))
                    targets_table.add_row("Actual Columns", str(targets_analysis.column_count_actual))
                    targets_table.add_row("Issues Found", str(len(targets_analysis.issues)))
                    
                    console.print(targets_table)
                    
                    # Check for specific missing columns mentioned in task
                    mentioned_cols = ['provider', 'requires_auth', 'last_validated', 'config_json']
                    console.print(f"\n🔍 [bold]Checking for specific columns mentioned in task:[/bold]")
                    
                    missing_mentioned = []
                    for issue in targets_analysis.issues:
                        if (issue.issue_type == 'missing_column' and 
                            issue.column_name in mentioned_cols):
                            missing_mentioned.append(issue)
                    
                    if missing_mentioned:
                        for issue in missing_mentioned:
                            console.print(f"❌ [red]Missing: {issue.column_name}[/red] ({issue.expected_value})")
                            if issue.migration_sql:
                                console.print(f"   [dim]SQL: {issue.migration_sql}[/dim]")
                    else:
                        console.print("✅ [green]All mentioned columns are present[/green]")
                
                # Provide actionable recommendations
                if report.critical_issues:
                    console.print(f"\n🚨 [bold red]CRITICAL ISSUES DETECTED![/bold red]")
                    console.print("These issues may cause data corruption or application failures.")
                    console.print("Recommended actions:")
                    console.print("1. Run database migrations: `gibson db upgrade`")
                    console.print("2. Review model definitions for consistency")
                    console.print("3. Back up your database before making changes")
                elif report.total_issues > 0:
                    console.print(f"\n📄 [bold yellow]Schema improvements recommended[/bold yellow]")
                    console.print("Consider running migrations or updating model definitions.")
                else:
                    console.print(f"\n✅ [bold green]Schema is healthy![/bold green]")
                    console.print("No issues detected. Database schema matches model definitions.")
                
        except Exception as e:
            console.print(f"[red]✗[/red] Schema analysis failed: {e}")
            raise typer.Exit(1)
        finally:
            await db_manager.close()
    
    asyncio.run(run())


if __name__ == "__main__":
    app()
