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

console = Console()
app = typer.Typer(help="Database management commands")


@app.command()
def init(
    force: bool = typer.Option(False, "--force", "-f", help="Force initialization even if database exists")
) -> None:
    """Initialize the database."""
    async def run():
        try:
            db_manager = DatabaseManager()
            await db_manager.init_db(force=force)
            console.print("[green]✓[/green] Database initialized successfully")
        except Exception as e:
            console.print(f"[red]✗[/red] Failed to initialize database: {e}")
            raise typer.Exit(1)
    
    asyncio.run(run())


@app.command()
def migrate(
    message: Optional[str] = typer.Argument(None, help="Migration message"),
    auto: bool = typer.Option(True, "--auto/--no-auto", help="Auto-generate migration from model changes"),
    sql: bool = typer.Option(False, "--sql", help="Generate SQL script only"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be done without executing")
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
                            migration.revision[:8],
                            migration.description or "No description"
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
                                    console.print(f"  [red]✗[/red] {check.check_name}: {check.message}")
                            
                            if not typer.confirm("Continue anyway?"):
                                raise typer.Exit(1)
                        
                        # Create backup
                        console.print("Creating database backup...")
                        backup = safety.create_backup(
                            migration_revision=status.head_revision,
                            description="Pre-migration backup"
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
                        migration.create_date.strftime("%Y-%m-%d %H:%M") if migration.create_date else "Unknown"
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
                        "[green]✓[/green] Current" if migration.is_current else ""
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
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be done without executing")
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
                    migration_revision=status.current_revision,
                    description=f"Pre-rollback backup"
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
                    migration.create_date.strftime("%Y-%m-%d %H:%M") if migration.create_date else "Unknown",
                    "[green]✓[/green] Current" if migration.is_current else ""
                )
            
            console.print(table)
            
            if len(history) > limit:
                console.print(f"[dim]Showing {limit} of {len(history)} total migrations[/dim]")
                
        except Exception as e:
            console.print(f"[red]✗[/red] Failed to get history: {e}")
            raise typer.Exit(1)
    
    asyncio.run(run())


@app.command()
def backup(
    description: Optional[str] = typer.Argument(None, help="Backup description")
) -> None:
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
                backup.migration_revision[:8] if backup.migration_revision else "-"
            )
        
        console.print(table)
        
    except Exception as e:
        console.print(f"[red]✗[/red] Failed to list backups: {e}")
        raise typer.Exit(1)


@app.command()
def restore(
    backup_id: str = typer.Argument(..., help="Backup ID to restore"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation")
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
                "critical": "bold red"
            }.get(check.severity, "white")
            
            console.print(f"{icon} {check.check_name}: [{severity_color}]{check.message}[/{severity_color}]")
        
        if passed:
            console.print("\n[green]All safety checks passed[/green]")
        else:
            console.print("\n[red]Some safety checks failed[/red]")
            raise typer.Exit(1)
            
    except Exception as e:
        console.print(f"[red]✗[/red] Safety check failed: {e}")
        raise typer.Exit(1)


if __name__ == "__main__":
    app()