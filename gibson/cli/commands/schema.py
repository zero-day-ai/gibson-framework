"""
Schema management CLI commands.

Commands for generating, validating, and managing JSON schemas.
"""

import json
from pathlib import Path
from typing import Optional
import typer
from rich.console import Console
from rich.table import Table
from rich.syntax import Syntax
from rich.panel import Panel

from gibson.utils.schema_generator import SchemaGenerator
from gibson.utils.payload_validator import PayloadValidator, SchemaVersionManager
from gibson.utils.schema_diff import BreakingChangeDetector
from gibson.models.payload import PayloadModel

# Import schema sync components
try:
    from gibson.core.schema_sync import SchemaOrchestrator

    SCHEMA_SYNC_AVAILABLE = True
except ImportError:
    SCHEMA_SYNC_AVAILABLE = False

app = typer.Typer(help="Schema management commands")
console = Console()


@app.command()
def generate(
    output_dir: Path = typer.Option(
        Path("schemas"), "--output", "-o", help="Output directory for schemas"
    ),
    version: str = typer.Option("latest", "--version", "-v", help="Version string (e.g., 1-0-0)"),
    typescript: bool = typer.Option(
        False, "--typescript", "-t", help="Also generate TypeScript types"
    ),
    markdown: bool = typer.Option(
        False, "--markdown", "-m", help="Also generate Markdown documentation"
    ),
):
    """Generate JSON schemas from Pydantic models."""
    try:
        console.print(f"[bold cyan]Generating schemas to {output_dir}...[/bold cyan]")

        # Import the orchestrator with proper path handling
        import sys
        from pathlib import Path

        scripts_path = Path(__file__).parent.parent.parent.parent / "scripts"
        sys.path.insert(0, str(scripts_path))

        from generate_schemas import SchemaOrchestrator

        orchestrator = SchemaOrchestrator(
            output_dir=output_dir,
            version=version,
        )

        # Generate schemas
        success = orchestrator.generate_all()

        if success:
            console.print("[bold green]✓[/bold green] Schemas generated successfully")

            # Show generated files
            version_dir = output_dir / version
            if version_dir.exists():
                table = Table(title="Generated Files")
                table.add_column("File", style="cyan")
                table.add_column("Size", style="green")

                for file in version_dir.glob("*"):
                    if file.is_file():
                        size = file.stat().st_size
                        table.add_row(file.name, f"{size} bytes")

                console.print(table)
        else:
            console.print("[bold red]✗[/bold red] Schema generation failed")
            raise typer.Exit(1)

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(1)


@app.command()
def validate(
    payload_file: Path = typer.Argument(..., help="Path to payload JSON file to validate"),
    schema_version: str = typer.Option(
        "latest", "--version", "-v", help="Schema version to validate against"
    ),
    verbose: bool = typer.Option(False, "--verbose", help="Show detailed validation errors"),
):
    """Validate a payload against the schema."""
    try:
        if not payload_file.exists():
            console.print(f"[bold red]Error:[/bold red] File not found: {payload_file}")
            raise typer.Exit(1)

        # Load payload
        with open(payload_file) as f:
            payload_data = json.load(f)

        # Create validator
        validator = PayloadValidator(version=schema_version)

        # Validate
        if verbose:
            is_valid, errors = validator.validate_with_details(payload_data)

            if is_valid:
                console.print("[bold green]✓[/bold green] Payload is valid")
            else:
                console.print("[bold red]✗[/bold red] Payload validation failed")

                # Show detailed errors
                for error in errors:
                    console.print(f"\n[bold yellow]Field:[/bold yellow] {error['field']}")
                    console.print(f"[bold red]Error:[/bold red] {error['message']}")
                    if error.get("validator_value"):
                        console.print(f"[dim]Expected: {error['validator_value']}[/dim]")
                    if error.get("instance"):
                        console.print(f"[dim]Got: {error['instance']}[/dim]")

                # Show suggestions
                suggestions = validator.suggest_fixes(payload_data)
                if suggestions:
                    console.print("\n[bold cyan]Suggestions:[/bold cyan]")
                    for suggestion in suggestions:
                        console.print(f"  • {suggestion}")

                raise typer.Exit(1)
        else:
            is_valid, error_msg = validator.validate(payload_data)

            if is_valid:
                console.print("[bold green]✓[/bold green] Payload is valid")
            else:
                console.print(f"[bold red]✗[/bold red] {error_msg}")
                raise typer.Exit(1)

    except json.JSONDecodeError as e:
        console.print(f"[bold red]Error:[/bold red] Invalid JSON: {e}")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(1)


@app.command()
def template(
    output_file: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Output file for template (stdout if not specified)"
    ),
    full: bool = typer.Option(False, "--full", "-f", help="Include all optional fields"),
    schema_version: str = typer.Option("latest", "--version", "-v", help="Schema version to use"),
):
    """Generate a payload template."""
    try:
        validator = PayloadValidator(version=schema_version)

        if full:
            template = validator.get_full_template()
        else:
            template = validator.get_template()

        # Format as JSON
        template_json = json.dumps(template, indent=2)

        if output_file:
            output_file.write_text(template_json)
            console.print(f"[bold green]✓[/bold green] Template written to {output_file}")
        else:
            # Display with syntax highlighting
            syntax = Syntax(template_json, "json", theme="monokai")
            console.print(Panel(syntax, title="Payload Template"))

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(1)


@app.command()
def diff(
    old_version: str = typer.Argument(..., help="Old schema version"),
    new_version: str = typer.Argument(..., help="New schema version"),
    schemas_dir: Path = typer.Option(Path("schemas"), "--dir", "-d", help="Schemas directory"),
):
    """Compare two schema versions for breaking changes."""
    try:
        old_schema_file = schemas_dir / old_version / "payload.json"
        new_schema_file = schemas_dir / new_version / "payload.json"

        if not old_schema_file.exists():
            console.print(f"[bold red]Error:[/bold red] Schema not found: {old_schema_file}")
            raise typer.Exit(1)

        if not new_schema_file.exists():
            console.print(f"[bold red]Error:[/bold red] Schema not found: {new_schema_file}")
            raise typer.Exit(1)

        # Load schemas
        with open(old_schema_file) as f:
            old_schema = json.load(f)
        with open(new_schema_file) as f:
            new_schema = json.load(f)

        # Detect changes
        detector = BreakingChangeDetector()
        all_changes = detector.analyze_changes(old_schema, new_schema)

        if not all_changes:
            console.print("[bold green]✓[/bold green] No changes detected")
            return

        # Group changes by category
        breaking = [c for c in all_changes if c.category.value == "breaking"]
        potentially = [c for c in all_changes if c.category.value == "potentially_breaking"]
        compatible = [c for c in all_changes if c.category.value == "compatible"]

        # Display changes
        if breaking:
            console.print("\n[bold red]Breaking Changes:[/bold red]")
            for change in breaking:
                console.print(f"  ✗ {change.description}")

        if potentially:
            console.print("\n[bold yellow]Potentially Breaking Changes:[/bold yellow]")
            for change in potentially:
                console.print(f"  ⚠ {change.description}")

        if compatible:
            console.print("\n[bold green]Compatible Changes:[/bold green]")
            for change in compatible:
                console.print(f"  ✓ {change.description}")

        # Recommend version bump
        if breaking:
            console.print("\n[bold]Recommendation:[/bold] Major version bump (MODEL)")
        elif potentially:
            console.print("\n[bold]Recommendation:[/bold] Minor version bump (REVISION)")
        else:
            console.print("\n[bold]Recommendation:[/bold] Patch version bump (ADDITION)")

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(1)


@app.command()
def info(
    field: Optional[str] = typer.Argument(None, help="Field name to get info about"),
    schema_version: str = typer.Option("latest", "--version", "-v", help="Schema version"),
):
    """Show schema information."""
    try:
        validator = PayloadValidator(version=schema_version)

        if field:
            # Show specific field info
            field_info = validator.get_field_info(field)

            if not field_info:
                console.print(f"[bold red]Error:[/bold red] Field '{field}' not found")
                raise typer.Exit(1)

            table = Table(title=f"Field: {field}")
            table.add_column("Property", style="cyan")
            table.add_column("Value", style="white")

            table.add_row("Required", "Yes" if field_info["required"] else "No")
            table.add_row("Type", field_info["type"])

            if field_info.get("description"):
                table.add_row("Description", field_info["description"])

            if field_info.get("enum"):
                enum_str = ", ".join(str(v) for v in field_info["enum"])
                table.add_row("Enum Values", enum_str)

            if field_info.get("constraints"):
                for key, value in field_info["constraints"].items():
                    table.add_row(key, str(value))

            console.print(table)
        else:
            # Show general schema info
            required = validator.list_required_fields()
            optional = validator.list_optional_fields()

            table = Table(title="Schema Information")
            table.add_column("Category", style="cyan")
            table.add_column("Fields", style="white")

            if required:
                table.add_row("Required", ", ".join(required))
            if optional:
                table.add_row("Optional", ", ".join(optional))

            console.print(table)

            # Show available commands
            console.print("\n[bold]Tips:[/bold]")
            console.print("  • Use 'gibson schema info <field>' for field details")
            console.print("  • Use 'gibson schema template' to generate a template")
            console.print("  • Use 'gibson schema validate <file>' to validate a payload")

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(1)


@app.command()
def sync(
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without applying them"),
    force: bool = typer.Option(False, "--force", help="Apply changes even with breaking changes"),
    version: Optional[str] = typer.Option(
        None, "--version", "-v", help="Specify version for migration"
    ),
    verbose: bool = typer.Option(False, "--verbose", help="Show detailed output"),
):
    """Synchronize database schema with PayloadModel changes."""
    if not SCHEMA_SYNC_AVAILABLE:
        console.print("[bold red]Error:[/bold red] Schema sync module not available")
        console.print("Please ensure all dependencies are installed")
        raise typer.Exit(1)

    try:
        console.print("[bold cyan]Starting schema synchronization...[/bold cyan]")

        # Create orchestrator
        orchestrator = SchemaOrchestrator(dry_run=dry_run, force=force)

        # Run sync
        result = orchestrator.sync_schemas(version=version)

        # Display results
        if result["status"] == "no_changes":
            console.print("[bold green]✓[/bold green] Schemas are already in sync")
            return

        if result["changes_detected"]:
            console.print(f"\n[bold]Changes Detected:[/bold] {result['change_count']} changes")
            console.print(f"[bold]Compatibility:[/bold] {result.get('compatibility', 'unknown')}")
            console.print(f"[bold]Risk Level:[/bold] {result.get('risk_level', 'unknown')}")

        # Show warnings
        if result.get("warnings"):
            console.print("\n[bold yellow]Warnings:[/bold yellow]")
            for warning in result["warnings"]:
                console.print(f"  ⚠ {warning}")

        # Show breaking changes
        if result.get("breaking_changes"):
            console.print("\n[bold red]Breaking Changes:[/bold red]")
            for change in result["breaking_changes"]:
                console.print(f"  ✗ {change['description']}")
                if verbose:
                    console.print(f"    Impact: {change['impact']}")
                    console.print(f"    Remediation: {change['suggested_remediation']}")

        # Show status
        if result["status"] == "success":
            console.print(f"\n[bold green]✓[/bold green] Schema sync completed successfully")
            console.print(f"Version: {result['version']}")
            if result.get("migration_id"):
                console.print(f"Migration ID: {result['migration_id']}")
        elif result["status"] == "dry_run_success":
            console.print(f"\n[bold cyan]✓[/bold cyan] Dry run completed successfully")
            console.print("No changes were applied. Run without --dry-run to apply changes.")
        elif result["status"] == "breaking_changes":
            console.print("\n[bold red]✗[/bold red] Sync blocked due to breaking changes")
            console.print("Use --force to apply changes anyway (use with caution!)")
            raise typer.Exit(1)
        else:
            console.print(f"\n[bold red]✗[/bold red] Sync failed: {result['status']}")
            if result.get("errors"):
                for error in result["errors"]:
                    console.print(f"  Error: {error}")
            raise typer.Exit(1)

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(1)


@app.command()
def check(
    verbose: bool = typer.Option(False, "--verbose", help="Show detailed validation"),
    ci: bool = typer.Option(False, "--ci", help="CI mode - exit with error if changes detected"),
):
    """Check if schemas are in sync with models."""
    if not SCHEMA_SYNC_AVAILABLE:
        console.print("[bold red]Error:[/bold red] Schema sync module not available")
        raise typer.Exit(1)

    try:
        orchestrator = SchemaOrchestrator(dry_run=True)

        # Validate current state
        validation = orchestrator.validate_current_state()

        if validation["valid"]:
            console.print("[bold green]✓[/bold green] Schemas are in sync")
            if validation.get("current_version"):
                console.print(f"Current version: {validation['current_version']}")
        else:
            console.print("[bold red]✗[/bold red] Schema synchronization issues detected")

            for issue in validation.get("issues", []):
                console.print(f"  • {issue}")

            if validation.get("pending_migrations"):
                console.print(
                    f"\nPending migrations: {', '.join(validation['pending_migrations'])}"
                )

            if ci:
                raise typer.Exit(1)

        # Check for uncommitted changes
        from gibson.models.payload import PayloadModel

        detector = orchestrator.detector
        current_schema = detector.get_model_schema(PayloadModel)
        current_hash = detector.calculate_schema_hash(PayloadModel)

        if verbose:
            console.print(f"\nSchema hash: {current_hash[:16]}")
            console.print(f"Model: PayloadModel")

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(1)


@app.command()
def history(
    limit: int = typer.Option(10, "--limit", "-n", help="Number of entries to show"),
):
    """Show schema migration history."""
    if not SCHEMA_SYNC_AVAILABLE:
        console.print("[bold red]Error:[/bold red] Schema sync module not available")
        raise typer.Exit(1)

    try:
        from gibson.core.schema_sync import VersionRegistry

        registry = VersionRegistry()
        history = registry.get_migration_history()

        if not history:
            console.print("No migration history found")
            return

        # Create table
        table = Table(title="Migration History")
        table.add_column("Migration ID", style="cyan")
        table.add_column("Version", style="green")
        table.add_column("Status", style="yellow")
        table.add_column("Applied At", style="white")

        for entry in history[:limit]:
            status_color = "green" if entry.status.value == "completed" else "red"
            table.add_row(
                entry.migration_id,
                entry.version,
                f"[{status_color}]{entry.status.value}[/{status_color}]",
                str(entry.applied_at),
            )

        console.print(table)

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(1)


@app.command()
def version():
    """Show current schema version."""
    if not SCHEMA_SYNC_AVAILABLE:
        console.print("[bold red]Error:[/bold red] Schema sync module not available")
        raise typer.Exit(1)

    try:
        from gibson.core.schema_sync import VersionRegistry

        registry = VersionRegistry()
        current = registry.get_current_version()

        if current:
            console.print(f"[bold]Current Schema Version:[/bold] {current.version}")
            console.print(f"[bold]Hash:[/bold] {current.hash[:16]}")
            console.print(f"[bold]Model:[/bold] {current.model_name}")
            console.print(f"[bold]Timestamp:[/bold] {current.timestamp}")

            if current.applied:
                console.print(f"[bold green]✓[/bold green] Applied at: {current.applied_at}")
            else:
                console.print("[bold yellow]⚠[/bold yellow] Not yet applied")
        else:
            console.print("No schema version found")
            console.print("Run 'gibson schema sync' to initialize")

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
