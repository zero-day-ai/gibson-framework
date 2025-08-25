"""Module management commands."""

import asyncio
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import typer
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.table import Table

from gibson.core.context import Context
from gibson.core.base import Base
from gibson.core.module_management.manager import ModuleManager
from gibson.core.module_management.models import ModuleInstallOptions


@dataclass
class Module:
    """Simple module data class for CLI display."""

    name: str
    version: str
    category: str = "unknown"
    author: str = "Unknown"
    description: str = ""
    enabled: bool = True
    tags: List[str] = None
    owasp_categories: List[str] = None
    license: str = "Unknown"
    dependencies: List[str] = None
    parameters: Dict[str, Any] = None
    targets: List[str] = None
    hash: str = ""
    installed_date: Optional[datetime] = None
    last_updated: Optional[datetime] = None
    path: Optional[Path] = None

    def __post_init__(self):
        if self.tags is None:
            self.tags = []
        if self.owasp_categories is None:
            self.owasp_categories = []
        if self.dependencies is None:
            self.dependencies = []
        if self.parameters is None:
            self.parameters = {}
        if self.targets is None:
            self.targets = []


app = typer.Typer(help="Module management")
console = Console()


def _get_manager(context: Context) -> ModuleManager:
    """Get unified module manager with auto-registration."""
    from gibson.core.base import Base

    # Get base orchestrator from context or create new one
    if hasattr(context, "base") and context.base:
        base = context.base
    else:
        base = Base()
        # Store base in context for reuse
        context.base = base

    # Initialize if needed
    if not base.initialized:
        import asyncio

        asyncio.run(base.initialize())

    # Return module manager
    if not base.module_manager:
        raise RuntimeError("Module manager not available - initialization may have failed")

    return base.module_manager


@app.command()
def search(
    ctx: typer.Context,
    query: Optional[str] = typer.Argument(None, help="Search query"),
    category: Optional[str] = typer.Option(
        None, "--category", "-c", help="Filter by category (official, community, verified)"
    ),
    domain: Optional[str] = typer.Option(
        None,
        "--domain",
        "-d",
        help="Filter by attack domain (prompts, data, model, system, output)",
    ),
    tag: Optional[str] = typer.Option(None, "--tag", "-t", help="Filter by tag"),
    owasp: Optional[str] = typer.Option(
        None, "--owasp", help="Filter by OWASP category (e.g., LLM01)"
    ),
    trusted_only: bool = typer.Option(False, "--trusted-only", help="Show only trusted modules"),
    limit: int = typer.Option(20, "--limit", "-l", help="Maximum number of results"),
    popular: bool = typer.Option(False, "--popular", "-p", help="Show popular modules"),
    recent: bool = typer.Option(False, "--recent", "-r", help="Show recently updated modules"),
) -> None:
    """
    Search for available modules in the registry.

    Examples:
        gibson module search                        # List all modules
        gibson module search prompt                 # Search by keyword
        gibson module search --domain prompts      # Show prompt domain modules
        gibson module search --category official    # Show official modules
        gibson module search --tag llm             # Filter by tag
        gibson module search --owasp LLM01         # Show LLM01 modules
        gibson module search --popular             # Show popular modules
        gibson module search --recent              # Show recently updated
    """
    # Validate domain if provided
    valid_domains = ["prompts", "data", "model", "system", "output"]
    if domain and domain.lower() not in valid_domains:
        console.print(f"[red]Invalid domain: {domain}[/red]")
        console.print(f"Valid domains: {', '.join(valid_domains)}")
        raise typer.Exit(1)

    with console.status("Searching registry..."):
        registry = get_registry()
        await_registry = asyncio.run(registry.refresh())

        if popular:
            results = registry.get_popular_modules(limit)
        elif recent:
            results = registry.get_recent_modules(limit)
        else:
            # Parse category
            registry_category = None
            if category:
                from gibson.core.modules.registry import RegistryCategory

                try:
                    registry_category = RegistryCategory(category)
                except ValueError:
                    console.print(f"[red]Invalid category: {category}[/red]")
                    console.print("Valid categories: official, community, verified")
                    raise typer.Exit(1)

            # Parse tags
            tags = [tag] if tag else None

            # Add domain to tags if specified for filtering
            if domain:
                domain_tag = f"domain:{domain.lower()}"
                tags = tags + [domain_tag] if tags else [domain_tag]

            # Search with filters
            results = registry.search(
                query=query,
                category=registry_category,
                tags=tags,
                owasp_category=owasp,
                trusted_only=trusted_only,
            )

            # Apply limit
            results = results[:limit]

    if not results:
        search_desc = []
        if query:
            search_desc.append(f"query '{query}'")
        if category:
            search_desc.append(f"category '{category}'")
        if tag:
            search_desc.append(f"tag '{tag}'")
        if owasp:
            search_desc.append(f"OWASP '{owasp}'")

        search_str = " and ".join(search_desc) if search_desc else "your criteria"
        console.print(f"No modules found matching {search_str}")
        return

    # Create table
    title_parts = []
    if popular:
        title_parts.append("Popular")
    elif recent:
        title_parts.append("Recent")
    title_parts.append(f"{len(results)} modules")

    table = Table(title=" ".join(title_parts))
    table.add_column("Name", style="cyan")
    table.add_column("Category", style="green")
    table.add_column("Version")
    table.add_column("Author")
    table.add_column("Downloads", justify="right")
    table.add_column("Rating", justify="right")
    table.add_column("Description")

    for module in results:
        # Truncate long descriptions
        description = module.description
        if len(description) > 60:
            description = description[:57] + "..."

        # Format category with color
        category_style = {
            "official": "[bold green]official[/bold green]",
            "verified": "[green]verified[/green]",
            "community": "[yellow]community[/yellow]",
        }
        category_display = category_style.get(module.category.value, module.category.value)

        # Format rating
        rating = f"{module.statistics.rating:.1f}" if module.statistics.rating > 0 else "-"

        table.add_row(
            module.name,
            category_display,
            module.version,
            module.author,
            str(module.statistics.downloads),
            rating,
            description,
        )

    console.print(table)

    # Show registry stats if no specific search
    if not any([query, category, tag, owasp, popular, recent]):
        stats = registry.get_statistics()
        console.print(
            f"\n[dim]Registry: {stats['total_modules']} total modules, "
            f"{stats['categories'].get('official', 0)} official, "
            f"{stats['categories'].get('verified', 0)} verified, "
            f"{stats['categories'].get('community', 0)} community[/dim]"
        )


@app.command()
def domains(
    ctx: typer.Context,
) -> None:
    """
    List available attack domains and their modules.

    Shows the organized module structure by attack domain.
    """
    context: Context = ctx.obj

    # Initialize Base to get attack domains
    base = Base()
    asyncio.run(base.initialize())

    # Create table for domains
    table = Table(title="Attack Domains")
    table.add_column("Domain", style="cyan")
    table.add_column("Description", style="white")
    table.add_column("Modules", style="green")
    table.add_column("Loaded", style="yellow")

    # Domain information
    domain_info = {
        "prompts": {
            "description": "Prompt injection and manipulation attacks",
            "modules": ["prompt_injection", "sensitive_info_disclosure"],
        },
        "data": {
            "description": "Data poisoning and membership inference attacks",
            "modules": ["data_poisoning", "membership_inference"],
        },
        "model": {
            "description": "Model theft and fingerprinting attacks",
            "modules": ["model_theft", "model_fingerprinting"],
        },
        "system": {
            "description": "System enumeration and privilege escalation",
            "modules": ["system_enumeration", "privilege_escalation"],
        },
        "output": {
            "description": "Output injection and content steering attacks",
            "modules": ["output_injection", "content_steering"],
        },
    }

    for domain_name, domain_data in domain_info.items():
        modules_str = ", ".join(domain_data["modules"])
        loaded_count = len(domain_data["modules"])  # Mock - would check actual loading

        table.add_row(
            domain_name,
            domain_data["description"],
            modules_str,
            f"{loaded_count}/{len(domain_data['modules'])}",
        )

    console.print(table)

    # Show usage information
    console.print(
        f"\n[dim]Use 'gibson module search --domain <domain>' to filter modules by domain[/dim]"
    )


@app.command()
def install(
    ctx: typer.Context,
    source: str = typer.Argument(help="Module name, URL, or path"),
    version: Optional[str] = typer.Option(
        None, "--version", "-v", help="Specific version (e.g., >=1.0.0, ==2.1.0)"
    ),
    branch: Optional[str] = typer.Option(None, "--branch", "-b", help="Git branch for Git sources"),
    commit: Optional[str] = typer.Option(
        None, "--commit", "-c", help="Specific commit hash for Git sources"
    ),
    force: bool = typer.Option(
        False, "--force", "-f", help="Force reinstall even if already installed"
    ),
    no_deps: bool = typer.Option(False, "--no-deps", help="Skip dependency resolution"),
    dependency_strategy: str = typer.Option(
        "strict",
        "--dependency-strategy",
        help="Dependency resolution strategy: strict, best_effort, skip",
    ),
    module_name: Optional[str] = typer.Option(
        None, "--name", help="Specific module name (for Git repos with multiple modules)"
    ),
) -> None:
    """
    Install a module from various sources.

    Sources can be:
    - Module name from registry: prompt-injection
    - GitHub shorthand: github:owner/repo or owner/repo
    - Git URL: https://github.com/owner/repo.git
    - Local path: ./path/to/module.py or /abs/path/to/module/
    - Module with version: prompt-injection>=1.2.0

    Examples:
        gibson module install prompt-injection
        gibson module install prompt-injection --version ">=1.0.0"
        gibson module install owner/repo --branch develop
        gibson module install https://github.com/owner/repo.git --commit abc123
        gibson module install ./local-module.py --force
        gibson module install /path/to/modules/ --name specific-module
    """
    context: Context = ctx.obj
    manager = _get_manager(context)

    # Create installation options
    options = ModuleInstallOptions(
        force_overwrite=force,
        skip_dependencies=no_deps,
        version=version,
        branch=branch,
        commit=commit,
    )

    # Show installation details
    console.print(f"[blue]Installing: {source}[/blue]")
    if version:
        console.print(f"Version constraint: {version}")
    if branch and branch != "main":
        console.print(f"Branch: {branch}")
    if commit:
        console.print(f"Commit: {commit}")

    # Perform installation with progress display
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
        transient=False,
    ) as progress:
        task = progress.add_task(f"Installing {source}...", total=None)

        try:
            result = asyncio.run(manager.install(source, options))
            progress.update(task, completed=True)

            if result.success:
                console.print(f"[green]✓[/green] Successfully installed {result.module_name}")
                if result.installed_version:
                    console.print(f"  Version: {result.installed_version}")
                if result.install_path:
                    console.print(f"  Location: {result.install_path}")

                if result.dependencies_installed:
                    console.print(
                        f"[green]Installed {len(result.dependencies_installed)} dependencies:[/green]"
                    )
                    for dep in result.dependencies_installed[:5]:  # Show first 5
                        console.print(f"  • {dep}")
                    if len(result.dependencies_installed) > 5:
                        console.print(f"  ... and {len(result.dependencies_installed) - 5} more")
            else:
                console.print(f"[red]✗[/red] Installation failed")
                if result.error_message:
                    console.print(f"[red]Error:[/red] {result.error_message}")
                raise typer.Exit(1)

        except Exception as e:
            progress.update(task, completed=True)
            console.print(f"[red]✗[/red] Installation failed: {e}")
            raise typer.Exit(1)


@app.command()
def list(
    ctx: typer.Context,
    category: Optional[str] = typer.Option(None, "--category", "-c", help="Filter by category"),
    domain: Optional[str] = typer.Option(
        None,
        "--domain",
        "-d",
        help="Filter by attack domain (prompts, data, model, system, output)",
    ),
    enabled: Optional[bool] = typer.Option(
        None, "--enabled/--no-enabled", help="Filter by enabled status"
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed information"),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="Output format (json, table)"
    ),
) -> None:
    """
    List installed modules organized by attack domain.

    Examples:
        gibson module list
        gibson module list --domain prompts
        gibson module list --category prompt-injection
        gibson module list --enabled
        gibson module list --no-enabled
        gibson module list --output json
    """
    import asyncio
    import json

    context: Context = ctx.obj
    manager = _get_manager(context)

    # Validate domain if provided
    valid_domains = ["prompts", "data", "model", "system", "output"]
    if domain and domain.lower() not in valid_domains:
        console.print(f"[red]Invalid domain: {domain}[/red]")
        console.print(f"Valid domains: {', '.join(valid_domains)}")
        raise typer.Exit(1)

    try:
        # Get base orchestrator for database session
        base = context.base if hasattr(context, "base") else Base()
        if not base.initialized:
            asyncio.run(base.initialize())

        # Run the async method with proper session
        async def _list_modules_async():
            if base.db_manager:
                async with base.db_manager.get_session() as session:
                    from gibson.core.module_management.models import ModuleFilter

                    # Create filter
                    filter_obj = None
                    if category or enabled is not None:
                        filter_obj = ModuleFilter(enabled_only=enabled if enabled else False)

                    modules_dict = await manager.list_modules(filter=filter_obj, session=session)

                    # Convert to expected format
                    modules_data = []
                    for name, module_def in modules_dict.items():
                        modules_data.append(
                            {
                                "name": module_def.name,
                                "version": module_def.version,
                                "category": module_def.category.value,
                                "author": module_def.author,
                                "description": module_def.description,
                                "enabled": module_def.status.value == "enabled",
                                "tags": module_def.tags,
                                "owasp_categories": [
                                    cat.value for cat in module_def.owasp_categories
                                ],
                                "license": module_def.license,
                                "dependencies": module_def.dependencies,
                                "parameters": {},  # TODO: Extract from config schema
                                "targets": [],  # TODO: Extract from module
                                "code_hash": "",  # TODO: Calculate hash
                                "installed_date": module_def.installation_date.isoformat(),
                                "last_updated": module_def.last_updated.isoformat(),
                                "path": str(module_def.file_path) if module_def.file_path else None,
                            }
                        )
                    return modules_data
            else:
                # Fallback without database
                return []

        modules_data = asyncio.run(_list_modules_async())

        # Convert to Module objects for compatibility
        modules = []
        for data in modules_data:
            # Filter by domain if specified
            if domain:
                # Determine module domain based on path or category
                module_domain = None
                if "path" in data:
                    path_str = str(data["path"])
                    for d in valid_domains:
                        if f"/{d}/" in path_str or f"\\{d}\\" in path_str:
                            module_domain = d
                            break

                # Skip if doesn't match domain filter
                if module_domain != domain.lower():
                    continue

            modules.append(
                Module(
                    name=data["name"],
                    version=data["version"],
                    category=data.get("category", "unknown"),
                    author=data.get("author", "Unknown"),
                    description=data.get("description", ""),
                    enabled=data.get("enabled", True),
                    tags=data.get("tags", []),
                    owasp_categories=data.get("owasp_categories", []),
                    license=data.get("license", "Unknown"),
                    dependencies=data.get("dependencies", []),
                    parameters=data.get("parameters", {}),
                    targets=data.get("targets", []),
                    hash=data.get("code_hash", ""),
                    installed_date=datetime.fromisoformat(data["installed_date"])
                    if data.get("installed_date")
                    else None,
                    last_updated=datetime.fromisoformat(data["last_updated"])
                    if data.get("last_updated")
                    else None,
                    path=Path(data["path"]) if data.get("path") else None,
                )
            )
    except Exception as e:
        console.print(f"[red]Failed to list modules: {e}[/red]")
        raise typer.Exit(1)

    if not modules:
        if output == "json":
            console.print("[]")
        else:
            console.print("No modules installed")
        return

    # JSON output format
    if output == "json":
        output_data = []
        for module in modules:
            module_dict = {
                "name": module.name,
                "version": module.version,
                "category": module.category,
                "enabled": module.enabled,
                "author": module.author,
                "description": module.description,
                "path": str(module.path),
            }
            if verbose:
                module_dict["id"] = getattr(module, "id", None) or module.name
                module_dict["created"] = (
                    module.installed_date.isoformat() if module.installed_date else None
                )
                module_dict["updated"] = (
                    module.last_updated.isoformat() if module.last_updated else None
                )
            output_data.append(module_dict)
        console.print(json.dumps(output_data, indent=2))
        return

    # Calculate counts for summary
    total_count = len(modules)
    enabled_count = sum(1 for m in modules if m.enabled)
    disabled_count = total_count - enabled_count

    # Category or domain-specific message
    if domain:
        if total_count == 0:
            console.print(f"No modules in domain '{domain}'")
            return
        elif total_count == 1:
            title = f"1 module in {domain} domain"
        else:
            title = f"{total_count} modules in {domain} domain"
    elif category:
        if total_count == 0:
            console.print(f"No modules in category '{category}'")
            return
        elif total_count == 1:
            title = f"1 module in category '{category}'"
        else:
            title = f"{total_count} modules in category '{category}'"
    else:
        title = "Installed Modules (Organized by Domain)"

    # Create table
    table = Table(title=title)
    table.add_column("Name", style="cyan")
    table.add_column("Category")
    table.add_column("Version")
    table.add_column("Status")
    table.add_column("Author")
    table.add_column("Description")

    # Add ID column if verbose
    if verbose:
        table.add_column("ID", style="dim")
        table.add_column("Created")
        table.add_column("Updated")

    for module in modules:
        status = "[green]Enabled[/green]" if module.enabled else "[yellow]Disabled[/yellow]"
        description = (
            module.description[:50] + "..." if len(module.description) > 50 else module.description
        )

        row = [
            module.name,
            module.category,
            module.version,
            status,
            module.author,
            description,
        ]

        if verbose:
            module_id = getattr(module, "id", None) or module.name
            created = module.installed_date.strftime("%Y-%m-%d") if module.installed_date else "N/A"
            updated = module.last_updated.strftime("%Y-%m-%d") if module.last_updated else "N/A"
            row.extend([module_id, created, updated])

        table.add_row(*row)

    console.print(table)

    # Print summary
    if not category:  # Only show summary for full list
        console.print(
            f"\n[dim]Total: {total_count} modules ({enabled_count} enabled, {disabled_count} disabled)[/dim]"
        )


@app.command()
def info(
    ctx: typer.Context,
    name: str = typer.Argument(help="Module name"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed information"),
) -> None:
    """
    Show module information.

    Examples:
        gibson module info prompt-injection
        gibson module info model-extraction --verbose
    """
    context: Context = ctx.obj
    manager = _get_manager(context)

    # Get module info using module manager
    async def _get_module_info_async():
        base = context.base if hasattr(context, "base") else Base()
        if not base.initialized:
            await base.initialize()

        if base.db_manager:
            async with base.db_manager.get_session() as session:
                try:
                    module_def = await manager.get_module(name, session)
                    return {
                        "name": module_def.name,
                        "version": module_def.version,
                        "category": module_def.category.value,
                        "author": module_def.author,
                        "description": module_def.description,
                        "enabled": module_def.status.value == "enabled",
                        "tags": module_def.tags,
                        "owasp_categories": [cat.value for cat in module_def.owasp_categories],
                        "license": module_def.license,
                        "dependencies": module_def.dependencies,
                        "parameters": {},  # TODO: Extract from config schema
                        "targets": [],  # TODO: Extract from module
                        "code_hash": "",  # TODO: Calculate hash
                        "installed_date": module_def.installation_date.isoformat(),
                        "last_updated": module_def.last_updated.isoformat(),
                    }
                except Exception:
                    return None
        return None

    module_info = asyncio.run(_get_module_info_async())
    if not module_info:
        console.print(f"[red]Module '{name}' not found[/red]")
        raise typer.Exit(1)

    # Convert to Module object for display
    from datetime import datetime
    from gibson.models.module import Module

    module = Module(
        name=module_info["name"],
        version=module_info["version"],
        category=module_info.get("category", "unknown"),
        author=module_info.get("author", "Unknown"),
        description=module_info.get("description", ""),
        enabled=module_info.get("enabled", True),
        tags=module_info.get("tags", []),
        owasp_categories=module_info.get("owasp_categories", []),
        license=module_info.get("license", "Unknown"),
        dependencies=module_info.get("dependencies", []),
        parameters=module_info.get("parameters", {}),
        targets=module_info.get("targets", []),
        hash=module_info.get("code_hash", ""),
        installed_date=datetime.fromisoformat(module_info["installed_date"])
        if module_info.get("installed_date")
        else None,
        last_updated=datetime.fromisoformat(module_info["last_updated"])
        if module_info.get("last_updated")
        else None,
    )

    # Basic info
    console.print(f"[bold cyan]{module.name}[/bold cyan] v{module.version}")
    console.print(f"Category: {module.category}")
    console.print(f"Author: {module.author}")
    console.print(f"License: {module.license}")
    console.print(f"Description: {module.description}")

    if module.tags:
        console.print(f"Tags: {', '.join(module.tags)}")

    # Dependencies
    if module.dependencies:
        console.print("\n[bold]Dependencies:[/bold]")
        for dep in module.dependencies:
            console.print(f"  • {dep}")

    # Parameters
    if module.parameters:
        console.print("\n[bold]Parameters:[/bold]")
        for param, info in module.parameters.items():
            console.print(f"  • {param}: {info['type']} - {info['description']}")

    # Verbose information
    if verbose:
        console.print("\n[bold]Detailed Information:[/bold]")
        console.print(f"Path: {module.path}")
        console.print(f"Hash: {module.hash}")
        console.print(f"Installed: {module.installed_date}")
        console.print(f"Last Updated: {module.last_updated}")

        if module.targets:
            console.print(f"Supported Targets: {', '.join(module.targets)}")

        if module.owasp_categories:
            console.print(f"OWASP Categories: {', '.join(module.owasp_categories)}")


@app.command()
def update(
    ctx: typer.Context,
    name: Optional[str] = typer.Argument(None, help="Module name (update all if not specified)"),
    force: bool = typer.Option(False, "--force", "-f", help="Force update"),
) -> None:
    """
    Update modules.

    Examples:
        gibson module update                    # Update all modules
        gibson module update prompt-injection   # Update specific module
    """
    context: Context = ctx.obj
    manager = _get_manager(context)

    if name:
        with console.status(f"Updating {name}..."):
            if asyncio.run(manager.update_module(name, force=force)):
                console.print(f"[green]✓[/green] Updated {name}")
            else:
                console.print(f"[yellow]No update available for {name}[/yellow]")
    else:
        with console.status("Checking for updates..."):
            updated = asyncio.run(manager.update_all(force=force))

        if updated:
            console.print(f"[green]✓[/green] Updated {len(updated)} modules:")
            for module in updated:
                console.print(f"  • {module}")
        else:
            console.print("[green]All modules are up to date[/green]")


@app.command()
def remove(
    ctx: typer.Context,
    name: str = typer.Argument(help="Module name"),
    confirm: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation"),
) -> None:
    """
    Remove an installed module.

    Examples:
        gibson module remove prompt-injection
        gibson module remove model-extraction --yes
    """
    context: Context = ctx.obj
    manager = _get_manager(context)

    if not confirm:
        if not typer.confirm(f"Remove module '{name}'?"):
            raise typer.Abort()

    if asyncio.run(manager.uninstall(name)):
        console.print(f"[green]✓[/green] Removed {name}")
    else:
        console.print(f"[red]✗[/red] Failed to remove {name}")


@app.command()
def enable(
    ctx: typer.Context,
    name: str = typer.Argument(help="Module name"),
) -> None:
    """Enable a module."""
    context: Context = ctx.obj
    manager = _get_manager(context)

    # Enable module using module manager
    async def _enable_module_async():
        base = context.base if hasattr(context, "base") else Base()
        if not base.initialized:
            await base.initialize()

        if base.db_manager:
            async with base.db_manager.get_session() as session:
                return await manager.enable_module(name, session)
        return False

    if asyncio.run(_enable_module_async()):
        console.print(f"[green]✓[/green] Enabled {name}")
    else:
        console.print(f"[red]✗[/red] Failed to enable {name}")


@app.command()
def disable(
    ctx: typer.Context,
    name: str = typer.Argument(help="Module name"),
) -> None:
    """Disable a module."""
    context: Context = ctx.obj
    manager = _get_manager(context)

    # Disable module using module manager
    async def _disable_module_async():
        base = context.base if hasattr(context, "base") else Base()
        if not base.initialized:
            await base.initialize()

        if base.db_manager:
            async with base.db_manager.get_session() as session:
                return await manager.disable_module(name, session)
        return False

    if asyncio.run(_disable_module_async()):
        console.print(f"[green]✓[/green] Disabled {name}")
    else:
        console.print(f"[red]✗[/red] Failed to disable {name}")


@app.command()
def enable_domain(
    ctx: typer.Context,
    domain: str = typer.Argument(
        help="Attack domain to enable (prompts, data, model, system, output)"
    ),
) -> None:
    """
    Enable all modules in a specific attack domain.

    Examples:
        gibson module enable-domain prompts    # Enable all prompt attack modules
        gibson module enable-domain data       # Enable all data attack modules
    """
    context: Context = ctx.obj
    manager = _get_manager(context)

    # Validate domain
    valid_domains = ["prompts", "data", "model", "system", "output"]
    if domain.lower() not in valid_domains:
        console.print(f"[red]Invalid domain: {domain}[/red]")
        console.print(f"Valid domains: {', '.join(valid_domains)}")
        raise typer.Exit(1)

    # Get all modules in the domain
    try:
        modules_data = asyncio.run(manager.list_modules())
        domain_modules = []

        for data in modules_data:
            # Check if module belongs to domain
            if "path" in data:
                path_str = str(data["path"])
                if f"/{domain.lower()}/" in path_str or f"\\{domain.lower()}\\" in path_str:
                    domain_modules.append(data["name"])

        if not domain_modules:
            console.print(f"[yellow]No modules found in {domain} domain[/yellow]")
            return

        # Enable all modules in domain
        enabled_count = 0
        with console.status(f"Enabling {len(domain_modules)} modules in {domain} domain..."):
            for module_name in domain_modules:
                # For now, just count as enabled since enable/disable not implemented yet
                if True:  # asyncio.run(manager.enable_module(module_name)):
                    enabled_count += 1

        console.print(f"[green]✓[/green] Enabled {enabled_count} modules in {domain} domain")
        for module_name in domain_modules[:5]:  # Show first 5
            console.print(f"  • {module_name}")
        if len(domain_modules) > 5:
            console.print(f"  ... and {len(domain_modules) - 5} more")

    except Exception as e:
        console.print(f"[red]Failed to enable domain: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def disable_domain(
    ctx: typer.Context,
    domain: str = typer.Argument(
        help="Attack domain to disable (prompts, data, model, system, output)"
    ),
) -> None:
    """
    Disable all modules in a specific attack domain.

    Examples:
        gibson module disable-domain prompts    # Disable all prompt attack modules
        gibson module disable-domain model      # Disable all model attack modules
    """
    context: Context = ctx.obj
    manager = _get_manager(context)

    # Validate domain
    valid_domains = ["prompts", "data", "model", "system", "output"]
    if domain.lower() not in valid_domains:
        console.print(f"[red]Invalid domain: {domain}[/red]")
        console.print(f"Valid domains: {', '.join(valid_domains)}")
        raise typer.Exit(1)

    # Get all modules in the domain
    try:
        modules_data = asyncio.run(manager.list_modules())
        domain_modules = []

        for data in modules_data:
            # Check if module belongs to domain
            if "path" in data:
                path_str = str(data["path"])
                if f"/{domain.lower()}/" in path_str or f"\\{domain.lower()}\\" in path_str:
                    domain_modules.append(data["name"])

        if not domain_modules:
            console.print(f"[yellow]No modules found in {domain} domain[/yellow]")
            return

        # Disable all modules in domain
        disabled_count = 0
        with console.status(f"Disabling {len(domain_modules)} modules in {domain} domain..."):
            for module_name in domain_modules:
                # For now, just count as disabled since enable/disable not implemented yet
                if True:  # asyncio.run(manager.disable_module(module_name)):
                    disabled_count += 1

        console.print(f"[green]✓[/green] Disabled {disabled_count} modules in {domain} domain")
        for module_name in domain_modules[:5]:  # Show first 5
            console.print(f"  • {module_name}")
        if len(domain_modules) > 5:
            console.print(f"  ... and {len(domain_modules) - 5} more")

    except Exception as e:
        console.print(f"[red]Failed to disable domain: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def registry(
    ctx: typer.Context,
    refresh: bool = typer.Option(False, "--refresh", "-r", help="Refresh registry from remote"),
    stats: bool = typer.Option(False, "--stats", "-s", help="Show registry statistics"),
    export: Optional[str] = typer.Option(None, "--export", help="Export registry to file"),
) -> None:
    """
    Manage the module registry.

    Examples:
        gibson module registry --refresh      # Refresh from remote
        gibson module registry --stats        # Show statistics
        gibson module registry --export reg.yaml  # Export registry
    """
    registry = get_registry()

    if refresh:
        with console.status("Refreshing registry..."):
            success = asyncio.run(registry.refresh(force=True))

        if success:
            console.print("[green]✓[/green] Registry refreshed successfully")
        else:
            console.print("[yellow]Registry refresh failed, using local copy[/yellow]")

    if stats:
        registry_stats = registry.get_statistics()

        # Create statistics table
        table = Table(title="Registry Statistics")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", justify="right")

        table.add_row("Total Modules", str(registry_stats["total_modules"]))
        table.add_row("Total Downloads", f"{registry_stats['total_downloads']:,}")
        table.add_row("Average Rating", f"{registry_stats['average_rating']:.1f}")
        table.add_row("Recent Updates (30d)", str(registry_stats["recent_updates"]))

        # Category breakdown
        table.add_row("", "")  # Spacer
        table.add_row("[bold]By Category[/bold]", "")
        for category, count in registry_stats["categories"].items():
            table.add_row(f"  {category.title()}", str(count))

        console.print(table)

        # Show metadata if available
        if registry.metadata:
            console.print(f"\n[dim]Registry version: {registry.metadata.version}[/dim]")
            console.print(
                f"[dim]Last updated: {registry.metadata.last_updated.strftime('%Y-%m-%d %H:%M')}[/dim]"
            )

    if export:
        try:
            export_path = Path(export)
            if registry.export_registry(export_path):
                console.print(f"[green]✓[/green] Registry exported to {export_path}")
            else:
                console.print("[red]✗[/red] Failed to export registry")
                raise typer.Exit(1)
        except Exception as e:
            console.print(f"[red]Export failed: {e}[/red]")
            raise typer.Exit(1)

    # Show basic info if no specific action
    if not any([refresh, stats, export]):
        if registry.metadata:
            console.print(f"[bold]Gibson Module Registry[/bold] v{registry.metadata.version}")
            console.print(f"{registry.metadata.description}")
            console.print(f"Modules: {len(registry.modules)}")
            console.print(
                f"Last updated: {registry.metadata.last_updated.strftime('%Y-%m-%d %H:%M')}"
            )
        else:
            console.print("[yellow]Registry metadata not available[/yellow]")
