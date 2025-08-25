"""Attack chain management commands."""

import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any
from enum import Enum

import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.tree import Tree
from loguru import logger
from pydantic import BaseModel, Field

from gibson.core.context import Context
from gibson.core.modules.base import ModuleCategory
from gibson.core.config import ConfigManager

app = typer.Typer(help="Attack chain management")
console = Console()


class ChainStepStatus(str, Enum):
    """Status of chain step execution."""

    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


class ChainStep(BaseModel):
    """Single step in an attack chain."""

    id: str = Field(description="Unique step identifier")
    module: str = Field(description="Module name to execute")
    description: str = Field(description="Human readable description")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Module parameters")
    depends_on: List[str] = Field(default_factory=list, description="Step dependencies")
    condition: Optional[str] = Field(default=None, description="Execution condition")
    timeout: int = Field(default=300, description="Step timeout in seconds")
    retry_count: int = Field(default=3, description="Number of retries")
    status: ChainStepStatus = Field(default=ChainStepStatus.PENDING, description="Execution status")
    error: Optional[str] = Field(default=None, description="Error message if failed")
    output: Optional[Dict[str, Any]] = Field(default=None, description="Step output")
    duration: Optional[float] = Field(default=None, description="Execution duration")


class AttackChain(BaseModel):
    """Attack chain configuration."""

    name: str = Field(description="Chain name")
    description: str = Field(description="Chain description")
    domain: str = Field(description="Primary attack domain")
    author: str = Field(default="Unknown", description="Chain author")
    version: str = Field(default="1.0.0", description="Chain version")
    created_at: datetime = Field(default_factory=datetime.now)
    tags: List[str] = Field(default_factory=list, description="Chain tags")
    steps: List[ChainStep] = Field(description="Chain execution steps")
    parallel_execution: bool = Field(default=False, description="Allow parallel step execution")
    continue_on_failure: bool = Field(default=False, description="Continue chain if step fails")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")


class ChainManager:
    """Manages attack chain storage and execution."""

    def __init__(self):
        self.chains_dir = Path.home() / ".gibson" / "chains"
        self.chains_dir.mkdir(parents=True, exist_ok=True)

    def save_chain(self, chain: AttackChain) -> None:
        """Save chain to disk."""
        chain_file = self.chains_dir / f"{chain.name}.json"
        with open(chain_file, "w") as f:
            json.dump(chain.model_dump(), f, indent=2, default=str)

    def load_chain(self, name: str) -> Optional[AttackChain]:
        """Load chain from disk."""
        chain_file = self.chains_dir / f"{name}.json"
        if not chain_file.exists():
            return None

        with open(chain_file, "r") as f:
            data = json.load(f)

        return AttackChain(**data)

    def list_chains(self) -> List[str]:
        """List available chain names."""
        return [f.stem for f in self.chains_dir.glob("*.json")]

    def delete_chain(self, name: str) -> bool:
        """Delete a chain."""
        chain_file = self.chains_dir / f"{name}.json"
        if chain_file.exists():
            chain_file.unlink()
            return True
        return False


@app.command()
def create(
    ctx: typer.Context,
    name: str = typer.Argument(help="Chain name"),
    domain: str = typer.Option(..., "--domain", "-d", help="Primary attack domain"),
    description: str = typer.Option("", "--description", help="Chain description"),
    template: Optional[str] = typer.Option(
        None, "--template", "-t", help="Use predefined template"
    ),
) -> None:
    """
    Create a new domain-based attack chain.

    Examples:
        gibson chain create my-llm-chain --domain llm-prompt-injection
        gibson chain create full-assessment --domain llm-prompt-injection --template comprehensive
    """
    context: Context = ctx.obj
    manager = ChainManager()

    # Check if chain already exists
    if manager.load_chain(name):
        console.print(f"[red]Chain '{name}' already exists[/red]")
        raise typer.Exit(1)

    try:
        # Create chain based on domain and template
        if template:
            chain = _create_from_template(name, domain, description, template)
        else:
            chain = _create_basic_chain(name, domain, description)

        # Save chain
        manager.save_chain(chain)

        console.print(f"[green]✓ Created attack chain:[/green] {name}")
        console.print(f"  Domain: {domain}")
        console.print(f"  Steps: {len(chain.steps)}")
        console.print(f"  Location: {manager.chains_dir / f'{name}.json'}")

        # Show next steps
        console.print("\n[dim]Next steps:[/dim]")
        console.print(f"  Edit: [cyan]gibson chain edit {name}[/cyan]")
        console.print(f"  Run: [cyan]gibson chain run {name} <target>[/cyan]")

    except Exception as e:
        logger.error(f"Failed to create chain: {e}")
        console.print(f"[red]Failed to create chain:[/red] {e}")
        raise typer.Exit(1)


@app.command("list")
def list_chains(
    ctx: typer.Context,
    domain: Optional[str] = typer.Option(None, "--domain", "-d", help="Filter by domain"),
    format: str = typer.Option("table", "--format", "-f", help="Output format"),
) -> None:
    """List available attack chains with domain filtering."""
    context: Context = ctx.obj
    manager = ChainManager()

    chain_names = manager.list_chains()

    if not chain_names:
        console.print("[yellow]No attack chains found[/yellow]")
        console.print(
            "\n[dim]Create one with:[/dim] [cyan]gibson chain create <name> --domain <domain>[/cyan]"
        )
        return

    # Load chains and filter by domain if specified
    chains = []
    for name in chain_names:
        try:
            chain = manager.load_chain(name)
            if chain and (not domain or chain.domain == domain):
                chains.append(chain)
        except Exception as e:
            logger.warning(f"Failed to load chain {name}: {e}")

    if not chains:
        if domain:
            console.print(f"[yellow]No chains found for domain: {domain}[/yellow]")
        else:
            console.print("[yellow]No valid chains found[/yellow]")
        return

    if format == "table":
        table = Table(title="Attack Chains")
        table.add_column("Name", style="cyan")
        table.add_column("Domain", style="magenta")
        table.add_column("Steps", style="green")
        table.add_column("Version", style="blue")
        table.add_column("Created", style="dim")
        table.add_column("Description")

        for chain in sorted(chains, key=lambda x: x.name):
            created_str = (
                chain.created_at.strftime("%Y-%m-%d")
                if hasattr(chain.created_at, "strftime")
                else str(chain.created_at)[:10]
            )

            table.add_row(
                chain.name,
                chain.domain,
                str(len(chain.steps)),
                chain.version,
                created_str,
                chain.description[:50] + "..."
                if len(chain.description) > 50
                else chain.description,
            )

        console.print(table)
    else:
        console.print("[red]Only table format supported currently[/red]")


@app.command()
def run(
    ctx: typer.Context,
    name: str = typer.Argument(help="Chain name"),
    target: str = typer.Argument(help="Target URL or identifier"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show execution plan without running"),
    parallel: bool = typer.Option(
        False, "--parallel", "-p", help="Enable parallel execution where possible"
    ),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file for results"),
) -> None:
    """
    Execute a domain-based attack chain against a target.

    Examples:
        gibson chain run my-llm-chain https://api.example.com
        gibson chain run comprehensive-test https://app.example.com --parallel
        gibson chain run assessment-chain target.com --output results.json
    """
    context: Context = ctx.obj
    manager = ChainManager()

    # Load chain
    chain = manager.load_chain(name)
    if not chain:
        console.print(f"[red]Chain '{name}' not found[/red]")
        console.print("\n[dim]Available chains:[/dim]")
        for chain_name in manager.list_chains():
            console.print(f"  • {chain_name}")
        raise typer.Exit(1)

    console.print(f"[cyan]Executing chain:[/cyan] {name}")
    console.print(f"[dim]Domain:[/dim] {chain.domain}")
    console.print(f"[dim]Target:[/dim] {target}")
    console.print(f"[dim]Steps:[/dim] {len(chain.steps)}")

    if dry_run:
        _show_execution_plan(chain)
        return

    try:
        # Execute chain
        results = asyncio.run(_execute_chain(chain, target, parallel or chain.parallel_execution))

        # Show results
        _show_execution_results(results, chain)

        # Save results if output specified
        if output:
            _save_results(results, output)
            console.print(f"\n[green]Results saved to:[/green] {output}")

    except KeyboardInterrupt:
        console.print("\n[yellow]Execution interrupted by user[/yellow]")
        raise typer.Exit(130)
    except Exception as e:
        logger.error(f"Chain execution failed: {e}")
        console.print(f"[red]Chain execution failed:[/red] {e}")
        raise typer.Exit(1)


@app.command()
def validate(
    ctx: typer.Context,
    name: str = typer.Argument(help="Chain name to validate"),
) -> None:
    """Validate attack chain configuration and dependencies."""
    context: Context = ctx.obj
    manager = ChainManager()

    chain = manager.load_chain(name)
    if not chain:
        console.print(f"[red]Chain '{name}' not found[/red]")
        raise typer.Exit(1)

    console.print(f"[cyan]Validating chain:[/cyan] {name}")

    try:
        validation_results = _validate_chain(chain)

        if validation_results["valid"]:
            console.print(f"[green]✓ Chain '{name}' is valid[/green]")
        else:
            console.print(f"[red]✗ Chain '{name}' has validation errors[/red]")

            for error in validation_results["errors"]:
                console.print(f"  [red]Error:[/red] {error}")

            for warning in validation_results["warnings"]:
                console.print(f"  [yellow]Warning:[/yellow] {warning}")

            if validation_results["errors"]:
                raise typer.Exit(1)

    except Exception as e:
        logger.error(f"Validation failed: {e}")
        console.print(f"[red]Validation failed:[/red] {e}")
        raise typer.Exit(1)


@app.command()
def templates(
    ctx: typer.Context,
    domain: Optional[str] = typer.Option(None, "--domain", "-d", help="Filter by domain"),
) -> None:
    """List available chain templates for domains."""
    context: Context = ctx.obj

    templates = _get_available_templates(domain)

    if not templates:
        console.print("[yellow]No templates available[/yellow]")
        return

    table = Table(title="Chain Templates")
    table.add_column("Name", style="cyan")
    table.add_column("Domain", style="magenta")
    table.add_column("Steps", style="green")
    table.add_column("Description")

    for template in templates:
        table.add_row(
            template["name"], template["domain"], str(template["steps"]), template["description"]
        )

    console.print(table)
    console.print(
        "\n[dim]Create from template:[/dim] [cyan]gibson chain create <name> --domain <domain> --template <template>[/cyan]"
    )


@app.command()
def delete(
    ctx: typer.Context,
    name: str = typer.Argument(help="Chain name to delete"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation"),
) -> None:
    """Delete an attack chain."""
    context: Context = ctx.obj
    manager = ChainManager()

    if not manager.load_chain(name):
        console.print(f"[red]Chain '{name}' not found[/red]")
        raise typer.Exit(1)

    if not force:
        confirm = typer.confirm(f"Are you sure you want to delete chain '{name}'?")
        if not confirm:
            console.print("[yellow]Cancelled[/yellow]")
            return

    if manager.delete_chain(name):
        console.print(f"[green]✓ Deleted chain:[/green] {name}")
    else:
        console.print(f"[red]Failed to delete chain:[/red] {name}")
        raise typer.Exit(1)


# Helper functions for chain management


def _create_from_template(name: str, domain: str, description: str, template: str) -> AttackChain:
    """Create chain from predefined template."""
    templates = {
        "comprehensive": _create_comprehensive_template,
        "basic": _create_basic_template,
        "reconnaissance": _create_recon_template,
        "exploitation": _create_exploitation_template,
    }

    if template not in templates:
        raise ValueError(f"Unknown template: {template}")

    return templates[template](name, domain, description)


def _create_basic_chain(name: str, domain: str, description: str) -> AttackChain:
    """Create basic chain with minimal steps."""
    steps = [
        ChainStep(
            id="reconnaissance",
            module="target_analysis",
            description="Initial target reconnaissance",
            parameters={"depth": "basic"},
        ),
        ChainStep(
            id="domain_test",
            module=_get_primary_module_for_domain(domain),
            description=f"Primary {domain} testing",
            depends_on=["reconnaissance"],
        ),
    ]

    return AttackChain(
        name=name,
        description=description or f"Basic {domain} attack chain",
        domain=domain,
        steps=steps,
    )


def _create_comprehensive_template(name: str, domain: str, description: str) -> AttackChain:
    """Create comprehensive testing chain."""
    steps = [
        ChainStep(
            id="recon",
            module="target_analysis",
            description="Comprehensive target analysis",
            parameters={"depth": "comprehensive"},
        ),
        ChainStep(
            id="fingerprinting",
            module="service_fingerprint",
            description="Service and technology fingerprinting",
            depends_on=["recon"],
        ),
    ]

    # Add domain-specific modules
    domain_modules = _get_modules_for_domain(domain)
    for i, module in enumerate(domain_modules):
        steps.append(
            ChainStep(
                id=f"test_{i+1}",
                module=module,
                description=f"{domain} testing with {module}",
                depends_on=["fingerprinting"],
            )
        )

    return AttackChain(
        name=name,
        description=description or f"Comprehensive {domain} assessment",
        domain=domain,
        steps=steps,
    )


def _create_basic_template(name: str, domain: str, description: str) -> AttackChain:
    """Create basic template."""
    return _create_basic_chain(name, domain, description)


def _create_recon_template(name: str, domain: str, description: str) -> AttackChain:
    """Create reconnaissance-focused template."""
    steps = [
        ChainStep(
            id="passive_recon",
            module="passive_reconnaissance",
            description="Passive information gathering",
        ),
        ChainStep(
            id="active_recon",
            module="active_reconnaissance",
            description="Active reconnaissance",
            depends_on=["passive_recon"],
        ),
        ChainStep(
            id="service_enum",
            module="service_enumeration",
            description="Service enumeration",
            depends_on=["active_recon"],
        ),
    ]

    return AttackChain(
        name=name,
        description=description or f"Reconnaissance chain for {domain}",
        domain=domain,
        steps=steps,
    )


def _create_exploitation_template(name: str, domain: str, description: str) -> AttackChain:
    """Create exploitation-focused template."""
    steps = []

    # Add domain-specific exploitation modules
    exploit_modules = _get_exploitation_modules_for_domain(domain)
    for i, module in enumerate(exploit_modules):
        depends = [f"exploit_{i}"] if i > 0 else []
        steps.append(
            ChainStep(
                id=f"exploit_{i+1}",
                module=module,
                description=f"Exploitation attempt with {module}",
                depends_on=depends,
            )
        )

    return AttackChain(
        name=name,
        description=description or f"Exploitation chain for {domain}",
        domain=domain,
        steps=steps,
    )


def _get_primary_module_for_domain(domain: str) -> str:
    """Get primary testing module for domain."""
    module_mapping = {
        "llm-prompt-injection": "prompt_injection",
        "llm-model-theft": "model_theft",
        "llm-sensitive-info": "sensitive_info_disclosure",
        "llm-model-dos": "model_dos",
        "llm-training-poisoning": "training_data_poisoning",
        "cv-adversarial": "adversarial_examples",
        "ml-pipeline-poisoning": "pipeline_poisoning",
    }
    return module_mapping.get(domain, "generic_test")


def _get_modules_for_domain(domain: str) -> List[str]:
    """Get all modules for domain."""
    domain_modules = {
        "llm-prompt-injection": [
            "prompt_injection",
            "jailbreak_detection",
            "indirect_injection",
            "system_prompt_leakage",
            "role_playing_bypass",
        ],
        "llm-model-theft": [
            "model_theft",
            "api_extraction",
            "weight_analysis",
            "query_based_extraction",
        ],
        "llm-sensitive-info": [
            "sensitive_info_disclosure",
            "data_extraction",
            "privacy_leakage",
            "training_data_inference",
        ],
    }
    return domain_modules.get(domain, [_get_primary_module_for_domain(domain)])


def _get_exploitation_modules_for_domain(domain: str) -> List[str]:
    """Get exploitation modules for domain."""
    exploit_mapping = {
        "llm-prompt-injection": ["advanced_injection", "payload_generation"],
        "llm-model-theft": ["model_extraction", "api_abuse"],
        "llm-sensitive-info": ["data_exfiltration", "inference_attack"],
    }
    return exploit_mapping.get(domain, ["generic_exploit"])


def _get_available_templates(domain_filter: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get available templates."""
    templates = [
        {
            "name": "comprehensive",
            "domain": "any",
            "steps": 5,
            "description": "Full assessment with multiple attack vectors",
        },
        {
            "name": "basic",
            "domain": "any",
            "steps": 2,
            "description": "Simple two-step attack chain",
        },
        {
            "name": "reconnaissance",
            "domain": "any",
            "steps": 3,
            "description": "Information gathering focused chain",
        },
        {
            "name": "exploitation",
            "domain": "any",
            "steps": 3,
            "description": "Exploitation focused attack chain",
        },
    ]

    if domain_filter:
        return [t for t in templates if t["domain"] == "any" or t["domain"] == domain_filter]

    return templates


async def _execute_chain(chain: AttackChain, target: str, parallel: bool = False) -> Dict[str, Any]:
    """Execute attack chain steps."""
    results = {
        "chain_name": chain.name,
        "target": target,
        "start_time": datetime.now(),
        "steps": [],
        "success": True,
        "total_duration": 0.0,
    }

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        console=console,
    ) as progress:
        task = progress.add_task(f"Executing {chain.name}", total=len(chain.steps))

        # For now, execute steps sequentially
        # TODO: Implement proper dependency resolution and parallel execution

        for step in chain.steps:
            progress.update(task, description=f"Running {step.module}...")

            step_start = datetime.now()
            step.status = ChainStepStatus.RUNNING

            try:
                # Simulate module execution (replace with actual module runner)
                await asyncio.sleep(1)  # Simulate work

                step.status = ChainStepStatus.SUCCESS
                step.output = {"simulated": True, "target": target}

            except Exception as e:
                step.status = ChainStepStatus.FAILED
                step.error = str(e)
                results["success"] = False

                if not chain.continue_on_failure:
                    break

            step.duration = (datetime.now() - step_start).total_seconds()
            results["steps"].append(step.model_dump())
            progress.advance(task)

    results["end_time"] = datetime.now()
    results["total_duration"] = (results["end_time"] - results["start_time"]).total_seconds()

    return results


def _validate_chain(chain: AttackChain) -> Dict[str, Any]:
    """Validate chain configuration."""
    errors = []
    warnings = []

    # Check for duplicate step IDs
    step_ids = [step.id for step in chain.steps]
    if len(step_ids) != len(set(step_ids)):
        errors.append("Duplicate step IDs found")

    # Check dependencies
    for step in chain.steps:
        for dep in step.depends_on:
            if dep not in step_ids:
                errors.append(f"Step '{step.id}' depends on non-existent step '{dep}'")

    # Check for circular dependencies (basic check)
    if _has_circular_dependencies(chain.steps):
        errors.append("Circular dependencies detected")

    # Check module availability (placeholder)
    available_modules = [
        "prompt_injection",
        "model_theft",
        "target_analysis",
    ]  # This would be dynamic
    for step in chain.steps:
        if step.module not in available_modules:
            warnings.append(f"Module '{step.module}' may not be available")

    return {"valid": len(errors) == 0, "errors": errors, "warnings": warnings}


def _has_circular_dependencies(steps: List[ChainStep]) -> bool:
    """Check for circular dependencies (simplified)."""
    # This is a simplified check - would need full graph analysis for complex cases
    step_map = {step.id: step.depends_on for step in steps}

    for step_id in step_map:
        visited = set()
        current = step_id

        while current in step_map:
            if current in visited:
                return True
            visited.add(current)

            # Get first dependency (simplified)
            deps = step_map[current]
            if deps:
                current = deps[0]
            else:
                break

    return False


def _show_execution_plan(chain: AttackChain) -> None:
    """Show chain execution plan."""
    console.print(f"\n[bold]Execution Plan for {chain.name}[/bold]")

    tree = Tree(f"🎯 Target: [target placeholder]")

    for step in chain.steps:
        step_node = tree.add(f"📋 {step.id}: {step.module}")
        step_node.add(f"Description: {step.description}")
        if step.depends_on:
            step_node.add(f"Depends on: {', '.join(step.depends_on)}")
        if step.parameters:
            step_node.add(f"Parameters: {step.parameters}")

    console.print(tree)


def _show_execution_results(results: Dict[str, Any], chain: AttackChain) -> None:
    """Show chain execution results."""
    console.print(f"\n[bold]Execution Results for {chain.name}[/bold]")

    success_count = sum(1 for step in results["steps"] if step["status"] == "success")
    total_steps = len(results["steps"])

    console.print(f"Success: {success_count}/{total_steps}")
    console.print(f"Duration: {results['total_duration']:.2f}s")

    # Show step results
    table = Table()
    table.add_column("Step", style="cyan")
    table.add_column("Status", style="bold")
    table.add_column("Duration", style="blue")
    table.add_column("Error", style="red")

    for step in results["steps"]:
        status_color = "green" if step["status"] == "success" else "red"
        duration = f"{step.get('duration', 0):.2f}s"
        error = step.get("error", "")[:50] if step.get("error") else ""

        table.add_row(
            step["id"], f"[{status_color}]{step['status']}[/{status_color}]", duration, error
        )

    console.print(table)


def _save_results(results: Dict[str, Any], output_file: str) -> None:
    """Save execution results to file."""
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2, default=str)
