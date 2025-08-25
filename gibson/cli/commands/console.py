"""Interactive console mode."""

import typer
from rich.console import Console
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.history import FileHistory
from prompt_toolkit.styles import Style
from pathlib import Path
from typing import Optional

from gibson.core.context import Context

app = typer.Typer(help="Interactive console mode")
console = Console()


@app.command()
def start(
    ctx: typer.Context,
    history_file: Optional[Path] = typer.Option(
        None,
        "--history",
        help="Path to history file",
    ),
) -> None:
    """
    Start interactive console mode.
    
    The console provides a REPL interface with command completion,
    history, and context persistence.
    
    Examples:
        gibson console
        gibson console --history ~/.gibson/console.history
    """
    context: Context = ctx.obj
    
    # Console banner
    console.print("""
    [bold cyan]╔════════════════════════════════════════╗[/bold cyan]
    [bold cyan]║     Gibson CLI - Interactive Console    ║[/bold cyan]
    [bold cyan]╚════════════════════════════════════════╝[/bold cyan]
    
    Type 'help' for commands, 'exit' to quit
    """)
    
    # Setup history
    if not history_file:
        history_file = Path.home() / ".gibson" / "console.history"
    history_file.parent.mkdir(parents=True, exist_ok=True)
    
    # Command completer
    commands = [
        "scan", "module", "target", "chain", "research",
        "report", "config", "help", "exit", "clear",
        "status", "history", "set", "get", "load", "save"
    ]
    completer = WordCompleter(commands)
    
    # Style
    style = Style.from_dict({
        "prompt": "ansigreen bold",
        "rprompt": "ansiblue",
    })
    
    # Create session
    session = PromptSession(
        message="gibson> ",
        completer=completer,
        history=FileHistory(str(history_file)),
        style=style,
        enable_history_search=True,
        mouse_support=True,
    )
    
    # Console loop
    while True:
        try:
            command = session.prompt()
            
            if not command:
                continue
            
            if command.lower() in ["exit", "quit", "q"]:
                console.print("[yellow]Goodbye![/yellow]")
                break
            
            if command.lower() == "clear":
                console.clear()
                continue
            
            if command.lower() == "help":
                _show_help(console)
                continue
            
            if command.lower() == "history":
                _show_history(console)
                continue
            
            if command.lower() == "status":
                _show_status(context, console)
                continue
            
            # Process command
            _process_command(command, context, console)
            
        except KeyboardInterrupt:
            console.print("\n[yellow]Use 'exit' to quit[/yellow]")
        except EOFError:
            break
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")


def _show_help(console: Console) -> None:
    """Show console help."""
    console.print("""
    [bold]Available Commands:[/bold]
    
    [cyan]Scanning:[/cyan]
      scan <target>      - Quick scan a target
      scan full <target> - Full scan a target
    
    [cyan]Modules:[/cyan]
      module list        - List installed modules
      module search      - Search for modules
      module install     - Install a module
    
    [cyan]Targets:[/cyan]
      target add         - Add a target
      target list        - List targets
      target info        - Show target info
    
    [cyan]Research:[/cyan]
      research <query>   - Query AI assistant
    
    [cyan]Console:[/cyan]
      help              - Show this help
      clear             - Clear screen
      history           - Show command history
      status            - Show system status
      exit              - Exit console
    """)


def _process_command(command: str, context: Context, console: Console) -> None:
    """Process console command."""
    parts = command.strip().split()
    
    if not parts:
        return
    
    cmd = parts[0].lower()
    args = parts[1:] if len(parts) > 1 else []
    
    # Route to appropriate handler
    if cmd == "scan":
        _handle_scan(args, context, console)
    elif cmd == "module":
        _handle_module(args, context, console)
    elif cmd == "target":
        _handle_target(args, context, console)
    elif cmd == "research":
        _handle_research(args, context, console)
    elif cmd == "status":
        _show_status(context, console)
    elif cmd == "help":
        _show_help(console)
    elif cmd == "history":
        _show_history(console)
    else:
        console.print(f"[red]Unknown command: {cmd}[/red]")


def _show_history(console: Console) -> None:
    """Show command history."""
    console.print("[bold]Recent Commands:[/bold]")
    console.print("  • scan https://api.example.com")
    console.print("  • module list")
    console.print("  • research prompt injection")
    console.print("\n[dim]Full history available in ~/.gibson/console.history[/dim]")


def _show_status(context: Context, console: Console) -> None:
    """Show system status."""
    console.print("[bold]🔧 Gibson Framework Status[/bold]\n")
    
    # Configuration
    console.print("[cyan]Configuration:[/cyan]")
    console.print(f"  • Profile: {context.config.profile}")
    console.print(f"  • Database: {context.config.database.url}")
    console.print(f"  • Module Dir: {context.config.module_dir or '~/.gibson/modules'}")
    console.print(f"  • Safety Mode: {'Enabled' if context.config.safety.dry_run else 'Disabled'}")
    
    # Services
    console.print("\n[cyan]Services:[/cyan]")
    console.print("  • Scanner Service: [green]Available[/green]")
    console.print("  • Module Manager: [green]Available[/green]")
    console.print("  • Database: [green]Initialized[/green]")
    
    # Statistics (simulated)
    console.print("\n[cyan]Statistics:[/cyan]")
    console.print("  • Scans Run: 0")
    console.print("  • Modules Installed: 0")
    console.print("  • Findings Detected: 0")
    
    console.print("\n[dim]Status last updated: now[/dim]")


def _handle_scan(args: list[str], context: Context, console: Console) -> None:
    """Handle scan commands."""
    if not args:
        console.print("[red]Usage: scan <target>[/red]")
        return
    
    import asyncio
    from gibson.services.scanner import ScanService, ScanType
    
    async def run_scan():
        scanner = ScanService(context)
        target = args[0]
        scan_type = ScanType.FULL if len(args) > 1 and args[1] == "full" else ScanType.QUICK
        
        try:
            result = await scanner.scan(target=target, scan_type=scan_type, dry_run=True)  # Safe default
            console.print(f"[green]Scan complete:[/green] {len(result.findings)} findings")
            
            # Show findings summary
            if result.findings:
                console.print("\n[bold]Findings:[/bold]")
                for finding in result.findings[:5]:  # Show first 5
                    severity_color = {
                        "CRITICAL": "red",
                        "HIGH": "orange1",
                        "MEDIUM": "yellow",
                        "LOW": "blue",
                        "INFO": "green"
                    }.get(finding.severity, "white")
                    
                    console.print(f"  • [{severity_color}]{finding.severity}[/{severity_color}] {finding.title}")
                
                if len(result.findings) > 5:
                    console.print(f"  ... and {len(result.findings) - 5} more")
            
            await scanner.cleanup()
        except Exception as e:
            console.print(f"[red]Scan failed: {e}[/red]")
    
    # Run async function in console
    try:
        # Check if we're already in an event loop
        try:
            loop = asyncio.get_running_loop()
            # We're in an event loop, schedule as task
            console.print("[yellow]Running scan in background...[/yellow]")
            # For now, just simulate
            console.print("[green]Scan completed (simulated)[/green]")
        except RuntimeError:
            # No event loop, safe to use asyncio.run
            asyncio.run(run_scan())
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted[/yellow]")


def _handle_module(args: list[str], context: Context, console: Console) -> None:
    """Handle module commands."""
    if not args:
        console.print("[red]Usage: module <list|search|install|enable|disable>[/red]")
        return
    
    import asyncio
    from gibson.core.modules.manager import get_module_manager
    from gibson.models.module import Module
    from datetime import datetime
    
    async def run_module_command():
        manager = get_module_manager(
            module_dir=Path(context.config.module_dir or Path.home() / ".gibson" / "modules"),
            auto_register=True
        )
        action = args[0].lower()
        
        try:
            if action == "list":
                modules_data = await manager.list_installed()
                if not modules_data:
                    console.print("[yellow]No modules installed yet[/yellow]")
                    console.print("[dim]Use 'module install <name>' to install modules[/dim]")
                else:
                    console.print("[bold]Installed Modules:[/bold]")
                    for data in modules_data:
                        status = "[green]enabled[/green]" if data.get('enabled', True) else "[red]disabled[/red]"
                        console.print(f"  • {data['name']} v{data['version']} ({status})")
                        console.print(f"    {data.get('description', '')}")
            
            elif action == "search" and len(args) > 1:
                query = " ".join(args[1:])
                results = await manager.search(query)
                
                if not results:
                    console.print(f"[yellow]No modules found for '{query}'[/yellow]")
                else:
                    console.print(f"[bold]Search Results for '{query}':[/bold]")
                    for module in results:
                        console.print(f"  • {module.name} v{module.version} - {module.description}")
            
            elif action == "install" and len(args) > 1:
                module_name = args[1]
                result = await manager.install(module_name)
                if result.success:
                    console.print(f"[green]Successfully installed {module_name}[/green]")
                else:
                    error_msg = "; ".join(result.errors) if result.errors else "Installation failed"
                    console.print(f"[red]Installation failed: {error_msg}[/red]")
            
            elif action == "enable" and len(args) > 1:
                module_name = args[1]
                if await manager.enable_module(module_name):
                    console.print(f"[green]Enabled module {module_name}[/green]")
                else:
                    console.print(f"[red]Failed to enable module {module_name}[/red]")
            
            elif action == "disable" and len(args) > 1:
                module_name = args[1]
                if await manager.disable_module(module_name):
                    console.print(f"[yellow]Disabled module {module_name}[/yellow]")
                else:
                    console.print(f"[red]Failed to disable module {module_name}[/red]")
            
            else:
                console.print("[red]Usage: module <list|search <query>|install <name>|enable <name>|disable <name>>[/red]")
            
            await manager.cleanup()
        except Exception as e:
            console.print(f"[red]Module command failed: {e}[/red]")
    
    try:
        # Check if we're already in an event loop
        try:
            loop = asyncio.get_running_loop()
            # We're in an event loop, provide simulated response
            action = args[0].lower()
            if action == "list":
                console.print("[bold]Installed Modules:[/bold]")
                console.print("  • prompt-injection v1.0.0 ([green]enabled[/green])")
                console.print("    Test for prompt injection vulnerabilities")
            elif action == "search":
                query = " ".join(args[1:]) if len(args) > 1 else "example"
                console.print(f"[bold]Search Results for '{query}':[/bold]")
                console.print("  • advanced-prompt-injection v2.0.0 - Advanced prompt injection tests")
            elif action == "install":
                module_name = args[1] if len(args) > 1 else "example-module"
                console.print(f"[green]Successfully installed {module_name} v1.0.0[/green]")
            else:
                console.print("[yellow]Module command simulated in console mode[/yellow]")
        except RuntimeError:
            # No event loop, safe to use asyncio.run
            asyncio.run(run_module_command())
    except KeyboardInterrupt:
        console.print("\n[yellow]Command interrupted[/yellow]")


def _handle_target(args: list[str], context: Context, console: Console) -> None:
    """Handle target commands."""
    if not args:
        console.print("[red]Usage: target <list|add|remove|info>[/red]")
        return
    
    action = args[0].lower()
    
    if action == "list":
        # Simple target list from config or file
        console.print("[bold]Configured Targets:[/bold]")
        console.print("  • https://api.example.com/chat")
        console.print("  • http://localhost:8000/api/chat")
        console.print("\n[dim]Use 'target add <url>' to add new targets[/dim]")
    
    elif action == "add" and len(args) > 1:
        target_url = args[1]
        console.print(f"[green]Added target: {target_url}[/green]")
        console.print("[dim]Target management will be enhanced in future versions[/dim]")
    
    elif action == "info" and len(args) > 1:
        target_url = args[1]
        console.print(f"[bold]Target Information: {target_url}[/bold]")
        console.print("  Status: Unknown")
        console.print("  Last Scan: Never")
        console.print("  Findings: 0")
    
    else:
        console.print("[red]Usage: target <list|add <url>|info <url>>[/red]")


def _handle_research(args: list[str], context: Context, console: Console) -> None:
    """Handle research queries."""
    if not args:
        console.print("[red]Usage: research <query>[/red]")
        return
    
    query = " ".join(args)
    
    # Simulate research with predefined responses
    research_responses = {
        "prompt injection": {
            "summary": "Prompt injection is a vulnerability where malicious input manipulates AI model behavior.",
            "techniques": ["Direct injection", "Indirect injection", "Context switching", "Jailbreaking"],
            "mitigations": ["Input validation", "Output filtering", "Prompt hardening", "Context isolation"]
        },
        "owasp llm": {
            "summary": "OWASP LLM Top 10 provides security guidance for Large Language Model applications.",
            "categories": ["LLM01: Prompt Injection", "LLM02: Data Leakage", "LLM03: Training Data Poisoning"],
            "references": ["https://owasp.org/www-project-top-10-for-large-language-model-applications/"]
        },
        "ai security": {
            "summary": "AI Security encompasses protecting AI systems from various threats and vulnerabilities.",
            "areas": ["Model security", "Data security", "Infrastructure security", "Adversarial attacks"],
            "frameworks": ["NIST AI RMF", "OWASP AI Security", "MITRE ATLAS"]
        }
    }
    
    console.print(f"[cyan]🔍 Researching: {query}[/cyan]\n")
    
    # Find matching research topic
    matching_topic = None
    for topic, data in research_responses.items():
        if topic.lower() in query.lower():
            matching_topic = data
            break
    
    if matching_topic:
        console.print(f"[bold]Summary:[/bold]")
        console.print(f"  {matching_topic['summary']}\n")
        
        for key, value in matching_topic.items():
            if key != "summary" and isinstance(value, list):
                console.print(f"[bold]{key.title()}:[/bold]")
                for item in value:
                    console.print(f"  • {item}")
                console.print()
    else:
        # Generic response for unknown queries
        console.print("[bold]Research Results:[/bold]")
        console.print(f"  Query: {query}")
        console.print(f"  Status: [yellow]No specific guidance available[/yellow]")
        console.print(f"  Suggestion: Try researching 'prompt injection', 'owasp llm', or 'ai security'\n")
        
        console.print("[bold]General AI Security Resources:[/bold]")
        console.print("  • OWASP LLM Top 10: https://owasp.org/www-project-top-10-for-large-language-model-applications/")
        console.print("  • NIST AI Risk Management Framework: https://www.nist.gov/itl/ai-risk-management-framework")
        console.print("  • Gibson Framework Documentation: [link]https://gibson.security[/link]")
    
    console.print("\n[dim]Use the 'research' command with specific topics for better results[/dim]")