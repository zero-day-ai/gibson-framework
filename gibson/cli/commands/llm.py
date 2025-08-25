"""LLM management commands for Gibson Framework."""

from typing import Optional, List
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
import asyncio
from loguru import logger

from gibson.core.context import Context
from gibson.core.llm import (
    EnvironmentManager,
    LLMProvider,
    create_llm_client_factory,
    create_completion_service,
    create_usage_tracker,
    create_rate_limiter,
)

app = typer.Typer(help="LLM provider management and configuration")
console = Console()


@app.command()
def status(ctx: typer.Context) -> None:
    """Show LLM provider status and configuration."""
    context: Context = ctx.obj

    # Discover available providers
    env_manager = EnvironmentManager()
    discovery = env_manager.discover_providers()

    # Create status table
    table = Table(title="LLM Provider Status", show_header=True)
    table.add_column("Provider", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("API Key", style="yellow")
    table.add_column("Configuration", style="dim")

    # Add available providers
    for provider in discovery.available_providers:
        config = discovery.provider_configs.get(provider, {})
        api_key = config.get("api_key", "")
        masked_key = f"{api_key[:8]}...{api_key[-4:]}" if len(api_key) > 12 else "***"

        status_icon = "✓ Available"

        # Show additional config
        extra_config = []
        if "base_url" in config:
            extra_config.append(f"URL: {config['base_url']}")
        if "deployment_name" in config:
            extra_config.append(f"Deployment: {config['deployment_name']}")

        table.add_row(
            provider.value,
            status_icon,
            masked_key,
            "\n".join(extra_config) if extra_config else "-",
        )

    # Add missing providers
    for provider in discovery.missing_providers:
        table.add_row(
            provider.value,
            "[red]✗ Not Configured[/red]",
            "[dim]Not Set[/dim]",
            "[dim]See 'gibson llm setup' for instructions[/dim]",
        )

    console.print(table)

    # Show summary
    console.print(f"\n[green]Available Providers:[/green] {discovery.total_providers}")
    console.print(f"[yellow]Missing Providers:[/yellow] {len(discovery.missing_providers)}")

    if discovery.missing_providers:
        console.print("\n[dim]Run 'gibson llm setup' for configuration instructions[/dim]")


@app.command()
def setup(
    ctx: typer.Context,
    provider: Optional[str] = typer.Argument(None, help="Specific provider to set up"),
) -> None:
    """Show setup instructions for LLM providers."""
    context: Context = ctx.obj

    env_manager = EnvironmentManager()

    if provider:
        # Show instructions for specific provider
        try:
            provider_enum = LLMProvider(provider.lower())
            instructions = env_manager.get_setup_instructions(provider_enum)

            panel = Panel(
                instructions,
                title=f"Setup Instructions for {provider_enum.value.upper()}",
                border_style="cyan",
            )
            console.print(panel)

        except ValueError:
            console.print(f"[red]Unknown provider: {provider}[/red]")
            console.print("[dim]Available providers:[/dim]")
            for p in LLMProvider:
                console.print(f"  - {p.value}")
    else:
        # Show all missing providers
        discovery = env_manager.discover_providers()

        if not discovery.missing_providers:
            console.print("[green]✓ All providers are configured![/green]")
            return

        instructions = env_manager.get_all_setup_instructions(discovery.missing_providers)
        console.print(instructions)


@app.command()
def test(
    ctx: typer.Context,
    provider: str = typer.Argument(help="Provider to test"),
    prompt: str = typer.Option("Hello, can you respond?", "--prompt", "-p", help="Test prompt"),
) -> None:
    """Test an LLM provider connection."""
    context: Context = ctx.obj

    async def run_test():
        try:
            # Create client factory
            factory = await create_llm_client_factory()

            # Check provider
            provider_enum = LLMProvider(provider.lower())

            if provider_enum not in factory.get_available_providers():
                console.print(f"[red]Provider {provider} is not configured[/red]")
                return

            # Test connection
            console.print(f"[yellow]Testing {provider}...[/yellow]")

            # Check health
            is_healthy = await factory.check_health(provider_enum)

            if is_healthy:
                console.print(f"[green]✓ {provider} is healthy and responding[/green]")

                # Try a simple completion
                from gibson.core.llm.types import CompletionRequest, ChatMessage

                request = CompletionRequest(
                    model="gpt-3.5-turbo"
                    if provider_enum == LLMProvider.OPENAI
                    else "claude-3-haiku-20240307",
                    messages=[ChatMessage(role="user", content=prompt)],
                    max_tokens=50,
                )

                client = await factory.get_client(provider_enum)
                console.print(f"\n[dim]Sending test prompt: {prompt}[/dim]")

                response = await client.complete(request)

                if response and response.choices:
                    console.print(
                        f"\n[green]Response:[/green] {response.choices[0].message.content}"
                    )

                    if response.usage:
                        console.print(f"\n[dim]Tokens used: {response.usage.total_tokens}[/dim]")
            else:
                console.print(f"[red]✗ {provider} health check failed[/red]")
                console.print("[dim]Check your API key and network connection[/dim]")

            await factory.cleanup()

        except Exception as e:
            logger.error(f"Test failed: {e}")
            console.print(f"[red]Test failed:[/red] {e}")

    asyncio.run(run_test())


@app.command()
def usage(
    ctx: typer.Context,
    period: str = typer.Option("today", "--period", "-p", help="Period: today, week, month"),
    provider: Optional[str] = typer.Option(None, "--provider", help="Filter by provider"),
) -> None:
    """Show LLM usage statistics and costs."""
    context: Context = ctx.obj

    async def show_usage():
        try:
            tracker = await create_usage_tracker()

            # Get usage summary
            from gibson.core.llm.usage_tracking import AggregationPeriod

            period_map = {
                "today": AggregationPeriod.DAY,
                "week": AggregationPeriod.WEEK,
                "month": AggregationPeriod.MONTH,
            }

            period_enum = period_map.get(period, AggregationPeriod.DAY)

            # Get provider filter
            provider_filter = None
            if provider:
                provider_filter = LLMProvider(provider.lower())

            summary = await tracker.get_usage_summary(period=period_enum, provider=provider_filter)

            # Create usage table
            table = Table(title=f"LLM Usage - {period.capitalize()}", show_header=True)
            table.add_column("Provider", style="cyan")
            table.add_column("Requests", justify="right")
            table.add_column("Tokens", justify="right")
            table.add_column("Cost", justify="right", style="yellow")

            for provider_name, stats in summary.by_provider.items():
                table.add_row(
                    provider_name,
                    str(stats["requests"]),
                    f"{stats['tokens']:,}",
                    f"${stats['cost']:.4f}",
                )

            console.print(table)

            # Show totals
            console.print(f"\n[bold]Total Requests:[/bold] {summary.total_requests:,}")
            console.print(f"[bold]Total Tokens:[/bold] {summary.total_tokens:,}")
            console.print(f"[bold]Total Cost:[/bold] ${summary.total_cost:.4f}")

            # Show trends if available
            if summary.trends:
                trend = summary.trends[0]
                if trend.change_percentage != 0:
                    trend_icon = "↑" if trend.change_percentage > 0 else "↓"
                    trend_color = "red" if trend.change_percentage > 0 else "green"
                    console.print(
                        f"\n[{trend_color}]{trend_icon} {abs(trend.change_percentage):.1f}% "
                        f"vs previous {period}[/{trend_color}]"
                    )

        except Exception as e:
            logger.error(f"Failed to get usage: {e}")
            console.print(f"[red]Failed to get usage:[/red] {e}")

    asyncio.run(show_usage())


@app.command()
def limits(
    ctx: typer.Context,
    provider: Optional[str] = typer.Option(None, "--provider", "-p", help="Provider to check"),
    set_rpm: Optional[int] = typer.Option(None, "--set-rpm", help="Set requests per minute"),
    set_tpm: Optional[int] = typer.Option(None, "--set-tpm", help="Set tokens per minute"),
) -> None:
    """Show or configure rate limits for LLM providers."""
    context: Context = ctx.obj

    async def manage_limits():
        try:
            limiter = create_rate_limiter()

            if set_rpm or set_tpm:
                # Set new limits
                if not provider:
                    console.print("[red]Provider required when setting limits[/red]")
                    return

                provider_enum = LLMProvider(provider.lower())

                from gibson.core.llm.rate_limiting import ProviderLimits

                # Get current limits
                status = await limiter.check_availability(provider_enum)

                # Create new limits
                new_limits = ProviderLimits(
                    provider=provider_enum,
                    requests_per_minute=set_rpm or status.rpm_remaining,
                    tokens_per_minute=set_tpm or status.tpm_remaining,
                    concurrent_requests=status.concurrent_remaining,
                )

                # Apply limits
                limiter._provider_limits[provider_enum] = new_limits

                console.print(f"[green]✓ Updated limits for {provider}[/green]")
                if set_rpm:
                    console.print(f"  RPM: {set_rpm}")
                if set_tpm:
                    console.print(f"  TPM: {set_tpm}")

            # Show current limits
            table = Table(title="Rate Limits", show_header=True)
            table.add_column("Provider", style="cyan")
            table.add_column("RPM", justify="right")
            table.add_column("TPM", justify="right")
            table.add_column("Concurrent", justify="right")
            table.add_column("Status")

            # Get all configured providers
            env_manager = EnvironmentManager()
            discovery = env_manager.discover_providers()

            for provider_enum in discovery.available_providers:
                status = await limiter.check_availability(provider_enum)

                status_color = "green" if status.status == "available" else "yellow"
                if status.status == "exhausted":
                    status_color = "red"

                table.add_row(
                    provider_enum.value,
                    f"{status.rpm_remaining}/{status.rpm_limit or '∞'}",
                    f"{status.tpm_remaining}/{status.tpm_limit or '∞'}",
                    f"{status.concurrent_remaining}/{status.concurrent_limit or '∞'}",
                    f"[{status_color}]{status.status}[/{status_color}]",
                )

            console.print(table)

            # Show queue status
            queue_status = await limiter.get_queue_status()
            if queue_status.total_queued > 0:
                console.print(f"\n[yellow]Queued Requests:[/yellow] {queue_status.total_queued}")
                console.print(f"[dim]Avg Wait Time: {queue_status.avg_wait_time:.2f}s[/dim]")

        except Exception as e:
            logger.error(f"Failed to manage limits: {e}")
            console.print(f"[red]Failed to manage limits:[/red] {e}")

    asyncio.run(manage_limits())


@app.command()
def providers(ctx: typer.Context) -> None:
    """List all supported LLM providers."""
    context: Context = ctx.obj

    table = Table(title="Supported LLM Providers", show_header=True)
    table.add_column("Provider", style="cyan")
    table.add_column("Name", style="yellow")
    table.add_column("Models", style="dim")

    provider_info = {
        LLMProvider.OPENAI: ("OpenAI", "GPT-4, GPT-3.5-Turbo"),
        LLMProvider.ANTHROPIC: ("Anthropic", "Claude 3 Opus, Sonnet, Haiku"),
        LLMProvider.AZURE_OPENAI: ("Azure OpenAI", "GPT-4, GPT-3.5-Turbo"),
        LLMProvider.GOOGLE_AI: ("Google AI", "Gemini Pro, Gemini Ultra"),
        LLMProvider.VERTEX_AI: ("Google Vertex AI", "Gemini, PaLM"),
        LLMProvider.BEDROCK: ("AWS Bedrock", "Claude, Llama 2, Jurassic"),
        LLMProvider.COHERE: ("Cohere", "Command, Command Light"),
        LLMProvider.AI21: ("AI21 Labs", "Jurassic-2"),
        LLMProvider.HUGGINGFACE: ("Hugging Face", "Various open models"),
        LLMProvider.REPLICATE: ("Replicate", "Various open models"),
        LLMProvider.TOGETHER: ("Together AI", "Various open models"),
        LLMProvider.ANYSCALE: ("Anyscale", "Llama 2, Mistral"),
        LLMProvider.PALM: ("Google PaLM", "PaLM 2"),
        LLMProvider.ALEPH_ALPHA: ("Aleph Alpha", "Luminous"),
        LLMProvider.OLLAMA: ("Ollama", "Local models"),
        LLMProvider.VLLM: ("vLLM", "Local models"),
        LLMProvider.SAGEMAKER: ("AWS SageMaker", "Custom deployed models"),
        LLMProvider.PETALS: ("Petals", "Distributed BLOOM"),
        LLMProvider.DEEPINFRA: ("DeepInfra", "Various open models"),
        LLMProvider.PERPLEXITY: ("Perplexity", "pplx-api models"),
        LLMProvider.GROQ: ("Groq", "Llama 2, Mixtral"),
        LLMProvider.FIREWORKS: ("Fireworks AI", "Various open models"),
    }

    for provider in LLMProvider:
        info = provider_info.get(provider, (provider.value, "Various models"))
        table.add_row(provider.value, info[0], info[1])

    console.print(table)
    console.print(f"\n[dim]Total providers supported: {len(list(LLMProvider))}[/dim]")
    console.print("[dim]Run 'gibson llm status' to see configured providers[/dim]")


def _create_app() -> typer.Typer:
    """Create the LLM CLI app."""
    return app
