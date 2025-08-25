"""
LLM integration for orchestrator - manages LLM clients for scan execution.
"""

import asyncio
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from loguru import logger

from gibson.core.llm import (
    LLMProvider,
    LLMClientFactory,
    CompletionService,
    UsageTracker,
    RateLimiter,
    FallbackManager,
    ProviderPool,
    LoadBalancedClient,
    create_llm_client_factory,
    create_completion_service,
    create_usage_tracker,
    create_rate_limiter,
    create_load_balancer,
)
from gibson.core.llm.types import (
    CompletionRequest,
    CompletionResponse,
    ChatMessage,
    LLMError,
    LLMErrorType,
)
from gibson.models.scan import ScanConfig
from gibson.models.target import Target


@dataclass
class LLMOrchestrator:
    """Orchestrates LLM operations for security scans."""

    # Core components
    client_factory: Optional[LLMClientFactory] = None
    completion_service: Optional[CompletionService] = None
    usage_tracker: Optional[UsageTracker] = None
    rate_limiter: Optional[RateLimiter] = None

    # Load balancing and fallback
    provider_pool: Optional[ProviderPool] = None
    fallback_manager: Optional[FallbackManager] = None
    load_balanced_client: Optional[LoadBalancedClient] = None

    # Configuration
    enable_fallback: bool = True
    enable_rate_limiting: bool = True
    enable_usage_tracking: bool = True
    enable_load_balancing: bool = False

    # Runtime state
    is_initialized: bool = field(default=False, init=False)
    active_scans: Dict[str, Any] = field(default_factory=dict, init=False)

    async def initialize(self) -> None:
        """Initialize all LLM components."""
        if self.is_initialized:
            return

        try:
            logger.info("Initializing LLM orchestrator")

            # Create client factory
            self.client_factory = await create_llm_client_factory(auto_initialize=True)

            # Create completion service
            self.completion_service = await create_completion_service(
                client_factory=self.client_factory
            )

            # Create usage tracker if enabled
            if self.enable_usage_tracking:
                self.usage_tracker = await create_usage_tracker()
                logger.debug("Usage tracking enabled")

            # Create rate limiter if enabled
            if self.enable_rate_limiting:
                self.rate_limiter = create_rate_limiter()
                logger.debug("Rate limiting enabled")

            # Create load balancer if enabled
            if self.enable_load_balancing:
                self.provider_pool, self.fallback_manager = create_load_balancer()
                self.load_balanced_client = LoadBalancedClient(
                    provider_pool=self.provider_pool,
                    fallback_manager=self.fallback_manager,
                    llm_client_factory=self.client_factory,
                )
                logger.debug("Load balancing enabled")

            self.is_initialized = True
            logger.info("LLM orchestrator initialized successfully")

        except Exception as e:
            logger.error(f"Failed to initialize LLM orchestrator: {e}")
            raise

    async def cleanup(self) -> None:
        """Clean up LLM components."""
        if not self.is_initialized:
            return

        try:
            logger.info("Cleaning up LLM orchestrator")

            # Stop health checks if load balancing
            if self.provider_pool:
                await self.provider_pool.stop_health_checks()

            # Clean up client factory
            if self.client_factory:
                await self.client_factory.cleanup()

            # Save usage data
            if self.usage_tracker:
                await self.usage_tracker.flush()

            self.is_initialized = False
            logger.info("LLM orchestrator cleaned up successfully")

        except Exception as e:
            logger.error(f"Error during LLM orchestrator cleanup: {e}")

    async def prepare_for_scan(
        self,
        scan_id: str,
        scan_config: ScanConfig,
        target: Target,
    ) -> None:
        """Prepare LLM components for a scan.

        Args:
            scan_id: Unique scan identifier
            scan_config: Scan configuration
            target: Target being scanned
        """
        if not self.is_initialized:
            await self.initialize()

        logger.info(f"Preparing LLM for scan {scan_id}")

        # Detect target's LLM provider if available
        detected_provider = target.detect_llm_provider()

        if detected_provider:
            logger.info(f"Detected LLM provider for target: {detected_provider}")

            # Ensure provider is available
            if detected_provider not in self.client_factory.get_available_providers():
                logger.warning(
                    f"Target uses {detected_provider} but it's not configured. "
                    f"Will use available providers with fallback."
                )

        # Set scan-specific rate limits if configured
        if self.rate_limiter and hasattr(scan_config, "rate_limits"):
            for provider, limits in scan_config.rate_limits.items():
                await self.rate_limiter.set_scan_limits(scan_id, limits)
                logger.debug(f"Set scan rate limits for {provider}: {limits}")

        # Track active scan
        self.active_scans[scan_id] = {
            "config": scan_config,
            "target": target,
            "provider": detected_provider,
            "start_time": asyncio.get_event_loop().time(),
        }

    async def complete_for_module(
        self,
        module_name: str,
        prompt: str,
        scan_id: Optional[str] = None,
        **kwargs,
    ) -> CompletionResponse:
        """Execute completion for a specific module.

        Args:
            module_name: Name of the module making the request
            prompt: Prompt to send
            scan_id: Optional scan ID for context
            **kwargs: Additional completion parameters

        Returns:
            Completion response
        """
        if not self.is_initialized:
            await self.initialize()

        # Build request
        request = CompletionRequest(
            model=kwargs.get("model", "gpt-3.5-turbo"),
            messages=[
                ChatMessage(role="system", content="You are a security testing assistant."),
                ChatMessage(role="user", content=prompt),
            ],
            temperature=kwargs.get("temperature", 0.7),
            max_tokens=kwargs.get("max_tokens", 1000),
        )

        # Get provider preference
        provider = None
        if scan_id and scan_id in self.active_scans:
            provider = self.active_scans[scan_id].get("provider")

        # Apply rate limiting
        if self.rate_limiter and provider:
            token = await self.rate_limiter.acquire(
                provider=provider,
                estimated_tokens=request.max_tokens or 1000,
                module_name=module_name,
                scan_id=scan_id,
            )

            if not token:
                raise LLMError(
                    type=LLMErrorType.RATE_LIMIT,
                    message=f"Rate limit exceeded for module {module_name}",
                    provider=provider,
                )

        try:
            # Execute completion
            if self.load_balanced_client and self.enable_load_balancing:
                # Use load balanced client
                response = await self.load_balanced_client.complete(
                    request=request,
                    session_id=scan_id,
                )
            else:
                # Use completion service
                response = await self.completion_service.complete(
                    request=request,
                    provider=provider,
                )

            # Track usage
            if self.usage_tracker and response.usage:
                await self.usage_tracker.track_usage(
                    provider=provider or LLMProvider.OPENAI,
                    model=request.model,
                    prompt_tokens=response.usage.prompt_tokens,
                    completion_tokens=response.usage.completion_tokens,
                    total_tokens=response.usage.total_tokens,
                    metadata={
                        "module": module_name,
                        "scan_id": scan_id,
                    },
                )

            # Release rate limit
            if self.rate_limiter and provider:
                await self.rate_limiter.release(
                    provider=provider,
                    success=True,
                    actual_tokens=response.usage.total_tokens if response.usage else None,
                )

            return response

        except Exception as e:
            # Release rate limit on error
            if self.rate_limiter and provider:
                await self.rate_limiter.release(
                    provider=provider,
                    success=False,
                )

            logger.error(f"Module {module_name} completion failed: {e}")
            raise

    async def get_scan_usage(
        self,
        scan_id: str,
    ) -> Dict[str, Any]:
        """Get LLM usage statistics for a scan.

        Args:
            scan_id: Scan identifier

        Returns:
            Usage statistics
        """
        if not self.usage_tracker:
            return {}

        # Get usage filtered by scan_id
        usage = await self.usage_tracker.get_usage_by_metadata(metadata_filter={"scan_id": scan_id})

        return {
            "total_requests": len(usage),
            "total_tokens": sum(u.total_tokens for u in usage),
            "total_cost": sum(u.estimated_cost or 0 for u in usage),
            "by_module": self._aggregate_by_module(usage),
        }

    async def complete_scan(
        self,
        scan_id: str,
    ) -> None:
        """Complete a scan and clean up resources.

        Args:
            scan_id: Scan identifier
        """
        if scan_id not in self.active_scans:
            return

        logger.info(f"Completing scan {scan_id}")

        # Log usage summary
        if self.usage_tracker:
            usage = await self.get_scan_usage(scan_id)
            logger.info(
                f"Scan {scan_id} LLM usage - "
                f"Requests: {usage.get('total_requests', 0)}, "
                f"Tokens: {usage.get('total_tokens', 0)}, "
                f"Cost: ${usage.get('total_cost', 0):.4f}"
            )

        # Remove scan-specific rate limits
        if self.rate_limiter:
            await self.rate_limiter.clear_scan_limits(scan_id)

        # Remove from active scans
        del self.active_scans[scan_id]

    def _aggregate_by_module(
        self,
        usage_records: List[Any],
    ) -> Dict[str, Dict[str, Any]]:
        """Aggregate usage records by module.

        Args:
            usage_records: List of usage records

        Returns:
            Usage aggregated by module
        """
        by_module = {}

        for record in usage_records:
            module = record.metadata.get("module", "unknown")
            if module not in by_module:
                by_module[module] = {
                    "requests": 0,
                    "tokens": 0,
                    "cost": 0.0,
                }

            by_module[module]["requests"] += 1
            by_module[module]["tokens"] += record.total_tokens
            by_module[module]["cost"] += record.estimated_cost or 0

        return by_module

    async def get_available_providers(self) -> List[LLMProvider]:
        """Get list of available LLM providers.

        Returns:
            List of available providers
        """
        if not self.is_initialized:
            await self.initialize()

        return self.client_factory.get_available_providers()

    async def check_provider_health(
        self,
        provider: LLMProvider,
    ) -> bool:
        """Check if a provider is healthy.

        Args:
            provider: Provider to check

        Returns:
            True if healthy, False otherwise
        """
        if not self.is_initialized:
            await self.initialize()

        return await self.client_factory.check_health(provider)


# Global orchestrator instance
_orchestrator: Optional[LLMOrchestrator] = None


async def get_llm_orchestrator() -> LLMOrchestrator:
    """Get or create the global LLM orchestrator.

    Returns:
        LLM orchestrator instance
    """
    global _orchestrator

    if _orchestrator is None:
        _orchestrator = LLMOrchestrator()
        await _orchestrator.initialize()

    return _orchestrator


async def cleanup_llm_orchestrator() -> None:
    """Clean up the global LLM orchestrator."""
    global _orchestrator

    if _orchestrator:
        await _orchestrator.cleanup()
        _orchestrator = None
