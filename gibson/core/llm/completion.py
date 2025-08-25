"""
Unified completion interface for Gibson Framework.

Provides a production-ready completion service with streaming support, usage tracking,
cost calculation, response caching, batch processing, and template management.
Integrates seamlessly with LiteLLM via the client factory.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from collections import defaultdict
from datetime import datetime, timedelta
from decimal import Decimal
from typing import (
    Any,
    AsyncIterator,
    Dict,
    List,
    Optional,
    Set,
    Tuple,
    Union,
)
from uuid import uuid4

from loguru import logger
from pydantic import BaseModel, Field, computed_field

from gibson.core.llm.client_factory import LLMClientFactory, create_llm_client_factory
from gibson.core.llm.types import (
    AsyncLLMClient,
    ChatMessage,
    CompletionRequest,
    CompletionResponse,
    CostModel,
    LLMError,
    LLMErrorType,
    LLMProvider,
    StreamResponse,
    TokenUsage,
    UsageRecord,
)
from gibson.models.base import GibsonBaseModel, TimestampedModel


# =============================================================================
# Template Management
# =============================================================================


class PromptTemplate(GibsonBaseModel):
    """Template for structured prompt management."""
    
    name: str = Field(description="Template name")
    template: str = Field(description="Template string with variables")
    variables: List[str] = Field(description="Required template variables")
    description: Optional[str] = Field(default=None, description="Template description")
    category: Optional[str] = Field(default=None, description="Template category")
    tags: Optional[List[str]] = Field(default=None, description="Template tags")
    
    # Default parameters for completions using this template
    default_max_tokens: Optional[int] = Field(default=None, description="Default max tokens")
    default_temperature: Optional[float] = Field(default=None, description="Default temperature")
    default_model: Optional[str] = Field(default=None, description="Default model")
    
    def render(self, variables: Dict[str, Any]) -> str:
        """Render template with provided variables."""
        # Check required variables
        missing_vars = set(self.variables) - set(variables.keys())
        if missing_vars:
            raise ValueError(f"Missing required template variables: {missing_vars}")
        
        try:
            return self.template.format(**variables)
        except KeyError as e:
            raise ValueError(f"Template variable not found: {e}")
        except Exception as e:
            raise ValueError(f"Template rendering failed: {e}")
    
    def create_request(
        self,
        variables: Dict[str, Any],
        role: str = "user",
        **kwargs
    ) -> CompletionRequest:
        """Create completion request from template."""
        content = self.render(variables)
        
        # Build request with template defaults
        request_kwargs = {
            "messages": [ChatMessage(role=role, content=content)],
            "model": self.default_model or kwargs.get("model", "gpt-3.5-turbo"),
        }
        
        # Apply template defaults
        if self.default_max_tokens:
            request_kwargs["max_tokens"] = self.default_max_tokens
        if self.default_temperature is not None:
            request_kwargs["temperature"] = self.default_temperature
        
        # Override with provided kwargs
        request_kwargs.update(kwargs)
        
        return CompletionRequest(**request_kwargs)


class TemplateManager(GibsonBaseModel):
    """Manager for prompt templates."""
    
    templates: Dict[str, PromptTemplate] = Field(default_factory=dict)
    
    def add_template(self, template: PromptTemplate) -> None:
        """Add a template to the manager."""
        self.templates[template.name] = template
        logger.debug(f"Added template: {template.name}")
    
    def get_template(self, name: str) -> PromptTemplate:
        """Get template by name."""
        if name not in self.templates:
            raise ValueError(f"Template '{name}' not found")
        return self.templates[name]
    
    def list_templates(
        self, 
        category: Optional[str] = None,
        tag: Optional[str] = None
    ) -> List[PromptTemplate]:
        """List templates with optional filtering."""
        templates = list(self.templates.values())
        
        if category:
            templates = [t for t in templates if t.category == category]
        
        if tag:
            templates = [t for t in templates if t.tags and tag in t.tags]
        
        return templates
    
    def remove_template(self, name: str) -> None:
        """Remove template by name."""
        if name in self.templates:
            del self.templates[name]
            logger.debug(f"Removed template: {name}")


# =============================================================================
# Response Caching
# =============================================================================


class CacheEntry(GibsonBaseModel):
    """Cache entry for completion responses."""
    
    key: str = Field(description="Cache key")
    response: CompletionResponse = Field(description="Cached response")
    expires_at: datetime = Field(description="Cache expiry time")
    hit_count: int = Field(default=0, description="Number of cache hits")
    
    @computed_field
    @property
    def is_expired(self) -> bool:
        """Check if cache entry is expired."""
        return datetime.utcnow() > self.expires_at


class ResponseCache:
    """LRU cache for completion responses."""
    
    def __init__(self, max_size: int = 1000, default_ttl: int = 3600):
        """Initialize cache with size and TTL limits."""
        self.max_size = max_size
        self.default_ttl = default_ttl
        self._cache: Dict[str, CacheEntry] = {}
        self._access_order: List[str] = []  # LRU tracking
        self._stats = {
            "hits": 0,
            "misses": 0,
            "evictions": 0,
            "expired": 0,
        }
    
    def _generate_key(self, request: CompletionRequest) -> str:
        """Generate cache key from request."""
        # Create deterministic hash from request content
        request_dict = {
            "messages": [msg.model_dump(mode='json') for msg in request.messages],
            "model": request.model,
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
            "top_p": request.top_p,
            "frequency_penalty": request.frequency_penalty,
            "presence_penalty": request.presence_penalty,
            "stop": request.stop,
            "seed": request.seed,
        }
        
        # Sort for consistency and handle JSON serialization
        content = json.dumps(request_dict, sort_keys=True, default=str)
        return hashlib.sha256(content.encode()).hexdigest()[:32]
    
    def get(self, request: CompletionRequest) -> Optional[CompletionResponse]:
        """Get cached response for request."""
        key = self._generate_key(request)
        
        if key not in self._cache:
            self._stats["misses"] += 1
            return None
        
        entry = self._cache[key]
        
        # Check expiry
        if entry.is_expired:
            del self._cache[key]
            if key in self._access_order:
                self._access_order.remove(key)
            self._stats["expired"] += 1
            self._stats["misses"] += 1
            return None
        
        # Update access order and hit count
        entry.hit_count += 1
        if key in self._access_order:
            self._access_order.remove(key)
        self._access_order.append(key)
        
        self._stats["hits"] += 1
        return entry.response
    
    def put(
        self, 
        request: CompletionRequest, 
        response: CompletionResponse,
        ttl: Optional[int] = None
    ) -> None:
        """Cache response for request."""
        key = self._generate_key(request)
        ttl = ttl or self.default_ttl
        
        # Evict oldest if at capacity
        if len(self._cache) >= self.max_size and key not in self._cache:
            self._evict_oldest()
        
        # Create cache entry
        expires_at = datetime.utcnow() + timedelta(seconds=ttl)
        entry = CacheEntry(
            key=key,
            response=response,
            expires_at=expires_at
        )
        
        # Update cache and access order
        self._cache[key] = entry
        if key in self._access_order:
            self._access_order.remove(key)
        self._access_order.append(key)
    
    def _evict_oldest(self) -> None:
        """Evict oldest cache entry."""
        if self._access_order:
            oldest_key = self._access_order.pop(0)
            if oldest_key in self._cache:
                del self._cache[oldest_key]
            self._stats["evictions"] += 1
    
    def clear(self) -> None:
        """Clear all cache entries."""
        self._cache.clear()
        self._access_order.clear()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        total_requests = self._stats["hits"] + self._stats["misses"]
        hit_rate = self._stats["hits"] / total_requests if total_requests > 0 else 0
        
        return {
            **self._stats,
            "size": len(self._cache),
            "max_size": self.max_size,
            "hit_rate": hit_rate,
        }


# =============================================================================
# Usage Tracking
# =============================================================================


class UsageTracker(TimestampedModel):
    """Tracks usage statistics and costs for completions."""
    
    total_requests: int = Field(default=0, description="Total requests processed")
    successful_requests: int = Field(default=0, description="Successful requests")
    failed_requests: int = Field(default=0, description="Failed requests")
    
    total_prompt_tokens: int = Field(default=0, description="Total prompt tokens")
    total_completion_tokens: int = Field(default=0, description="Total completion tokens")
    total_tokens: int = Field(default=0, description="Total tokens")
    
    total_cost: Decimal = Field(default=Decimal("0"), description="Total estimated cost")
    
    # Per-provider tracking
    provider_stats: Dict[str, Dict[str, Any]] = Field(
        default_factory=dict, description="Statistics per provider"
    )
    
    # Cost models for pricing
    cost_models: Dict[str, CostModel] = Field(
        default_factory=dict, description="Cost models by provider/model"
    )
    
    def record_request(
        self,
        request: CompletionRequest,
        response: Optional[CompletionResponse] = None,
        error: Optional[Exception] = None,
        provider: Optional[str] = None,
        response_time: Optional[float] = None,
    ) -> UsageRecord:
        """Record a completion request and response."""
        self.total_requests += 1
        
        # Create usage record
        usage_record = UsageRecord(
            request_id=str(uuid4()),
            provider=provider or LLMProvider.OPENAI,  # Default fallback
            model=request.model,
            usage=TokenUsage(
                prompt_tokens=0,
                completion_tokens=0,
                total_tokens=0,
            ),
            response_time=response_time or 0.0,
        )
        
        # Update statistics based on response or error
        if response and response.usage:
            self.successful_requests += 1
            usage = response.usage
            
            # Update token counts
            self.total_prompt_tokens += usage.prompt_tokens
            self.total_completion_tokens += usage.completion_tokens
            self.total_tokens += usage.total_tokens
            
            # Update usage record
            usage_record.usage = usage
            
            # Calculate cost
            cost = self._calculate_cost(request.model, usage, provider)
            if cost:
                self.total_cost += cost
                usage_record.calculated_cost = cost
            
        else:
            self.failed_requests += 1
            if error:
                # Convert exception to LLM error
                usage_record.error = self._convert_error(error, request.model, provider)
        
        # Update provider statistics
        provider_key = provider or "unknown"
        if provider_key not in self.provider_stats:
            self.provider_stats[provider_key] = {
                "requests": 0,
                "successes": 0,
                "failures": 0,
                "tokens": 0,
                "cost": Decimal("0"),
            }
        
        self.provider_stats[provider_key]["requests"] += 1
        if response:
            self.provider_stats[provider_key]["successes"] += 1
            if response.usage:
                self.provider_stats[provider_key]["tokens"] += response.usage.total_tokens
        else:
            self.provider_stats[provider_key]["failures"] += 1
        
        self.update_timestamp()
        return usage_record
    
    def _calculate_cost(
        self, 
        model: str, 
        usage: TokenUsage, 
        provider: Optional[str]
    ) -> Optional[Decimal]:
        """Calculate cost based on usage and cost models."""
        cost_key = f"{provider}_{model}"
        if cost_key not in self.cost_models:
            # Try to find generic cost model
            return self._estimate_generic_cost(model, usage)
        
        cost_model = self.cost_models[cost_key]
        
        # Calculate prompt cost
        prompt_cost = (Decimal(usage.prompt_tokens) / Decimal(1000)) * cost_model.prompt_cost_per_1k
        
        # Calculate completion cost
        completion_cost = (Decimal(usage.completion_tokens) / Decimal(1000)) * cost_model.completion_cost_per_1k
        
        return prompt_cost + completion_cost
    
    def _estimate_generic_cost(self, model: str, usage: TokenUsage) -> Optional[Decimal]:
        """Estimate cost using generic pricing."""
        # Generic cost estimates (USD per 1K tokens)
        generic_costs = {
            # OpenAI models
            "gpt-4": {"prompt": Decimal("0.03"), "completion": Decimal("0.06")},
            "gpt-4-turbo": {"prompt": Decimal("0.01"), "completion": Decimal("0.03")},
            "gpt-3.5-turbo": {"prompt": Decimal("0.001"), "completion": Decimal("0.002")},
            
            # Anthropic models
            "claude-3-opus": {"prompt": Decimal("0.015"), "completion": Decimal("0.075")},
            "claude-3-sonnet": {"prompt": Decimal("0.003"), "completion": Decimal("0.015")},
            "claude-3-haiku": {"prompt": Decimal("0.00025"), "completion": Decimal("0.00125")},
        }
        
        # Find matching model (partial match)
        for model_key, costs in generic_costs.items():
            if model_key in model.lower():
                prompt_cost = (Decimal(usage.prompt_tokens) / Decimal(1000)) * costs["prompt"]
                completion_cost = (Decimal(usage.completion_tokens) / Decimal(1000)) * costs["completion"]
                return prompt_cost + completion_cost
        
        # Default generic cost if no match
        default_prompt_cost = Decimal("0.001")
        default_completion_cost = Decimal("0.002")
        
        prompt_cost = (Decimal(usage.prompt_tokens) / Decimal(1000)) * default_prompt_cost
        completion_cost = (Decimal(usage.completion_tokens) / Decimal(1000)) * default_completion_cost
        
        return prompt_cost + completion_cost
    
    def _convert_error(self, error: Exception, model: str, provider: Optional[str]) -> LLMError:
        """Convert exception to LLM error."""
        error_type = LLMErrorType.PROVIDER_ERROR
        
        # Map common error types
        error_str = str(error).lower()
        if 'api key' in error_str or 'authentication' in error_str:
            error_type = LLMErrorType.AUTHENTICATION_ERROR
        elif 'rate limit' in error_str:
            error_type = LLMErrorType.RATE_LIMIT_EXCEEDED
        elif 'timeout' in error_str:
            error_type = LLMErrorType.TIMEOUT_ERROR
        elif 'context length' in error_str:
            error_type = LLMErrorType.CONTEXT_LENGTH_EXCEEDED
        
        return LLMError(
            type=error_type,
            message=str(error),
            model=model,
            provider=LLMProvider(provider) if provider and isinstance(provider, str) else provider,
        )
    
    def add_cost_model(self, cost_model: CostModel) -> None:
        """Add cost model for pricing calculations."""
        provider_str = cost_model.provider if isinstance(cost_model.provider, str) else cost_model.provider.value
        key = f"{provider_str}_{cost_model.model}"
        self.cost_models[key] = cost_model
        logger.debug(f"Added cost model: {key}")
    
    def get_summary(self) -> Dict[str, Any]:
        """Get usage summary statistics."""
        success_rate = (
            self.successful_requests / self.total_requests 
            if self.total_requests > 0 else 0
        )
        
        avg_tokens_per_request = (
            self.total_tokens / self.successful_requests
            if self.successful_requests > 0 else 0
        )
        
        return {
            "total_requests": self.total_requests,
            "successful_requests": self.successful_requests,
            "failed_requests": self.failed_requests,
            "success_rate": success_rate,
            "total_tokens": self.total_tokens,
            "total_prompt_tokens": self.total_prompt_tokens,
            "total_completion_tokens": self.total_completion_tokens,
            "avg_tokens_per_request": avg_tokens_per_request,
            "total_cost": float(self.total_cost),
            "provider_stats": self.provider_stats,
        }


# =============================================================================
# Model Selection
# =============================================================================


class ModelCapabilities(GibsonBaseModel):
    """Model capabilities and characteristics."""
    
    model: str = Field(description="Model identifier")
    provider: LLMProvider = Field(description="Provider")
    
    # Capabilities
    supports_streaming: bool = Field(default=True, description="Supports streaming")
    supports_functions: bool = Field(default=False, description="Supports function calling")
    supports_vision: bool = Field(default=False, description="Supports vision inputs")
    supports_json_mode: bool = Field(default=False, description="Supports JSON mode")
    
    # Limits
    max_tokens: int = Field(description="Maximum context length")
    max_output_tokens: Optional[int] = Field(default=None, description="Maximum output tokens")
    
    # Performance characteristics
    avg_latency: Optional[float] = Field(default=None, description="Average latency in seconds")
    cost_per_1k_tokens: Optional[Decimal] = Field(default=None, description="Cost per 1K tokens")
    
    # Quality metrics
    quality_score: Optional[float] = Field(
        default=None, ge=0.0, le=1.0, description="Quality score (0-1)"
    )


class ModelSelector:
    """Selects optimal models based on requirements and capabilities."""
    
    def __init__(self):
        self.model_capabilities: Dict[str, ModelCapabilities] = {}
        self._load_default_capabilities()
    
    def _load_default_capabilities(self) -> None:
        """Load default model capabilities."""
        default_models = [
            ModelCapabilities(
                model="gpt-4-turbo",
                provider=LLMProvider.OPENAI,
                supports_functions=True,
                supports_vision=True,
                supports_json_mode=True,
                max_tokens=128000,
                max_output_tokens=4096,
                cost_per_1k_tokens=Decimal("0.01"),
                quality_score=0.95,
            ),
            ModelCapabilities(
                model="gpt-3.5-turbo",
                provider=LLMProvider.OPENAI,
                supports_functions=True,
                supports_json_mode=True,
                max_tokens=16384,
                max_output_tokens=4096,
                cost_per_1k_tokens=Decimal("0.001"),
                quality_score=0.8,
            ),
            ModelCapabilities(
                model="claude-3-opus-20240229",
                provider=LLMProvider.ANTHROPIC,
                supports_vision=True,
                max_tokens=200000,
                max_output_tokens=4096,
                cost_per_1k_tokens=Decimal("0.015"),
                quality_score=0.98,
            ),
            ModelCapabilities(
                model="claude-3-haiku-20240307",
                provider=LLMProvider.ANTHROPIC,
                max_tokens=200000,
                max_output_tokens=4096,
                cost_per_1k_tokens=Decimal("0.00025"),
                quality_score=0.85,
                avg_latency=0.5,
            ),
        ]
        
        for model in default_models:
            self.add_model(model)
    
    def add_model(self, capabilities: ModelCapabilities) -> None:
        """Add model capabilities."""
        provider_str = capabilities.provider if isinstance(capabilities.provider, str) else capabilities.provider.value
        key = f"{provider_str}_{capabilities.model}"
        self.model_capabilities[key] = capabilities
    
    def select_model(
        self,
        available_providers: List[str],
        requirements: Optional[Dict[str, Any]] = None,
        optimize_for: str = "balanced",  # "cost", "quality", "speed", "balanced"
    ) -> Optional[str]:
        """Select optimal model based on requirements and optimization criteria."""
        requirements = requirements or {}
        
        # Filter available models
        available_models = []
        for provider in available_providers:
            provider_prefix = provider.split("_")[0]
            for key, capabilities in self.model_capabilities.items():
                if key.startswith(provider_prefix):
                    available_models.append((key, capabilities))
        
        if not available_models:
            return None
        
        # Filter by requirements
        filtered_models = []
        for key, capabilities in available_models:
            if self._meets_requirements(capabilities, requirements):
                filtered_models.append((key, capabilities))
        
        if not filtered_models:
            # Fallback to any available model
            filtered_models = available_models
        
        # Select based on optimization criteria
        return self._optimize_selection(filtered_models, optimize_for)
    
    def _meets_requirements(self, capabilities: ModelCapabilities, requirements: Dict[str, Any]) -> bool:
        """Check if model meets requirements."""
        # Check function calling requirement
        if requirements.get("functions") and not capabilities.supports_functions:
            return False
        
        # Check vision requirement
        if requirements.get("vision") and not capabilities.supports_vision:
            return False
        
        # Check JSON mode requirement
        if requirements.get("json_mode") and not capabilities.supports_json_mode:
            return False
        
        # Check streaming requirement
        if requirements.get("streaming") and not capabilities.supports_streaming:
            return False
        
        # Check context length requirement
        if requirements.get("max_tokens"):
            if capabilities.max_tokens < requirements["max_tokens"]:
                return False
        
        return True
    
    def _optimize_selection(
        self, 
        models: List[Tuple[str, ModelCapabilities]], 
        optimize_for: str
    ) -> str:
        """Select model based on optimization criteria."""
        if not models:
            raise ValueError("No models available for selection")
        
        if optimize_for == "cost":
            # Sort by cost (ascending)
            models.sort(key=lambda x: x[1].cost_per_1k_tokens or Decimal("999"))
        
        elif optimize_for == "quality":
            # Sort by quality score (descending)
            models.sort(key=lambda x: x[1].quality_score or 0.0, reverse=True)
        
        elif optimize_for == "speed":
            # Sort by latency (ascending)
            models.sort(key=lambda x: x[1].avg_latency or 999.0)
        
        elif optimize_for == "balanced":
            # Balanced scoring
            def balanced_score(capabilities: ModelCapabilities) -> float:
                quality = capabilities.quality_score or 0.5
                cost = float(capabilities.cost_per_1k_tokens or Decimal("0.01"))
                latency = capabilities.avg_latency or 2.0
                
                # Normalize and combine (lower is better for cost and latency)
                quality_norm = quality  # 0-1, higher is better
                cost_norm = max(0, 1 - (cost / 0.1))  # Normalize cost, lower is better
                latency_norm = max(0, 1 - (latency / 5.0))  # Normalize latency, lower is better
                
                return (quality_norm * 0.4) + (cost_norm * 0.3) + (latency_norm * 0.3)
            
            models.sort(key=lambda x: balanced_score(x[1]), reverse=True)
        
        return models[0][0]


# =============================================================================
# Main Completion Service
# =============================================================================


class CompletionService:
    """Unified completion service with advanced features."""
    
    def __init__(
        self,
        client_factory: Optional[LLMClientFactory] = None,
        enable_caching: bool = True,
        cache_size: int = 1000,
        cache_ttl: int = 3600,
        enable_usage_tracking: bool = True,
        max_retries: int = 3,
        retry_delay: float = 1.0,
    ):
        """Initialize completion service."""
        self.client_factory = client_factory
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        
        # Initialize components
        self.template_manager = TemplateManager()
        self.model_selector = ModelSelector()
        
        # Optional components
        self.cache = ResponseCache(max_size=cache_size, default_ttl=cache_ttl) if enable_caching else None
        self.usage_tracker = UsageTracker() if enable_usage_tracking else None
        
        # Internal state
        self._closed = False
        self._own_factory = client_factory is None  # Track if we own the factory
        
        logger.info(f"Initialized completion service (caching={enable_caching}, tracking={enable_usage_tracking})")
    
    async def __aenter__(self) -> CompletionService:
        """Async context manager entry."""
        await self._ensure_factory()
        return self
    
    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        await self.close()
    
    async def _ensure_factory(self) -> None:
        """Ensure client factory is available."""
        if self.client_factory is None:
            self.client_factory = LLMClientFactory()
            await self.client_factory._initialize()
    
    async def complete(
        self,
        request: CompletionRequest,
        provider: Optional[str] = None,
        use_cache: bool = True,
        track_usage: bool = True,
    ) -> CompletionResponse:
        """Generate a completion with full feature support."""
        if self._closed:
            raise RuntimeError("Completion service is closed")
        
        await self._ensure_factory()
        
        # Check cache first
        if use_cache and self.cache:
            cached_response = self.cache.get(request)
            if cached_response:
                logger.debug("Returning cached response")
                return cached_response
        
        # Select provider if not specified
        if provider is None:
            available_providers = await self.client_factory.get_available_providers()
            provider = self.model_selector.select_model(
                available_providers,
                requirements=self._extract_requirements(request),
                optimize_for="balanced"
            )
        
        if not provider:
            raise ValueError("No suitable provider available")
        
        # Get client and make request
        client = await self.client_factory.get_client(provider)
        
        start_time = time.time()
        error = None
        response = None
        
        try:
            response = await client.complete(request)
            
            # Cache response
            if use_cache and self.cache and response:
                self.cache.put(request, response)
            
            return response
            
        except Exception as e:
            error = e
            logger.error(f"Completion failed: {e}")
            raise
        
        finally:
            # Track usage
            if track_usage and self.usage_tracker:
                response_time = time.time() - start_time
                self.usage_tracker.record_request(
                    request=request,
                    response=response,
                    error=error,
                    provider=provider,
                    response_time=response_time,
                )
    
    async def stream_complete(
        self,
        request: CompletionRequest,
        provider: Optional[str] = None,
        track_usage: bool = True,
    ) -> AsyncIterator[StreamResponse]:
        """Generate streaming completion."""
        if self._closed:
            raise RuntimeError("Completion service is closed")
        
        await self._ensure_factory()
        
        # Select provider if not specified
        if provider is None:
            available_providers = await self.client_factory.get_available_providers()
            provider = self.model_selector.select_model(
                available_providers,
                requirements=self._extract_requirements(request),
                optimize_for="balanced"
            )
        
        if not provider:
            raise ValueError("No suitable provider available")
        
        # Get client and stream
        client = await self.client_factory.get_client(provider)
        
        start_time = time.time()
        error = None
        final_response = None
        
        try:
            # Collect chunks for tracking
            chunks = []
            
            async for chunk in client.complete_stream(request):
                chunks.append(chunk)
                yield chunk
            
            # Build final response for tracking
            if chunks and track_usage and self.usage_tracker:
                final_chunk = chunks[-1]
                if final_chunk.usage:
                    # Create mock CompletionResponse for tracking
                    final_response = CompletionResponse(
                        id=final_chunk.id,
                        object="chat.completion",
                        created=final_chunk.created,
                        model=final_chunk.model,
                        provider=final_chunk.provider,
                        choices=[],  # Not needed for tracking
                        usage=final_chunk.usage,
                    )
            
        except Exception as e:
            error = e
            logger.error(f"Streaming completion failed: {e}")
            raise
        
        finally:
            # Track usage
            if track_usage and self.usage_tracker:
                response_time = time.time() - start_time
                self.usage_tracker.record_request(
                    request=request,
                    response=final_response,
                    error=error,
                    provider=provider,
                    response_time=response_time,
                )
    
    async def batch_complete(
        self,
        requests: List[CompletionRequest],
        provider: Optional[str] = None,
        max_concurrent: int = 10,
        use_cache: bool = True,
        track_usage: bool = True,
    ) -> List[CompletionResponse]:
        """Process multiple completion requests concurrently."""
        if self._closed:
            raise RuntimeError("Completion service is closed")
        
        # Create semaphore for concurrency control
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def process_request(request: CompletionRequest) -> CompletionResponse:
            async with semaphore:
                return await self.complete(
                    request=request,
                    provider=provider,
                    use_cache=use_cache,
                    track_usage=track_usage,
                )
        
        # Process all requests concurrently
        tasks = [process_request(request) for request in requests]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Convert exceptions to failed responses
        results = []
        for i, response in enumerate(responses):
            if isinstance(response, Exception):
                logger.error(f"Batch request {i} failed: {response}")
                raise response  # Re-raise for now, could be made more tolerant
            results.append(response)
        
        return results
    
    async def complete_with_retry(
        self,
        request: CompletionRequest,
        max_retries: Optional[int] = None,
        provider: Optional[str] = None,
        use_cache: bool = True,
        track_usage: bool = True,
    ) -> CompletionResponse:
        """Complete with automatic retry on failure."""
        max_retries = max_retries or self.max_retries
        last_error = None
        
        for attempt in range(max_retries + 1):
            try:
                return await self.complete(
                    request=request,
                    provider=provider,
                    use_cache=use_cache and attempt == 0,  # Only use cache on first attempt
                    track_usage=track_usage,
                )
            
            except Exception as e:
                last_error = e
                
                if attempt < max_retries:
                    delay = self.retry_delay * (2 ** attempt)  # Exponential backoff
                    logger.warning(f"Completion attempt {attempt + 1} failed, retrying in {delay}s: {e}")
                    await asyncio.sleep(delay)
                else:
                    logger.error(f"All {max_retries + 1} completion attempts failed")
        
        raise last_error
    
    def estimate_cost(
        self, 
        request: CompletionRequest, 
        response: CompletionResponse
    ) -> Optional[float]:
        """Estimate cost for a completion."""
        if not self.usage_tracker or not response.usage:
            return None
        
        provider = response.provider
        cost = self.usage_tracker._calculate_cost(
            model=response.model,
            usage=response.usage,
            provider=provider,
        )
        
        return float(cost) if cost else None
    
    async def complete_with_template(
        self,
        template_name: str,
        variables: Dict[str, Any],
        provider: Optional[str] = None,
        **kwargs
    ) -> CompletionResponse:
        """Complete using a prompt template."""
        template = self.template_manager.get_template(template_name)
        request = template.create_request(variables, **kwargs)
        
        return await self.complete(request, provider=provider)
    
    def _extract_requirements(self, request: CompletionRequest) -> Dict[str, Any]:
        """Extract requirements from completion request."""
        requirements = {}
        
        if request.functions:
            requirements["functions"] = True
        
        if request.tools:
            requirements["functions"] = True
        
        if request.response_format:
            if request.response_format.get("type") == "json_object":
                requirements["json_mode"] = True
        
        if request.stream:
            requirements["streaming"] = True
        
        # Estimate required context length
        estimated_tokens = sum(len(msg.content or "") // 4 for msg in request.messages)
        if request.max_tokens:
            estimated_tokens += request.max_tokens
        
        requirements["max_tokens"] = estimated_tokens
        
        return requirements
    
    def get_usage_stats(self) -> Optional[Dict[str, Any]]:
        """Get usage statistics."""
        return self.usage_tracker.get_summary() if self.usage_tracker else None
    
    def get_cache_stats(self) -> Optional[Dict[str, Any]]:
        """Get cache statistics."""
        return self.cache.get_stats() if self.cache else None
    
    def clear_cache(self) -> None:
        """Clear response cache."""
        if self.cache:
            self.cache.clear()
            logger.info("Response cache cleared")
    
    def add_template(self, template: PromptTemplate) -> None:
        """Add a prompt template."""
        self.template_manager.add_template(template)
    
    def add_cost_model(self, cost_model: CostModel) -> None:
        """Add a cost model for pricing."""
        if self.usage_tracker:
            self.usage_tracker.add_cost_model(cost_model)
    
    async def close(self) -> None:
        """Close the completion service."""
        if self._closed:
            return
        
        logger.info("Closing completion service")
        self._closed = True
        
        # Close client factory if we own it
        if self._own_factory and self.client_factory:
            await self.client_factory.close()
        
        # Clear cache
        if self.cache:
            self.cache.clear()
        
        logger.info("Completion service closed")


# =============================================================================
# Convenience Functions
# =============================================================================


async def create_completion_service(**kwargs) -> CompletionService:
    """Create and initialize a completion service."""
    service = CompletionService(**kwargs)
    await service._ensure_factory()
    return service


async def quick_complete(
    messages: List[Dict[str, str]], 
    model: str = "gpt-3.5-turbo",
    **kwargs
) -> CompletionResponse:
    """Quick completion for simple use cases."""
    # Convert dict messages to ChatMessage objects
    chat_messages = [
        ChatMessage(role=msg["role"], content=msg["content"])
        for msg in messages
    ]
    
    request = CompletionRequest(
        messages=chat_messages,
        model=model,
        **kwargs
    )
    
    async with create_completion_service() as service:
        return await service.complete(request)


async def quick_stream(
    messages: List[Dict[str, str]], 
    model: str = "gpt-3.5-turbo",
    **kwargs
) -> AsyncIterator[StreamResponse]:
    """Quick streaming completion for simple use cases."""
    # Convert dict messages to ChatMessage objects
    chat_messages = [
        ChatMessage(role=msg["role"], content=msg["content"])
        for msg in messages
    ]
    
    request = CompletionRequest(
        messages=chat_messages,
        model=model,
        stream=True,
        **kwargs
    )
    
    async with create_completion_service() as service:
        async for chunk in service.stream_complete(request):
            yield chunk


# Export main classes and functions
__all__ = [
    "CompletionService",
    "PromptTemplate",
    "TemplateManager",
    "ResponseCache",
    "UsageTracker",
    "ModelSelector",
    "ModelCapabilities",
    "create_completion_service",
    "quick_complete",
    "quick_stream",
]
