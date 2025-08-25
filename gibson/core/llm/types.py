"""
Comprehensive type definitions for LiteLLM integration in Gibson Framework.

This module provides type-safe interfaces for LLM operations including provider
configuration, request/response types, usage tracking, and async client protocols.
All types are designed to be compatible with LiteLLM's actual API structure.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from datetime import datetime
from decimal import Decimal
from enum import Enum
from typing import (
    Any,
    Literal,
    Optional,
    Protocol,
    TypedDict,
    Union,
    runtime_checkable,
)
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator
from typing_extensions import NotRequired

from gibson.models.base import GibsonBaseModel, TimestampedModel

# =============================================================================
# Provider Types and Enums
# =============================================================================


class LLMProvider(str, Enum):
    """Supported LLM providers in LiteLLM."""

    # OpenAI and compatible
    OPENAI = "openai"
    AZURE_OPENAI = "azure"
    OPENAI_COMPATIBLE = "openai_compatible"

    # Anthropic
    ANTHROPIC = "anthropic"

    # Google
    GOOGLE_AI = "google_ai"
    VERTEX_AI = "vertex_ai"
    GEMINI = "gemini"

    # AWS
    BEDROCK = "bedrock"
    SAGEMAKER = "sagemaker"

    # Other cloud providers
    HUGGINGFACE = "huggingface"
    COHERE = "cohere"
    REPLICATE = "replicate"
    TOGETHER_AI = "together_ai"
    GROQ = "groq"
    MISTRAL = "mistral"
    PALM = "palm"

    # Local/self-hosted
    OLLAMA = "ollama"
    VLLM = "vllm"
    TEXT_GENERATION_INFERENCE = "text-generation-inference"
    LLAMACPP = "llamacpp"

    # Enterprise
    DATABRICKS = "databricks"
    WATSONX = "watsonx"


class ModelType(str, Enum):
    """LLM model types and capabilities."""

    # Text generation models
    COMPLETION = "completion"
    CHAT = "chat"

    # Specialized models
    EMBEDDING = "embedding"
    MODERATION = "moderation"
    FUNCTION_CALLING = "function_calling"
    VISION = "vision"
    CODE_GENERATION = "code_generation"


class TokenType(str, Enum):
    """Token usage categories for cost calculation."""

    PROMPT = "prompt_tokens"
    COMPLETION = "completion_tokens"
    TOTAL = "total_tokens"
    CACHED = "cached_tokens"  # For providers that support prompt caching


class ResponseFormat(str, Enum):
    """Response format options for structured output."""

    TEXT = "text"
    JSON = "json_object"
    JSON_SCHEMA = "json_schema"


class FinishReason(str, Enum):
    """Completion finish reasons."""

    STOP = "stop"
    LENGTH = "length"
    FUNCTION_CALL = "function_call"
    TOOL_CALLS = "tool_calls"
    CONTENT_FILTER = "content_filter"
    ERROR = "error"


# =============================================================================
# TypedDict Definitions for LiteLLM Compatibility
# =============================================================================


class MessageDict(TypedDict):
    """Chat message structure compatible with LiteLLM."""

    role: Literal["system", "user", "assistant", "function", "tool"]
    content: str | None
    name: NotRequired[str]
    function_call: NotRequired[dict[str, Any]]
    tool_calls: NotRequired[list[dict[str, Any]]]
    tool_call_id: NotRequired[str]


class FunctionDict(TypedDict):
    """Function definition for function calling."""

    name: str
    description: NotRequired[str]
    parameters: NotRequired[dict[str, Any]]


class ToolDict(TypedDict):
    """Tool definition for tool calling."""

    type: Literal["function"]
    function: FunctionDict


class UsageDict(TypedDict):
    """Token usage information from LiteLLM response."""

    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    cached_tokens: NotRequired[int]
    prompt_tokens_details: NotRequired[dict[str, Any]]
    completion_tokens_details: NotRequired[dict[str, Any]]


class ChoiceDict(TypedDict):
    """Individual choice in completion response."""

    index: int
    message: MessageDict
    finish_reason: str | None
    logprobs: NotRequired[dict[str, Any]]


class CompletionResponseDict(TypedDict):
    """Complete LiteLLM response structure."""

    id: str
    object: Literal["chat.completion", "text_completion"]
    created: int
    model: str
    choices: list[ChoiceDict]
    usage: NotRequired[UsageDict]
    system_fingerprint: NotRequired[str]
    provider: NotRequired[str]
    _hidden_params: NotRequired[dict[str, Any]]


class StreamChoiceDict(TypedDict):
    """Streaming response choice structure."""

    index: int
    delta: MessageDict
    finish_reason: str | None
    logprobs: NotRequired[dict[str, Any]]


class StreamResponseDict(TypedDict):
    """Streaming response structure."""

    id: str
    object: Literal["chat.completion.chunk"]
    created: int
    model: str
    choices: list[StreamChoiceDict]
    usage: NotRequired[UsageDict]
    system_fingerprint: NotRequired[str]
    provider: NotRequired[str]


class EmbeddingDict(TypedDict):
    """Embedding response structure."""

    object: Literal["embedding"]
    embedding: list[float]
    index: int


class EmbeddingResponseDict(TypedDict):
    """Complete embedding response."""

    object: Literal["list"]
    data: list[EmbeddingDict]
    model: str
    usage: UsageDict


# =============================================================================
# Provider Configuration Models
# =============================================================================


class BaseProviderConfig(GibsonBaseModel):
    """Base configuration for all LLM providers."""

    provider: LLMProvider = Field(description="LLM provider identifier")
    model: str = Field(description="Model identifier")
    api_key: Optional[str] = Field(default=None, description="API key for authentication")
    api_base: Optional[str] = Field(default=None, description="Custom API base URL")
    api_version: Optional[str] = Field(default=None, description="API version")
    timeout: float = Field(default=60.0, ge=1.0, description="Request timeout in seconds")
    max_retries: int = Field(default=3, ge=0, description="Maximum retry attempts")
    default_headers: Optional[dict[str, str]] = Field(default=None, description="Default headers")
    tags: Optional[list[str]] = Field(default=None, description="Provider tags for organization")

    model_config = ConfigDict(
        extra="allow",  # Allow provider-specific fields
        json_schema_extra={
            "example": {
                "provider": "openai",
                "model": "gpt-4-turbo-preview",
                "api_key": "sk-...",
                "timeout": 60.0,
                "max_retries": 3,
            }
        },
    )


class OpenAIConfig(BaseProviderConfig):
    """OpenAI-specific configuration."""

    provider: Literal[LLMProvider.OPENAI] = LLMProvider.OPENAI
    organization: Optional[str] = Field(default=None, description="OpenAI organization ID")
    project: Optional[str] = Field(default=None, description="OpenAI project ID")


class AnthropicConfig(BaseProviderConfig):
    """Anthropic-specific configuration."""

    provider: Literal[LLMProvider.ANTHROPIC] = LLMProvider.ANTHROPIC


class AzureOpenAIConfig(BaseProviderConfig):
    """Azure OpenAI-specific configuration."""

    provider: Literal[LLMProvider.AZURE_OPENAI] = LLMProvider.AZURE_OPENAI
    azure_endpoint: str = Field(description="Azure OpenAI endpoint")
    azure_deployment: str = Field(description="Azure deployment name")
    azure_ad_token: Optional[str] = Field(default=None, description="Azure AD token")


class BedrockConfig(BaseProviderConfig):
    """AWS Bedrock-specific configuration."""

    provider: Literal[LLMProvider.BEDROCK] = LLMProvider.BEDROCK
    aws_region: str = Field(description="AWS region")
    aws_access_key_id: Optional[str] = Field(default=None, description="AWS access key")
    aws_secret_access_key: Optional[str] = Field(default=None, description="AWS secret key")
    aws_session_token: Optional[str] = Field(default=None, description="AWS session token")


class VertexAIConfig(BaseProviderConfig):
    """Google Vertex AI-specific configuration."""

    provider: Literal[LLMProvider.VERTEX_AI] = LLMProvider.VERTEX_AI
    vertex_project: str = Field(description="Google Cloud project ID")
    vertex_location: str = Field(description="Vertex AI location")
    service_account_key: Optional[str] = Field(default=None, description="Service account key")


# Union type for all provider configurations
ProviderConfig = Union[
    OpenAIConfig,
    AnthropicConfig,
    AzureOpenAIConfig,
    BedrockConfig,
    VertexAIConfig,
    BaseProviderConfig,  # Fallback for unsupported providers
]


# =============================================================================
# Request and Response Models
# =============================================================================


class ChatMessage(GibsonBaseModel):
    """Structured chat message model."""

    role: Literal["system", "user", "assistant", "function", "tool"] = Field(
        description="Message role"
    )
    content: Optional[str] = Field(description="Message content")
    name: Optional[str] = Field(default=None, description="Message author name")
    function_call: Optional[dict[str, Any]] = Field(
        default=None, description="Function call information"
    )
    tool_calls: Optional[list[dict[str, Any]]] = Field(
        default=None, description="Tool calls information"
    )
    tool_call_id: Optional[str] = Field(default=None, description="Tool call ID")


class CompletionRequest(GibsonBaseModel):
    """Structured completion request model."""

    messages: list[ChatMessage] = Field(description="List of chat messages")
    model: str = Field(description="Model identifier")
    provider: Optional[LLMProvider] = Field(default=None, description="Provider override")
    max_tokens: Optional[int] = Field(default=None, ge=1, description="Maximum tokens to generate")
    temperature: Optional[float] = Field(
        default=None, ge=0.0, le=2.0, description="Sampling temperature"
    )
    top_p: Optional[float] = Field(
        default=None, ge=0.0, le=1.0, description="Nucleus sampling parameter"
    )
    top_k: Optional[int] = Field(default=None, ge=1, description="Top-k sampling parameter")
    frequency_penalty: Optional[float] = Field(
        default=None, ge=-2.0, le=2.0, description="Frequency penalty"
    )
    presence_penalty: Optional[float] = Field(
        default=None, ge=-2.0, le=2.0, description="Presence penalty"
    )
    stop: Optional[Union[str, list[str]]] = Field(default=None, description="Stop sequences")
    stream: bool = Field(default=False, description="Enable streaming response")
    functions: Optional[list[dict[str, Any]]] = Field(
        default=None, description="Function definitions"
    )
    tools: Optional[list[dict[str, Any]]] = Field(default=None, description="Tool definitions")
    tool_choice: Optional[Union[str, dict[str, Any]]] = Field(
        default=None, description="Tool choice strategy"
    )
    response_format: Optional[dict[str, Any]] = Field(
        default=None, description="Response format specification"
    )
    seed: Optional[int] = Field(default=None, description="Random seed for reproducibility")
    logit_bias: Optional[dict[str, float]] = Field(
        default=None, description="Logit bias adjustments"
    )
    user: Optional[str] = Field(default=None, description="User identifier")

    # Provider-specific parameters
    extra_headers: Optional[dict[str, str]] = Field(default=None, description="Additional headers")
    extra_body: Optional[dict[str, Any]] = Field(
        default=None, description="Additional body parameters"
    )
    timeout: Optional[float] = Field(default=None, ge=1.0, description="Request timeout override")


class TokenUsage(GibsonBaseModel):
    """Token usage information with cost calculation."""

    prompt_tokens: int = Field(ge=0, description="Number of prompt tokens")
    completion_tokens: int = Field(ge=0, description="Number of completion tokens")
    total_tokens: int = Field(ge=0, description="Total number of tokens")
    cached_tokens: Optional[int] = Field(default=None, ge=0, description="Number of cached tokens")

    # Cost information
    prompt_cost: Optional[Decimal] = Field(default=None, description="Cost of prompt tokens")
    completion_cost: Optional[Decimal] = Field(
        default=None, description="Cost of completion tokens"
    )
    total_cost: Optional[Decimal] = Field(default=None, description="Total cost")

    @computed_field
    def calculated_total(self) -> int:
        """Calculate total tokens from prompt and completion."""
        return self.prompt_tokens + self.completion_tokens


class CompletionChoice(GibsonBaseModel):
    """Individual completion choice."""

    index: int = Field(ge=0, description="Choice index")
    message: ChatMessage = Field(description="Completion message")
    finish_reason: Optional[FinishReason] = Field(default=None, description="Reason for completion")
    logprobs: Optional[dict[str, Any]] = Field(default=None, description="Log probabilities")


class CompletionResponse(BaseModel):
    """Structured completion response model."""

    id: str = Field(description="Completion ID from LLM provider")
    object: Literal["chat.completion", "text_completion"] = Field(
        description="Response object type"
    )
    created: datetime = Field(description="Creation timestamp")
    model: str = Field(description="Model used for completion")
    provider: Optional[str] = Field(default=None, description="Provider used")
    choices: list[CompletionChoice] = Field(description="List of completion choices")
    usage: Optional[TokenUsage] = Field(default=None, description="Token usage information")
    system_fingerprint: Optional[str] = Field(default=None, description="System fingerprint")

    # Metadata
    response_time: Optional[float] = Field(default=None, description="Response time in seconds")
    request_id: Optional[str] = Field(default=None, description="Request correlation ID")

    @field_validator("created", mode="before")
    @classmethod
    def parse_created(cls, v: Union[int, datetime]) -> datetime:
        """Parse Unix timestamp to datetime."""
        if isinstance(v, int):
            return datetime.fromtimestamp(v)
        return v


class StreamChoice(GibsonBaseModel):
    """Streaming completion choice."""

    index: int = Field(ge=0, description="Choice index")
    delta: ChatMessage = Field(description="Delta message content")
    finish_reason: Optional[FinishReason] = Field(default=None, description="Finish reason")
    logprobs: Optional[dict[str, Any]] = Field(default=None, description="Log probabilities")


class StreamResponse(BaseModel):
    """Streaming completion response."""

    id: str = Field(description="Completion ID from LLM provider")
    object: Literal["chat.completion.chunk"] = Field(description="Stream object type")
    created: datetime = Field(description="Creation timestamp")
    model: str = Field(description="Model identifier")
    provider: Optional[str] = Field(default=None, description="Provider identifier")
    choices: list[StreamChoice] = Field(description="Stream choices")
    usage: Optional[TokenUsage] = Field(default=None, description="Token usage (final chunk only)")

    @field_validator("created", mode="before")
    @classmethod
    def parse_created(cls, v: Union[int, datetime]) -> datetime:
        """Parse Unix timestamp to datetime."""
        if isinstance(v, int):
            return datetime.fromtimestamp(v)
        return v


# =============================================================================
# Error Types
# =============================================================================


class LLMErrorType(str, Enum):
    """LLM-specific error types."""

    # Authentication errors
    AUTHENTICATION_ERROR = "authentication_error"
    PERMISSION_DENIED = "permission_denied"
    INVALID_API_KEY = "invalid_api_key"

    # Request errors
    INVALID_REQUEST = "invalid_request"
    MODEL_NOT_FOUND = "model_not_found"
    CONTEXT_LENGTH_EXCEEDED = "context_length_exceeded"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    CONTENT_FILTER = "content_filter"

    # Provider errors
    PROVIDER_ERROR = "provider_error"
    PROVIDER_TIMEOUT = "provider_timeout"
    PROVIDER_UNAVAILABLE = "provider_unavailable"

    # Network errors
    NETWORK_ERROR = "network_error"
    TIMEOUT_ERROR = "timeout_error"
    CONNECTION_ERROR = "connection_error"

    # Service errors
    INTERNAL_SERVER_ERROR = "internal_server_error"
    SERVICE_UNAVAILABLE = "service_unavailable"
    BAD_GATEWAY = "bad_gateway"


class LLMError(GibsonBaseModel):
    """Structured LLM error model."""

    type: LLMErrorType = Field(description="Error type")
    message: str = Field(description="Error message")
    code: Optional[str] = Field(default=None, description="Provider-specific error code")
    param: Optional[str] = Field(default=None, description="Parameter that caused the error")
    details: Optional[dict[str, Any]] = Field(default=None, description="Additional error details")
    retry_after: Optional[int] = Field(default=None, description="Retry after seconds")

    # Request context
    request_id: Optional[str] = Field(default=None, description="Request correlation ID")
    model: Optional[str] = Field(default=None, description="Model that caused the error")
    provider: Optional[LLMProvider] = Field(
        default=None, description="Provider that caused the error"
    )


# =============================================================================
# Rate Limiting and Fallback Configuration
# =============================================================================


class RateLimitConfig(GibsonBaseModel):
    """Rate limiting configuration for LLM requests."""

    requests_per_minute: Optional[int] = Field(
        default=None, ge=1, description="Max requests per minute"
    )
    tokens_per_minute: Optional[int] = Field(
        default=None, ge=1, description="Max tokens per minute"
    )
    concurrent_requests: Optional[int] = Field(
        default=None, ge=1, description="Max concurrent requests"
    )

    # Burst handling
    burst_size: Optional[int] = Field(default=None, ge=1, description="Burst capacity")
    burst_refill_rate: Optional[float] = Field(
        default=None, ge=0.1, description="Burst refill per second"
    )

    # Backoff strategy
    backoff_strategy: Literal["exponential", "linear", "fixed"] = Field(
        default="exponential", description="Backoff strategy for rate limits"
    )
    base_delay: float = Field(default=1.0, ge=0.1, description="Base delay in seconds")
    max_delay: float = Field(default=60.0, ge=1.0, description="Maximum delay in seconds")
    jitter: bool = Field(default=True, description="Add random jitter to delays")


class FallbackConfig(GibsonBaseModel):
    """Fallback configuration for provider failures."""

    enabled: bool = Field(default=True, description="Enable fallback providers")
    fallback_providers: list[str] = Field(description="Ordered list of fallback providers")
    max_fallback_attempts: int = Field(default=3, ge=1, description="Maximum fallback attempts")

    # Fallback triggers
    trigger_on_error_types: list[LLMErrorType] = Field(
        default_factory=lambda: [
            LLMErrorType.PROVIDER_UNAVAILABLE,
            LLMErrorType.SERVICE_UNAVAILABLE,
            LLMErrorType.RATE_LIMIT_EXCEEDED,
        ],
        description="Error types that trigger fallback",
    )

    # Circuit breaker
    circuit_breaker_enabled: bool = Field(default=True, description="Enable circuit breaker")
    failure_threshold: int = Field(default=5, ge=1, description="Failures before opening circuit")
    recovery_timeout: int = Field(
        default=60, ge=1, description="Seconds before attempting recovery"
    )


class LoadBalancingConfig(GibsonBaseModel):
    """Load balancing configuration for multiple providers."""

    strategy: Literal["round_robin", "weighted", "least_latency", "random"] = Field(
        default="round_robin", description="Load balancing strategy"
    )
    weights: Optional[dict[str, float]] = Field(default=None, description="Provider weights")
    health_check_enabled: bool = Field(default=True, description="Enable health checks")
    health_check_interval: int = Field(
        default=30, ge=5, description="Health check interval in seconds"
    )


# =============================================================================
# Protocol Interfaces for Async Operations
# =============================================================================


@runtime_checkable
class AsyncLLMClient(Protocol):
    """Protocol for async LLM client implementations."""

    async def complete(
        self,
        request: CompletionRequest,
        provider_config: Optional[ProviderConfig] = None,
    ) -> CompletionResponse:
        """Generate a completion."""
        ...

    async def complete_stream(
        self,
        request: CompletionRequest,
        provider_config: Optional[ProviderConfig] = None,
    ) -> AsyncGenerator[StreamResponse, None]:
        """Generate a streaming completion."""
        ...

    async def embed(
        self,
        texts: list[str],
        model: str,
        provider_config: Optional[ProviderConfig] = None,
    ) -> list[list[float]]:
        """Generate embeddings."""
        ...

    async def moderate(
        self,
        content: str,
        model: str,
        provider_config: Optional[ProviderConfig] = None,
    ) -> dict[str, Any]:
        """Moderate content."""
        ...

    async def health_check(self, provider_config: ProviderConfig) -> bool:
        """Check provider health."""
        ...

    async def get_models(self, provider_config: ProviderConfig) -> list[str]:
        """Get available models."""
        ...


@runtime_checkable
class AsyncLLMManager(Protocol):
    """Protocol for async LLM manager implementations."""

    async def add_provider(self, config: ProviderConfig) -> None:
        """Add a provider configuration."""
        ...

    async def remove_provider(self, provider_id: str) -> None:
        """Remove a provider configuration."""
        ...

    async def get_provider(self, provider_id: str) -> Optional[ProviderConfig]:
        """Get provider configuration."""
        ...

    async def list_providers(self) -> list[ProviderConfig]:
        """List all provider configurations."""
        ...

    async def complete(
        self,
        request: CompletionRequest,
        provider_id: Optional[str] = None,
    ) -> CompletionResponse:
        """Complete with provider selection and fallback."""
        ...

    async def complete_stream(
        self,
        request: CompletionRequest,
        provider_id: Optional[str] = None,
    ) -> AsyncGenerator[StreamResponse, None]:
        """Streaming complete with provider selection and fallback."""
        ...


# =============================================================================
# Usage Tracking and Cost Models
# =============================================================================


class CostModel(GibsonBaseModel):
    """Cost model for different providers and models."""

    provider: LLMProvider = Field(description="Provider identifier")
    model: str = Field(description="Model identifier")

    # Pricing per 1K tokens
    prompt_cost_per_1k: Decimal = Field(description="Cost per 1K prompt tokens")
    completion_cost_per_1k: Decimal = Field(description="Cost per 1K completion tokens")

    # Special pricing
    cached_prompt_cost_per_1k: Optional[Decimal] = Field(
        default=None, description="Cost per 1K cached prompt tokens"
    )

    # Currency and effective dates
    currency: str = Field(default="USD", description="Currency code")
    effective_date: datetime = Field(description="When pricing becomes effective")
    expires_date: Optional[datetime] = Field(default=None, description="When pricing expires")


class UsageRecord(TimestampedModel):
    """Usage tracking record."""

    request_id: str = Field(description="Request correlation ID")
    provider: LLMProvider = Field(description="Provider used")
    model: str = Field(description="Model used")

    # Usage metrics
    usage: TokenUsage = Field(description="Token usage information")
    response_time: float = Field(description="Response time in seconds")

    # Cost information
    cost_model_id: Optional[UUID] = Field(default=None, description="Cost model used")
    calculated_cost: Optional[Decimal] = Field(default=None, description="Calculated cost")

    # Request metadata
    user_id: Optional[str] = Field(default=None, description="User identifier")
    session_id: Optional[str] = Field(default=None, description="Session identifier")
    tags: Optional[list[str]] = Field(default=None, description="Request tags")

    # Error information
    error: Optional[LLMError] = Field(default=None, description="Error information if failed")
    fallback_used: bool = Field(default=False, description="Whether fallback was used")


class UsageAggregation(GibsonBaseModel):
    """Aggregated usage statistics."""

    period_start: datetime = Field(description="Aggregation period start")
    period_end: datetime = Field(description="Aggregation period end")

    # Aggregation dimensions
    provider: Optional[LLMProvider] = Field(default=None, description="Provider filter")
    model: Optional[str] = Field(default=None, description="Model filter")
    user_id: Optional[str] = Field(default=None, description="User filter")

    # Metrics
    total_requests: int = Field(description="Total number of requests")
    successful_requests: int = Field(description="Successful requests")
    failed_requests: int = Field(description="Failed requests")

    total_prompt_tokens: int = Field(description="Total prompt tokens")
    total_completion_tokens: int = Field(description="Total completion tokens")
    total_tokens: int = Field(description="Total tokens")

    total_cost: Optional[Decimal] = Field(default=None, description="Total cost")

    # Performance metrics
    avg_response_time: float = Field(description="Average response time")
    p95_response_time: float = Field(description="95th percentile response time")

    # Error analysis
    error_rate: float = Field(ge=0.0, le=1.0, description="Error rate")
    fallback_rate: float = Field(ge=0.0, le=1.0, description="Fallback usage rate")


# =============================================================================
# Type Aliases and Unions
# =============================================================================

# Union types for different response formats
LLMResponse = Union[CompletionResponse, StreamResponse]
LLMRequest = CompletionRequest

# Type aliases for async operations
StreamAsyncIterator = AsyncGenerator[StreamResponse, None]

# Provider configuration union (re-exported for convenience)
__all__ = [
    # Enums
    "LLMProvider",
    "ModelType",
    "TokenType",
    "ResponseFormat",
    "FinishReason",
    "LLMErrorType",
    # TypedDict definitions
    "MessageDict",
    "FunctionDict",
    "ToolDict",
    "UsageDict",
    "ChoiceDict",
    "CompletionResponseDict",
    "StreamChoiceDict",
    "StreamResponseDict",
    "EmbeddingDict",
    "EmbeddingResponseDict",
    # Configuration models
    "BaseProviderConfig",
    "OpenAIConfig",
    "AnthropicConfig",
    "AzureOpenAIConfig",
    "BedrockConfig",
    "VertexAIConfig",
    "ProviderConfig",
    "RateLimitConfig",
    "FallbackConfig",
    "LoadBalancingConfig",
    # Request/Response models
    "ChatMessage",
    "CompletionRequest",
    "TokenUsage",
    "CompletionChoice",
    "CompletionResponse",
    "StreamChoice",
    "StreamResponse",
    # Error models
    "LLMError",
    # Protocol interfaces
    "AsyncLLMClient",
    "AsyncLLMManager",
    # Usage and cost models
    "CostModel",
    "UsageRecord",
    "UsageAggregation",
    # Type aliases
    "LLMResponse",
    "LLMRequest",
    "StreamAsyncIterator",
]
