"""Built-in support for major AI service API providers."""
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, Tuple
import httpx
from pydantic import BaseModel, Field
from gibson.models.auth import ApiKeyFormat, AuthErrorType


def validate_api_key_format(format_value: str) -> ApiKeyFormat:
    """Validate and convert API key format string to enum.

    Args:
        format_value: String representation of API key format

    Returns:
        Valid ApiKeyFormat enum value

    Raises:
        ValueError: If format_value is not a valid ApiKeyFormat
    """
    try:
        return ApiKeyFormat(format_value)
    except ValueError:
        format_upper = format_value.upper()
        for member in ApiKeyFormat:
            if member.name == format_upper:
                return member
        valid_formats = [f.value for f in ApiKeyFormat]
        raise ValueError(
            f"Invalid API key format: {format_value}. Valid formats: {', '.join(valid_formats)}"
        )


class RateLimitInfo(BaseModel):
    """Rate limit information from API response."""

    limit: Optional[int] = None
    remaining: Optional[int] = None
    reset_at: Optional[int] = None
    retry_after: Optional[int] = None


class ProviderConfig(BaseModel):
    """Configuration for an API provider."""

    name: str
    base_url: str
    validation_endpoint: str
    key_format: ApiKeyFormat
    header_name: Optional[str] = None
    query_param: Optional[str] = None
    rate_limit_headers: Dict[str, str] = Field(default_factory=dict)
    error_patterns: Dict[str, AuthErrorType] = Field(default_factory=dict)

    def __init__(self, **data):
        """Initialize with enum validation."""
        if "key_format" in data and isinstance(data["key_format"], str):
            data["key_format"] = validate_api_key_format(data["key_format"])
        super().__init__(**data)


class APIProvider(ABC):
    """Base class for API provider implementations."""

    def __init__(self, config: ProviderConfig):
        """Initialize provider with configuration."""
        self.config = config

    @abstractmethod
    def format_auth_header(self, api_key: str) -> Dict[str, str]:
        """Format authentication headers for this provider."""
        pass

    @abstractmethod
    def get_validation_endpoint(self) -> str:
        """Get the endpoint URL for validating credentials."""
        pass

    @abstractmethod
    def parse_rate_limit_info(self, response: httpx.Response) -> RateLimitInfo:
        """Parse rate limit information from response headers."""
        pass

    @abstractmethod
    def detect_auth_error(self, response: httpx.Response) -> Tuple[AuthErrorType, str]:
        """Detect and categorize authentication errors."""
        pass

    def validate_api_key(self, api_key: str) -> bool:
        """Validate API key format for this provider."""
        if self.config.name == "openai":
            return api_key.startswith("sk-")
        elif self.config.name == "anthropic":
            return api_key.startswith("sk-ant-")
        return len(api_key) > 0


class OpenAIProvider(APIProvider):
    """OpenAI API provider implementation."""

    def __init__(self):
        """Initialize OpenAI provider configuration."""
        config = ProviderConfig(
            name="openai",
            base_url="https://api.openai.com/v1",
            validation_endpoint="/models",
            key_format=ApiKeyFormat.BEARER_TOKEN,
            rate_limit_headers={
                "limit": "x-ratelimit-limit-requests",
                "remaining": "x-ratelimit-remaining-requests",
                "reset": "x-ratelimit-reset-requests",
            },
            error_patterns={
                "invalid_api_key": AuthErrorType.INVALID_CREDENTIALS,
                "insufficient_quota": AuthErrorType.QUOTA_EXCEEDED,
                "rate_limit_exceeded": AuthErrorType.RATE_LIMITED,
            },
        )
        super().__init__(config)

    def format_auth_header(self, api_key: str) -> Dict[str, str]:
        """Format OpenAI authentication headers."""
        return {"Authorization": f"Bearer {api_key}", "OpenAI-Beta": "assistants=v2"}

    def get_validation_endpoint(self) -> str:
        """Get OpenAI validation endpoint."""
        return f"{self.config.base_url}{self.config.validation_endpoint}"

    def parse_rate_limit_info(self, response: httpx.Response) -> RateLimitInfo:
        """Parse OpenAI rate limit headers."""
        headers = response.headers
        return RateLimitInfo(
            limit=int(headers.get("x-ratelimit-limit-requests", 0)) or None,
            remaining=int(headers.get("x-ratelimit-remaining-requests", 0)) or None,
            reset_at=int(headers.get("x-ratelimit-reset-requests", 0)) or None,
        )

    def detect_auth_error(self, response: httpx.Response) -> Tuple[AuthErrorType, str]:
        """Detect OpenAI authentication errors."""
        if response.status_code == 401:
            error_data = response.model_dump_json() if response.content else {}
            error_msg = error_data.get("error", {}).get("message", "Authentication failed")
            if "invalid_api_key" in error_msg.lower():
                return AuthErrorType.INVALID_CREDENTIALS, error_msg
            elif "quota" in error_msg.lower():
                return AuthErrorType.QUOTA_EXCEEDED, error_msg
            return AuthErrorType.AUTHENTICATION_FAILED, error_msg
        elif response.status_code == 429:
            return AuthErrorType.RATE_LIMITED, "Rate limit exceeded"
        elif response.status_code == 403:
            return (AuthErrorType.INSUFFICIENT_PERMISSIONS, "Insufficient permissions")
        return AuthErrorType.UNKNOWN, f"HTTP {response.status_code}"


class AnthropicProvider(APIProvider):
    """Anthropic Claude API provider implementation."""

    def __init__(self):
        """Initialize Anthropic provider configuration."""
        config = ProviderConfig(
            name="anthropic",
            base_url="https://api.anthropic.com",
            validation_endpoint="/v1/messages",
            key_format=ApiKeyFormat.CUSTOM_HEADER,
            header_name="x-api-key",
            rate_limit_headers={
                "limit": "anthropic-ratelimit-requests-limit",
                "remaining": "anthropic-ratelimit-requests-remaining",
                "reset": "anthropic-ratelimit-requests-reset",
            },
            error_patterns={
                "invalid_api_key": AuthErrorType.INVALID_CREDENTIALS,
                "rate_limit_error": AuthErrorType.RATE_LIMITED,
            },
        )
        super().__init__(config)

    def format_auth_header(self, api_key: str) -> Dict[str, str]:
        """Format Anthropic authentication headers."""
        return {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }

    def get_validation_endpoint(self) -> str:
        """Get Anthropic validation endpoint."""
        return f"{self.config.base_url}{self.config.validation_endpoint}"

    def parse_rate_limit_info(self, response: httpx.Response) -> RateLimitInfo:
        """Parse Anthropic rate limit headers."""
        headers = response.headers
        return RateLimitInfo(
            limit=int(headers.get("anthropic-ratelimit-requests-limit", 0)) or None,
            remaining=int(headers.get("anthropic-ratelimit-requests-remaining", 0)) or None,
            reset_at=int(headers.get("anthropic-ratelimit-requests-reset", 0)) or None,
            retry_after=int(headers.get("retry-after", 0)) or None,
        )

    def detect_auth_error(self, response: httpx.Response) -> Tuple[AuthErrorType, str]:
        """Detect Anthropic authentication errors."""
        if response.status_code == 401:
            error_data = response.model_dump_json() if response.content else {}
            error_msg = error_data.get("error", {}).get("message", "Authentication failed")
            return AuthErrorType.INVALID_CREDENTIALS, error_msg
        elif response.status_code == 429:
            return AuthErrorType.RATE_LIMITED, "Rate limit exceeded"
        elif response.status_code == 403:
            return (AuthErrorType.INSUFFICIENT_PERMISSIONS, "Insufficient permissions")
        return AuthErrorType.UNKNOWN, f"HTTP {response.status_code}"


class GoogleAIProvider(APIProvider):
    """Google AI (Gemini) API provider implementation."""

    def __init__(self):
        """Initialize Google AI provider configuration."""
        config = ProviderConfig(
            name="google",
            base_url="https://generativelanguage.googleapis.com",
            validation_endpoint="/v1beta/models",
            key_format=ApiKeyFormat.QUERY_PARAMETER,
            query_param="key",
            error_patterns={
                "API_KEY_INVALID": AuthErrorType.INVALID_CREDENTIALS,
                "RATE_LIMIT_EXCEEDED": AuthErrorType.RATE_LIMITED,
            },
        )
        super().__init__(config)

    def format_auth_header(self, api_key: str) -> Dict[str, str]:
        """Format Google AI authentication headers."""
        return {}

    def format_auth_params(self, api_key: str) -> Dict[str, str]:
        """Format Google AI query parameters."""
        return {"key": api_key}

    def get_validation_endpoint(self) -> str:
        """Get Google AI validation endpoint."""
        return f"{self.config.base_url}{self.config.validation_endpoint}"

    def parse_rate_limit_info(self, response: httpx.Response) -> RateLimitInfo:
        """Parse Google AI rate limit information."""
        return RateLimitInfo()

    def detect_auth_error(self, response: httpx.Response) -> Tuple[AuthErrorType, str]:
        """Detect Google AI authentication errors."""
        if response.status_code == 400 or response.status_code == 401:
            error_data = response.model_dump_json() if response.content else {}
            error_msg = error_data.get("error", {}).get("message", "Authentication failed")
            if "API_KEY_INVALID" in error_msg:
                return AuthErrorType.INVALID_CREDENTIALS, error_msg
            return AuthErrorType.AUTHENTICATION_FAILED, error_msg
        elif response.status_code == 429:
            return AuthErrorType.RATE_LIMITED, "Rate limit exceeded"
        return AuthErrorType.UNKNOWN, f"HTTP {response.status_code}"


class AzureOpenAIProvider(APIProvider):
    """Azure OpenAI Service provider implementation."""

    def __init__(self, resource_name: str = None, deployment_name: str = None):
        """Initialize Azure OpenAI provider configuration."""
        self.resource_name = resource_name or "your-resource-name"
        self.deployment_name = deployment_name or "your-deployment-name"
        config = ProviderConfig(
            name="azure_openai",
            base_url=f"https://{self.resource_name}.openai.azure.com",
            validation_endpoint=f"/openai/deployments/{self.deployment_name}/completions",
            key_format=ApiKeyFormat.CUSTOM_HEADER,
            header_name="api-key",
            error_patterns={
                "invalid_api_key": AuthErrorType.INVALID_CREDENTIALS,
                "rate_limit": AuthErrorType.RATE_LIMITED,
            },
        )
        super().__init__(config)

    def format_auth_header(self, api_key: str) -> Dict[str, str]:
        """Format Azure OpenAI authentication headers."""
        return {"api-key": api_key, "Content-Type": "application/json"}

    def get_validation_endpoint(self) -> str:
        """Get Azure OpenAI validation endpoint."""
        return f"{self.config.base_url}{self.config.validation_endpoint}?api-version=2024-02-01"

    def parse_rate_limit_info(self, response: httpx.Response) -> RateLimitInfo:
        """Parse Azure rate limit headers."""
        headers = response.headers
        return RateLimitInfo(
            remaining=int(headers.get("x-ratelimit-remaining-requests", 0)) or None,
            retry_after=int(headers.get("retry-after", 0)) or None,
        )

    def detect_auth_error(self, response: httpx.Response) -> Tuple[AuthErrorType, str]:
        """Detect Azure OpenAI authentication errors."""
        if response.status_code == 401:
            return AuthErrorType.INVALID_CREDENTIALS, "Invalid API key"
        elif response.status_code == 429:
            return AuthErrorType.RATE_LIMITED, "Rate limit exceeded"
        elif response.status_code == 403:
            return AuthErrorType.INSUFFICIENT_PERMISSIONS, "Access denied"
        return AuthErrorType.UNKNOWN, f"HTTP {response.status_code}"


class AWSBedrockProvider(APIProvider):
    """AWS Bedrock provider implementation."""

    def __init__(self):
        """Initialize AWS Bedrock provider configuration."""
        config = ProviderConfig(
            name="aws_bedrock",
            base_url="https://bedrock-runtime.{region}.amazonaws.com",
            validation_endpoint="/model/{model_id}/invoke",
            key_format=ApiKeyFormat.CUSTOM_HEADER,
            error_patterns={
                "UnrecognizedClientException": AuthErrorType.INVALID_CREDENTIALS,
                "ThrottlingException": AuthErrorType.RATE_LIMITED,
            },
        )
        super().__init__(config)

    def format_auth_header(self, api_key: str) -> Dict[str, str]:
        """Format AWS Bedrock authentication headers."""
        return {
            "Authorization": f"AWS4-HMAC-SHA256 Credential={api_key}",
            "Content-Type": "application/json",
        }

    def get_validation_endpoint(self) -> str:
        """Get AWS Bedrock validation endpoint."""
        return self.config.base_url.format(region="us-east-1")

    def parse_rate_limit_info(self, response: httpx.Response) -> RateLimitInfo:
        """Parse AWS rate limit information."""
        return RateLimitInfo()

    def detect_auth_error(self, response: httpx.Response) -> Tuple[AuthErrorType, str]:
        """Detect AWS Bedrock authentication errors."""
        if response.status_code == 403:
            error_data = response.model_dump_json() if response.content else {}
            error_type = error_data.get("__type", "")
            if "UnrecognizedClientException" in error_type:
                return (AuthErrorType.INVALID_CREDENTIALS, "Invalid AWS credentials")
            return AuthErrorType.INSUFFICIENT_PERMISSIONS, "Access denied"
        elif response.status_code == 429:
            return AuthErrorType.RATE_LIMITED, "Rate limit exceeded"
        return AuthErrorType.UNKNOWN, f"HTTP {response.status_code}"


class ProviderRegistry:
    """Registry for API providers."""

    _providers: Dict[str, APIProvider] = {}

    @classmethod
    def register(cls, name: str, provider: APIProvider) -> None:
        """Register a provider."""
        cls._providers[name.lower()] = provider

    @classmethod
    def get(cls, name: str) -> Optional[APIProvider]:
        """Get a provider by name."""
        return cls._providers.get(name.lower())

    @classmethod
    def list_providers(cls) -> list[str]:
        """List all registered provider names."""
        return list(cls._providers.keys())

    @classmethod
    def initialize_defaults(cls) -> None:
        """Initialize default providers."""
        cls.register("openai", OpenAIProvider())
        cls.register("anthropic", AnthropicProvider())
        cls.register("google", GoogleAIProvider())
        cls.register("azure_openai", AzureOpenAIProvider())
        cls.register("aws_bedrock", AWSBedrockProvider())


ProviderRegistry.initialize_defaults()


def get_provider(provider_name: str) -> Optional[APIProvider]:
    """Get a provider instance by name."""
    return ProviderRegistry.get(provider_name)


def detect_provider_from_url(url: str) -> Optional[str]:
    """Detect provider from API URL."""
    url_lower = url.lower()
    if "openai.com" in url_lower:
        return "openai"
    elif "anthropic.com" in url_lower:
        return "anthropic"
    elif "googleapis.com" in url_lower and "generativelanguage" in url_lower:
        return "google"
    elif "openai.azure.com" in url_lower:
        return "azure_openai"
    elif "bedrock" in url_lower and "amazonaws.com" in url_lower:
        return "aws_bedrock"
    return None


def detect_provider_from_key(api_key: str) -> Optional[str]:
    """Detect provider from API key format."""
    if api_key.startswith("sk-proj-"):
        return "openai"
    elif api_key.startswith("sk-ant-"):
        return "anthropic"
    elif len(api_key) == 39 and api_key.startswith("AI"):
        return "google"
    return None
