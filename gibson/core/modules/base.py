"""Base module class for core Gibson Framework modules."""

import asyncio
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from gibson.models.scan import Finding
from gibson.models.target import TargetModel as Target
from gibson.models.domain import ModuleCategory, Severity
from gibson.core.config import Config

# LLM imports with graceful fallback
try:
    from gibson.core.llm.client_factory import LLMClientFactory
    from gibson.core.llm.types import AsyncLLMClient

    LLM_AVAILABLE = True
except ImportError:
    LLM_AVAILABLE = False
    if TYPE_CHECKING:
        from gibson.core.llm.client_factory import LLMClientFactory
        from gibson.core.llm.types import AsyncLLMClient


class BaseModule(ABC):
    """
    Base class for all Gibson Framework security modules.

    This class provides the core interface that all modules must implement,
    along with common functionality for configuration, validation, and lifecycle management.

    Core maintained modules should inherit from this class and implement
    the required abstract methods.
    """

    # Module metadata (must be set by subclasses)
    name: str = "base"
    version: str = "1.0.0"
    description: str = "Base module class"
    category: ModuleCategory = ModuleCategory.UNSPECIFIED

    def __init__(
        self,
        config: Config = None,
        base_orchestrator=None,
        llm_client_factory: Optional["LLMClientFactory"] = None,
    ):
        """
        Initialize the module.

        Args:
            config: Configuration object
            base_orchestrator: Reference to Base orchestrator for shared services
            llm_client_factory: Optional LLM client factory for AI-enabled modules
        """
        self.config = config or Config()
        self.base_orchestrator = base_orchestrator
        self.llm_client_factory = llm_client_factory
        self._initialized = False
        self._enabled = True
        self._llm_client: Optional["AsyncLLMClient"] = None

    @abstractmethod
    async def run(self, target: Target, config: Optional[Dict[str, Any]] = None) -> List[Finding]:
        """
        Execute the module against a target.

        Args:
            target: Target to test
            config: Optional runtime configuration

        Returns:
            List of findings discovered during execution
        """
        pass

    @abstractmethod
    def get_config_schema(self) -> Dict[str, Any]:
        """
        Return JSON schema for module configuration validation.

        Returns:
            JSON schema dictionary
        """
        pass

    async def setup(self) -> None:
        """
        Module setup/initialization hook.

        Override this method to perform any module-specific initialization
        such as loading resources, validating configuration, etc.
        """
        pass

    async def teardown(self) -> None:
        """
        Module cleanup hook.

        Override this method to clean up any resources allocated during
        module execution.
        """
        pass

    async def validate_target(self, target: Target) -> bool:
        """
        Validate if this module can be executed against the given target.

        Args:
            target: Target to validate

        Returns:
            True if target is valid for this module, False otherwise
        """
        return True  # Default: accept all targets

    async def get_metadata(self) -> Dict[str, Any]:
        """
        Get module metadata.

        Returns:
            Dictionary containing module metadata
        """
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "category": self.category.value
            if hasattr(self.category, "value")
            else str(self.category),
            "enabled": self._enabled,
        }

    def enable(self) -> None:
        """Enable this module."""
        self._enabled = True

    def disable(self) -> None:
        """Disable this module."""
        self._enabled = False

    @property
    def enabled(self) -> bool:
        """Check if module is enabled."""
        return self._enabled

    @property
    def initialized(self) -> bool:
        """Check if module has been initialized."""
        return self._initialized

    async def initialize(self) -> None:
        """Initialize the module if not already initialized."""
        if not self._initialized:
            await self.setup()
            self._initialized = True

    async def cleanup(self) -> None:
        """Cleanup the module."""
        if self._initialized:
            await self.teardown()
            self._initialized = False

    @property
    def llm_available(self) -> bool:
        """
        Check if LLM functionality is available.

        Returns:
            True if LLM client factory is available and LiteLLM is installed
        """
        return LLM_AVAILABLE and self.llm_client_factory is not None

    async def get_llm_client(self, provider: Optional[str] = None) -> "AsyncLLMClient":
        """
        Get an authenticated LLM client for AI operations.

        Args:
            provider: Optional specific provider to use (auto-detects if None)

        Returns:
            AsyncLLMClient instance ready for use

        Raises:
            RuntimeError: If LLM functionality is not available
            ValueError: If no providers are configured
        """
        if not self.llm_available:
            raise RuntimeError(
                "LLM functionality not available. Ensure LiteLLM is installed and "
                "LLMClientFactory is provided during module initialization."
            )

        # Use cached client if available and no specific provider requested
        if provider is None and self._llm_client is not None:
            return self._llm_client

        # Get client from factory
        client = await self.llm_client_factory.get_client(provider)

        # Cache default client for reuse
        if provider is None:
            self._llm_client = client

        return client

    async def get_available_llm_providers(self) -> List[str]:
        """
        Get list of available LLM providers.

        Returns:
            List of provider identifiers

        Raises:
            RuntimeError: If LLM functionality is not available
        """
        if not self.llm_available:
            raise RuntimeError("LLM functionality not available")

        return await self.llm_client_factory.get_available_providers()

    async def check_llm_health(self, provider: Optional[str] = None) -> bool:
        """
        Check health of LLM provider.

        Args:
            provider: Optional specific provider to check

        Returns:
            True if provider is healthy and available
        """
        if not self.llm_available:
            return False

        try:
            if provider is None:
                # Check if any providers are available
                providers = await self.get_available_llm_providers()
                if not providers:
                    return False
                provider = providers[0]  # Check first available

            health_status = await self.llm_client_factory.health_check(provider)
            return health_status.is_healthy

        except Exception:
            return False


# Legacy compatibility alias
BasePromptModule = BaseModule
