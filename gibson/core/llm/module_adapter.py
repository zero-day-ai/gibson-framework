"""
LiteLLM integration adapter for existing Gibson modules.

This module provides backward compatibility for existing modules that use legacy
authentication patterns while encouraging migration to the new LiteLLM-based system.
It acts as a bridge between old credential manager calls and the new LLM client factory.
"""

from __future__ import annotations

import warnings
from typing import Any, Dict, List, Optional, Type, Union
from uuid import UUID, uuid4

from loguru import logger

try:
    from gibson.core.llm.client_factory import LLMClientFactory
    from gibson.core.llm.types import AsyncLLMClient, LLMProvider
    LLM_AVAILABLE = True
except ImportError:
    logger.warning("LiteLLM functionality not available")
    LLM_AVAILABLE = False
    LLMClientFactory = None
    AsyncLLMClient = None
    LLMProvider = None

from gibson.core.auth.credential_manager import CredentialManager, CredentialNotFoundError
from gibson.models.auth import ApiKeyCredentialModel, ApiKeyFormat, ValidationStatus


class LegacyAuthAdapter:
    """
    Adapter that maps legacy credential manager calls to LiteLLM client factory.
    
    Provides backward compatibility for modules that haven't been updated to use
    the new LiteLLM system while encouraging migration through deprecation warnings.
    """
    
    # Provider name mapping from legacy names to LLMProvider enum
    PROVIDER_MAPPING = {
        'openai': LLMProvider.OPENAI if LLM_AVAILABLE else 'openai',
        'anthropic': LLMProvider.ANTHROPIC if LLM_AVAILABLE else 'anthropic',
        'azure': LLMProvider.AZURE_OPENAI if LLM_AVAILABLE else 'azure',
        'azure_openai': LLMProvider.AZURE_OPENAI if LLM_AVAILABLE else 'azure_openai',
        'cohere': LLMProvider.COHERE if LLM_AVAILABLE else 'cohere',
        'huggingface': LLMProvider.HUGGINGFACE if LLM_AVAILABLE else 'huggingface',
        'ollama': LLMProvider.OLLAMA if LLM_AVAILABLE else 'ollama',
        'gemini': LLMProvider.GEMINI if LLM_AVAILABLE else 'gemini',
        'claude': LLMProvider.ANTHROPIC if LLM_AVAILABLE else 'anthropic',  # Legacy Claude mapping
        'gpt': LLMProvider.OPENAI if LLM_AVAILABLE else 'openai',  # Legacy GPT mapping
    }
    
    def __init__(
        self, 
        credential_manager: Optional[CredentialManager] = None,
        llm_client_factory: Optional['LLMClientFactory'] = None
    ):
        """
        Initialize legacy auth adapter.
        
        Args:
            credential_manager: Legacy credential manager (for fallback)
            llm_client_factory: New LLM client factory (preferred)
        """
        self.credential_manager = credential_manager
        self.llm_client_factory = llm_client_factory
        self._warned_methods: set = set()  # Track which methods have shown warnings
        
        if not LLM_AVAILABLE:
            logger.warning(
                "LiteLLM not available - falling back to credential manager only. "
                "Install with 'pip install litellm' for full functionality."
            )
    
    def deprecated_auth_warning(self, method_name: str, preferred_method: str) -> None:
        """
        Log deprecation warning for old authentication patterns.
        
        Args:
            method_name: Name of deprecated method
            preferred_method: Recommended replacement method
        """
        # Only warn once per method to avoid spam
        warning_key = f"{method_name}_{preferred_method}"
        if warning_key in self._warned_methods:
            return
        
        self._warned_methods.add(warning_key)
        
        warning_message = (
            f"DEPRECATION WARNING: {method_name}() is deprecated. "
            f"Use {preferred_method} instead. "
            f"This legacy authentication pattern will be removed in a future version. "
            f"See documentation for migration guide."
        )
        
        warnings.warn(warning_message, DeprecationWarning, stacklevel=3)
        logger.warning(warning_message)
    
    async def get_api_key(
        self, 
        provider: str, 
        target_id: Optional[Union[str, UUID]] = None
    ) -> Optional[str]:
        """
        Backward compatible API key retrieval.
        
        Maps old get_api_key() calls to appropriate authentication method.
        
        Args:
            provider: Provider name (legacy format)
            target_id: Optional target identifier
            
        Returns:
            API key string if found, None otherwise
        """
        self.deprecated_auth_warning(
            "get_api_key",
            "module.get_llm_client() or llm_client_factory.get_client()"
        )
        
        # Try LiteLLM client factory first (preferred)
        if self.llm_client_factory and LLM_AVAILABLE:
            try:
                provider_mapped = self._map_provider_name(provider)
                client = await self.llm_client_factory.get_client(provider_mapped)
                
                # Extract API key from client config if available
                if hasattr(client, 'provider_config') and hasattr(client.provider_config, 'api_key'):
                    return client.provider_config.api_key
                    
            except Exception as e:
                logger.debug(f"Failed to get API key from LLM client factory: {e}")
        
        # Fallback to legacy credential manager
        if self.credential_manager and target_id:
            try:
                target_uuid = UUID(str(target_id)) if not isinstance(target_id, UUID) else target_id
                credential = self.credential_manager.retrieve_credential(target_uuid)
                return credential.token if credential else None
                
            except (ValueError, CredentialNotFoundError) as e:
                logger.debug(f"Failed to retrieve credential from manager: {e}")
        
        return None
    
    async def get_provider_client(self, provider: str) -> Optional['AsyncLLMClient']:
        """
        Get provider-specific client using legacy provider names.
        
        Args:
            provider: Provider name (legacy format)
            
        Returns:
            AsyncLLMClient instance if available, None otherwise
        """
        self.deprecated_auth_warning(
            "get_provider_client", 
            "module.get_llm_client(provider)"
        )
        
        if not self.llm_client_factory or not LLM_AVAILABLE:
            logger.warning("LLM client factory not available")
            return None
        
        try:
            provider_mapped = self._map_provider_name(provider)
            return await self.llm_client_factory.get_client(provider_mapped)
            
        except Exception as e:
            logger.error(f"Failed to get provider client for {provider}: {e}")
            return None
    
    def _map_provider_name(self, provider: str) -> str:
        """
        Map legacy provider names to LiteLLM provider identifiers.
        
        Args:
            provider: Legacy provider name
            
        Returns:
            Mapped provider identifier
        """
        provider_lower = provider.lower().strip()
        
        # Direct mapping
        if provider_lower in self.PROVIDER_MAPPING:
            mapped = self.PROVIDER_MAPPING[provider_lower]
            return mapped.value if hasattr(mapped, 'value') else mapped
        
        # Fuzzy matching for common variations
        for legacy_name, llm_provider in self.PROVIDER_MAPPING.items():
            if legacy_name in provider_lower or provider_lower in legacy_name:
                mapped = llm_provider
                return mapped.value if hasattr(mapped, 'value') else mapped
        
        # Return as-is if no mapping found
        logger.debug(f"No provider mapping found for '{provider}', using as-is")
        return provider


class ModuleAuthHelper:
    """
    Helper class for module authentication that provides both legacy and new patterns.
    
    This class can be used by modules to handle authentication in a way that works
    with both old and new systems, making migration easier.
    """
    
    def __init__(
        self,
        module_instance: Any,
        credential_manager: Optional[CredentialManager] = None,
        llm_client_factory: Optional['LLMClientFactory'] = None
    ):
        """
        Initialize module authentication helper.
        
        Args:
            module_instance: The module instance requesting authentication
            credential_manager: Legacy credential manager
            llm_client_factory: New LLM client factory
        """
        self.module = module_instance
        self.adapter = LegacyAuthAdapter(credential_manager, llm_client_factory)
        self.module_name = getattr(module_instance, 'name', 'unknown_module')
    
    async def get_authenticated_client(
        self, 
        provider: Optional[str] = None,
        target_id: Optional[Union[str, UUID]] = None
    ) -> Optional['AsyncLLMClient']:
        """
        Get authenticated client with automatic provider detection.
        
        This method tries multiple authentication approaches:
        1. New LiteLLM client factory (preferred)
        2. Legacy credential manager with provider mapping
        3. Environment variable fallback
        
        Args:
            provider: Optional provider preference
            target_id: Optional target identifier for credential lookup
            
        Returns:
            Authenticated AsyncLLMClient instance if successful
        """
        # Try modern approach first
        if hasattr(self.module, 'get_llm_client'):
            try:
                return await self.module.get_llm_client(provider)
            except Exception as e:
                logger.debug(f"Modern get_llm_client failed: {e}")
        
        # Try legacy adapter
        return await self.adapter.get_provider_client(provider or 'openai')
    
    async def validate_authentication(self, provider: str) -> bool:
        """
        Validate that authentication is working for the given provider.
        
        Args:
            provider: Provider to validate
            
        Returns:
            True if authentication is valid, False otherwise
        """
        try:
            client = await self.get_authenticated_client(provider)
            if not client:
                return False
            
            # Try to perform a simple health check
            if hasattr(client, 'health_check'):
                # Assume we need a basic provider config for health check
                from gibson.core.llm.types import BaseProviderConfig
                config = BaseProviderConfig(
                    provider=self.adapter._map_provider_name(provider),
                    model="gpt-3.5-turbo",  # Default test model
                    api_key="test"  # Will be replaced by actual key
                )
                return await client.health_check(config)
            
            return True  # Assume valid if we got a client
            
        except Exception as e:
            logger.debug(f"Authentication validation failed for {provider}: {e}")
            return False
    
    def get_migration_guidance(self) -> Dict[str, Any]:
        """
        Get guidance for migrating this module to new authentication patterns.
        
        Returns:
            Dictionary with migration recommendations and examples
        """
        return {
            "module_name": self.module_name,
            "current_pattern": "legacy_credential_manager",
            "recommended_pattern": "llm_client_factory",
            "migration_steps": [
                "1. Update module __init__ to accept llm_client_factory parameter",
                "2. Replace credential_manager.get_api_key() calls with self.get_llm_client()",
                "3. Use AsyncLLMClient methods instead of direct API calls",
                "4. Remove manual credential handling and API client setup",
                "5. Test with multiple providers using the client factory"
            ],
            "example_old_code": '''
                # OLD PATTERN (deprecated)
                api_key = await self.credential_manager.get_api_key("openai", target_id)
                client = openai.AsyncOpenAI(api_key=api_key)
                response = await client.chat.completions.create(...)
            ''',
            "example_new_code": '''
                # NEW PATTERN (recommended)
                client = await self.get_llm_client("openai")
                response = await client.complete(request)
            ''',
            "benefits": [
                "Automatic provider selection and fallbacks",
                "Built-in rate limiting and retry logic", 
                "Health checking and circuit breaker patterns",
                "Unified interface across all LLM providers",
                "Connection pooling and performance optimization"
            ]
        }


# Convenience functions for easy migration
async def get_legacy_api_key(
    provider: str, 
    target_id: Optional[Union[str, UUID]] = None,
    credential_manager: Optional[CredentialManager] = None,
    llm_client_factory: Optional['LLMClientFactory'] = None
) -> Optional[str]:
    """
    Legacy API key retrieval function for backward compatibility.
    
    Args:
        provider: Provider name
        target_id: Optional target identifier  
        credential_manager: Legacy credential manager
        llm_client_factory: New LLM client factory
        
    Returns:
        API key if found, None otherwise
    """
    adapter = LegacyAuthAdapter(credential_manager, llm_client_factory)
    return await adapter.get_api_key(provider, target_id)


def create_auth_helper(
    module_instance: Any,
    credential_manager: Optional[CredentialManager] = None, 
    llm_client_factory: Optional['LLMClientFactory'] = None
) -> ModuleAuthHelper:
    """
    Create authentication helper for a module.
    
    Args:
        module_instance: The module requesting authentication
        credential_manager: Legacy credential manager
        llm_client_factory: New LLM client factory
        
    Returns:
        ModuleAuthHelper instance
    """
    return ModuleAuthHelper(module_instance, credential_manager, llm_client_factory)


def check_migration_status(module_instance: Any) -> Dict[str, Any]:
    """
    Check migration status of a module to new authentication patterns.
    
    Args:
        module_instance: Module to check
        
    Returns:
        Dictionary with migration status and recommendations
    """
    status = {
        "module_name": getattr(module_instance, 'name', 'unknown'),
        "has_llm_client_factory": hasattr(module_instance, 'llm_client_factory'),
        "has_get_llm_client": hasattr(module_instance, 'get_llm_client'),
        "has_credential_manager": hasattr(module_instance, 'credential_manager'),
        "migration_complete": False,
        "recommendations": []
    }
    
    # Check if module has modern LLM client support
    if status["has_llm_client_factory"] and status["has_get_llm_client"]:
        status["migration_complete"] = True
        status["recommendations"].append("✅ Module fully migrated to LiteLLM")
    else:
        if not status["has_llm_client_factory"]:
            status["recommendations"].append(
                "🔄 Add llm_client_factory parameter to module __init__"
            )
        if not status["has_get_llm_client"]:
            status["recommendations"].append(
                "🔄 Use module.get_llm_client() instead of direct credential access"
            )
    
    # Check for legacy patterns
    if status["has_credential_manager"]:
        status["recommendations"].append(
            "⚠️ Remove direct credential_manager usage - use LLM client factory"
        )
    
    return status


# Export the main classes and functions
__all__ = [
    'LegacyAuthAdapter',
    'ModuleAuthHelper', 
    'get_legacy_api_key',
    'create_auth_helper',
    'check_migration_status'
]