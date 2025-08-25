"""
Unit tests for the LiteLLM module adapter.

Tests backward compatibility, deprecation warnings, and migration functionality.
"""

import asyncio
import pytest
import warnings
from unittest.mock import Mock, AsyncMock, patch
from uuid import uuid4

from gibson.core.llm.module_adapter import (
    LegacyAuthAdapter,
    ModuleAuthHelper,
    get_legacy_api_key,
    create_auth_helper,
    check_migration_status
)


class TestLegacyAuthAdapter:
    """Test the legacy authentication adapter."""
    
    @pytest.fixture
    def mock_credential_manager(self):
        """Create mock credential manager."""
        manager = Mock()
        manager.retrieve_credential = AsyncMock()
        return manager
    
    @pytest.fixture
    def mock_llm_client_factory(self):
        """Create mock LLM client factory."""
        factory = Mock()
        factory.get_client = AsyncMock()
        return factory
    
    @pytest.fixture
    def adapter(self, mock_credential_manager, mock_llm_client_factory):
        """Create adapter with mocked dependencies."""
        return LegacyAuthAdapter(mock_credential_manager, mock_llm_client_factory)
    
    def test_provider_mapping(self, adapter):
        """Test provider name mapping."""
        # Test direct mappings
        assert adapter._map_provider_name("openai") == "openai"
        assert adapter._map_provider_name("anthropic") == "anthropic"
        
        # Test legacy mappings
        assert adapter._map_provider_name("claude") == "anthropic"
        assert adapter._map_provider_name("gpt") == "openai"
        
        # Test case insensitive
        assert adapter._map_provider_name("OPENAI") == "openai"
        assert adapter._map_provider_name("Claude") == "anthropic"
        
        # Test unknown provider
        assert adapter._map_provider_name("unknown") == "unknown"
    
    def test_deprecation_warning(self, adapter):
        """Test deprecation warning functionality."""
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            
            adapter.deprecated_auth_warning("test_method", "new_method")
            
            assert len(w) == 1
            assert issubclass(w[0].category, DeprecationWarning)
            assert "test_method() is deprecated" in str(w[0].message)
            assert "new_method" in str(w[0].message)
            
            # Should only warn once
            adapter.deprecated_auth_warning("test_method", "new_method")
            assert len(w) == 1  # No additional warning
    
    @pytest.mark.asyncio
    async def test_get_api_key_llm_factory(self, adapter, mock_llm_client_factory):
        """Test API key retrieval via LLM client factory."""
        # Setup mock client with provider config
        mock_client = Mock()
        mock_client.provider_config = Mock()
        mock_client.provider_config.api_key = "test-api-key"
        mock_llm_client_factory.get_client.return_value = mock_client
        
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            api_key = await adapter.get_api_key("openai")
            
            assert api_key == "test-api-key"
            mock_llm_client_factory.get_client.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_api_key_credential_manager_fallback(self, adapter, mock_credential_manager):
        """Test API key retrieval fallback to credential manager."""
        # Setup LLM factory to fail
        adapter.llm_client_factory = None
        
        # Setup credential manager mock
        mock_credential = Mock()
        mock_credential.token = "fallback-api-key"
        mock_credential_manager.retrieve_credential.return_value = mock_credential
        
        target_id = uuid4()
        
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            api_key = await adapter.get_api_key("openai", target_id)
            
            assert api_key == "fallback-api-key"
            mock_credential_manager.retrieve_credential.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_provider_client(self, adapter, mock_llm_client_factory):
        """Test provider client retrieval."""
        mock_client = Mock()
        mock_llm_client_factory.get_client.return_value = mock_client
        
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            client = await adapter.get_provider_client("openai")
            
            assert client == mock_client
            mock_llm_client_factory.get_client.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_provider_client_no_factory(self, mock_credential_manager):
        """Test provider client retrieval without LLM factory."""
        adapter = LegacyAuthAdapter(mock_credential_manager, None)
        
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            client = await adapter.get_provider_client("openai")
            
            assert client is None


class TestModuleAuthHelper:
    """Test the module authentication helper."""
    
    @pytest.fixture
    def mock_module(self):
        """Create mock module instance."""
        module = Mock()
        module.name = "test_module"
        module.get_llm_client = AsyncMock()
        return module
    
    @pytest.fixture
    def auth_helper(self, mock_module):
        """Create auth helper with mock module."""
        return ModuleAuthHelper(mock_module, None, None)
    
    @pytest.mark.asyncio
    async def test_get_authenticated_client_modern(self, auth_helper, mock_module):
        """Test authenticated client retrieval using modern pattern."""
        mock_client = Mock()
        mock_module.get_llm_client.return_value = mock_client
        
        client = await auth_helper.get_authenticated_client("openai")
        
        assert client == mock_client
        mock_module.get_llm_client.assert_called_once_with("openai")
    
    @pytest.mark.asyncio
    async def test_get_authenticated_client_legacy_fallback(self, mock_module):
        """Test authenticated client retrieval fallback to legacy adapter."""
        # Remove modern method
        delattr(mock_module, 'get_llm_client')
        
        mock_llm_factory = Mock()
        mock_client = Mock()
        mock_llm_factory.get_client = AsyncMock(return_value=mock_client)
        
        auth_helper = ModuleAuthHelper(mock_module, None, mock_llm_factory)
        
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            client = await auth_helper.get_authenticated_client("openai")
            
            assert client == mock_client
    
    @pytest.mark.asyncio
    async def test_validate_authentication(self, auth_helper, mock_module):
        """Test authentication validation."""
        mock_client = Mock()
        mock_client.health_check = AsyncMock(return_value=True)
        mock_module.get_llm_client.return_value = mock_client
        
        is_valid = await auth_helper.validate_authentication("openai")
        
        assert is_valid is True
    
    def test_get_migration_guidance(self, auth_helper):
        """Test migration guidance generation."""
        guidance = auth_helper.get_migration_guidance()
        
        assert guidance["module_name"] == "test_module"
        assert guidance["current_pattern"] == "legacy_credential_manager"
        assert guidance["recommended_pattern"] == "llm_client_factory"
        assert len(guidance["migration_steps"]) > 0
        assert len(guidance["benefits"]) > 0


class TestUtilityFunctions:
    """Test utility functions."""
    
    @pytest.mark.asyncio
    async def test_get_legacy_api_key(self):
        """Test legacy API key retrieval function."""
        mock_factory = Mock()
        mock_client = Mock()
        mock_client.provider_config = Mock()
        mock_client.provider_config.api_key = "test-key"
        mock_factory.get_client = AsyncMock(return_value=mock_client)
        
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            api_key = await get_legacy_api_key(
                "openai", 
                llm_client_factory=mock_factory
            )
            
            assert api_key == "test-key"
    
    def test_create_auth_helper(self):
        """Test auth helper creation function."""
        mock_module = Mock()
        mock_module.name = "test"
        
        helper = create_auth_helper(mock_module)
        
        assert isinstance(helper, ModuleAuthHelper)
        assert helper.module == mock_module
    
    def test_check_migration_status_modern(self):
        """Test migration status check for modern module."""
        mock_module = Mock()
        mock_module.name = "modern_module"
        mock_module.llm_client_factory = Mock()
        mock_module.get_llm_client = Mock()
        
        status = check_migration_status(mock_module)
        
        assert status["migration_complete"] is True
        assert status["has_llm_client_factory"] is True
        assert status["has_get_llm_client"] is True
        assert "✅ Module fully migrated" in status["recommendations"][0]
    
    def test_check_migration_status_legacy(self):
        """Test migration status check for legacy module."""
        mock_module = Mock()
        mock_module.name = "legacy_module"
        mock_module.credential_manager = Mock()
        # Remove modern attributes
        if hasattr(mock_module, 'llm_client_factory'):
            delattr(mock_module, 'llm_client_factory')
        if hasattr(mock_module, 'get_llm_client'):
            delattr(mock_module, 'get_llm_client')
        
        status = check_migration_status(mock_module)
        
        assert status["migration_complete"] is False
        assert status["has_llm_client_factory"] is False
        assert status["has_get_llm_client"] is False
        assert status["has_credential_manager"] is True
        assert len(status["recommendations"]) >= 3  # Should have multiple recommendations


class TestIntegration:
    """Integration tests for the adapter system."""
    
    def test_adapter_without_litellm(self):
        """Test adapter behavior when LiteLLM is not available."""
        # This test would need to mock the LiteLLM import
        with patch('gibson.core.llm.module_adapter.LLM_AVAILABLE', False):
            adapter = LegacyAuthAdapter()
            
            # Should handle gracefully without LiteLLM
            assert adapter.PROVIDER_MAPPING['openai'] == 'openai'
            assert adapter._map_provider_name('openai') == 'openai'
    
    @pytest.mark.asyncio
    async def test_full_authentication_flow(self):
        """Test complete authentication flow from module to client."""
        # Create a mock module that simulates the full flow
        mock_module = Mock()
        mock_module.name = "integration_test_module"
        
        # Create mock LLM factory
        mock_factory = Mock()
        mock_client = Mock()
        mock_client.provider_config = Mock()
        mock_client.provider_config.api_key = "integration-test-key"
        mock_factory.get_client = AsyncMock(return_value=mock_client)
        
        # Create auth helper
        helper = ModuleAuthHelper(mock_module, None, mock_factory)
        
        # Test the flow
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            client = await helper.get_authenticated_client("openai")
            
            assert client == mock_client
            mock_factory.get_client.assert_called_once()


# Fixtures for pytest
@pytest.fixture
def event_loop():
    """Create an event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


if __name__ == "__main__":
    pytest.main([__file__])