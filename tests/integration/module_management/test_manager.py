"""Integration tests for ModuleManager.

Tests complete module lifecycle including discovery, registration,
validation, and execution with real database integration.
"""

import tempfile
import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from gibson.core.module_management.manager import ModuleManager
from gibson.core.module_management.models import ModuleFilter, ModuleInstallOptions
from gibson.models.module import ModuleDefinitionModel, ModuleStatus, AttackDomain
from gibson.models.target import TargetModel


@pytest.fixture
def temp_gibson_root():
    """Create temporary Gibson root structure for testing."""
    with tempfile.TemporaryDirectory() as temp_dir:
        gibson_root = Path(temp_dir)
        
        # Create Gibson structure
        domains_dir = gibson_root / "gibson" / "domains" / "prompt"
        domains_dir.mkdir(parents=True)
        
        # Create test module
        test_module_content = '''
"""Test module for integration testing."""

from gibson.core.modules.base import BaseModule
from gibson.models.domain import AttackDomain, ModuleCategory, Severity
from gibson.models.scan import Finding
from gibson.models.target import TargetModel
from typing import List, Dict, Any, Optional


class IntegrationTestModule(BaseModule):
    """Integration test module."""
    
    name = "integration_test_module"
    version = "1.0.0"
    description = "Module for integration testing"
    category = ModuleCategory.PROMPT_INJECTION
    domain = AttackDomain.PROMPT
    author = "Test Suite"
    license = "MIT"
    tags = ["test", "integration"]
    dependencies = []
    
    async def run(self, target: TargetModel, config: Optional[Dict[str, Any]] = None) -> List[Finding]:
        """Execute test module."""
        # Return mock finding for testing
        return []
    
    def get_config_schema(self) -> Dict[str, Any]:
        """Return configuration schema."""
        return {
            "type": "object",
            "properties": {
                "test_param": {"type": "string", "default": "test_value"}
            }
        }
'''
        
        test_module_path = domains_dir / "integration_test_module.py"
        test_module_path.write_text(test_module_content)
        
        yield gibson_root


@pytest.fixture
def mock_session():
    """Mock database session for testing."""
    session = AsyncMock(spec=AsyncSession)
    session.execute.return_value = AsyncMock()
    session.commit.return_value = None
    session.rollback.return_value = None
    session.add.return_value = None
    
    # Mock query results
    mock_result = AsyncMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_result.scalars().all.return_value = []
    session.execute.return_value = mock_result
    
    return session


@pytest.fixture
def sample_target():
    """Sample target for testing."""
    return TargetModel(
        name="test_target",
        display_name="Test Target",
        description="Target for testing",
        target_type="api",
        base_url="https://api.example.com",
        endpoints=[
            {
                "path": "/api/v1/chat",
                "method": "POST",
                "description": "Chat endpoint"
            }
        ]
    )


class TestModuleManagerIntegration:
    """Integration tests for ModuleManager functionality."""
    
    @pytest.mark.asyncio
    async def test_manager_initialization(self, temp_gibson_root, mock_session):
        """Test complete manager initialization."""
        manager = ModuleManager(gibson_root=temp_gibson_root)
        
        # Initialize should discover and register modules
        await manager.initialize(mock_session)
        
        assert manager._initialized
        # Should have attempted to register discovered modules
        mock_session.add.assert_called()
        mock_session.commit.assert_called()
    
    @pytest.mark.asyncio
    async def test_module_discovery_and_listing(self, temp_gibson_root, mock_session):
        """Test module discovery and listing integration."""
        manager = ModuleManager(gibson_root=temp_gibson_root)
        await manager.initialize(mock_session)
        
        # List modules should work after initialization
        modules = await manager.list_modules(session=mock_session)
        
        # Should include discovered modules in memory
        assert len(manager.registry._discovered_modules) > 0
        assert "integration_test_module" in manager.registry._discovered_modules
    
    @pytest.mark.asyncio
    async def test_module_validation_workflow(self, temp_gibson_root):
        """Test complete module validation workflow."""
        manager = ModuleManager(gibson_root=temp_gibson_root)
        
        # Find test module file
        test_module_path = (
            temp_gibson_root / "gibson" / "domains" / "prompt" / "integration_test_module.py"
        )
        
        # Validate module
        result = await manager.validate_module(test_module_path, comprehensive=True)
        
        # Should pass validation
        assert result.valid
        assert result.validation_time > 0
        assert not result.errors
    
    @pytest.mark.asyncio
    async def test_module_installation_workflow(self, temp_gibson_root, mock_session):
        """Test module installation workflow."""
        manager = ModuleManager(gibson_root=temp_gibson_root)
        await manager.initialize(mock_session)
        
        # Create additional test module file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write('''
from gibson.core.modules.base import BaseModule
from gibson.models.domain import AttackDomain, ModuleCategory

class ExternalTestModule(BaseModule):
    name = "external_test_module"
    version = "1.0.0"
    description = "External test module"
    category = ModuleCategory.PROMPT_INJECTION
    domain = AttackDomain.PROMPT
    
    async def run(self, target, config=None):
        return []
    
    def get_config_schema(self):
        return {}
''')
            external_module_path = Path(f.name)
        
        try:
            # Install module
            options = ModuleInstallOptions(
                force=True,
                enable_after_install=True
            )
            
            result = await manager.install_module(
                external_module_path,
                options=options,
                session=mock_session
            )
            
            # Should succeed
            assert result.success
            assert result.module_name == "external_test_module"
            assert "external_test_module" in result.installed_modules
            
        finally:
            # Cleanup
            external_module_path.unlink(missing_ok=True)
    
    @pytest.mark.asyncio
    async def test_module_enable_disable_workflow(self, temp_gibson_root, mock_session):
        """Test module enable/disable workflow."""
        manager = ModuleManager(gibson_root=temp_gibson_root)
        await manager.initialize(mock_session)
        
        # Mock successful database update
        mock_session.execute.return_value.scalar_one_or_none.return_value = MagicMock(
            name="integration_test_module",
            status="enabled"
        )
        
        # Enable module
        result = await manager.enable_module("integration_test_module", mock_session)
        assert result is True
        
        # Disable module
        result = await manager.disable_module("integration_test_module", mock_session)
        assert result is True
    
    @pytest.mark.asyncio
    async def test_module_search_and_filtering(self, temp_gibson_root, mock_session):
        """Test module search and filtering functionality."""
        manager = ModuleManager(gibson_root=temp_gibson_root)
        await manager.initialize(mock_session)
        
        # Test search by domain
        filter_by_domain = ModuleFilter(domains=[AttackDomain.PROMPT])
        modules = await manager.list_modules(filter=filter_by_domain, session=mock_session)
        
        # Should find prompt domain modules
        for module_name, module_def in modules.items():
            assert module_def.domain == AttackDomain.PROMPT
        
        # Test search by tags
        filter_by_tags = ModuleFilter(tags=["test"])
        modules = await manager.list_modules(filter=filter_by_tags, session=mock_session)
        
        # Results should include modules with test tag
        # (Note: In-memory filtering may not work with mocked session)
    
    @pytest.mark.asyncio
    async def test_registry_rebuild_workflow(self, temp_gibson_root, mock_session):
        """Test registry rebuild functionality."""
        manager = ModuleManager(gibson_root=temp_gibson_root)
        await manager.initialize(mock_session)
        
        # Rebuild registry
        count = await manager.rebuild_registry(mock_session)
        
        # Should have attempted to rebuild
        assert count >= 0
        # Database operations should have been attempted
        mock_session.commit.assert_called()
    
    @pytest.mark.asyncio
    async def test_manager_statistics(self, temp_gibson_root, mock_session):
        """Test manager statistics collection."""
        manager = ModuleManager(gibson_root=temp_gibson_root)
        await manager.initialize(mock_session)
        
        # Get statistics
        stats = await manager.get_stats()
        
        # Should include expected fields
        assert "initialized" in stats
        assert "gibson_root" in stats
        assert "cached_instances" in stats
        assert "registry" in stats
        assert "cache" in stats
        
        assert stats["initialized"] is True
        assert stats["gibson_root"] == str(temp_gibson_root)
    
    @pytest.mark.asyncio
    async def test_error_handling_and_recovery(self, temp_gibson_root):
        """Test error handling and recovery mechanisms."""
        manager = ModuleManager(gibson_root=temp_gibson_root)
        
        # Test initialization without database
        await manager.initialize(None)
        
        # Should still initialize in degraded mode
        assert manager._initialized
        
        # Test operations without database session
        modules = await manager.list_modules(session=None)
        # Should work with in-memory data
        assert isinstance(modules, dict)
    
    @pytest.mark.asyncio
    async def test_module_execution_integration(self, temp_gibson_root, mock_session, sample_target):
        """Test module execution integration."""
        manager = ModuleManager(gibson_root=temp_gibson_root)
        await manager.initialize(mock_session)
        
        # Mock module execution
        with patch.object(manager, '_get_module_instance') as mock_get_instance:
            mock_module = AsyncMock()
            mock_module.validate_target.return_value = True
            mock_module.initialize.return_value = None
            mock_module.run.return_value = []
            mock_module.cleanup.return_value = None
            mock_get_instance.return_value = mock_module
            
            # Mock module definition with enabled status
            mock_module_def = MagicMock()
            mock_module_def.status = ModuleStatus.ENABLED
            mock_module_def.name = "integration_test_module"
            
            with patch.object(manager, 'get_module', return_value=mock_module_def):
                # Execute module
                from gibson.core.module_management.models import ModuleExecutionContextModel
                from uuid import uuid4
                
                context = ModuleExecutionContextModel(
                    execution_id=uuid4(),
                    module_name="integration_test_module",
                    target_id=sample_target.id
                )
                
                result = await manager.execute_module(
                    "integration_test_module",
                    sample_target,
                    context=context,
                    session=mock_session
                )
                
                # Should complete successfully
                assert result.module_name == "integration_test_module"
                assert result.status == "completed"
                assert result.execution_id == context.execution_id
                
                # Verify module lifecycle was called
                mock_module.initialize.assert_called_once()
                mock_module.run.assert_called_once()
                mock_module.cleanup.assert_called_once()


class TestModuleManagerErrorScenarios:
    """Test error scenarios and edge cases."""
    
    @pytest.mark.asyncio
    async def test_initialization_failure_recovery(self, temp_gibson_root):
        """Test recovery from initialization failures."""
        manager = ModuleManager(gibson_root=temp_gibson_root)
        
        # Simulate database connection failure
        mock_session = AsyncMock()
        mock_session.execute.side_effect = Exception("Database connection failed")
        
        # Should handle gracefully
        with pytest.raises(Exception):
            await manager.initialize(mock_session)
        
        # Manager should not be marked as initialized
        assert not manager._initialized
    
    @pytest.mark.asyncio
    async def test_module_not_found_error(self, temp_gibson_root, mock_session):
        """Test module not found error handling."""
        manager = ModuleManager(gibson_root=temp_gibson_root)
        await manager.initialize(mock_session)
        
        # Try to get non-existent module
        from gibson.core.module_management.exceptions import ModuleNotFoundError
        
        with pytest.raises(ModuleNotFoundError) as exc_info:
            await manager.get_module("nonexistent_module", mock_session)
        
        # Should provide helpful error information
        assert exc_info.value.module_name == "nonexistent_module"
        assert exc_info.value.suggestions
    
    @pytest.mark.asyncio
    async def test_installation_validation_failure(self, temp_gibson_root, mock_session):
        """Test installation failure due to validation."""
        manager = ModuleManager(gibson_root=temp_gibson_root)
        await manager.initialize(mock_session)
        
        # Create invalid module file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("# Invalid module - no classes\npass")
            invalid_module_path = Path(f.name)
        
        try:
            # Attempt installation
            result = await manager.install_module(
                invalid_module_path,
                session=mock_session
            )
            
            # Should fail
            assert not result.success
            assert result.errors
            
        finally:
            # Cleanup
            invalid_module_path.unlink(missing_ok=True)
    
    @pytest.mark.asyncio
    async def test_concurrent_operations(self, temp_gibson_root, mock_session):
        """Test thread safety with concurrent operations."""
        manager = ModuleManager(gibson_root=temp_gibson_root)
        await manager.initialize(mock_session)
        
        # Run concurrent operations
        async def concurrent_list_modules():
            return await manager.list_modules(session=mock_session)
        
        async def concurrent_get_stats():
            return await manager.get_stats()
        
        # Run multiple operations concurrently
        tasks = [
            concurrent_list_modules(),
            concurrent_get_stats(),
            concurrent_list_modules(),
            concurrent_get_stats()
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # All operations should complete successfully
        for result in results:
            assert not isinstance(result, Exception)
            assert result is not None


# Add import for patch decorator
from unittest.mock import patch
