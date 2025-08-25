"""Tests for TargetManager."""

import pytest
from unittest.mock import Mock, AsyncMock, patch
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from gibson.core.targets.manager import (
    TargetManager,
    TargetManagerError,
    TargetValidationError
)
from gibson.core.targets.repository import TargetAlreadyExistsError
from gibson.models.target import TargetModel, TargetType, TargetStatus, LLMProvider
from gibson.models.auth import ApiKeyFormat
from gibson.db.base import Base


@pytest.fixture
async def async_session():
    """Create async test database session."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    async_session = sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    
    async with async_session() as session:
        yield session
    
    await engine.dispose()


@pytest.fixture
def mock_credential_manager():
    """Create mock credential manager."""
    mock = Mock()
    mock.store_credential = Mock(return_value=True)
    mock.delete_credential = Mock(return_value=True)
    mock.retrieve_credential = Mock(return_value=None)
    return mock


@pytest.fixture
def mock_litellm_adapter():
    """Create mock LiteLLM adapter."""
    mock = Mock()
    mock.auto_detect_provider = Mock(return_value=LLMProvider.OPENAI)
    mock.get_provider_config = Mock(return_value={"model": "gpt-3.5-turbo"})
    mock.validate_provider_config = Mock(return_value=(True, []))
    return mock


@pytest.fixture
def target_manager(async_session, mock_credential_manager, mock_litellm_adapter):
    """Create TargetManager instance."""
    return TargetManager(
        session=async_session,
        credential_manager=mock_credential_manager,
        litellm_adapter=mock_litellm_adapter
    )


class TestTargetManager:
    """Test cases for TargetManager."""
    
    @pytest.mark.asyncio
    async def test_create_target_basic(self, target_manager, mock_litellm_adapter):
        """Test creating a basic target."""
        target = await target_manager.create_target(
            name="test-api",
            base_url="https://api.test.com",
            target_type=TargetType.API,
            description="Test API"
        )
        
        assert target.name == "test-api"
        assert target.base_url == "https://api.test.com"
        assert target.target_type == TargetType.API
        assert target.description == "Test API"
        assert target.provider == LLMProvider.OPENAI  # Auto-detected
        assert target.status == TargetStatus.PENDING_VERIFICATION
    
    @pytest.mark.asyncio
    async def test_create_target_with_api_key(self, target_manager, mock_credential_manager):
        """Test creating target with API key."""
        target = await target_manager.create_target(
            name="openai-api",
            base_url="https://api.openai.com/v1",
            api_key="sk-test123",
            key_format=ApiKeyFormat.BEARER_TOKEN
        )
        
        assert target.requires_auth is True
        mock_credential_manager.store_credential.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_create_target_duplicate_name_raises_error(self, target_manager):
        """Test that creating target with duplicate name raises error."""
        # Create first target
        await target_manager.create_target(
            name="duplicate",
            base_url="https://api.test.com"
        )
        
        # Try to create second with same name
        with pytest.raises(TargetAlreadyExistsError):
            await target_manager.create_target(
                name="duplicate",
                base_url="https://api.other.com"
            )
    
    @pytest.mark.asyncio
    async def test_get_target_by_id(self, target_manager):
        """Test getting target by ID."""
        created = await target_manager.create_target(
            name="test-get",
            base_url="https://api.test.com"
        )
        
        retrieved = await target_manager.get_target(created.id)
        assert retrieved is not None
        assert retrieved.id == created.id
    
    @pytest.mark.asyncio
    async def test_get_target_by_name(self, target_manager):
        """Test getting target by name."""
        created = await target_manager.create_target(
            name="test-get-name",
            base_url="https://api.test.com"
        )
        
        retrieved = await target_manager.get_target("test-get-name")
        assert retrieved is not None
        assert retrieved.name == "test-get-name"
    
    @pytest.mark.asyncio
    async def test_update_target(self, target_manager):
        """Test updating target."""
        created = await target_manager.create_target(
            name="test-update",
            base_url="https://api.test.com"
        )
        
        updated = await target_manager.update_target(
            created,
            description="Updated description",
            status=TargetStatus.ACTIVE
        )
        
        assert updated.description == "Updated description"
        assert updated.status == TargetStatus.ACTIVE
    
    @pytest.mark.asyncio
    async def test_delete_target(self, target_manager, mock_credential_manager):
        """Test deleting target."""
        created = await target_manager.create_target(
            name="test-delete",
            base_url="https://api.test.com"
        )
        
        success = await target_manager.delete_target(created.id)
        assert success is True
        
        # Verify target is deleted
        retrieved = await target_manager.get_target(created.id)
        assert retrieved is None
        
        # Verify credentials are deleted
        mock_credential_manager.delete_credential.assert_called_once_with(created.id)
    
    @pytest.mark.asyncio
    async def test_list_targets(self, target_manager):
        """Test listing targets with filters."""
        # Create test targets
        for i in range(3):
            await target_manager.create_target(
                name=f"list-test-{i}",
                base_url=f"https://api{i}.test.com",
                environment="production" if i % 2 == 0 else "development"
            )
        
        # List all targets
        all_targets = await target_manager.list_targets()
        assert len(all_targets) >= 3
        
        # List with environment filter
        prod_targets = await target_manager.list_targets(environment="production")
        assert len(prod_targets) >= 2
        
        # List with limit
        limited = await target_manager.list_targets(limit=2)
        assert len(limited) == 2
    
    @pytest.mark.asyncio
    async def test_search_targets(self, target_manager):
        """Test searching targets."""
        await target_manager.create_target(
            name="search-test",
            base_url="https://api.search.com",
            description="Searchable target"
        )
        
        # Search by name
        results = await target_manager.search_targets("search-test")
        assert len(results) == 1
        
        # Search by description
        results = await target_manager.search_targets("Searchable")
        assert len(results) == 1
    
    @pytest.mark.asyncio
    async def test_validate_target(self, target_manager, mock_litellm_adapter):
        """Test target validation."""
        # Mock validation to return success
        mock_litellm_adapter.validate_provider_config.return_value = (True, [])
        
        created = await target_manager.create_target(
            name="validate-test",
            base_url="https://api.test.com"
        )
        
        with patch('gibson.core.targets.manager.aiohttp.ClientSession') as mock_session:
            # Mock successful HTTP response
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.headers = {}
            
            mock_session.return_value.__aenter__.return_value.head.return_value.__aenter__.return_value = mock_response
            
            result = await target_manager.validate_target(
                created.id,
                test_connection=True,
                validate_credentials=False
            )
            
            assert result['overall_valid'] is True
            assert result['config_valid'] is True
            assert result['connectivity_valid'] is True
    
    @pytest.mark.asyncio
    async def test_set_target_credential(self, target_manager, mock_credential_manager):
        """Test setting target credential."""
        created = await target_manager.create_target(
            name="cred-test",
            base_url="https://api.test.com"
        )
        
        success = await target_manager.set_target_credential(
            created.id,
            api_key="sk-test123",
            key_format=ApiKeyFormat.BEARER_TOKEN
        )
        
        assert success is True
        mock_credential_manager.store_credential.assert_called()
    
    @pytest.mark.asyncio
    async def test_remove_target_credential(self, target_manager, mock_credential_manager):
        """Test removing target credential."""
        created = await target_manager.create_target(
            name="cred-remove-test",
            base_url="https://api.test.com"
        )
        
        success = await target_manager.remove_target_credential(created.id)
        
        assert success is True
        mock_credential_manager.delete_credential.assert_called_once_with(created.id)
    
    @pytest.mark.asyncio
    async def test_export_targets(self, target_manager, tmp_path):
        """Test exporting targets to JSON."""
        # Create test targets
        for i in range(2):
            await target_manager.create_target(
                name=f"export-test-{i}",
                base_url=f"https://api{i}.test.com"
            )
        
        export_file = tmp_path / "targets.json"
        count = await target_manager.export_targets(export_file)
        
        assert count >= 2
        assert export_file.exists()
    
    @pytest.mark.asyncio
    async def test_import_targets(self, target_manager, tmp_path):
        """Test importing targets from JSON."""
        import json
        
        # Create test import file
        import_data = {
            "export_timestamp": "2024-01-01T00:00:00",
            "gibson_version": "1.0.0",
            "targets": [
                {
                    "id": str(uuid4()),
                    "name": "import-test-1",
                    "display_name": "Import Test 1",
                    "target_type": "api",
                    "base_url": "https://api.import1.com",
                    "status": "active",
                    "enabled": True,
                    "provider": "openai",
                    "requires_auth": False,
                    "endpoints": [],
                    "tags": ["import"],
                    "environment": "test",
                    "priority": 3,
                    "compliance_requirements": [],
                    "requires_approval": False,
                    "scan_count": 0,
                    "finding_count": 0,
                    "metadata": {}
                }
            ]
        }
        
        import_file = tmp_path / "import.json"
        with open(import_file, 'w') as f:
            json.dump(import_data, f)
        
        stats = await target_manager.import_targets(import_file)
        
        assert stats["total"] == 1
        assert stats["created"] == 1
        assert stats["errors"] == 0
    
    @pytest.mark.asyncio
    async def test_get_statistics(self, target_manager):
        """Test getting target statistics."""
        # Create test targets
        for i in range(3):
            await target_manager.create_target(
                name=f"stats-test-{i}",
                base_url=f"https://api{i}.test.com"
            )
        
        stats = await target_manager.get_statistics()
        
        assert "total_targets" in stats
        assert stats["total_targets"] >= 3