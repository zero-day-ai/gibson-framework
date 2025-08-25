"""Unit tests for ModuleRegistry implementation.

Tests module discovery, registration, search functionality,
and database integration with mocked dependencies.
"""

import asyncio
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4
from datetime import datetime

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from gibson.core.module_management.registry import ModuleRegistry
from gibson.core.module_management.cache import ModuleCache
from gibson.core.module_management.exceptions import (
    ModuleManagementError,
    ModuleNotFoundError,
    ModuleRegistryError,
)
from gibson.models.module import (
    ModuleDefinitionModel,
    ModuleStatus,
    AttackDomain,
    ModuleCategory,
)
from gibson.models.database import ModuleRecord
from gibson.models.domain import Severity


@pytest.fixture
def mock_cache():
    """Mock cache for testing."""
    cache = MagicMock(spec=ModuleCache)
    cache.get.return_value = None
    cache.set.return_value = None
    cache.invalidate.return_value = None
    cache.clear.return_value = 0
    cache._max_size = 1000
    return cache


@pytest.fixture
def sample_module_definition():
    """Sample module definition for testing."""
    return ModuleDefinitionModel(
        name="test_module",
        version="1.0.0",
        display_name="Test Module",
        description="A test security module",
        author="Test Author",
        license="Apache-2.0",
        domain=AttackDomain.PROMPT,
        category=ModuleCategory.PROMPT_INJECTION,
        severity=Severity.MEDIUM,
        owasp_categories=[],
        tags=["testing", "security"],
        dependencies=["requests>=2.28.0"],
        status=ModuleStatus.INSTALLED,
    )


@pytest.fixture
def sample_module_record():
    """Sample database record for testing."""
    return ModuleRecord(
        id=uuid4(),
        name="test_module",
        version="1.0.0",
        display_name="Test Module",
        description="A test security module",
        author="Test Author",
        license="Apache-2.0",
        domain="prompt",
        category="prompt_injection",
        severity="medium",
        owasp_categories=[],
        tags=["testing", "security"],
        dependencies=["requests>=2.28.0"],
        status="installed",
        installation_date=datetime.utcnow(),
        last_updated=datetime.utcnow(),
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )


@pytest.fixture
def mock_session():
    """Mock async database session."""
    session = AsyncMock(spec=AsyncSession)
    session.execute.return_value = AsyncMock()
    session.commit.return_value = None
    session.rollback.return_value = None
    return session


@pytest.fixture
def temp_module_file():
    """Create a temporary module file for testing."""
    module_content = '''
"""Test module for registry testing."""

from gibson.core.modules.base import BaseModule
from gibson.models.domain import AttackDomain, ModuleCategory, Severity
from gibson.models.scan import Finding
from gibson.models.target import TargetModel
from typing import List, Dict, Any, Optional


class TestSecurityModule(BaseModule):
    """Test security module for registry testing."""
    
    name = "test_security_module"
    version = "1.2.0"
    description = "Test module for security testing"
    category = ModuleCategory.PROMPT_INJECTION
    domain = AttackDomain.PROMPT
    severity = Severity.HIGH
    author = "Test Developer"
    tags = ["test", "security", "prompt"]
    dependencies = ["httpx>=0.24.0"]
    
    async def run(self, target: TargetModel, config: Optional[Dict[str, Any]] = None) -> List[Finding]:
        return []
    
    def get_config_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "timeout": {"type": "integer", "default": 30}
            }
        }
'''

    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(module_content)
        f.flush()
        yield Path(f.name)

    # Cleanup
    Path(f.name).unlink(missing_ok=True)


class TestModuleRegistry:
    """Test ModuleRegistry functionality."""

    def test_registry_initialization(self, mock_cache):
        """Test registry initialization."""
        registry = ModuleRegistry(cache=mock_cache)

        assert registry.cache is mock_cache
        assert registry.discovery_paths == []
        assert registry._discovered_modules == {}
        assert not registry._discovery_completed

    def test_registry_initialization_with_paths(self):
        """Test registry with custom discovery paths."""
        paths = [Path("/custom/path1"), Path("/custom/path2")]
        registry = ModuleRegistry(discovery_paths=paths)

        assert registry.discovery_paths == paths
        assert isinstance(registry.cache, ModuleCache)

    @pytest.mark.asyncio
    async def test_discover_modules_cached_results(self, mock_cache):
        """Test discovery returns cached results when completed."""
        registry = ModuleRegistry(cache=mock_cache)
        registry._discovery_completed = True
        registry._discovered_modules = {"test": MagicMock()}

        results = await registry.discover_modules()

        assert len(results) == 1
        # Should not attempt new discovery

    @pytest.mark.asyncio
    async def test_discover_modules_force_refresh(self, mock_cache):
        """Test force refresh bypasses cached results."""
        registry = ModuleRegistry(cache=mock_cache)
        registry._discovery_completed = True
        registry._discovered_modules = {"old": MagicMock()}

        with patch.object(registry, "_discover_builtin_modules", return_value=[]):
            results = await registry.discover_modules(force_refresh=True)

        assert results == []
        assert registry._discovery_completed  # Should be completed again

    @pytest.mark.asyncio
    async def test_discover_builtin_modules(self, mock_cache, temp_module_file):
        """Test discovery of built-in modules."""
        registry = ModuleRegistry(cache=mock_cache)

        # Create temporary Gibson structure
        with tempfile.TemporaryDirectory() as temp_dir:
            gibson_root = Path(temp_dir)
            domains_dir = gibson_root / "gibson" / "domains" / "prompt"
            domains_dir.mkdir(parents=True)

            # Copy test module to domains directory
            test_module_path = domains_dir / "test_module.py"
            test_module_path.write_text(temp_module_file.read_text())

            with patch.object(registry, "_load_module_from_file") as mock_load:
                mock_module = MagicMock(spec=ModuleDefinitionModel)
                mock_module.name = "test_module"
                mock_load.return_value = mock_module

                results = await registry._discover_builtin_modules(gibson_root)

                assert len(results) > 0
                mock_load.assert_called()

    @pytest.mark.asyncio
    async def test_load_module_from_file(self, mock_cache, temp_module_file):
        """Test loading module from Python file."""
        registry = ModuleRegistry(cache=mock_cache)

        module_def = await registry._load_module_from_file(
            temp_module_file, default_domain="prompt"
        )

        assert module_def is not None
        assert module_def.name == "test_security_module"
        assert module_def.version == "1.2.0"
        assert module_def.domain == AttackDomain.PROMPT
        assert module_def.category == ModuleCategory.PROMPT_INJECTION
        assert module_def.severity == Severity.HIGH
        assert "test" in module_def.tags
        assert "httpx>=0.24.0" in module_def.dependencies

    @pytest.mark.asyncio
    async def test_load_module_invalid_file(self, mock_cache):
        """Test loading from invalid/non-existent file."""
        registry = ModuleRegistry(cache=mock_cache)

        # Test with non-existent file
        result = await registry._load_module_from_file(Path("/nonexistent.py"))
        assert result is None

        # Test with file without BaseModule subclasses
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py") as f:
            f.write("# Empty module\npass")
            f.flush()

            result = await registry._load_module_from_file(Path(f.name))
            assert result is None

    @pytest.mark.asyncio
    async def test_register_module_new(self, mock_cache, mock_session, sample_module_definition):
        """Test registering new module."""
        registry = ModuleRegistry(cache=mock_cache)

        # Mock database query to return no existing module
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result

        await registry.register_module(sample_module_definition, mock_session)

        # Verify database operations
        mock_session.execute.assert_called_once()
        mock_session.add.assert_called_once()
        mock_session.commit.assert_called_once()

        # Verify cache update
        mock_cache.set.assert_called_once()

        # Verify internal state
        assert sample_module_definition.name in registry._discovered_modules

    @pytest.mark.asyncio
    async def test_register_module_existing_no_overwrite(
        self, mock_cache, mock_session, sample_module_definition, sample_module_record
    ):
        """Test registering existing module without overwrite."""
        registry = ModuleRegistry(cache=mock_cache)

        # Mock database query to return existing module
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = sample_module_record
        mock_session.execute.return_value = mock_result

        await registry.register_module(sample_module_definition, mock_session, overwrite=False)

        # Should not add or commit
        mock_session.add.assert_not_called()
        mock_session.commit.assert_not_called()

    @pytest.mark.asyncio
    async def test_register_module_existing_with_overwrite(
        self, mock_cache, mock_session, sample_module_definition, sample_module_record
    ):
        """Test registering existing module with overwrite."""
        registry = ModuleRegistry(cache=mock_cache)

        # Mock database query to return existing module
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = sample_module_record
        mock_session.execute.return_value = mock_result

        await registry.register_module(sample_module_definition, mock_session, overwrite=True)

        # Should update existing record
        assert sample_module_record.version == sample_module_definition.version
        assert sample_module_record.description == sample_module_definition.description
        mock_session.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_register_module_database_error(
        self, mock_cache, mock_session, sample_module_definition
    ):
        """Test handling database errors during registration."""
        registry = ModuleRegistry(cache=mock_cache)

        # Mock database error
        mock_session.execute.side_effect = Exception("Database error")

        with pytest.raises(ModuleManagementError):
            await registry.register_module(sample_module_definition, mock_session)

        # Should rollback transaction
        mock_session.rollback.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_module_from_cache(self, mock_cache, sample_module_definition):
        """Test getting module from cache."""
        registry = ModuleRegistry(cache=mock_cache)
        mock_cache.get.return_value = sample_module_definition

        result = await registry.get_module("test_module")

        assert result == sample_module_definition
        mock_cache.get.assert_called_with("module:test_module")

    @pytest.mark.asyncio
    async def test_get_module_from_database(self, mock_cache, mock_session, sample_module_record):
        """Test getting module from database when not in cache."""
        registry = ModuleRegistry(cache=mock_cache)
        mock_cache.get.return_value = None  # Cache miss

        # Mock database query
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = sample_module_record
        mock_session.execute.return_value = mock_result

        with patch.object(registry, "_record_to_model") as mock_convert:
            mock_module = MagicMock(spec=ModuleDefinitionModel)
            mock_convert.return_value = mock_module

            result = await registry.get_module("test_module", session=mock_session)

            assert result == mock_module
            mock_cache.set.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_module_from_discovered(self, mock_cache, sample_module_definition):
        """Test getting module from discovered modules."""
        registry = ModuleRegistry(cache=mock_cache)
        mock_cache.get.return_value = None  # Cache miss
        registry._discovered_modules["test_module"] = sample_module_definition

        result = await registry.get_module("test_module")

        assert result == sample_module_definition
        mock_cache.set.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_module_not_found(self, mock_cache):
        """Test getting non-existent module."""
        registry = ModuleRegistry(cache=mock_cache)
        mock_cache.get.return_value = None

        result = await registry.get_module("nonexistent")

        assert result is None

    @pytest.mark.asyncio
    async def test_search_modules_from_cache(self, mock_cache):
        """Test search with cached results."""
        registry = ModuleRegistry(cache=mock_cache)
        mock_results = [MagicMock(spec=ModuleDefinitionModel)]
        mock_cache.get.return_value = mock_results

        results = await registry.search_modules(query="test")

        assert results == mock_results
        # Should use cache key with search parameters
        mock_cache.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_search_modules_database(self, mock_cache, mock_session, sample_module_record):
        """Test search using database query."""
        registry = ModuleRegistry(cache=mock_cache)
        mock_cache.get.return_value = None  # Cache miss

        # Mock database query
        mock_result = AsyncMock()
        mock_result.scalars().all.return_value = [sample_module_record]
        mock_session.execute.return_value = mock_result

        with patch.object(registry, "_record_to_model") as mock_convert:
            mock_module = MagicMock(spec=ModuleDefinitionModel)
            mock_module.tags = ["test"]
            mock_convert.return_value = mock_module

            results = await registry.search_modules(
                query="test", domain=AttackDomain.PROMPT, session=mock_session
            )

            assert len(results) == 1
            mock_cache.set.assert_called_once()

    def test_search_in_memory(self, mock_cache, sample_module_definition):
        """Test in-memory search functionality."""
        registry = ModuleRegistry(cache=mock_cache)
        registry._discovered_modules = {
            "test_module": sample_module_definition,
            "other_module": MagicMock(
                spec=ModuleDefinitionModel,
                name="other_module",
                domain=AttackDomain.DATA,
                tags=["data"],
                description="Other module",
                display_name="Other Module",
            ),
        }

        # Test domain filter
        results = registry._search_in_memory(domain=AttackDomain.PROMPT)
        assert len(results) == 1
        assert results[0].name == "test_module"

        # Test query search
        results = registry._search_in_memory(query="test")
        assert len(results) == 1
        assert results[0].name == "test_module"

        # Test tag search
        results = registry._search_in_memory(tags=["testing"])
        assert len(results) == 1
        assert results[0].name == "test_module"

        # Test limit
        results = registry._search_in_memory(limit=0)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_update_status(self, mock_cache, mock_session, sample_module_record):
        """Test updating module status."""
        registry = ModuleRegistry(cache=mock_cache)

        # Mock database query
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = sample_module_record
        mock_session.execute.return_value = mock_result

        result = await registry.update_status("test_module", ModuleStatus.DISABLED, mock_session)

        assert result is True
        assert sample_module_record.status == ModuleStatus.DISABLED.value
        mock_session.commit.assert_called_once()

        # Verify cache invalidation
        mock_cache.invalidate.assert_any_call("module:test_module")
        mock_cache.invalidate_pattern.assert_called_with("search:*")

    @pytest.mark.asyncio
    async def test_update_status_not_found(self, mock_cache, mock_session):
        """Test updating status of non-existent module."""
        registry = ModuleRegistry(cache=mock_cache)

        # Mock database query returning None
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result

        result = await registry.update_status("nonexistent", ModuleStatus.DISABLED, mock_session)

        assert result is False
        mock_session.commit.assert_not_called()

    @pytest.mark.asyncio
    async def test_update_status_database_error(self, mock_cache, mock_session):
        """Test handling database errors during status update."""
        registry = ModuleRegistry(cache=mock_cache)
        mock_session.execute.side_effect = Exception("Database error")

        with pytest.raises(ModuleManagementError):
            await registry.update_status("test_module", ModuleStatus.DISABLED, mock_session)

        mock_session.rollback.assert_called_once()

    @pytest.mark.asyncio
    async def test_rebuild_registry(self, mock_cache, mock_session, sample_module_definition):
        """Test registry rebuild functionality."""
        registry = ModuleRegistry(cache=mock_cache)
        mock_cache.clear.return_value = 5  # 5 entries cleared

        with patch.object(registry, "discover_modules") as mock_discover:
            mock_discover.return_value = [sample_module_definition]

            with patch.object(registry, "register_module") as mock_register:
                mock_register.return_value = None

                count = await registry.rebuild_registry(mock_session)

                assert count == 1
                mock_cache.clear.assert_called_once()
                mock_discover.assert_called_with(force_refresh=True, gibson_root=None)
                mock_register.assert_called_once_with(
                    sample_module_definition, mock_session, overwrite=True
                )

    @pytest.mark.asyncio
    async def test_rebuild_registry_error(self, mock_cache, mock_session):
        """Test rebuild registry error handling."""
        registry = ModuleRegistry(cache=mock_cache)

        with patch.object(registry, "discover_modules") as mock_discover:
            mock_discover.side_effect = Exception("Discovery failed")

            with pytest.raises(ModuleRegistryError):
                await registry.rebuild_registry(mock_session)

    def test_get_stats(self, mock_cache, sample_module_definition):
        """Test registry statistics."""
        registry = ModuleRegistry(cache=mock_cache)
        registry._discovery_completed = True
        registry._discovered_modules = {
            "module1": sample_module_definition,
            "module2": MagicMock(
                spec=ModuleDefinitionModel, domain=AttackDomain.DATA, status=ModuleStatus.DISABLED
            ),
        }

        # Mock cache stats
        mock_cache_stats = MagicMock()
        mock_cache_stats.to_dict.return_value = {"hits": 10, "misses": 2}
        mock_cache.get_stats.return_value = mock_cache_stats

        stats = registry.get_stats()

        assert stats["total_modules"] == 2
        assert stats["discovery_completed"] is True
        assert stats["domain_distribution"]["prompt"] == 1
        assert stats["domain_distribution"]["data"] == 1
        assert stats["status_distribution"]["installed"] == 1
        assert stats["status_distribution"]["disabled"] == 1
        assert stats["cache_stats"]["hits"] == 10

    @pytest.mark.asyncio
    async def test_record_to_model_conversion(self, mock_cache, sample_module_record):
        """Test database record to Pydantic model conversion."""
        registry = ModuleRegistry(cache=mock_cache)

        model = await registry._record_to_model(sample_module_record)

        assert isinstance(model, ModuleDefinitionModel)
        assert model.name == sample_module_record.name
        assert model.version == sample_module_record.version
        assert model.domain == AttackDomain(sample_module_record.domain)
        assert model.category == ModuleCategory(sample_module_record.category)
        assert model.severity == Severity(sample_module_record.severity)
        assert model.status == ModuleStatus(sample_module_record.status)

    def test_calculate_file_hash(self, mock_cache, temp_module_file):
        """Test file hash calculation."""
        registry = ModuleRegistry(cache=mock_cache)

        hash1 = registry._calculate_file_hash(temp_module_file)
        hash2 = registry._calculate_file_hash(temp_module_file)

        # Same file should produce same hash
        assert hash1 == hash2
        assert len(hash1) == 64  # SHA-256 produces 64-character hex string
        assert all(c in "0123456789abcdef" for c in hash1.lower())


class TestModuleRegistryIntegration:
    """Integration tests for ModuleRegistry with realistic scenarios."""

    @pytest.mark.asyncio
    async def test_full_discovery_and_registration_flow(self, mock_session, temp_module_file):
        """Test complete flow from discovery to registration."""
        registry = ModuleRegistry()

        # Create temporary Gibson structure
        with tempfile.TemporaryDirectory() as temp_dir:
            gibson_root = Path(temp_dir)
            domains_dir = gibson_root / "gibson" / "domains" / "prompt"
            domains_dir.mkdir(parents=True)

            # Copy test module
            test_module_path = domains_dir / "test_module.py"
            test_module_path.write_text(temp_module_file.read_text())

            # Mock database operations for registration
            mock_result = AsyncMock()
            mock_result.scalar_one_or_none.return_value = None  # No existing module
            mock_session.execute.return_value = mock_result

            # Discover modules
            discovered = await registry.discover_modules(gibson_root=gibson_root)

            assert len(discovered) > 0
            module = discovered[0]
            assert module.name == "test_security_module"

            # Register discovered module
            await registry.register_module(module, mock_session)

            # Verify registration
            mock_session.add.assert_called_once()
            mock_session.commit.assert_called_once()

            # Verify module is in registry
            cached_module = await registry.get_module("test_security_module")
            assert cached_module is not None
            assert cached_module.name == "test_security_module"

    @pytest.mark.asyncio
    async def test_search_with_various_filters(self, temp_module_file):
        """Test search functionality with different filter combinations."""
        registry = ModuleRegistry()

        # Create test module and add to discovered modules
        module_def = await registry._load_module_from_file(temp_module_file)
        registry._discovered_modules[module_def.name] = module_def

        # Test various search combinations

        # Search by query
        results = await registry.search_modules(query="test")
        assert len(results) == 1

        # Search by domain
        results = await registry.search_modules(domain=AttackDomain.PROMPT)
        assert len(results) == 1

        # Search by category
        results = await registry.search_modules(category=ModuleCategory.PROMPT_INJECTION)
        assert len(results) == 1

        # Search by tags
        results = await registry.search_modules(tags=["test"])
        assert len(results) == 1

        # Search with no matches
        results = await registry.search_modules(domain=AttackDomain.DATA)
        assert len(results) == 0

        # Search with limit
        results = await registry.search_modules(limit=0)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_concurrent_registry_operations(self, mock_session):
        """Test thread safety with concurrent operations."""
        registry = ModuleRegistry()

        # Mock modules for testing
        modules = []
        for i in range(10):
            module = ModuleDefinitionModel(
                name=f"module_{i}",
                version="1.0.0",
                display_name=f"Module {i}",
                description=f"Test module {i}",
                author="Test",
                domain=AttackDomain.PROMPT,
                category=ModuleCategory.PROMPT_INJECTION,
            )
            modules.append(module)
            registry._discovered_modules[module.name] = module

        # Concurrent search operations
        async def search_worker(query: str):
            return await registry.search_modules(query=query)

        # Run concurrent searches
        tasks = [search_worker(f"module_{i}") for i in range(5)]

        results = await asyncio.gather(*tasks)

        # Verify all searches completed successfully
        assert len(results) == 5
        for result_list in results:
            assert len(result_list) <= 10  # Should find matching modules
