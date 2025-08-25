"""Unit tests for repository factory and registration."""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from sqlalchemy.ext.asyncio import AsyncSession

from gibson.db.base import BaseDBModel
from gibson.db.repositories.base import BaseRepository, IRepository
from gibson.db.repositories.factory import (
    RepositoryRegistry,
    RepositoryFactory,
    ScopedRepositoryFactory,
    DependencyInjector,
    get_repository_factory,
    register_repository,
    get_repository
)


# Test models
class TestModel(BaseDBModel):
    """Test model for factory tests."""
    __tablename__ = 'test_model'


class AnotherModel(BaseDBModel):
    """Another test model."""
    __tablename__ = 'another_model'


# Test repositories
class TestRepository(BaseRepository):
    """Custom repository for TestModel."""
    pass


class AnotherRepository(BaseRepository):
    """Custom repository for AnotherModel."""
    pass


@pytest.fixture
def mock_session():
    """Create mock async session."""
    session = AsyncMock(spec=AsyncSession)
    return session


@pytest.fixture
def registry():
    """Create repository registry."""
    return RepositoryRegistry()


@pytest.fixture
def factory(registry):
    """Create repository factory."""
    return RepositoryFactory(registry)


class TestRepositoryRegistry:
    """Tests for RepositoryRegistry."""
    
    def test_register_default(self, registry):
        """Test registering with default repository."""
        registry.register(TestModel)
        
        repo_class = registry.get_repository_class(TestModel)
        assert repo_class == BaseRepository
    
    def test_register_custom_class(self, registry):
        """Test registering custom repository class."""
        registry.register(TestModel, TestRepository)
        
        repo_class = registry.get_repository_class(TestModel)
        assert repo_class == TestRepository
    
    def test_register_factory_function(self, registry, mock_session):
        """Test registering with factory function."""
        def custom_factory(session, **kwargs):
            return TestRepository(TestModel, session)
        
        registry.register(TestModel, factory=custom_factory)
        
        repo = registry.create(TestModel, mock_session)
        assert isinstance(repo, TestRepository)
    
    def test_unregister(self, registry):
        """Test unregistering repository."""
        registry.register(TestModel, TestRepository)
        registry.unregister(TestModel)
        
        # Should return default after unregister
        repo_class = registry.get_repository_class(TestModel)
        assert repo_class == BaseRepository
    
    def test_singleton_pattern(self, registry, mock_session):
        """Test singleton repository pattern."""
        registry.register(TestModel, TestRepository, singleton=True)
        
        repo1 = registry.create(TestModel, mock_session)
        repo2 = registry.create(TestModel, mock_session)
        
        assert repo1 is repo2  # Same instance
    
    def test_clear_singletons(self, registry, mock_session):
        """Test clearing singleton instances."""
        registry.register(TestModel, TestRepository, singleton=True)
        
        repo1 = registry.create(TestModel, mock_session)
        registry.clear_singletons()
        repo2 = registry.create(TestModel, mock_session)
        
        assert repo1 is not repo2  # Different instances after clear
    
    def test_is_registered(self, registry):
        """Test checking if model is registered."""
        assert not registry.is_registered(TestModel)
        
        registry.register(TestModel)
        assert registry.is_registered(TestModel)


class TestRepositoryFactory:
    """Tests for RepositoryFactory."""
    
    def test_get_repository(self, factory, mock_session):
        """Test getting repository instance."""
        factory.register_repository(TestModel, TestRepository)
        
        repo = factory.get(TestModel, mock_session)
        assert isinstance(repo, TestRepository)
    
    def test_session_factory(self, factory):
        """Test using session factory."""
        mock_session = AsyncMock(spec=AsyncSession)
        session_factory = MagicMock(return_value=mock_session)
        
        factory.set_session_factory(session_factory)
        factory.register_repository(TestModel)
        
        repo = factory.get(TestModel)  # No session provided
        
        session_factory.assert_called_once()
        assert repo.session == mock_session
    
    def test_no_session_error(self, factory):
        """Test error when no session and no factory."""
        factory.register_repository(TestModel)
        
        with pytest.raises(ValueError, match="No session provided"):
            factory.get(TestModel)
    
    def test_bulk_register(self, factory, mock_session):
        """Test bulk registration of repositories."""
        mappings = {
            TestModel: TestRepository,
            AnotherModel: AnotherRepository
        }
        
        factory.bulk_register(mappings)
        
        test_repo = factory.get(TestModel, mock_session)
        another_repo = factory.get(AnotherModel, mock_session)
        
        assert isinstance(test_repo, TestRepository)
        assert isinstance(another_repo, AnotherRepository)
    
    def test_create_scoped(self, factory, mock_session):
        """Test creating scoped factory."""
        factory.register_repository(TestModel)
        
        scoped = factory.create_scoped(mock_session)
        
        assert isinstance(scoped, ScopedRepositoryFactory)
        assert scoped.session == mock_session


class TestScopedRepositoryFactory:
    """Tests for ScopedRepositoryFactory."""
    
    def test_get_cached(self, factory, mock_session):
        """Test getting cached repository instances."""
        factory.register_repository(TestModel)
        scoped = factory.create_scoped(mock_session)
        
        repo1 = scoped.get(TestModel)
        repo2 = scoped.get(TestModel)
        
        assert repo1 is repo2  # Same cached instance
    
    def test_get_uncached(self, factory, mock_session):
        """Test getting uncached repository instances."""
        factory.register_repository(TestModel)
        scoped = factory.create_scoped(mock_session)
        
        repo1 = scoped.get(TestModel, cached=False)
        repo2 = scoped.get(TestModel, cached=False)
        
        assert repo1 is not repo2  # Different instances
    
    def test_clear_cache(self, factory, mock_session):
        """Test clearing scoped cache."""
        factory.register_repository(TestModel)
        scoped = factory.create_scoped(mock_session)
        
        repo1 = scoped.get(TestModel)
        scoped.clear_cache()
        repo2 = scoped.get(TestModel)
        
        assert repo1 is not repo2  # Different after cache clear


class TestDependencyInjector:
    """Tests for DependencyInjector."""
    
    @pytest.mark.asyncio
    async def test_inject_repositories(self, factory, mock_session):
        """Test injecting repositories into function."""
        factory.register_repository(TestModel)
        factory.set_session_factory(lambda: mock_session)
        
        injector = DependencyInjector(factory)
        
        @injector.inject
        async def test_func(repo: IRepository[TestModel]):
            return repo
        
        # Call without providing repo
        result = await test_func()
        
        assert isinstance(result, BaseRepository)
        assert result.model == TestModel
    
    def test_auto_inject_class(self, factory, mock_session):
        """Test auto-injecting into class methods."""
        factory.register_repository(TestModel)
        factory.set_session_factory(lambda: mock_session)
        
        injector = DependencyInjector(factory)
        
        @injector.auto_inject
        class TestService:
            async def get_data(self, repo: IRepository[TestModel]):
                return repo
        
        # Methods should be wrapped
        service = TestService()
        assert hasattr(service.get_data, '__wrapped__')


class TestGlobalFactory:
    """Tests for global factory functions."""
    
    def test_get_global_factory(self):
        """Test getting global factory instance."""
        factory1 = get_repository_factory()
        factory2 = get_repository_factory()
        
        assert factory1 is factory2  # Same instance
    
    def test_global_registration(self, mock_session):
        """Test registering with global factory."""
        register_repository(TestModel, TestRepository)
        
        repo = get_repository(TestModel, mock_session)
        
        assert isinstance(repo, TestRepository)
    
    def test_set_global_factory(self):
        """Test setting custom global factory."""
        custom_factory = RepositoryFactory()
        
        from gibson.db.repositories import factory as factory_module
        factory_module.set_repository_factory(custom_factory)
        
        retrieved = get_repository_factory()
        assert retrieved is custom_factory