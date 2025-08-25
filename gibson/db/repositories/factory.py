"""Repository factory for dependency injection and registration."""

from typing import Dict, Type, TypeVar, Optional, Callable, Any
from functools import lru_cache
import inspect

from sqlalchemy.ext.asyncio import AsyncSession

from gibson.db.base import BaseDBModel
from gibson.db.repositories.base import BaseRepository, IRepository

T = TypeVar("T", bound=BaseDBModel)
R = TypeVar("R", bound=IRepository)


class RepositoryRegistry:
    """Registry for managing repository instances and their dependencies."""
    
    def __init__(self):
        """Initialize repository registry."""
        self._repositories: Dict[Type[BaseDBModel], Type[IRepository]] = {}
        self._custom_factories: Dict[Type[BaseDBModel], Callable] = {}
        self._singletons: Dict[str, IRepository] = {}
        self._default_repository_class = BaseRepository
    
    def register(
        self,
        model: Type[T],
        repository_class: Optional[Type[R]] = None,
        factory: Optional[Callable] = None,
        singleton: bool = False
    ) -> None:
        """Register a repository for a model.
        
        Args:
            model: SQLAlchemy model class
            repository_class: Repository class to use (optional)
            factory: Custom factory function (optional)
            singleton: Whether to use singleton pattern
        """
        if factory:
            self._custom_factories[model] = factory
        elif repository_class:
            self._repositories[model] = repository_class
        else:
            # Use default repository
            self._repositories[model] = self._default_repository_class
        
        # Mark for singleton if requested
        if singleton:
            key = f"{model.__name__}_singleton"
            if key not in self._singletons:
                self._singletons[key] = None
    
    def unregister(self, model: Type[T]) -> None:
        """Unregister a repository.
        
        Args:
            model: Model class to unregister
        """
        self._repositories.pop(model, None)
        self._custom_factories.pop(model, None)
        
        # Clear singleton if exists
        key = f"{model.__name__}_singleton"
        self._singletons.pop(key, None)
    
    def get_repository_class(self, model: Type[T]) -> Type[IRepository]:
        """Get repository class for a model.
        
        Args:
            model: Model class
            
        Returns:
            Repository class
        """
        return self._repositories.get(model, self._default_repository_class)
    
    def create(
        self,
        model: Type[T],
        session: AsyncSession,
        **kwargs
    ) -> IRepository[T]:
        """Create repository instance.
        
        Args:
            model: Model class
            session: Database session
            **kwargs: Additional arguments for repository
            
        Returns:
            Repository instance
        """
        # Check for singleton
        singleton_key = f"{model.__name__}_singleton"
        if singleton_key in self._singletons:
            if self._singletons[singleton_key] is not None:
                return self._singletons[singleton_key]
        
        # Use custom factory if available
        if model in self._custom_factories:
            factory = self._custom_factories[model]
            repository = factory(session, **kwargs)
        else:
            # Use registered or default repository class
            repo_class = self.get_repository_class(model)
            
            # Check if repository class needs model in constructor
            sig = inspect.signature(repo_class.__init__)
            params = sig.parameters
            
            if 'model' in params:
                repository = repo_class(model=model, session=session, **kwargs)
            else:
                # Assume it's a model-specific repository
                repository = repo_class(session=session, **kwargs)
        
        # Store singleton if needed
        if singleton_key in self._singletons:
            self._singletons[singleton_key] = repository
        
        return repository
    
    def clear_singletons(self) -> None:
        """Clear all singleton instances."""
        for key in self._singletons:
            self._singletons[key] = None
    
    def is_registered(self, model: Type[T]) -> bool:
        """Check if model has registered repository.
        
        Args:
            model: Model class
            
        Returns:
            True if registered
        """
        return model in self._repositories or model in self._custom_factories


class RepositoryFactory:
    """Factory for creating repository instances with dependency injection."""
    
    def __init__(self, registry: Optional[RepositoryRegistry] = None):
        """Initialize repository factory.
        
        Args:
            registry: Repository registry to use
        """
        self.registry = registry or RepositoryRegistry()
        self._session_factory: Optional[Callable] = None
    
    def set_session_factory(self, factory: Callable) -> None:
        """Set session factory for automatic session creation.
        
        Args:
            factory: Callable that returns AsyncSession
        """
        self._session_factory = factory
    
    def register_repository(
        self,
        model: Type[T],
        repository_class: Optional[Type[R]] = None,
        **kwargs
    ) -> None:
        """Register a repository with the factory.
        
        Args:
            model: Model class
            repository_class: Repository class
            **kwargs: Additional registration options
        """
        self.registry.register(model, repository_class, **kwargs)
    
    def get(
        self,
        model: Type[T],
        session: Optional[AsyncSession] = None,
        **kwargs
    ) -> IRepository[T]:
        """Get repository instance for a model.
        
        Args:
            model: Model class
            session: Database session (optional if session factory set)
            **kwargs: Additional arguments
            
        Returns:
            Repository instance
            
        Raises:
            ValueError: If no session provided and no session factory set
        """
        if session is None:
            if self._session_factory is None:
                raise ValueError(
                    "No session provided and no session factory configured"
                )
            session = self._session_factory()
        
        return self.registry.create(model, session, **kwargs)
    
    @lru_cache(maxsize=128)
    def get_cached(
        self,
        model: Type[T],
        cache_key: str = "default"
    ) -> Type[IRepository]:
        """Get cached repository class for a model.
        
        Args:
            model: Model class
            cache_key: Cache key for different configurations
            
        Returns:
            Repository class (not instance)
        """
        return self.registry.get_repository_class(model)
    
    def create_scoped(self, session: AsyncSession) -> "ScopedRepositoryFactory":
        """Create a scoped factory with fixed session.
        
        Args:
            session: Database session to use
            
        Returns:
            Scoped repository factory
        """
        return ScopedRepositoryFactory(self, session)
    
    def bulk_register(self, mappings: Dict[Type[T], Type[R]]) -> None:
        """Register multiple repositories at once.
        
        Args:
            mappings: Dictionary of model to repository mappings
        """
        for model, repo_class in mappings.items():
            self.register_repository(model, repo_class)


class ScopedRepositoryFactory:
    """Repository factory scoped to a specific session."""
    
    def __init__(self, factory: RepositoryFactory, session: AsyncSession):
        """Initialize scoped factory.
        
        Args:
            factory: Parent repository factory
            session: Database session to use
        """
        self.factory = factory
        self.session = session
        self._instances: Dict[Type[BaseDBModel], IRepository] = {}
    
    def get(
        self,
        model: Type[T],
        cached: bool = True,
        **kwargs
    ) -> IRepository[T]:
        """Get repository instance for model.
        
        Args:
            model: Model class
            cached: Whether to cache instance
            **kwargs: Additional arguments
            
        Returns:
            Repository instance
        """
        if cached and model in self._instances:
            return self._instances[model]
        
        repository = self.factory.get(model, self.session, **kwargs)
        
        if cached:
            self._instances[model] = repository
        
        return repository
    
    def clear_cache(self) -> None:
        """Clear cached repository instances."""
        self._instances.clear()


class DependencyInjector:
    """Dependency injector for repositories."""
    
    def __init__(self, factory: RepositoryFactory):
        """Initialize dependency injector.
        
        Args:
            factory: Repository factory
        """
        self.factory = factory
    
    def inject(self, func: Callable) -> Callable:
        """Decorator to inject repositories into function.
        
        Args:
            func: Function to decorate
            
        Returns:
            Decorated function
        """
        sig = inspect.signature(func)
        
        async def wrapper(*args, **kwargs):
            # Inject repositories for type-hinted parameters
            for param_name, param in sig.parameters.items():
                if param.annotation and param_name not in kwargs:
                    # Check if it's a repository type hint
                    origin = getattr(param.annotation, '__origin__', None)
                    if origin is type(IRepository):
                        # Get the model type from generic
                        model_type = param.annotation.__args__[0]
                        kwargs[param_name] = self.factory.get(model_type)
            
            return await func(*args, **kwargs)
        
        return wrapper
    
    def auto_inject(self, cls: Type) -> Type:
        """Class decorator to auto-inject repositories.
        
        Args:
            cls: Class to decorate
            
        Returns:
            Decorated class
        """
        for name, method in inspect.getmembers(cls):
            if inspect.iscoroutinefunction(method):
                setattr(cls, name, self.inject(method))
        return cls


# Global factory instance
_global_factory: Optional[RepositoryFactory] = None


def get_repository_factory() -> RepositoryFactory:
    """Get global repository factory instance.
    
    Returns:
        Global repository factory
    """
    global _global_factory
    if _global_factory is None:
        _global_factory = RepositoryFactory()
    return _global_factory


def set_repository_factory(factory: RepositoryFactory) -> None:
    """Set global repository factory instance.
    
    Args:
        factory: Repository factory to set as global
    """
    global _global_factory
    _global_factory = factory


# Convenience functions
def register_repository(
    model: Type[T],
    repository_class: Optional[Type[R]] = None,
    **kwargs
) -> None:
    """Register a repository with global factory.
    
    Args:
        model: Model class
        repository_class: Repository class
        **kwargs: Additional options
    """
    factory = get_repository_factory()
    factory.register_repository(model, repository_class, **kwargs)


def get_repository(
    model: Type[T],
    session: AsyncSession,
    **kwargs
) -> IRepository[T]:
    """Get repository from global factory.
    
    Args:
        model: Model class
        session: Database session
        **kwargs: Additional arguments
        
    Returns:
        Repository instance
    """
    factory = get_repository_factory()
    return factory.get(model, session, **kwargs)


# Export main components
__all__ = [
    "RepositoryRegistry",
    "RepositoryFactory",
    "ScopedRepositoryFactory",
    "DependencyInjector",
    "get_repository_factory",
    "set_repository_factory",
    "register_repository",
    "get_repository"
]