"""Database test utilities for Gibson framework testing."""

import tempfile
from pathlib import Path
from typing import AsyncGenerator, Dict, Any
import pytest
import pytest_asyncio
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

from gibson.db.base import Base, BaseDBModel, CRUDMixin
from gibson.db.manager import DatabaseManager
from gibson.db.repositories.factory import RepositoryFactory
from gibson.db.utils.transaction import TransactionManager


class TestUtilities:
    """Test utilities for database operations."""
    
    @staticmethod
    def create_in_memory_database() -> DatabaseManager:
        """Create an in-memory SQLite database for testing.
        
        Returns:
            Database manager configured for in-memory testing
        """
        # Use in-memory SQLite with connection pooling disabled for tests
        db_url = "sqlite+aiosqlite:///:memory:"
        return DatabaseManager(
            database_url=db_url,
            validate_on_init=False,
            pool_size=1,
            echo=False
        )
    
    @staticmethod
    def create_temp_database() -> tuple[DatabaseManager, Path]:
        """Create a temporary file-based SQLite database for testing.
        
        Returns:
            Tuple of (database manager, temp file path)
        """
        temp_file = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        temp_path = Path(temp_file.name)
        temp_file.close()
        
        db_url = f"sqlite+aiosqlite:///{temp_path}"
        manager = DatabaseManager(
            database_url=db_url,
            validate_on_init=False,
            echo=False
        )
        
        return manager, temp_path
    
    @staticmethod
    async def setup_test_database(manager: DatabaseManager) -> None:
        """Set up test database with all tables.
        
        Args:
            manager: Database manager to initialize
        """
        await manager.initialize(auto_migrate=False)
        
        # Create all tables
        async with manager.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    
    @staticmethod
    async def cleanup_test_database(manager: DatabaseManager) -> None:
        """Clean up test database.
        
        Args:
            manager: Database manager to clean up
        """
        if manager.engine:
            await manager.close()
    
    @staticmethod
    async def create_test_data(session: AsyncSession) -> Dict[str, Any]:
        """Create test data in the database.
        
        Args:
            session: Database session
            
        Returns:
            Dictionary of created test data
        """
        test_data = {}
        
        # Import test models if available
        try:
            from gibson.db.models.target import Target
            
            # Create test target
            target = Target(
                name="test_target",
                display_name="Test Target",
                description="Test target for unit tests",
                target_type="api",
                base_url="https://api.example.com",
                status="active",
                enabled=True
            )
            session.add(target)
            await session.commit()
            await session.refresh(target)
            test_data['target'] = target
            
        except ImportError:
            pass
        
        try:
            from gibson.db.models.scan import ModuleRecord, ScanRecord
            
            # Create test module
            module = ModuleRecord(
                name="test_module",
                module_version="1.0.0",
                display_name="Test Module",
                description="Test module for unit tests",
                author="Test Author",
                domain="prompt",
                category="injection",
                status="installed"
            )
            session.add(module)
            
            # Create test scan if we have a target
            if 'target' in test_data:
                scan = ScanRecord(
                    target_id=test_data['target'].id,
                    target_url=test_data['target'].base_url,
                    scan_type="full",
                    config={"test": True},
                    status="pending"
                )
                session.add(scan)
                test_data['scan'] = scan
            
            await session.commit()
            await session.refresh(module)
            test_data['module'] = module
            
            if 'scan' in test_data:
                await session.refresh(test_data['scan'])
            
        except ImportError:
            pass
        
        return test_data
    
    @staticmethod
    async def clear_all_data(session: AsyncSession) -> None:
        """Clear all data from test database.
        
        Args:
            session: Database session
        """
        # Get all table names
        table_names = list(Base.metadata.tables.keys())
        
        # Clear in reverse dependency order to avoid foreign key issues
        for table_name in reversed(table_names):
            try:
                await session.execute(f"DELETE FROM {table_name}")
            except Exception:
                # Ignore errors for tables that might not exist
                pass
        
        await session.commit()


# Pytest fixtures for database testing
@pytest_asyncio.fixture
async def in_memory_db() -> AsyncGenerator[DatabaseManager, None]:
    """Provide an in-memory database for testing."""
    manager = TestUtilities.create_in_memory_database()
    await TestUtilities.setup_test_database(manager)
    
    try:
        yield manager
    finally:
        await TestUtilities.cleanup_test_database(manager)


@pytest_asyncio.fixture
async def temp_db() -> AsyncGenerator[tuple[DatabaseManager, Path], None]:
    """Provide a temporary file database for testing."""
    manager, temp_path = TestUtilities.create_temp_database()
    await TestUtilities.setup_test_database(manager)
    
    try:
        yield manager, temp_path
    finally:
        await TestUtilities.cleanup_test_database(manager)
        # Clean up temp file
        if temp_path.exists():
            temp_path.unlink()


@pytest_asyncio.fixture
async def db_session(in_memory_db: DatabaseManager) -> AsyncGenerator[AsyncSession, None]:
    """Provide a database session for testing."""
    async with in_memory_db.session() as session:
        yield session


@pytest_asyncio.fixture
async def db_with_data(in_memory_db: DatabaseManager) -> AsyncGenerator[tuple[AsyncSession, Dict[str, Any]], None]:
    """Provide a database session with test data."""
    async with in_memory_db.session() as session:
        test_data = await TestUtilities.create_test_data(session)
        yield session, test_data


@pytest_asyncio.fixture
async def repository_factory(in_memory_db: DatabaseManager) -> RepositoryFactory:
    """Provide a repository factory for testing."""
    return in_memory_db._repository_factory


@pytest_asyncio.fixture
async def transaction_manager(db_session: AsyncSession) -> TransactionManager:
    """Provide a transaction manager for testing."""
    return TransactionManager(db_session)


# Assertion helpers
class DatabaseAssertions:
    """Helper class for database-related assertions."""
    
    @staticmethod
    async def assert_record_exists(session: AsyncSession, model_class: type, **filters) -> Any:
        """Assert that a record exists with given filters.
        
        Args:
            session: Database session
            model_class: Model class to search
            **filters: Filter criteria
            
        Returns:
            Found record
            
        Raises:
            AssertionError: If record not found
        """
        from sqlalchemy.future import select
        
        query = select(model_class).filter_by(**filters)
        result = await session.execute(query)
        record = result.scalar_one_or_none()
        
        assert record is not None, f"Record not found: {model_class.__name__} with {filters}"
        return record
    
    @staticmethod
    async def assert_record_not_exists(session: AsyncSession, model_class: type, **filters) -> None:
        """Assert that no record exists with given filters.
        
        Args:
            session: Database session
            model_class: Model class to search
            **filters: Filter criteria
            
        Raises:
            AssertionError: If record is found
        """
        from sqlalchemy.future import select
        
        query = select(model_class).filter_by(**filters)
        result = await session.execute(query)
        record = result.scalar_one_or_none()
        
        assert record is None, f"Unexpected record found: {model_class.__name__} with {filters}"
    
    @staticmethod
    async def assert_record_count(
        session: AsyncSession,
        model_class: type,
        expected_count: int,
        **filters
    ) -> None:
        """Assert the count of records matching criteria.
        
        Args:
            session: Database session
            model_class: Model class to count
            expected_count: Expected number of records
            **filters: Filter criteria
            
        Raises:
            AssertionError: If count doesn't match
        """
        from sqlalchemy.future import select
        from sqlalchemy import func
        
        query = select(func.count()).select_from(model_class)
        if filters:
            query = query.filter_by(**filters)
        
        result = await session.execute(query)
        actual_count = result.scalar()
        
        assert actual_count == expected_count, (
            f"Expected {expected_count} records, found {actual_count} "
            f"for {model_class.__name__} with {filters}"
        )
    
    @staticmethod
    def assert_model_valid(instance: BaseDBModel) -> None:
        """Assert that a model instance is valid.
        
        Args:
            instance: Model instance to validate
            
        Raises:
            AssertionError: If validation fails
        """
        errors = instance.validate()
        assert not errors, f"Model validation failed: {', '.join(errors)}"
    
    @staticmethod
    def assert_audit_fields_set(instance: BaseDBModel, created_by: str = None) -> None:
        """Assert that audit fields are properly set.
        
        Args:
            instance: Model instance to check
            created_by: Expected created_by value
            
        Raises:
            AssertionError: If audit fields are not set correctly
        """
        assert hasattr(instance, 'created_at'), "Missing created_at field"
        assert hasattr(instance, 'updated_at'), "Missing updated_at field"
        assert instance.created_at is not None, "created_at should be set"
        assert instance.updated_at is not None, "updated_at should be set"
        
        if hasattr(instance, 'version'):
            assert instance.version >= 1, "Version should be >= 1"
        
        if created_by and hasattr(instance, 'created_by'):
            assert instance.created_by == created_by, f"Expected created_by={created_by}"


# Mock data generators
class MockDataGenerator:
    """Generator for mock test data."""
    
    @staticmethod
    def generate_target_data(**overrides) -> Dict[str, Any]:
        """Generate mock target data.
        
        Args:
            **overrides: Fields to override
            
        Returns:
            Dictionary of target data
        """
        data = {
            "name": f"test_target_{uuid4().hex[:8]}",
            "display_name": "Test Target",
            "description": "Generated test target",
            "target_type": "api",
            "base_url": "https://api.example.com",
            "status": "active",
            "enabled": True
        }
        data.update(overrides)
        return data
    
    @staticmethod
    def generate_module_data(**overrides) -> Dict[str, Any]:
        """Generate mock module data.
        
        Args:
            **overrides: Fields to override
            
        Returns:
            Dictionary of module data
        """
        data = {
            "name": f"test_module_{uuid4().hex[:8]}",
            "module_version": "1.0.0",
            "display_name": "Test Module",
            "description": "Generated test module",
            "author": "Test Author",
            "domain": "prompt",
            "category": "injection",
            "status": "installed"
        }
        data.update(overrides)
        return data
    
    @staticmethod
    def generate_scan_data(target_id: str, **overrides) -> Dict[str, Any]:
        """Generate mock scan data.
        
        Args:
            target_id: Target ID for the scan
            **overrides: Fields to override
            
        Returns:
            Dictionary of scan data
        """
        data = {
            "target_id": target_id,
            "target_url": "https://api.example.com",
            "scan_type": "full",
            "config": {"test": True},
            "status": "pending"
        }
        data.update(overrides)
        return data


# Performance testing utilities
class PerformanceTestUtils:
    """Utilities for database performance testing."""
    
    @staticmethod
    async def time_query(session: AsyncSession, query_func) -> tuple[Any, float]:
        """Time the execution of a database query.
        
        Args:
            session: Database session
            query_func: Function that executes the query
            
        Returns:
            Tuple of (result, execution_time_seconds)
        """
        import time
        
        start_time = time.time()
        result = await query_func(session)
        execution_time = time.time() - start_time
        
        return result, execution_time
    
    @staticmethod
    async def assert_query_performance(
        session: AsyncSession,
        query_func,
        max_time_seconds: float = 1.0
    ) -> Any:
        """Assert that a query executes within time limit.
        
        Args:
            session: Database session
            query_func: Function that executes the query
            max_time_seconds: Maximum allowed execution time
            
        Returns:
            Query result
            
        Raises:
            AssertionError: If query takes too long
        """
        result, execution_time = await PerformanceTestUtils.time_query(session, query_func)
        
        assert execution_time <= max_time_seconds, (
            f"Query took {execution_time:.3f}s, expected <= {max_time_seconds}s"
        )
        
        return result


# Export test utilities
__all__ = [
    "TestUtilities",
    "DatabaseAssertions", 
    "MockDataGenerator",
    "PerformanceTestUtils",
    "in_memory_db",
    "temp_db",
    "db_session",
    "db_with_data",
    "repository_factory",
    "transaction_manager"
]