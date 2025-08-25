"""Tests for TargetRepository."""

import pytest
from datetime import datetime
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from gibson.core.targets.repository import (
    TargetRepository,
    TargetNotFoundError,
    TargetAlreadyExistsError,
)
from gibson.models.target import TargetModel, TargetType, TargetStatus, LLMProvider
from gibson.db.base import Base


@pytest.fixture
async def async_session():
    """Create async test database session."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with async_session() as session:
        yield session

    await engine.dispose()


@pytest.fixture
def repository(async_session):
    """Create TargetRepository instance."""
    return TargetRepository(async_session)


@pytest.fixture
def sample_target():
    """Create sample target model."""
    return TargetModel(
        id=uuid4(),
        name="test-api",
        display_name="Test API",
        description="Test API for unit tests",
        target_type=TargetType.API,
        base_url="https://api.test.com",
        status=TargetStatus.ACTIVE,
        provider=LLMProvider.OPENAI,
        tags=["test", "api"],
    )


class TestTargetRepository:
    """Test cases for TargetRepository."""

    @pytest.mark.asyncio
    async def test_create_target(self, repository, sample_target):
        """Test creating a new target."""
        created = await repository.create(sample_target)

        assert created.id == sample_target.id
        assert created.name == sample_target.name
        assert created.target_type == sample_target.target_type
        assert created.created_at is not None

    @pytest.mark.asyncio
    async def test_create_duplicate_target_raises_error(self, repository, sample_target):
        """Test that creating duplicate target raises error."""
        await repository.create(sample_target)

        # Try to create another target with same name
        duplicate = TargetModel(
            id=uuid4(),
            name=sample_target.name,  # Same name
            display_name="Duplicate",
            target_type=TargetType.API,
            base_url="https://api.duplicate.com",
        )

        with pytest.raises(TargetAlreadyExistsError):
            await repository.create(duplicate)

    @pytest.mark.asyncio
    async def test_get_target_by_id(self, repository, sample_target):
        """Test retrieving target by ID."""
        created = await repository.create(sample_target)
        retrieved = await repository.get_by_id(created.id)

        assert retrieved is not None
        assert retrieved.id == created.id
        assert retrieved.name == created.name

    @pytest.mark.asyncio
    async def test_get_target_by_name(self, repository, sample_target):
        """Test retrieving target by name."""
        created = await repository.create(sample_target)
        retrieved = await repository.get_by_name(created.name)

        assert retrieved is not None
        assert retrieved.id == created.id
        assert retrieved.name == created.name

    @pytest.mark.asyncio
    async def test_get_nonexistent_target_returns_none(self, repository):
        """Test that getting nonexistent target returns None."""
        result = await repository.get_by_id(uuid4())
        assert result is None

        result = await repository.get_by_name("nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_update_target(self, repository, sample_target):
        """Test updating an existing target."""
        created = await repository.create(sample_target)

        # Update fields
        created.description = "Updated description"
        created.status = TargetStatus.INACTIVE

        updated = await repository.update(created)

        assert updated.description == "Updated description"
        assert updated.status == TargetStatus.INACTIVE
        assert updated.updated_at > updated.created_at

    @pytest.mark.asyncio
    async def test_update_nonexistent_target_raises_error(self, repository, sample_target):
        """Test that updating nonexistent target raises error."""
        with pytest.raises(TargetNotFoundError):
            await repository.update(sample_target)

    @pytest.mark.asyncio
    async def test_delete_target(self, repository, sample_target):
        """Test deleting a target."""
        created = await repository.create(sample_target)

        success = await repository.delete(created.id)
        assert success is True

        # Verify target is deleted
        retrieved = await repository.get_by_id(created.id)
        assert retrieved is None

    @pytest.mark.asyncio
    async def test_delete_nonexistent_target_returns_false(self, repository):
        """Test that deleting nonexistent target returns False."""
        success = await repository.delete(uuid4())
        assert success is False

    @pytest.mark.asyncio
    async def test_list_targets(self, repository):
        """Test listing targets with filtering."""
        # Create test targets
        targets = [
            TargetModel(
                id=uuid4(),
                name=f"target-{i}",
                display_name=f"Target {i}",
                target_type=TargetType.API,
                base_url=f"https://api{i}.test.com",
                status=TargetStatus.ACTIVE if i % 2 == 0 else TargetStatus.INACTIVE,
                environment="production" if i % 2 == 0 else "development",
            )
            for i in range(5)
        ]

        for target in targets:
            await repository.create(target)

        # Test listing all
        all_targets = await repository.list_all()
        assert len(all_targets) == 5

        # Test filtering by status
        active_targets = await repository.list_all(status=TargetStatus.ACTIVE)
        assert len(active_targets) == 3

        # Test filtering by environment
        prod_targets = await repository.list_all(environment="production")
        assert len(prod_targets) == 3

        # Test enabled only filter
        enabled_targets = await repository.list_all(enabled_only=True)
        assert len(enabled_targets) == 5  # All are enabled by default

        # Test limit
        limited_targets = await repository.list_all(limit=2)
        assert len(limited_targets) == 2

    @pytest.mark.asyncio
    async def test_search_targets(self, repository, sample_target):
        """Test searching targets."""
        await repository.create(sample_target)

        # Search by name
        results = await repository.search("test-api")
        assert len(results) == 1
        assert results[0].name == sample_target.name

        # Search by description
        results = await repository.search("unit tests")
        assert len(results) == 1

        # Search by URL
        results = await repository.search("api.test.com")
        assert len(results) == 1

        # Search with no matches
        results = await repository.search("nonexistent")
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_get_by_tags(self, repository, sample_target):
        """Test getting targets by tags."""
        await repository.create(sample_target)

        # Search by existing tag
        results = await repository.get_by_tags(["api"])
        assert len(results) == 1
        assert results[0].name == sample_target.name

        # Search by multiple tags
        results = await repository.get_by_tags(["test", "api"])
        assert len(results) == 1

        # Search by non-existent tag
        results = await repository.get_by_tags(["nonexistent"])
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_update_statistics(self, repository, sample_target):
        """Test updating target statistics."""
        created = await repository.create(sample_target)

        # Update statistics
        await repository.update_statistics(
            created.id, scan_count_increment=2, finding_count_increment=5
        )

        # Verify updates
        updated = await repository.get_by_id(created.id)
        assert updated.scan_count == 2
        assert updated.finding_count == 5
        assert updated.last_scanned is not None

    @pytest.mark.asyncio
    async def test_get_statistics(self, repository):
        """Test getting repository statistics."""
        # Create test targets with different statuses
        targets = [
            TargetModel(
                id=uuid4(),
                name=f"target-{i}",
                display_name=f"Target {i}",
                target_type=TargetType.API,
                base_url=f"https://api{i}.test.com",
                status=TargetStatus.ACTIVE if i < 3 else TargetStatus.INACTIVE,
                environment="production" if i < 2 else "development",
            )
            for i in range(5)
        ]

        for target in targets:
            await repository.create(target)

        stats = await repository.get_statistics()

        assert stats["total_targets"] == 5
        assert stats["active_targets"] == 3
        assert stats["inactive_targets"] == 2
        assert stats["targets_by_type"]["api"] == 5
        assert stats["targets_by_environment"]["production"] == 2
        assert stats["targets_by_environment"]["development"] == 3
