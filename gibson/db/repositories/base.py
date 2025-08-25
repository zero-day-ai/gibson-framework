"""Base repository pattern implementation for database operations."""

from abc import ABC, abstractmethod
from typing import Any, Dict, Generic, List, Optional, Type, TypeVar
from uuid import UUID
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy import func, and_, or_

from gibson.db.base import BaseDBModel
from gibson.db.utils.model_validator import ModelValidator, ValidationResult

T = TypeVar("T", bound=BaseDBModel)


class IRepository(ABC, Generic[T]):
    """Interface for repository pattern."""
    
    @abstractmethod
    async def create(self, entity: T) -> T:
        """Create a new entity."""
        pass
    
    @abstractmethod
    async def get(self, id: UUID) -> Optional[T]:
        """Get entity by ID."""
        pass
    
    @abstractmethod
    async def list(
        self,
        filters: Optional[Dict[str, Any]] = None,
        offset: int = 0,
        limit: int = 100,
        order_by: Optional[str] = None
    ) -> List[T]:
        """List entities with filtering and pagination."""
        pass
    
    @abstractmethod
    async def update(self, id: UUID, updates: Dict[str, Any]) -> Optional[T]:
        """Update entity by ID."""
        pass
    
    @abstractmethod
    async def delete(self, id: UUID, soft: bool = True) -> bool:
        """Delete entity by ID."""
        pass
    
    @abstractmethod
    async def exists(self, filters: Dict[str, Any]) -> bool:
        """Check if entity exists."""
        pass
    
    @abstractmethod
    async def count(self, filters: Optional[Dict[str, Any]] = None) -> int:
        """Count entities matching filters."""
        pass


class BaseRepository(IRepository[T]):
    """Base repository with common CRUD operations using async SQLAlchemy."""
    
    def __init__(
        self,
        model: Type[T],
        session: AsyncSession,
        validate: bool = True,
        include_deleted: bool = False
    ):
        """Initialize repository.
        
        Args:
            model: SQLAlchemy model class
            session: Async database session
            validate: Whether to validate entities before save
            include_deleted: Whether to include soft-deleted records
        """
        self.model = model
        self.session = session
        self.validate = validate
        self.include_deleted = include_deleted
    
    async def create(self, entity: T, created_by: Optional[str] = None) -> T:
        """Create a new entity.
        
        Args:
            entity: Entity to create
            created_by: User creating the entity
            
        Returns:
            Created entity
            
        Raises:
            ValueError: If validation fails
            IntegrityError: If database constraints are violated
        """
        # Validate if enabled
        if self.validate:
            result = ModelValidator.validate_model(entity)
            if not result.is_valid:
                raise ValueError(f"Validation failed: {', '.join(result.errors)}")
        
        # Set audit fields
        if created_by and hasattr(entity, 'created_by'):
            entity.created_by = created_by
            entity.updated_by = created_by
        
        try:
            self.session.add(entity)
            await self.session.commit()
            await self.session.refresh(entity)
            return entity
        except IntegrityError as e:
            await self.session.rollback()
            raise IntegrityError(f"Database constraint violation: {str(e)}", None, None)
        except Exception as e:
            await self.session.rollback()
            raise
    
    async def get(self, id: UUID) -> Optional[T]:
        """Get entity by ID.
        
        Args:
            id: Entity ID
            
        Returns:
            Entity or None if not found
        """
        query = select(self.model).where(self.model.id == id)
        
        # Filter soft-deleted if needed
        if not self.include_deleted and hasattr(self.model, 'is_deleted'):
            query = query.where(self.model.is_deleted == False)
        
        result = await self.session.execute(query)
        return result.scalar_one_or_none()
    
    async def list(
        self,
        filters: Optional[Dict[str, Any]] = None,
        offset: int = 0,
        limit: int = 100,
        order_by: Optional[str] = None
    ) -> List[T]:
        """List entities with filtering and pagination.
        
        Args:
            filters: Filter criteria
            offset: Number of records to skip
            limit: Maximum number of records to return
            order_by: Field to order by (prefix with '-' for descending)
            
        Returns:
            List of entities
        """
        query = select(self.model)
        
        # Apply filters
        if filters:
            for key, value in filters.items():
                if hasattr(self.model, key):
                    if isinstance(value, list):
                        # IN clause for lists
                        query = query.where(getattr(self.model, key).in_(value))
                    elif value is None:
                        # IS NULL
                        query = query.where(getattr(self.model, key).is_(None))
                    else:
                        # Equality
                        query = query.where(getattr(self.model, key) == value)
        
        # Filter soft-deleted if needed
        if not self.include_deleted and hasattr(self.model, 'is_deleted'):
            query = query.where(self.model.is_deleted == False)
        
        # Apply ordering
        if order_by:
            if order_by.startswith('-'):
                # Descending order
                field = order_by[1:]
                if hasattr(self.model, field):
                    query = query.order_by(getattr(self.model, field).desc())
            else:
                # Ascending order
                if hasattr(self.model, order_by):
                    query = query.order_by(getattr(self.model, order_by))
        else:
            # Default ordering by created_at desc
            if hasattr(self.model, 'created_at'):
                query = query.order_by(self.model.created_at.desc())
        
        # Apply pagination
        query = query.offset(offset).limit(limit)
        
        result = await self.session.execute(query)
        return list(result.scalars().all())
    
    async def update(
        self,
        id: UUID,
        updates: Dict[str, Any],
        updated_by: Optional[str] = None
    ) -> Optional[T]:
        """Update entity by ID.
        
        Args:
            id: Entity ID
            updates: Fields to update
            updated_by: User updating the entity
            
        Returns:
            Updated entity or None if not found
            
        Raises:
            ValueError: If validation fails
        """
        entity = await self.get(id)
        if not entity:
            return None
        
        # Apply updates
        for key, value in updates.items():
            if hasattr(entity, key):
                setattr(entity, key, value)
        
        # Update audit fields
        if updated_by and hasattr(entity, 'updated_by'):
            entity.updated_by = updated_by
        
        # Increment version for optimistic locking
        if hasattr(entity, 'version'):
            entity.version += 1
        
        # Validate if enabled
        if self.validate:
            result = ModelValidator.validate_model(entity)
            if not result.is_valid:
                raise ValueError(f"Validation failed: {', '.join(result.errors)}")
        
        try:
            await self.session.commit()
            await self.session.refresh(entity)
            return entity
        except IntegrityError as e:
            await self.session.rollback()
            raise IntegrityError(f"Database constraint violation: {str(e)}", None, None)
        except Exception:
            await self.session.rollback()
            raise
    
    async def delete(
        self,
        id: UUID,
        soft: bool = True,
        deleted_by: Optional[str] = None
    ) -> bool:
        """Delete entity by ID.
        
        Args:
            id: Entity ID
            soft: Whether to soft delete (default) or hard delete
            deleted_by: User deleting the entity
            
        Returns:
            True if deleted, False if not found
        """
        entity = await self.get(id)
        if not entity:
            return False
        
        if soft and hasattr(entity, 'is_deleted'):
            # Soft delete
            entity.is_deleted = True
            if deleted_by and hasattr(entity, 'updated_by'):
                entity.updated_by = deleted_by
            if hasattr(entity, 'version'):
                entity.version += 1
            await self.session.commit()
        else:
            # Hard delete
            await self.session.delete(entity)
            await self.session.commit()
        
        return True
    
    async def exists(self, filters: Dict[str, Any]) -> bool:
        """Check if entity exists.
        
        Args:
            filters: Filter criteria
            
        Returns:
            True if exists, False otherwise
        """
        query = select(func.count()).select_from(self.model)
        
        # Apply filters
        for key, value in filters.items():
            if hasattr(self.model, key):
                query = query.where(getattr(self.model, key) == value)
        
        # Filter soft-deleted if needed
        if not self.include_deleted and hasattr(self.model, 'is_deleted'):
            query = query.where(self.model.is_deleted == False)
        
        result = await self.session.execute(query)
        count = result.scalar()
        return count > 0
    
    async def count(self, filters: Optional[Dict[str, Any]] = None) -> int:
        """Count entities matching filters.
        
        Args:
            filters: Filter criteria
            
        Returns:
            Count of matching entities
        """
        query = select(func.count()).select_from(self.model)
        
        # Apply filters
        if filters:
            for key, value in filters.items():
                if hasattr(self.model, key):
                    query = query.where(getattr(self.model, key) == value)
        
        # Filter soft-deleted if needed
        if not self.include_deleted and hasattr(self.model, 'is_deleted'):
            query = query.where(self.model.is_deleted == False)
        
        result = await self.session.execute(query)
        return result.scalar()
    
    async def bulk_create(
        self,
        entities: List[T],
        created_by: Optional[str] = None
    ) -> List[T]:
        """Create multiple entities in a single transaction.
        
        Args:
            entities: List of entities to create
            created_by: User creating the entities
            
        Returns:
            List of created entities
            
        Raises:
            ValueError: If validation fails
        """
        # Validate all entities first
        if self.validate:
            for i, entity in enumerate(entities):
                result = ModelValidator.validate_model(entity)
                if not result.is_valid:
                    raise ValueError(
                        f"Validation failed for entity {i}: {', '.join(result.errors)}"
                    )
        
        # Set audit fields
        if created_by:
            for entity in entities:
                if hasattr(entity, 'created_by'):
                    entity.created_by = created_by
                    entity.updated_by = created_by
        
        try:
            self.session.add_all(entities)
            await self.session.commit()
            
            # Refresh all entities
            for entity in entities:
                await self.session.refresh(entity)
            
            return entities
        except IntegrityError as e:
            await self.session.rollback()
            raise IntegrityError(f"Database constraint violation: {str(e)}", None, None)
        except Exception:
            await self.session.rollback()
            raise
    
    async def bulk_update(
        self,
        filters: Dict[str, Any],
        updates: Dict[str, Any],
        updated_by: Optional[str] = None
    ) -> int:
        """Update multiple entities matching filters.
        
        Args:
            filters: Filter criteria
            updates: Fields to update
            updated_by: User updating the entities
            
        Returns:
            Number of entities updated
        """
        # Get entities to update
        entities = await self.list(filters=filters, limit=10000)
        
        if not entities:
            return 0
        
        # Apply updates to each entity
        for entity in entities:
            for key, value in updates.items():
                if hasattr(entity, key):
                    setattr(entity, key, value)
            
            if updated_by and hasattr(entity, 'updated_by'):
                entity.updated_by = updated_by
            
            if hasattr(entity, 'version'):
                entity.version += 1
        
        try:
            await self.session.commit()
            return len(entities)
        except Exception:
            await self.session.rollback()
            raise
    
    async def bulk_delete(
        self,
        filters: Dict[str, Any],
        soft: bool = True,
        deleted_by: Optional[str] = None
    ) -> int:
        """Delete multiple entities matching filters.
        
        Args:
            filters: Filter criteria
            soft: Whether to soft delete
            deleted_by: User deleting the entities
            
        Returns:
            Number of entities deleted
        """
        # Get entities to delete
        entities = await self.list(filters=filters, limit=10000)
        
        if not entities:
            return 0
        
        if soft and hasattr(self.model, 'is_deleted'):
            # Soft delete
            for entity in entities:
                entity.is_deleted = True
                if deleted_by and hasattr(entity, 'updated_by'):
                    entity.updated_by = deleted_by
                if hasattr(entity, 'version'):
                    entity.version += 1
        else:
            # Hard delete
            for entity in entities:
                await self.session.delete(entity)
        
        try:
            await self.session.commit()
            return len(entities)
        except Exception:
            await self.session.rollback()
            raise
    
    async def find_one(self, filters: Dict[str, Any]) -> Optional[T]:
        """Find single entity matching filters.
        
        Args:
            filters: Filter criteria
            
        Returns:
            First matching entity or None
        """
        entities = await self.list(filters=filters, limit=1)
        return entities[0] if entities else None
    
    async def get_or_create(
        self,
        defaults: Dict[str, Any],
        **filters
    ) -> tuple[T, bool]:
        """Get existing entity or create new one.
        
        Args:
            defaults: Default values for creation
            **filters: Filter criteria
            
        Returns:
            Tuple of (entity, created)
        """
        entity = await self.find_one(filters)
        if entity:
            return entity, False
        
        # Create new entity
        params = dict(filters)
        params.update(defaults)
        new_entity = self.model(**params)
        created_entity = await self.create(new_entity)
        return created_entity, True
    
    @asynccontextmanager
    async def transaction(self):
        """Context manager for explicit transaction handling.
        
        Usage:
            async with repo.transaction():
                await repo.create(entity1)
                await repo.create(entity2)
        """
        async with self.session.begin():
            yield self.session


# Export main components
__all__ = [
    "IRepository",
    "BaseRepository"
]