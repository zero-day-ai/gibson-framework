"""Base database models and utilities for Gibson framework."""

from datetime import datetime
from typing import Any, Dict, List, Optional, Type, TypeVar
from uuid import uuid4

from pydantic import BaseModel as PydanticBaseModel
from sqlalchemy import Boolean, Column, DateTime, Integer, String, func
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session

# Single Base instance for all models
Base = declarative_base()

# Type variable for generic database operations
T = TypeVar("T", bound="BaseDBModel")


class BaseDBModel(Base):
    """Enhanced base database model with audit and versioning fields."""

    __abstract__ = True

    # Primary key - use string UUID for better SQLite compatibility
    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    
    # Timestamp fields - use Python datetime for SQLite compatibility
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    # Audit fields
    created_by = Column(String(100), nullable=True)
    updated_by = Column(String(100), nullable=True)
    
    # Versioning and soft delete
    version = Column(Integer, default=1, nullable=False)
    is_deleted = Column(Boolean, default=False, nullable=False)
    
    def to_dict(self, exclude_deleted: bool = True) -> Dict[str, Any]:
        """Convert model instance to dictionary.
        
        Args:
            exclude_deleted: Whether to exclude soft-deleted records
            
        Returns:
            Dictionary representation of model
        """
        if exclude_deleted and self.is_deleted:
            return {}
        
        result = {}
        for column in self.__table__.columns:
            value = getattr(self, column.name)
            # Handle UUID and datetime serialization
            if hasattr(value, 'hex'):  # UUID
                result[column.name] = str(value)
            elif isinstance(value, datetime):
                result[column.name] = value.isoformat()
            else:
                result[column.name] = value
        return result
    
    @classmethod
    def from_pydantic(cls: Type[T], model: PydanticBaseModel, **kwargs) -> T:
        """Create database model instance from Pydantic model.
        
        Args:
            model: Pydantic model instance
            **kwargs: Additional fields to set
            
        Returns:
            Database model instance
        """
        data = model.model_dump(exclude_unset=True)
        data.update(kwargs)
        return cls(**data)
    
    def validate(self) -> List[str]:
        """Validate model instance.
        
        Returns:
            List of validation error messages
        """
        errors = []
        
        # Check required fields
        for column in self.__table__.columns:
            if not column.nullable and column.default is None:
                value = getattr(self, column.name, None)
                if value is None:
                    errors.append(f"Required field '{column.name}' is missing")
        
        # Check version is positive
        if hasattr(self, 'version') and self.version is not None and self.version < 1:
            errors.append("Version must be positive")
        
        return errors
    
    def soft_delete(self, session: Session, deleted_by: Optional[str] = None) -> None:
        """Soft delete the record.
        
        Args:
            session: Database session
            deleted_by: User who deleted the record
        """
        self.is_deleted = True
        if deleted_by:
            self.updated_by = deleted_by
        self.version += 1
        session.add(self)
        session.commit()
    
    def restore(self, session: Session, restored_by: Optional[str] = None) -> None:
        """Restore a soft-deleted record.
        
        Args:
            session: Database session
            restored_by: User who restored the record
        """
        self.is_deleted = False
        if restored_by:
            self.updated_by = restored_by
        self.version += 1
        session.add(self)
        session.commit()


class TimestampMixin:
    """Mixin for adding timestamp fields to models."""

    created_at = Column(DateTime, default=func.now(), nullable=False)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), nullable=False)


class CRUDMixin:
    """Enhanced mixin providing CRUD operations with soft delete support."""

    @classmethod
    def create(cls: Type[T], session: Session, created_by: Optional[str] = None, **kwargs) -> T:
        """Create a new instance of the model.

        Args:
            session: Database session
            created_by: User creating the record
            **kwargs: Model field values

        Returns:
            Created model instance
        """
        if created_by and hasattr(cls, 'created_by'):
            kwargs['created_by'] = created_by
            kwargs['updated_by'] = created_by
        instance = cls(**kwargs)
        session.add(instance)
        session.commit()
        session.refresh(instance)
        return instance

    @classmethod
    def get(cls: Type[T], session: Session, include_deleted: bool = False, **filters) -> Optional[T]:
        """Get a single instance matching filters.

        Args:
            session: Database session
            include_deleted: Whether to include soft-deleted records
            **filters: Query filters

        Returns:
            Model instance or None
        """
        query = session.query(cls).filter_by(**filters)
        if not include_deleted and hasattr(cls, 'is_deleted'):
            query = query.filter_by(is_deleted=False)
        return query.first()

    @classmethod
    def get_or_create(
        cls: Type[T], session: Session, defaults: Optional[Dict[str, Any]] = None, **filters
    ) -> tuple[T, bool]:
        """Get existing instance or create new one.

        Args:
            session: Database session
            defaults: Default values for creation
            **filters: Query filters

        Returns:
            Tuple of (instance, created)
        """
        instance = cls.get(session, **filters)
        if instance:
            return instance, False

        params = dict(filters)
        if defaults:
            params.update(defaults)
        instance = cls.create(session, **params)
        return instance, True

    def update(self, session: Session, updated_by: Optional[str] = None, **kwargs) -> None:
        """Update model instance fields with version increment.

        Args:
            session: Database session
            updated_by: User updating the record
            **kwargs: Fields to update
        """
        for key, value in kwargs.items():
            setattr(self, key, value)
        
        # Update audit fields
        if updated_by and hasattr(self, 'updated_by'):
            self.updated_by = updated_by
        
        # Increment version for optimistic locking
        if hasattr(self, 'version'):
            self.version += 1
            
        session.add(self)
        session.commit()
        session.refresh(self)

    def delete(self, session: Session, soft: bool = True, deleted_by: Optional[str] = None) -> None:
        """Delete model instance (soft or hard delete).

        Args:
            session: Database session
            soft: Whether to soft delete (default) or hard delete
            deleted_by: User deleting the record (for soft delete)
        """
        if soft and hasattr(self, 'is_deleted'):
            self.soft_delete(session, deleted_by)
        else:
            session.delete(self)
            session.commit()

    @classmethod
    def all(cls: Type[T], session: Session, include_deleted: bool = False) -> list[T]:
        """Get all instances of the model.

        Args:
            session: Database session
            include_deleted: Whether to include soft-deleted records

        Returns:
            List of all model instances
        """
        query = session.query(cls)
        if not include_deleted and hasattr(cls, 'is_deleted'):
            query = query.filter_by(is_deleted=False)
        return query.all()

    @classmethod
    def filter(cls: Type[T], session: Session, include_deleted: bool = False, **filters) -> list[T]:
        """Filter instances by criteria.

        Args:
            session: Database session
            include_deleted: Whether to include soft-deleted records
            **filters: Query filters

        Returns:
            List of matching instances
        """
        query = session.query(cls).filter_by(**filters)
        if not include_deleted and hasattr(cls, 'is_deleted'):
            query = query.filter_by(is_deleted=False)
        return query.all()

    @classmethod
    def count(cls: Type[T], session: Session, include_deleted: bool = False, **filters) -> int:
        """Count instances matching filters.

        Args:
            session: Database session
            include_deleted: Whether to include soft-deleted records
            **filters: Query filters

        Returns:
            Count of matching instances
        """
        query = session.query(cls)
        if filters:
            query = query.filter_by(**filters)
        if not include_deleted and hasattr(cls, 'is_deleted'):
            query = query.filter_by(is_deleted=False)
        return query.count()



# Export all base components
__all__ = [
    "Base",
    "BaseDBModel",
    "TimestampMixin",
    "CRUDMixin",
]
