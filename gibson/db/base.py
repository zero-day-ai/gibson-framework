"""Base database models and utilities for Gibson framework."""

from datetime import datetime
from typing import Any, Dict, Optional, Type, TypeVar

from sqlalchemy import Column, DateTime, Integer, String, func
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session

# Single Base instance for all models
Base = declarative_base()

# Type variable for generic database operations
T = TypeVar('T', bound='BaseDBModel')


class BaseDBModel(Base):
    """Base database model with common fields."""
    __abstract__ = True
    
    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=func.gen_random_uuid())
    created_at = Column(DateTime, default=func.now(), nullable=False)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), nullable=False)


class TimestampMixin:
    """Mixin for adding timestamp fields to models."""
    created_at = Column(DateTime, default=func.now(), nullable=False)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), nullable=False)


class CRUDMixin:
    """Mixin providing basic CRUD operations for models."""
    
    @classmethod
    def create(cls: Type[T], session: Session, **kwargs) -> T:
        """Create a new instance of the model.
        
        Args:
            session: Database session
            **kwargs: Model field values
            
        Returns:
            Created model instance
        """
        instance = cls(**kwargs)
        session.add(instance)
        session.commit()
        session.refresh(instance)
        return instance
    
    @classmethod
    def get(cls: Type[T], session: Session, **filters) -> Optional[T]:
        """Get a single instance matching filters.
        
        Args:
            session: Database session
            **filters: Query filters
            
        Returns:
            Model instance or None
        """
        return session.query(cls).filter_by(**filters).first()
    
    @classmethod
    def get_or_create(cls: Type[T], session: Session, defaults: Optional[Dict[str, Any]] = None, **filters) -> tuple[T, bool]:
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
    
    def update(self, session: Session, **kwargs) -> None:
        """Update model instance fields.
        
        Args:
            session: Database session
            **kwargs: Fields to update
        """
        for key, value in kwargs.items():
            setattr(self, key, value)
        session.add(self)
        session.commit()
        session.refresh(self)
    
    def delete(self, session: Session) -> None:
        """Delete model instance.
        
        Args:
            session: Database session
        """
        session.delete(self)
        session.commit()
    
    @classmethod
    def all(cls: Type[T], session: Session) -> list[T]:
        """Get all instances of the model.
        
        Args:
            session: Database session
            
        Returns:
            List of all model instances
        """
        return session.query(cls).all()
    
    @classmethod
    def filter(cls: Type[T], session: Session, **filters) -> list[T]:
        """Filter instances by criteria.
        
        Args:
            session: Database session
            **filters: Query filters
            
        Returns:
            List of matching instances
        """
        return session.query(cls).filter_by(**filters).all()
    
    @classmethod
    def count(cls: Type[T], session: Session, **filters) -> int:
        """Count instances matching filters.
        
        Args:
            session: Database session
            **filters: Query filters
            
        Returns:
            Count of matching instances
        """
        query = session.query(cls)
        if filters:
            query = query.filter_by(**filters)
        return query.count()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert model instance to dictionary.
        
        Returns:
            Dictionary representation of model
        """
        return {
            column.name: getattr(self, column.name)
            for column in self.__table__.columns
        }


# Export all base components
__all__ = [
    'Base',
    'BaseDBModel',
    'TimestampMixin',
    'CRUDMixin',
]