"""Gibson database models package - base classes and essential imports only.

This package provides base classes and utilities. 
Model registration is handled by gibson.db.models package to avoid circular imports.
"""

# Base classes and utilities only - no model imports to avoid circular dependencies
from gibson.db.base import Base, BaseDBModel, CRUDMixin, TimestampMixin

# Export only base classes to avoid circular imports
__all__ = [
    "Base",
    "BaseDBModel", 
    "CRUDMixin",
    "TimestampMixin",
]
