"""Database schema validation utility for Gibson framework."""

import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from sqlalchemy import inspect, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import DeclarativeBase

from gibson.db import Base

logger = logging.getLogger(__name__)


class ValidationResult(BaseModel):
    """Result of database schema validation."""
    
    is_valid: bool = Field(description="Whether the schema is valid")
    expected_tables: List[str] = Field(default_factory=list, description="Tables expected from models")
    actual_tables: List[str] = Field(default_factory=list, description="Tables found in database")
    missing_tables: List[str] = Field(default_factory=list, description="Expected tables not found")
    extra_tables: List[str] = Field(default_factory=list, description="Unexpected tables in database")
    validation_timestamp: datetime = Field(default_factory=datetime.utcnow)
    error_messages: List[str] = Field(default_factory=list, description="Validation error messages")


class SchemaValidator:
    """Validates database schema against SQLAlchemy models."""
    
    def __init__(self, base: Optional[DeclarativeBase] = None):
        """Initialize schema validator.
        
        Args:
            base: SQLAlchemy declarative base to use for validation.
                 Defaults to gibson.db.Base if not provided.
        """
        self.base = base or Base
        
    async def validate_schema(self, session: AsyncSession) -> ValidationResult:
        """Validate database schema against registered models.
        
        Args:
            session: Async database session
            
        Returns:
            ValidationResult with validation details
        """
        result = ValidationResult(is_valid=True)  # Initialize with default value
        
        try:
            # Get expected tables from SQLAlchemy metadata
            expected_tables = self._get_expected_tables()
            result.expected_tables = expected_tables
            
            # Get actual tables from database
            actual_tables = await self._get_actual_tables(session)
            result.actual_tables = actual_tables
            
            # Find missing and extra tables
            result.missing_tables = self._get_missing_tables(expected_tables, actual_tables)
            result.extra_tables = self._get_extra_tables(expected_tables, actual_tables)
            
            # Determine if schema is valid
            if result.missing_tables:
                result.is_valid = False
                result.error_messages.append(
                    f"Missing {len(result.missing_tables)} required tables: {', '.join(result.missing_tables)}"
                )
            else:
                result.is_valid = True
                
            if result.extra_tables:
                # Extra tables are a warning, not an error
                logger.warning(f"Found {len(result.extra_tables)} unexpected tables: {', '.join(result.extra_tables)}")
                
            logger.info(
                f"Schema validation complete: valid={result.is_valid}, "
                f"expected={len(result.expected_tables)}, "
                f"actual={len(result.actual_tables)}, "
                f"missing={len(result.missing_tables)}"
            )
            
        except Exception as e:
            logger.error(f"Schema validation failed: {e}")
            result.is_valid = False
            result.error_messages.append(f"Validation error: {str(e)}")
            
        return result
        
    def _get_expected_tables(self) -> List[str]:
        """Get list of expected table names from SQLAlchemy models.
        
        Returns:
            List of expected table names
        """
        tables = list(self.base.metadata.tables.keys())
        logger.debug(f"Expected tables from metadata: {tables}")
        return sorted(tables)
        
    async def _get_actual_tables(self, session: AsyncSession) -> List[str]:
        """Get list of actual tables in the database.
        
        Args:
            session: Async database session
            
        Returns:
            List of actual table names
        """
        # Use raw SQL to get table names (works for SQLite)
        query = text("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        result = await session.execute(query)
        tables = [row[0] for row in result.fetchall()]
        
        # Filter out alembic version table
        tables = [t for t in tables if t != 'alembic_version']
        
        logger.debug(f"Actual tables in database: {tables}")
        return sorted(tables)
        
    def _get_missing_tables(self, expected: List[str], actual: List[str]) -> List[str]:
        """Get list of missing tables.
        
        Args:
            expected: Expected table names
            actual: Actual table names
            
        Returns:
            List of missing table names
        """
        missing = sorted(set(expected) - set(actual))
        if missing:
            logger.warning(f"Missing tables: {missing}")
        return missing
        
    def _get_extra_tables(self, expected: List[str], actual: List[str]) -> List[str]:
        """Get list of extra/unexpected tables.
        
        Args:
            expected: Expected table names
            actual: Actual table names
            
        Returns:
            List of extra table names
        """
        extra = sorted(set(actual) - set(expected))
        if extra:
            logger.debug(f"Extra tables (not in models): {extra}")
        return extra
        
    async def get_table_row_counts(self, session: AsyncSession) -> Dict[str, int]:
        """Get row counts for all tables.
        
        Args:
            session: Async database session
            
        Returns:
            Dictionary mapping table names to row counts
        """
        counts = {}
        actual_tables = await self._get_actual_tables(session)
        
        for table in actual_tables:
            try:
                query = text(f"SELECT COUNT(*) FROM {table}")
                result = await session.execute(query)
                count = result.scalar()
                counts[table] = count or 0
            except Exception as e:
                logger.error(f"Failed to count rows in {table}: {e}")
                counts[table] = -1
                
        return counts
        
    async def check_critical_tables(self, session: AsyncSession, critical_tables: Optional[List[str]] = None) -> bool:
        """Check if critical tables exist.
        
        Args:
            session: Async database session
            critical_tables: List of critical table names. If None, uses default critical tables.
            
        Returns:
            True if all critical tables exist, False otherwise
        """
        if critical_tables is None:
            # Default critical tables for Gibson
            critical_tables = [
                'targets',
                'scans', 
                'findings',
                'modules',
                'payloads',
                'prompts'
            ]
            
        actual_tables = await self._get_actual_tables(session)
        missing_critical = [t for t in critical_tables if t not in actual_tables]
        
        if missing_critical:
            logger.error(f"Missing critical tables: {missing_critical}")
            return False
            
        logger.info(f"All critical tables present: {critical_tables}")
        return True


# Convenience functions
async def validate_schema(session: AsyncSession, base: Optional[DeclarativeBase] = None) -> ValidationResult:
    """Validate database schema.
    
    Args:
        session: Async database session
        base: Optional SQLAlchemy base to use
        
    Returns:
        ValidationResult
    """
    validator = SchemaValidator(base)
    return await validator.validate_schema(session)


async def get_missing_tables(session: AsyncSession, base: Optional[DeclarativeBase] = None) -> List[str]:
    """Get list of missing tables.
    
    Args:
        session: Async database session
        base: Optional SQLAlchemy base to use
        
    Returns:
        List of missing table names
    """
    result = await validate_schema(session, base)
    return result.missing_tables


async def get_extra_tables(session: AsyncSession, base: Optional[DeclarativeBase] = None) -> List[str]:
    """Get list of extra/unexpected tables.
    
    Args:
        session: Async database session
        base: Optional SQLAlchemy base to use
        
    Returns:
        List of extra table names
    """
    result = await validate_schema(session, base)
    return result.extra_tables