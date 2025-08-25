"""Database manager for Gibson Framework using consolidated models."""

import asyncio
from pathlib import Path
from typing import Any, Dict, List, Optional

from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.future import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import text

from gibson.db.base import Base


def convert_to_async_url(database_url: str) -> str:
    """Convert database URL to async-compatible format.
    
    Args:
        database_url: Database URL (e.g., 'sqlite:///path/to/db.db')
        
    Returns:
        Async-compatible database URL (e.g., 'sqlite+aiosqlite:///path/to/db.db')
    """
    if database_url.startswith("sqlite://") and "+aiosqlite" not in database_url:
        # Convert sqlite:// to sqlite+aiosqlite://
        return database_url.replace("sqlite://", "sqlite+aiosqlite://")
    return database_url


def is_async_driver_available() -> bool:
    """Check if aiosqlite driver is available.
    
    Returns:
        True if aiosqlite is available, False otherwise
    """
    try:
        import aiosqlite
        return True
    except ImportError:
        return False


class DatabaseManager:
    """Async database manager for Gibson Framework."""
    
    def __init__(self, database_url: str) -> None:
        """Initialize database manager."""
        # Ensure usage tracking tables are registered
        try:
            from gibson.core.llm.table_registry import register_usage_tracking_tables
            register_usage_tracking_tables()
        except ImportError:
            logger.debug("Usage tracking tables not available")
        
        # Convert to async-compatible URL format
        self.database_url = convert_to_async_url(database_url)
        
        # Check if async driver is available, provide helpful error if not
        if not is_async_driver_available() and self.database_url.startswith("sqlite+aiosqlite://"):
            logger.warning(
                "aiosqlite not available. Install with: pip install aiosqlite. "
                "Falling back to synchronous operations may cause test failures."
            )
            
        self.engine = create_async_engine(self.database_url, echo=False)
        self.session_factory = async_sessionmaker(
            self.engine, class_=AsyncSession, expire_on_commit=False
        )
    
    async def initialize(self, auto_migrate: bool = True) -> None:
        """Initialize database tables and check for migrations.
        
        Args:
            auto_migrate: Whether to automatically apply pending migrations
        """
        try:
            # Check if Alembic is configured
            alembic_ini = Path(__file__).parent.parent.parent / "alembic.ini"
            if alembic_ini.exists():
                # Use Alembic for migrations
                from gibson.core.migrations import MigrationManager
                
                manager = MigrationManager()
                status = await manager.get_status()
                
                if status.needs_migration:
                    if auto_migrate:
                        logger.info("Pending migrations detected, applying automatically...")
                        await manager.auto_upgrade()
                    else:
                        logger.warning(
                            f"Database needs migration: {status.pending_count} pending migrations. "
                            f"Run 'gibson db upgrade' to apply migrations."
                        )
                else:
                    logger.debug("Database schema is up to date")
            else:
                # Fall back to creating tables directly (development/testing)
                logger.debug("Alembic not configured, creating tables directly")
                async with self.engine.begin() as conn:
                    await conn.run_sync(Base.metadata.create_all)
                    
        except Exception as e:
            logger.warning(f"Could not check migrations: {e}. Creating tables directly.")
            async with self.engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
    
    def get_session(self) -> AsyncSession:
        """Get a new database session.
        
        Returns:
            New AsyncSession instance
        """
        return self.session_factory()
    
    async def close(self) -> None:
        """Close database connections."""
        await self.engine.dispose()
    
    async def test_connection(self) -> bool:
        """Test database connection.
        
        Returns:
            True if connection successful, False otherwise
        """
        try:
            async with self.session_factory() as session:
                await session.execute(select(1))
            return True
        except Exception as e:
            logger.error(f"Database connection test failed: {e}")
            return False
    
    async def get_table_stats(self) -> Dict[str, int]:
        """Get count of records in each table.
        
        Returns:
            Dictionary mapping table names to record counts
        """
        stats = {}
        async with self.session_factory() as session:
            for table in Base.metadata.tables.keys():
                try:
                    result = await session.execute(
                        text(f"SELECT COUNT(*) FROM {table}")
                    )
                    count = result.scalar()
                    stats[table] = count or 0
                except Exception as e:
                    logger.debug(f"Could not get count for table {table}: {e}")
                    stats[table] = 0
        return stats


# Export the manager and utilities
__all__ = [
    'DatabaseManager',
    'convert_to_async_url',
    'is_async_driver_available',
]