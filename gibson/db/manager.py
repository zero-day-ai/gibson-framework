"""Enhanced database manager for Gibson Framework with repository support."""

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional, Type, TypeVar

from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.future import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import text, pool

from gibson.db.base import Base, BaseDBModel
from gibson.db.utils.schema_validator import SchemaValidator
from gibson.db.repositories.factory import RepositoryFactory, get_repository_factory
from gibson.db.utils.transaction import TransactionManager

T = TypeVar("T", bound=BaseDBModel)


def convert_to_async_url(database_url: str) -> str:
    """Convert database URL to async-compatible format.

    Args:
        database_url: Database URL (e.g., 'sqlite:///path/to/db.db')

    Returns:
        Async-compatible database URL (e.g., 'sqlite+aiosqlite:///path/to/db.db')
    """
    if database_url.startswith("sqlite://") and "+aiosqlite" not in database_url:
        # Convert sqlite:// to sqlite+aiosqlite://
        url = database_url.replace("sqlite://", "sqlite+aiosqlite://")
    elif database_url.startswith("sqlite:") and not database_url.startswith("sqlite://"):
        # Handle sqlite:filename format
        url = database_url.replace("sqlite:", "sqlite+aiosqlite://")
    else:
        url = database_url
    
    # Expand ~ to home directory
    if "~" in url:
        from pathlib import Path
        url_parts = url.split("///")
        if len(url_parts) > 1:
            path_part = url_parts[1]
            if path_part.startswith("~"):
                expanded_path = str(Path(path_part).expanduser().resolve())
                url = f"{url_parts[0]}///{expanded_path}"
    
    return url


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
    """Enhanced async database manager with repository and transaction support."""

    def __init__(
        self,
        database_url: str,
        validate_on_init: bool = True,
        pool_size: int = 5,
        max_overflow: int = 10,
        pool_timeout: int = 30,
        echo: bool = False
    ) -> None:
        """Initialize enhanced database manager.
        
        Args:
            database_url: Database connection URL
            validate_on_init: Whether to validate schema on initialization
            pool_size: Number of connections to maintain in pool
            max_overflow: Maximum overflow connections allowed
            pool_timeout: Timeout for getting connection from pool
            echo: Whether to echo SQL statements
        """
        # BULLETPROOF: Initialize directory system first
        self._initialize_gibson_directory()
        
        # BULLETPROOF: Import all models to ensure table registration
        try:
            import gibson.db.models  # This triggers all model imports
            logger.debug("All database models imported and registered")
        except ImportError as e:
            logger.error(f"Failed to import database models: {e}")
        
        # Ensure usage tracking tables are registered early
        try:
            from gibson.core.llm.table_registry import register_usage_tracking_tables
            register_usage_tracking_tables()
            logger.debug("Usage tracking tables registered successfully")
        except ImportError:
            logger.debug("Usage tracking tables not available")

        # Convert to async-compatible URL format and force ~/.gibson
        self.database_url = self._ensure_canonical_database_path(convert_to_async_url(database_url))
        self.validate_on_init = validate_on_init

        # Check if async driver is available, provide helpful error if not
        if not is_async_driver_available() and self.database_url.startswith("sqlite+aiosqlite://"):
            logger.warning(
                "aiosqlite not available. Install with: pip install aiosqlite. "
                "Falling back to synchronous operations may cause test failures."
            )

        # Configure connection pooling
        pool_config = {}
        if not self.database_url.startswith("sqlite"):
            # SQLite doesn't support these pooling options
            pool_config = {
                "poolclass": pool.AsyncAdaptedQueuePool,
                "pool_size": pool_size,
                "max_overflow": max_overflow,
                "pool_timeout": pool_timeout,
                "pool_recycle": 3600,  # Recycle connections after 1 hour
                "pool_pre_ping": True,  # Test connections before using
            }

        self.engine = create_async_engine(
            self.database_url,
            echo=echo,
            **pool_config
        )
        
        self.session_factory = async_sessionmaker(
            self.engine, class_=AsyncSession, expire_on_commit=False
        )
        
        # Initialize repository factory
        self._repository_factory = RepositoryFactory()
        self._repository_factory.set_session_factory(self.get_session)
        
        # Register repositories
        self._register_repositories()

    async def initialize(self, auto_migrate: bool = True, force_create_missing: bool = True) -> None:
        """Initialize database tables and check for migrations.

        Args:
            auto_migrate: Whether to automatically apply pending migrations
            force_create_missing: Whether to create missing tables directly
        """
        try:
            # Ensure database directory exists
            await self._ensure_database_directory()
            
            # Check if Alembic is configured
            alembic_ini = Path(__file__).parent.parent.parent / "alembic.ini"
            if alembic_ini.exists():
                # Use Alembic for migrations
                from gibson.core.migrations import MigrationManager

                manager = MigrationManager()
                try:
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
                except Exception as migration_error:
                    logger.warning(f"Migration system failed: {migration_error}")
                    if force_create_missing:
                        await self._create_tables_directly()
            else:
                # Fall back to creating tables directly (development/testing)
                logger.debug("Alembic not configured, creating tables directly")
                await self._create_tables_directly()

        except Exception as e:
            logger.warning(f"Could not initialize via migrations: {e}. Creating tables directly.")
            if force_create_missing:
                await self._create_tables_directly()
        
        # Handle missing tables that weren't created by migrations
        if force_create_missing:
            await self._create_missing_tables()
        
        # BULLETPROOF: Enhanced schema validation with auto-fix
        if self.validate_on_init:
            validation_passed = await self.validate_schema(fix_missing=True)
            if not validation_passed:
                logger.error("Schema validation failed even after attempting to create missing tables")
            else:
                logger.info("Database schema validation completed successfully")

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
        """Test database connection with bulletproof error handling.

        Returns:
            True if connection successful, False otherwise
        """
        try:
            logger.debug("Testing database connection...")
            
            # First test engine connection
            async with self.engine.begin() as conn:
                result = await conn.execute(text("SELECT 1"))
                test_value = result.scalar()
                if test_value != 1:
                    logger.error(f"Connection test returned unexpected value: {test_value}")
                    return False
            
            # Test session factory
            async with self.session_factory() as session:
                result = await session.execute(select(1))
                test_value = result.scalar()
                if test_value != 1:
                    logger.error(f"Session test returned unexpected value: {test_value}")
                    return False
            
            logger.debug("Database connection test passed")
            return True
            
        except Exception as e:
            logger.error(f"Database connection test failed: {e}")
            
            # Try to provide more specific error information
            if "no such file" in str(e).lower():
                logger.error("Database file does not exist - may need initialization")
            elif "permission denied" in str(e).lower():
                logger.error("Database file permission denied - check file permissions")
            elif "locked" in str(e).lower():
                logger.error("Database is locked - another process may be using it")
                
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
                    result = await session.execute(text(f"SELECT COUNT(*) FROM {table}"))
                    count = result.scalar()
                    stats[table] = count or 0
                except Exception as e:
                    logger.debug(f"Could not get count for table {table}: {e}")
                    stats[table] = 0
        return stats
    
    async def validate_schema(self, fix_missing: bool = False) -> bool:
        """Validate database schema against models with bulletproof validation.
        
        Args:
            fix_missing: Whether to automatically create missing tables
        
        Returns:
            True if schema is valid, False otherwise
        """
        try:
            # BULLETPROOF: Check if database file exists for SQLite
            if self.database_url.startswith("sqlite"):
                url_parts = self.database_url.split("///")
                if len(url_parts) > 1:
                    from pathlib import Path
                    db_path = Path(url_parts[1])
                    if not db_path.exists():
                        logger.warning(f"Database file does not exist: {db_path}")
                        if fix_missing:
                            # Trigger table creation
                            await self._create_tables_directly()
                            logger.info(f"Created database file: {db_path}")
                        else:
                            return False
            
            validator = SchemaValidator()
            async with self.session_factory() as session:
                result = await validator.validate_schema(session)
                
                if not result.is_valid:
                    logger.error(f"Schema validation failed: {result.error_messages}")
                    if result.missing_tables:
                        logger.error(f"Missing tables: {', '.join(result.missing_tables)}")
                        if fix_missing:
                            logger.info("Attempting to create missing tables...")
                            await self._create_missing_tables()
                            # Re-validate after creating tables
                            result = await validator.validate_schema(session)
                            if result.is_valid:
                                logger.info("Schema validation passed after creating missing tables")
                                return True
                    return False
                    
                logger.info(f"Schema validation passed: {len(result.actual_tables)} tables present")
                return True
                
        except Exception as e:
            logger.error(f"Failed to validate schema: {e}")
            return False
    
    def _register_repositories(self) -> None:
        """Register all repository mappings."""
        try:
            # Import repositories
            from gibson.db.repositories.target import TargetRepository
            from gibson.db.repositories.module import ModuleRepository, ModuleResultRepository
            from gibson.db.repositories.scan import ScanRepository, FindingRepository
            from gibson.db.models.target import Target
            from gibson.db.models.scan import (
                ModuleRecord, ModuleResultRecord,
                ScanRecord, FindingRecord
            )
            
            # Register repository mappings
            self._repository_factory.bulk_register({
                Target: TargetRepository,
                ModuleRecord: ModuleRepository,
                ModuleResultRecord: ModuleResultRepository,
                ScanRecord: ScanRepository,
                FindingRecord: FindingRepository
            })
            
            logger.debug("Registered all repository mappings")
        except ImportError as e:
            logger.warning(f"Could not register all repositories: {e}")
    
    def get_repository(self, model: Type[T]) -> Any:
        """Get repository for a model.
        
        Args:
            model: Model class
            
        Returns:
            Repository instance
        """
        return self._repository_factory.get(model)
    
    @asynccontextmanager
    async def session(self):
        """Bulletproof context manager for database session with comprehensive error handling.
        
        Yields:
            AsyncSession instance
        """
        session = None
        try:
            session = self.session_factory()
            logger.debug("Created new database session")
            yield session
            await session.commit()
            logger.debug("Database session committed successfully")
        except Exception as e:
            if session:
                try:
                    await session.rollback()
                    logger.debug(f"Database session rolled back due to error: {e}")
                except Exception as rollback_error:
                    logger.error(f"Failed to rollback session: {rollback_error}")
            raise
        finally:
            if session:
                try:
                    await session.close()
                    logger.debug("Database session closed")
                except Exception as close_error:
                    logger.error(f"Failed to close session: {close_error}")
    
    @asynccontextmanager
    async def transaction(self):
        """Context manager for database transaction with automatic retry.
        
        Yields:
            TransactionManager instance
        """
        async with self.session_factory() as session:
            manager = TransactionManager(session)
            async with manager.atomic():
                yield manager
    
    async def _ensure_database_directory(self) -> None:
        """Ensure database directory exists for SQLite databases."""
        if self.database_url.startswith("sqlite"):
            # BULLETPROOF: Always ensure ~/.gibson exists for database
            gibson_dir = Path.home() / ".gibson"
            gibson_dir.mkdir(parents=True, exist_ok=True)
            logger.debug(f"Ensured ~/.gibson directory exists: {gibson_dir}")
            
            # Extract database path and ensure its parent directory exists
            url_parts = self.database_url.split("///")
            if len(url_parts) > 1:
                db_path = Path(url_parts[1])
                db_dir = db_path.parent
                if db_dir != Path("."):
                    db_dir.mkdir(parents=True, exist_ok=True)
                    logger.debug(f"Ensured database directory exists: {db_dir}")
                    
                logger.info(f"Database file will be: {db_path}")
    
    async def _create_tables_directly(self) -> None:
        """Create all tables directly using SQLAlchemy metadata with bulletproof error handling."""
        try:
            table_count = len(Base.metadata.tables)
            logger.info(f"Creating {table_count} database tables directly from metadata")
            
            # List all tables that will be created for debugging
            table_names = list(Base.metadata.tables.keys())
            logger.debug(f"Tables to create: {', '.join(table_names)}")
            
            async with self.engine.begin() as conn:
                def create_tables_sync(sync_conn):
                    Base.metadata.create_all(sync_conn, checkfirst=True)
                    
                await conn.run_sync(create_tables_sync)
            
            logger.info(f"Successfully created {table_count} database tables")
            
            # Verify tables were actually created
            async with self.session_factory() as session:
                for table_name in table_names:
                    try:
                        result = await session.execute(text(f"SELECT 1 FROM {table_name} LIMIT 1"))
                        logger.debug(f"Verified table exists: {table_name}")
                    except Exception as e:
                        logger.error(f"Table creation verification failed for {table_name}: {e}")
                        
        except Exception as e:
            logger.error(f"Failed to create tables directly: {e}")
            raise
    
    async def _create_missing_tables(self) -> None:
        """Create any missing tables that should exist with bulletproof error handling."""
        try:
            # Get missing tables by direct validation
            from gibson.db.utils.schema_validator import SchemaValidator
            validator = SchemaValidator()
            async with self.session_factory() as session:
                result = await validator.validate_schema(session)
                missing = result.missing_tables if hasattr(result, 'missing_tables') else []
            
            if not missing:
                logger.debug("No missing tables detected")
                return
                
            logger.warning(f"Found {len(missing)} missing tables: {', '.join(missing)}")
            
            # Create missing tables individually for better error handling
            created_count = 0
            failed_tables = []
            
            async with self.engine.begin() as conn:
                for table_name in missing:
                    try:
                        if table_name in Base.metadata.tables:
                            table = Base.metadata.tables[table_name]
                            def create_single_table(sync_conn):
                                table.create(sync_conn, checkfirst=True)
                            
                            await conn.run_sync(create_single_table)
                            logger.debug(f"Created missing table: {table_name}")
                            created_count += 1
                            
                            # Verify table was created
                            try:
                                result = await session.execute(text(f"SELECT 1 FROM {table_name} LIMIT 1"))
                                logger.debug(f"Verified table creation: {table_name}")
                            except Exception as verify_error:
                                logger.warning(f"Table {table_name} created but verification failed: {verify_error}")
                                
                        else:
                            logger.error(f"Table '{table_name}' not found in metadata")
                            failed_tables.append(table_name)
                    except Exception as table_error:
                        logger.error(f"Failed to create table {table_name}: {table_error}")
                        failed_tables.append(table_name)
            
            if created_count > 0:
                logger.info(f"Successfully created {created_count}/{len(missing)} missing tables")
            
            if failed_tables:
                logger.error(f"Failed to create tables: {', '.join(failed_tables)}")
                
        except Exception as e:
            logger.error(f"Failed to create missing tables: {e}")
            raise
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform comprehensive bulletproof health check.
        
        Returns:
            Dictionary with detailed health status information
        """
        health = {
            "status": "unknown",
            "timestamp": datetime.utcnow().isoformat(),
            "database_url": self.database_url.split("@")[-1] if "@" in self.database_url else self.database_url,
            "checks": {},
            "details": {},
            "recommendations": []
        }
        
        # Check 1: Database file existence (for SQLite)
        if self.database_url.startswith("sqlite"):
            try:
                url_parts = self.database_url.split("///")
                if len(url_parts) > 1:
                    from pathlib import Path
                    db_path = Path(url_parts[1])
                    file_exists = db_path.exists()
                    health["checks"]["database_file"] = "exists" if file_exists else "missing"
                    health["details"]["database_path"] = str(db_path)
                    health["details"]["file_size"] = db_path.stat().st_size if file_exists else 0
                    
                    if not file_exists:
                        health["recommendations"].append("Database file does not exist - run initialization")
            except Exception as e:
                health["checks"]["database_file"] = f"error: {str(e)}"
        
        # Check 2: Connection test
        connection_ok = await self.test_connection()
        health["checks"]["connection"] = "ok" if connection_ok else "failed"
        
        if not connection_ok:
            health["recommendations"].append("Database connection failed - check configuration and permissions")
        
        # Check 3: Pool status (if applicable)
        try:
            if hasattr(self.engine.pool, "size"):
                pool_info = {
                    "size": self.engine.pool.size(),
                    "checked_in": self.engine.pool.checkedin(),
                    "checked_out": self.engine.pool.checkedout(),
                    "overflow": self.engine.pool.overflow(),
                    "total": getattr(self.engine.pool, 'total', lambda: 0)()
                }
                health["checks"]["connection_pool"] = "ok"
                health["details"]["pool"] = pool_info
                
                # Pool health recommendations
                if pool_info["checked_out"] > pool_info["size"] * 0.8:
                    health["recommendations"].append("High connection pool usage - consider increasing pool size")
            else:
                health["checks"]["connection_pool"] = "not_available"
        except Exception as e:
            health["checks"]["connection_pool"] = f"error: {str(e)}"
        
        # Check 4: Table existence and stats
        try:
            stats = await self.get_table_stats()
            health["checks"]["tables"] = "ok"
            health["details"]["tables"] = {
                "count": len(stats),
                "total_records": sum(stats.values()),
                "table_stats": stats
            }
            
            if len(stats) == 0:
                health["recommendations"].append("No tables found - database may need initialization")
            elif any(count == 0 for count in stats.values()):
                empty_tables = [name for name, count in stats.items() if count == 0]
                health["details"]["empty_tables"] = empty_tables
                
        except Exception as e:
            health["checks"]["tables"] = f"error: {str(e)}"
            health["recommendations"].append("Cannot access database tables - check schema and permissions")
        
        # Check 5: Schema validation
        try:
            schema_valid = await self.validate_schema(fix_missing=False)
            health["checks"]["schema"] = "valid" if schema_valid else "invalid"
            
            if not schema_valid:
                health["recommendations"].append("Schema validation failed - run migration or table creation")
        except Exception as e:
            health["checks"]["schema"] = f"error: {str(e)}"
            health["recommendations"].append("Schema validation error - check database structure")
        
        # Check 6: Model registration
        try:
            expected_models = [
                "payloads", "payload_collections", "payload_sources",
                "scans", "modules", "module_results", "findings", "targets"
            ]
            registered_tables = set(Base.metadata.tables.keys())
            health["details"]["registered_tables"] = list(registered_tables)
            
            missing_models = set(expected_models) - registered_tables
            if missing_models:
                health["checks"]["models"] = "incomplete"
                health["details"]["missing_models"] = list(missing_models)
                health["recommendations"].append(f"Missing model registrations: {', '.join(missing_models)}")
            else:
                health["checks"]["models"] = "ok"
                
        except Exception as e:
            health["checks"]["models"] = f"error: {str(e)}"
        
        # Overall status determination
        failed_checks = [k for k, v in health["checks"].items() if v not in ["ok", "valid", "exists", "not_available"]]
        critical_checks = ["connection", "schema", "tables"]
        critical_failures = [check for check in failed_checks if check in critical_checks]
        
        if not critical_failures:
            if not failed_checks:
                health["status"] = "healthy"
            else:
                health["status"] = "degraded"
                health["details"]["non_critical_issues"] = failed_checks
        else:
            health["status"] = "unhealthy"
            health["details"]["critical_failures"] = critical_failures
        
        # Add summary
        health["summary"] = {
            "total_checks": len(health["checks"]),
            "passed_checks": len([v for v in health["checks"].values() if v in ["ok", "valid", "exists"]]),
            "failed_checks": len(failed_checks),
            "recommendations_count": len(health["recommendations"])
        }
        
        return health
    
    async def get_pool_status(self) -> Dict[str, Any]:
        """Get connection pool status.
        
        Returns:
            Dictionary with pool statistics
        """
        if not hasattr(self.engine.pool, "size"):
            return {"message": "Connection pooling not available for this database"}
        
        return {
            "size": self.engine.pool.size(),
            "checked_in": self.engine.pool.checkedin(),
            "checked_out": self.engine.pool.checkedout(),
            "overflow": self.engine.pool.overflow(),
            "total": self.engine.pool.total(),
            "max_overflow": getattr(self.engine.pool, '_max_overflow', None)
        }
    
    def _initialize_gibson_directory(self) -> None:
        """Initialize ~/.gibson directory structure."""
        gibson_dir = Path.home() / ".gibson"
        gibson_dir.mkdir(parents=True, exist_ok=True)
        
        # Create essential subdirectories
        for subdir in ["data", "cache", "modules", "backups"]:
            (gibson_dir / subdir).mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Initialized Gibson directory structure at: {gibson_dir}")
    
    def _ensure_canonical_database_path(self, database_url: str) -> str:
        """Force database to use canonical ~/.gibson/gibson.db path."""
        gibson_dir = Path.home() / ".gibson"
        canonical_db_path = gibson_dir / "gibson.db"
        canonical_url = f"sqlite+aiosqlite:///{canonical_db_path}"
        
        if database_url != canonical_url and database_url.startswith("sqlite"):
            logger.info(f"Forcing database from '{database_url}' to canonical path: '{canonical_url}'")
            return canonical_url
        
        return database_url


# Export the manager and utilities
__all__ = [
    "DatabaseManager",
    "convert_to_async_url",
    "is_async_driver_available",
]
