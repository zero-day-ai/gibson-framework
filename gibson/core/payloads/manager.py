"""Main payload management orchestrator."""

import asyncio
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession

from gibson.core.config import get_config
from gibson.db.manager import DatabaseManager
from .cache import PayloadCache
from .database import PayloadDatabase
from .git_sync import GitSync
from .git_models import GitURL
from .models.git_sync import CloneResult, UpdateResult, AuthMethod
from .organizer import PayloadOrganizer
from .url_parser import URLParser
from gibson.models.payload import PayloadModel
# PayloadCompatibilityAdapter removed - no longer needed with clean migration
from .types import PayloadQuery, ImportResult, SyncResult, PayloadMetrics


class PayloadManager:
    """Main orchestrator for payload management system.

    Coordinates between database, file system, cache, and remote repositories
    to provide a unified interface for payload operations.
    """

    def __init__(
        self,
        data_path: Optional[Path] = None,
        cache_size: int = 1000,
        cache_ttl_seconds: int = 3600,
    ):
        """Initialize payload manager.

        Args:
            data_path: Base path for payload storage
            cache_size: Maximum cache size
            cache_ttl_seconds: Cache TTL in seconds
        """
        self.config = get_config()

        # Set up data path
        if data_path:
            self.data_path = Path(data_path)
        else:
            # Use config.data_dir if available, otherwise use default
            data_dir = self.config.data_dir if self.config.data_dir else Path("gibson/data")
            self.data_path = Path(data_dir) / "payloads"

        # Initialize components
        self.organizer = PayloadOrganizer(self.data_path)
        self.cache = PayloadCache(max_size=cache_size, default_ttl_seconds=cache_ttl_seconds)
        self.url_parser = URLParser()

        # Set up workspace for Git operations
        self.workspace_dir = self.data_path / "repositories"
        self.workspace_dir.mkdir(parents=True, exist_ok=True)

        # Database and git sync will be initialized lazily
        self._db: Optional[PayloadDatabase] = None
        self._git_sync: Optional[GitSync] = None
        self._session: Optional[AsyncSession] = None

        # Track initialization state
        self._initialized = False

        logger.debug(f"PayloadManager initialized with data_path={self.data_path}")

    async def initialize(self) -> None:
        """Initialize async components."""
        if self._initialized:
            return

        try:
            # Get database session
            from gibson.models.config import DatabaseConfigModel

            config = DatabaseConfigModel()
            db_url = config.url.replace("~", str(Path.home()))
            db_manager = DatabaseManager(db_url)
            self._session = db_manager.get_session()
            self._db = PayloadDatabase(self._session)

            # Initialize cache background tasks
            await self.cache.start()

            self._initialized = True
            logger.info("PayloadManager initialized successfully")

        except Exception as e:
            logger.error(f"Failed to initialize PayloadManager: {e}")
            raise

    async def shutdown(self) -> None:
        """Shutdown and cleanup resources."""
        try:
            # Stop cache background tasks
            await self.cache.stop()

            # Close database session
            if self._session:
                await self._session.close()
                self._session = None

            # GitSync doesn't need explicit cleanup
            self._git_sync = None

            self._initialized = False
            logger.info("PayloadManager shutdown complete")

        except Exception as e:
            logger.error(f"Error during PayloadManager shutdown: {e}")

    async def __aenter__(self):
        """Async context manager entry."""
        await self.initialize()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.shutdown()

    async def _ensure_initialized(self) -> None:
        """Ensure manager is initialized."""
        if not self._initialized:
            await self.initialize()

    async def _get_db(self) -> PayloadDatabase:
        """Get database instance."""
        await self._ensure_initialized()
        return self._db

    async def _get_git_sync(self) -> GitSync:
        """Get GitSync instance."""
        if not self._git_sync:
            self._git_sync = GitSync(self.workspace_dir, shallow=True)
        return self._git_sync

    async def store_payload(self, payload: PayloadModel) -> int:
        """Store payload in system.

        Args:
            payload: PayloadModel to store

        Returns:
            Database ID of stored payload

        Raises:
            Exception: If storage fails
        """
        try:
            await self._ensure_initialized()

            # Store content to file system
            file_path = await self.organizer.store_payload(payload)
            # Note: file_path is not stored in PayloadModel, it's managed by organizer

            # Store metadata to database
            db = await self._get_db()
            payload_id = await db.store_payload(payload)

            # Cache the payload
            await self.cache.set_payload(payload)
            if payload.hash:
                await self.cache.set_payload_by_hash(payload.hash, payload)

            # Invalidate related query cache
            await self.cache.invalidate_query_cache()

            logger.info(f"Stored payload {payload.name} with ID {payload_id}")
            return payload_id

        except Exception as e:
            logger.error(f"Failed to store payload {payload.name}: {e}")
            raise

    async def get_payload_by_id(self, payload_id: int) -> Optional[PayloadModel]:
        """Get payload by database ID.

        Args:
            payload_id: Database ID

        Returns:
            Payload if found, None otherwise
        """
        try:
            await self._ensure_initialized()

            # Try cache first
            payload = await self.cache.get_payload(payload_id)
            if payload:
                return payload

            # Get from database
            db = await self._get_db()
            payload = await db.get_payload_by_id(payload_id)

            if payload:
                # Content is loaded from database, no file_path tracking in PayloadModel

                # Cache the payload
                await self.cache.set_payload(payload)

                return payload

            return None

        except Exception as e:
            logger.error(f"Failed to get payload {payload_id}: {e}")
            return None

    async def get_payload_by_hash(self, hash_value: str) -> Optional[PayloadModel]:
        """Get payload by content hash.

        Args:
            hash_value: Content hash

        Returns:
            Payload if found, None otherwise
        """
        try:
            await self._ensure_initialized()

            # Try cache first
            payload = await self.cache.get_payload_by_hash(hash_value)
            if payload:
                return payload

            # Get from database
            db = await self._get_db()
            payload = await db.get_payload_by_hash(hash_value)

            if payload:
                # Content is loaded from database, no file_path tracking in PayloadModel

                # Cache the payload
                await self.cache.set_payload_by_hash(hash_value, payload)

                return payload

            return None

        except Exception as e:
            logger.error(f"Failed to get payload by hash {hash_value}: {e}")
            return None

    async def query_payloads(self, query: PayloadQuery) -> Tuple[List[PayloadModel], int]:
        """Query payloads with filtering and pagination.

        Args:
            query: Query parameters

        Returns:
            Tuple of (payloads, total_count)
        """
        try:
            await self._ensure_initialized()

            # Try cache first for exact query matches
            cached_result = await self.cache.get_query_result(query)
            if cached_result:
                return cached_result

            # Query database
            db = await self._get_db()
            payloads, total_count = await db.query_payloads(query)

            # Load content from file system for payloads that need it
            for payload in payloads:
                if payload.file_path and not payload.content:
                    try:
                        content = await self.organizer.load_payload_content(payload.file_path)
                        payload.content = content
                    except FileNotFoundError:
                        logger.warning(f"Payload file not found: {payload.file_path}")

            # Cache the result
            await self.cache.set_query_result(query, payloads, total_count)

            # Cache individual payloads
            for payload in payloads:
                await self.cache.set_payload(payload)
                if payload.hash:
                    await self.cache.set_payload_by_hash(payload.hash, payload)

            return payloads, total_count

        except Exception as e:
            logger.error(f"Failed to query payloads: {e}")
            return [], 0

    async def update_payload(self, payload: PayloadModel) -> bool:
        """Update existing payload.

        Args:
            payload: Updated payload

        Returns:
            True if update successful
        """
        try:
            await self._ensure_initialized()

            if not payload.id:
                logger.error("Cannot update payload without ID")
                return False

            # Update file system - always store/update the payload
            # The organizer manages the file path internally
            file_path = await self.organizer.store_payload(payload)

            # Update database
            db = await self._get_db()
            success = await db.update_payload(payload)

            if success:
                # Invalidate cache entries
                await self.cache.invalidate_payload(payload.id)
                await self.cache.invalidate_query_cache()

                logger.info(f"Updated payload {payload.name}")
                return True

            return False

        except Exception as e:
            logger.error(f"Failed to update payload {payload.name}: {e}")
            return False

    async def delete_payload(self, payload_id: int) -> bool:
        """Delete payload from system.

        Args:
            payload_id: Database ID of payload to delete

        Returns:
            True if deletion successful
        """
        try:
            await self._ensure_initialized()

            # Get payload to find file path
            payload = await self.get_payload_by_id(payload_id)

            # Delete from database
            db = await self._get_db()
            db_success = await db.delete_payload(payload_id)

            # Note: File deletion handled separately by organizer
            # PayloadModel doesn't track file_path

            if db_success:
                # Invalidate cache
                await self.cache.invalidate_payload(payload_id)
                await self.cache.invalidate_query_cache()

                logger.info(f"Deleted payload {payload_id}")
                return True

            return False

        except Exception as e:
            logger.error(f"Failed to delete payload {payload_id}: {e}")
            return False

    async def sync_repository(
        self,
        repository_url: str,
        branch: str = "main",
        target_domains: Optional[List[str]] = None,
        force_update: bool = False,
    ) -> SyncResult:
        """Synchronize payloads from Git repository.

        Args:
            repository_url: Full Git repository URL
            branch: Git branch to sync from
            target_domains: Specific domains to sync (currently unused)
            force_update: Force update even if no changes

        Returns:
            SyncResult with operation details
        """
        try:
            await self._ensure_initialized()

            # Parse Git URL
            try:
                git_url = GitURL.from_url(repository_url)
            except ValueError as e:
                logger.error(f"Invalid repository URL: {e}")
                return SyncResult(
                    success=False,
                    repository=repository_url,
                    branch=branch,
                    errors=[f"Invalid URL: {str(e)}"],
                )

            git_sync = await self._get_git_sync()

            # Determine repository path
            repo_path = self.workspace_dir / git_url.repo

            # Check if repository exists and needs update
            if repo_path.exists() and not force_update:
                # Update existing repository
                update_result = await git_sync.update_repository(repo_path, branch=branch)

                if update_result.success:
                    logger.info(
                        f"Repository updated: {git_url.repo} (auth: {update_result.auth_method_used.value})"
                    )

                    # Process payloads from repository
                    new_payloads = await self._process_repository_payloads(
                        repo_path, target_domains
                    )

                    # Invalidate cache after sync
                    await self.cache.invalidate_query_cache()

                    return SyncResult(
                        success=True,
                        repository=repository_url,
                        branch=branch,
                        new_payloads=[str(id) for id in new_payloads],
                        updated_payloads=[],
                        total_processed=len(new_payloads),
                    )
                else:
                    return SyncResult(
                        success=False,
                        repository=repository_url,
                        branch=branch,
                        errors=[update_result.error_message or "Update failed"],
                    )
            else:
                # Clone new repository or force clone
                if repo_path.exists():
                    # Remove existing for force update
                    import shutil

                    shutil.rmtree(repo_path)

                clone_result = await git_sync.clone_repository(
                    git_url, target_path=repo_path, branch=branch
                )

                if clone_result.success:
                    logger.info(
                        f"Repository cloned: {git_url.repo} (auth: {clone_result.auth_method_used.value})"
                    )

                    # Process payloads from repository
                    new_payloads = await self._process_repository_payloads(
                        repo_path, target_domains
                    )

                    # Invalidate cache after sync
                    await self.cache.invalidate_query_cache()

                    return SyncResult(
                        success=True,
                        repository=repository_url,
                        branch=branch,
                        new_payloads=[str(id) for id in new_payloads],
                        updated_payloads=[],
                        total_processed=len(new_payloads),
                    )
                else:
                    return SyncResult(
                        success=False,
                        repository=repository_url,
                        branch=branch,
                        errors=[clone_result.error_message or "Clone failed"],
                    )

        except Exception as e:
            logger.error(f"Failed to sync repository {repository_url}: {e}")
            return SyncResult(
                success=False,
                repository=repository_url,
                branch=branch,
                errors=[f"Sync failed: {str(e)}"],
            )

    async def import_payloads(self, source_path: Path, format_type: str = "auto") -> ImportResult:
        """Import payloads from local file or directory.

        Args:
            source_path: Path to import from
            format_type: Format type ('auto', 'json', 'yaml', 'text')

        Returns:
            ImportResult with operation details
        """
        try:
            await self._ensure_initialized()

            start_time = datetime.utcnow()
            result = ImportResult(success=False)

            if not source_path.exists():
                result.errors.append(f"Source path does not exist: {source_path}")
                return result

            # Handle directory vs file import
            if source_path.is_dir():
                files_to_import = (
                    list(source_path.glob("**/*.txt"))
                    + list(source_path.glob("**/*.json"))
                    + list(source_path.glob("**/*.yaml"))
                    + list(source_path.glob("**/*.yml"))
                )
            else:
                files_to_import = [source_path]

            for file_path in files_to_import:
                try:
                    # Read file content
                    async with aiofiles.open(file_path, "r", encoding="utf-8") as f:
                        content = await f.read()

                    # Parse payload based on format
                    payload = await self._parse_import_file(file_path, content, format_type)

                    if payload:
                        # Check if payload already exists
                        existing = await self.get_payload_by_hash(payload.hash)

                        if existing:
                            result.skipped_payloads.append(payload.name)
                            result.skipped_count += 1
                        else:
                            # Store new payload
                            payload_id = await self.store_payload(payload)
                            result.imported_payloads.append(payload.name)
                            result.imported_count += 1
                    else:
                        result.errors.append(f"Failed to parse {file_path}")
                        result.error_count += 1

                except Exception as e:
                    logger.error(f"Error importing {file_path}: {e}")
                    result.errors.append(f"Error importing {file_path}: {str(e)}")
                    result.error_count += 1

            # Calculate processing time
            end_time = datetime.utcnow()
            result.processing_time_ms = int((end_time - start_time).total_seconds() * 1000)

            result.success = result.imported_count > 0 or result.error_count == 0

            logger.info(
                f"Import completed: {result.imported_count} imported, "
                f"{result.skipped_count} skipped, {result.error_count} errors"
            )

            return result

        except Exception as e:
            logger.error(f"Failed to import payloads from {source_path}: {e}")
            return ImportResult(success=False, errors=[f"Import failed: {str(e)}"])

    async def _process_repository_payloads(
        self, repo_path: Path, target_domains: Optional[List[str]] = None
    ) -> List[int]:
        """Process payloads from cloned repository.

        Args:
            repo_path: Path to cloned repository
            target_domains: Optional domain filter

        Returns:
            List of new payload IDs
        """
        new_payload_ids = []

        try:
            # Find payload files in repository
            payload_files = []

            # Look for common payload file patterns
            for pattern in ["*.yml", "*.yaml", "*.json", "*.txt"]:
                payload_files.extend(repo_path.rglob(pattern))

            for file_path in payload_files:
                try:
                    # Skip non-payload files
                    if file_path.name in [".gitignore", "README.md", "LICENSE"]:
                        continue

                    # Read and parse payload file
                    with open(file_path, "r", encoding="utf-8") as f:
                        content = f.read()

                    # Parse payload based on file format
                    payload_data = None
                    if file_path.suffix.lower() in [".json"]:
                        import json

                        try:
                            payload_data = json.loads(content)
                        except json.JSONDecodeError:
                            pass
                    elif file_path.suffix.lower() in [".yaml", ".yml"]:
                        import yaml

                        try:
                            payload_data = yaml.safe_load(content)
                        except yaml.YAMLError:
                            pass

                    # Handle both single payload and array of payloads
                    payloads_to_process = []

                    if payload_data:
                        if isinstance(payload_data, list):
                            # Array of payloads
                            for item in payload_data:
                                if isinstance(item, dict):
                                    item["source"] = f"git:{repo_path.name}"
                                    try:
                                        payload = PayloadModel.from_repository_json(item)
                                        payloads_to_process.append(payload)
                                    except Exception as e:
                                        logger.debug(f"Failed to parse payload item: {e}")
                                        continue
                        elif isinstance(payload_data, dict):
                            # Single payload
                            payload_data["source"] = f"git:{repo_path.name}"
                            try:
                                payload = PayloadModel.from_repository_json(payload_data)
                                payloads_to_process.append(payload)
                            except Exception as e:
                                logger.debug(f"Failed to parse payload: {e}")
                    else:
                        # Plain text file - treat as single payload
                        from gibson.models.domain import AttackDomain, ModuleCategory

                        try:
                            payload = PayloadModel.from_minimal(
                                name=file_path.stem,
                                content=content,
                                domain=AttackDomain.PROMPT,  # Default domain
                                category=ModuleCategory.UNSPECIFIED,  # Default category
                                author="repository",
                            )
                            payload.source = f"git:{repo_path.name}"
                            payloads_to_process.append(payload)
                        except Exception as e:
                            logger.debug(f"Failed to create minimal payload: {e}")

                    # Process all payloads from this file
                    for payload in payloads_to_process:
                        # Apply domain filter if specified
                        if (
                            target_domains
                            and hasattr(payload, "domain")
                            and payload.domain not in target_domains
                        ):
                            continue

                        # Store payload
                        try:
                            payload_id = await self.store_payload(payload)
                            new_payload_ids.append(payload_id)
                        except Exception as e:
                            logger.debug(f"Failed to store payload {payload.name}: {e}")
                            continue

                except Exception as e:
                    logger.warning(f"Failed to process payload file {file_path}: {e}")
                    continue

            logger.info(f"Processed {len(new_payload_ids)} payloads from {repo_path}")

        except Exception as e:
            logger.error(f"Failed to process repository payloads: {e}")

        return new_payload_ids

    async def get_metrics(self) -> PayloadMetrics:
        """Get comprehensive payload metrics.

        Returns:
            PayloadMetrics with system statistics
        """
        try:
            await self._ensure_initialized()

            # Get database metrics
            db = await self._get_db()
            metrics = await db.get_payload_metrics()

            # Add cache metrics
            cache_stats = await self.cache.get_cache_stats()
            metrics.cache_hit_rate = cache_stats.get("hit_rate_percent", 0) / 100

            # Add storage metrics
            storage_stats = self.organizer.get_storage_stats()
            metrics.total_size_bytes = storage_stats.get("total_size_bytes", 0)

            return metrics

        except Exception as e:
            logger.error(f"Failed to get payload metrics: {e}")
            return PayloadMetrics()

    async def cleanup_system(self) -> Dict[str, Any]:
        """Perform system cleanup operations.

        Returns:
            Cleanup results
        """
        try:
            await self._ensure_initialized()

            results = {
                "orphaned_records": 0,
                "expired_cache_entries": 0,
                "empty_directories": 0,
                "total_cleanup_time_ms": 0,
            }

            start_time = datetime.utcnow()

            # Cleanup database
            db = await self._get_db()
            results["orphaned_records"] = await db.cleanup_orphaned_records()

            # Cleanup cache
            results["expired_cache_entries"] = await self.cache.prune_expired()

            # Cleanup file system
            results["empty_directories"] = self.organizer.cleanup_empty_directories()

            # Calculate total time
            end_time = datetime.utcnow()
            results["total_cleanup_time_ms"] = int((end_time - start_time).total_seconds() * 1000)

            logger.info(f"System cleanup completed: {results}")
            return results

        except Exception as e:
            logger.error(f"System cleanup failed: {e}")
            return {"error": str(e)}

    async def validate_system_integrity(self) -> Dict[str, Any]:
        """Validate system integrity.

        Returns:
            Validation results
        """
        try:
            await self._ensure_initialized()

            results = {
                "valid_payloads": 0,
                "invalid_payloads": 0,
                "missing_files": 0,
                "orphaned_files": 0,
                "validation_errors": [],
            }

            # Get all payloads from database
            query = PayloadQuery(limit=None)
            payloads, _ = await self.query_payloads(query)

            for payload in payloads:
                try:
                    # Validate file integrity
                    if self.organizer.validate_file_integrity(payload):
                        results["valid_payloads"] += 1
                    else:
                        results["invalid_payloads"] += 1
                        results["validation_errors"].append(
                            f"Integrity check failed for payload {payload.name}"
                        )

                except Exception as e:
                    results["validation_errors"].append(
                        f"Validation error for payload {payload.name}: {str(e)}"
                    )

            logger.info(f"System validation completed: {results}")
            return results

        except Exception as e:
            logger.error(f"System validation failed: {e}")
            return {"error": str(e)}

    async def _parse_import_file(
        self, file_path: Path, content: str, format_type: str
    ) -> Optional[PayloadModel]:
        """Parse import file into PayloadModel object.

        Args:
            file_path: Source file path
            content: File content
            format_type: Format type hint

        Returns:
            Parsed PayloadModel or None if parsing failed
        """
        try:
            # Determine format
            if format_type == "auto":
                if file_path.suffix.lower() == ".json":
                    format_type = "json"
                elif file_path.suffix.lower() in [".yaml", ".yml"]:
                    format_type = "yaml"
                else:
                    format_type = "text"

            # Parse payload based on format
            from gibson.models.domain import AttackDomain, ModuleCategory

            payload_data = None

            # Format-specific parsing
            if format_type == "json":
                import json

                try:
                    data = json.loads(content)
                    if isinstance(data, dict):
                        payload_data = data
                except json.JSONDecodeError:
                    # Fall back to treating as plain text
                    pass
            elif format_type == "yaml":
                import yaml

                try:
                    data = yaml.safe_load(content)
                    if isinstance(data, dict):
                        payload_data = data
                except yaml.YAMLError:
                    # Fall back to treating as plain text
                    pass

            # Create payload using PayloadModel
            if payload_data:
                # Use structured data
                payload_data["source_path"] = str(file_path)
                payload = PayloadModel.from_repository_json(payload_data)
            else:
                # Use minimal constructor for plain text
                payload = PayloadModel.from_minimal(
                    name=file_path.stem,
                    content=content.strip(),
                    domain=AttackDomain.PROMPT,  # Default
                    category=ModuleCategory.UNSPECIFIED,  # Default
                    author="imported",
                )
                payload.source_path = str(file_path)

            return payload

        except Exception as e:
            logger.error(f"Failed to parse import file {file_path}: {e}")
            return None
