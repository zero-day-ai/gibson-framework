"""Module registry for discovering and managing Gibson Framework modules.

Provides centralized registry functionality with database persistence,
caching, and search capabilities for both built-in and external modules.
"""

import asyncio
import fnmatch
import importlib.util
import inspect
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Type, Union
from datetime import datetime
import hashlib

from loguru import logger
from sqlalchemy import select, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from gibson.core.module_management.cache import ModuleCache
from gibson.core.module_management.exceptions import (
    ModuleManagementError,
    ModuleNotFoundError,
    ModuleRegistryError,
)
from gibson.core.modules.base import BaseModule
from gibson.models.module import (
    ModuleDefinitionModel,
    ModuleStatus,
    AttackDomain,
    ModuleCategory,
)
from gibson.db import ModuleRecord
from gibson.models.domain import Severity


class ModuleRegistry:
    """Central registry for discovering and managing modules.
    
    Features:
    - Automatic discovery of built-in modules
    - Database persistence for module metadata
    - LRU cache for fast lookups
    - Fuzzy search capabilities
    - Module validation and health checking
    - Thread-safe operations
    """
    
    def __init__(
        self,
        cache: Optional[ModuleCache] = None,
        discovery_paths: Optional[List[Path]] = None
    ):
        """Initialize module registry.
        
        Args:
            cache: Module cache instance (creates default if None)
            discovery_paths: Additional paths to search for modules
        """
        self.cache = cache or ModuleCache(
            max_size=1000,
            default_ttl=3600  # 1 hour cache TTL
        )
        
        # Default discovery paths for Gibson modules
        self.discovery_paths = discovery_paths or []
        
        # Track discovered modules
        self._discovered_modules: Dict[str, ModuleDefinitionModel] = {}
        self._discovery_completed = False
        self._discovery_lock = asyncio.Lock()
        
        logger.debug(
            f"Initialized ModuleRegistry with {len(self.discovery_paths)} "
            f"discovery paths and cache max_size={self.cache._max_size}"
        )
    
    async def discover_modules(
        self,
        force_refresh: bool = False,
        gibson_root: Optional[Path] = None
    ) -> List[ModuleDefinitionModel]:
        """Discover all available modules from configured paths.
        
        Args:
            force_refresh: Force rediscovery even if already completed
            gibson_root: Root path of Gibson installation
            
        Returns:
            List of discovered module definitions
        """
        async with self._discovery_lock:
            if self._discovery_completed and not force_refresh:
                logger.debug("Module discovery already completed, using cached results")
                return list(self._discovered_modules.values())
            
            logger.info("Starting module discovery process")
            start_time = datetime.utcnow()
            discovered = []
            
            try:
                # Discover built-in Gibson modules
                if gibson_root:
                    builtin_modules = await self._discover_builtin_modules(gibson_root)
                    discovered.extend(builtin_modules)
                    logger.info(
                        f"Discovered {len(builtin_modules)} built-in modules"
                    )
                
                # Discover modules from additional paths
                for path in self.discovery_paths:
                    if path.exists() and path.is_dir():
                        path_modules = await self._discover_modules_in_path(path)
                        discovered.extend(path_modules)
                        logger.debug(
                            f"Discovered {len(path_modules)} modules in {path}"
                        )
                
                # Update internal registry
                self._discovered_modules = {
                    module.name: module for module in discovered
                }
                self._discovery_completed = True
                
                duration = (datetime.utcnow() - start_time).total_seconds()
                logger.info(
                    f"Module discovery completed: {len(discovered)} modules "
                    f"found in {duration:.2f}s"
                )
                
                return discovered
                
            except Exception as e:
                logger.error(f"Module discovery failed: {e}")
                raise ModuleRegistryError(
                    "Failed to discover modules",
                    corruption_detected=True
                ) from e
    
    async def register_module(
        self,
        module: ModuleDefinitionModel,
        session: AsyncSession,
        overwrite: bool = False
    ) -> None:
        """Register a module in the database.
        
        Args:
            module: Module definition to register
            session: Database session
            overwrite: Whether to overwrite existing module
        """
        try:
            # Check if module already exists
            existing = await session.execute(
                select(ModuleRecord).where(ModuleRecord.name == module.name)
            )
            existing_module = existing.scalar_one_or_none()
            
            if existing_module and not overwrite:
                logger.warning(
                    f"Module {module.name} already registered. "
                    f"Use overwrite=True to update."
                )
                return
            
            # Calculate source hash for integrity checking
            source_hash = None
            if module.file_path and module.file_path.exists():
                source_hash = self._calculate_file_hash(module.file_path)
            
            if existing_module:
                # Update existing module
                existing_module.version = module.version
                existing_module.display_name = module.display_name
                existing_module.description = module.description
                existing_module.author = module.author
                existing_module.license = module.license
                existing_module.domain = module.domain.value
                existing_module.category = module.category.value
                existing_module.severity = module.severity.value
                existing_module.owasp_categories = [
                    cat.value for cat in module.owasp_categories
                ]
                existing_module.tags = module.tags
                existing_module.dependencies = module.dependencies
                existing_module.config = module.config.model_dump() if module.config else {}
                existing_module.file_path = str(module.file_path) if module.file_path else None
                existing_module.source_url = module.source_url
                existing_module.documentation_url = module.documentation_url
                existing_module.source_hash = source_hash
                existing_module.status = module.status.value
                existing_module.last_updated = datetime.utcnow()
                
                logger.info(f"Updated module registration: {module.name}")
            else:
                # Create new module record
                module_record = ModuleRecord(
                    name=module.name,
                    version=module.version,
                    display_name=module.display_name,
                    description=module.description,
                    author=module.author,
                    license=module.license,
                    domain=module.domain.value,
                    category=module.category.value,
                    severity=module.severity.value,
                    owasp_categories=[
                        cat.value for cat in module.owasp_categories
                    ],
                    tags=module.tags,
                    dependencies=module.dependencies,
                    config=module.config.model_dump() if module.config else {},
                    file_path=str(module.file_path) if module.file_path else None,
                    source_url=module.source_url,
                    documentation_url=module.documentation_url,
                    source_hash=source_hash,
                    status=module.status.value,
                    installation_date=module.installation_date,
                    last_updated=datetime.utcnow()
                )
                session.add(module_record)
                logger.info(f"Registered new module: {module.name}")
            
            await session.commit()
            
            # Update cache
            self.cache.set(f"module:{module.name}", module)
            self._discovered_modules[module.name] = module
            
        except Exception as e:
            await session.rollback()
            logger.error(f"Failed to register module {module.name}: {e}")
            raise ModuleManagementError(
                f"Failed to register module {module.name}",
                module_name=module.name
            ) from e
    
    async def get_module(
        self,
        name: str,
        session: Optional[AsyncSession] = None
    ) -> Optional[ModuleDefinitionModel]:
        """Get module by name from cache or database.
        
        Args:
            name: Module name to retrieve
            session: Optional database session
            
        Returns:
            Module definition or None if not found
        """
        # Try cache first
        cache_key = f"module:{name}"
        cached_module = self.cache.get(cache_key)
        if cached_module:
            logger.debug(f"Module {name} retrieved from cache")
            return cached_module
        
        # Fall back to database if session provided
        if session:
            try:
                result = await session.execute(
                    select(ModuleRecord).where(ModuleRecord.name == name)
                )
                record = result.scalar_one_or_none()
                
                if record:
                    module = await self._record_to_model(record)
                    # Cache for future use
                    self.cache.set(cache_key, module)
                    logger.debug(f"Module {name} retrieved from database")
                    return module
                    
            except Exception as e:
                logger.error(f"Database error retrieving module {name}: {e}")
        
        # Check discovered modules
        if name in self._discovered_modules:
            module = self._discovered_modules[name]
            self.cache.set(cache_key, module)
            return module
        
        logger.debug(f"Module {name} not found")
        return None
    
    async def search_modules(
        self,
        query: Optional[str] = None,
        domain: Optional[AttackDomain] = None,
        category: Optional[ModuleCategory] = None,
        tags: Optional[List[str]] = None,
        status: Optional[ModuleStatus] = None,
        session: Optional[AsyncSession] = None,
        limit: Optional[int] = None
    ) -> List[ModuleDefinitionModel]:
        """Search modules with various filters.
        
        Args:
            query: Text query for name/description search
            domain: Filter by attack domain
            category: Filter by module category  
            tags: Filter by tags (any match)
            status: Filter by module status
            session: Database session
            limit: Maximum results to return
            
        Returns:
            List of matching modules
        """
        # Build cache key for search results caching
        cache_params = [
            f"query:{query or 'none'}",
            f"domain:{domain.value if domain else 'none'}",
            f"category:{category.value if category else 'none'}",
            f"tags:{'|'.join(tags) if tags else 'none'}",
            f"status:{status.value if status else 'none'}",
            f"limit:{limit or 'none'}"
        ]
        cache_key = f"search:{'|'.join(cache_params)}"
        
        # Try cache first
        cached_results = self.cache.get(cache_key)
        if cached_results:
            logger.debug(f"Search results retrieved from cache: {len(cached_results)} modules")
            return cached_results
        
        # Search in database if session provided
        results = []
        if session:
            try:
                query_stmt = select(ModuleRecord)
                filters = []
                
                # Text search in name and description
                if query:
                    search_term = f"%{query.lower()}%"
                    filters.append(
                        or_(
                            ModuleRecord.name.ilike(search_term),
                            ModuleRecord.description.ilike(search_term),
                            ModuleRecord.display_name.ilike(search_term)
                        )
                    )
                
                # Filter by domain
                if domain:
                    filters.append(ModuleRecord.domain == domain.value)
                
                # Filter by category
                if category:
                    filters.append(ModuleRecord.category == category.value)
                
                # Filter by status
                if status:
                    filters.append(ModuleRecord.status == status.value)
                
                # Apply filters
                if filters:
                    query_stmt = query_stmt.where(and_(*filters))
                
                # Apply limit
                if limit:
                    query_stmt = query_stmt.limit(limit)
                
                # Execute query
                db_results = await session.execute(query_stmt)
                records = db_results.scalars().all()
                
                # Convert to models
                for record in records:
                    module = await self._record_to_model(record)
                    
                    # Additional filtering for tags (SQLAlchemy JSON filtering can be complex)
                    if tags:
                        module_tags_lower = [tag.lower() for tag in module.tags]
                        if not any(tag.lower() in module_tags_lower for tag in tags):
                            continue
                    
                    results.append(module)
                
                logger.debug(f"Database search found {len(results)} modules")
                
            except Exception as e:
                logger.error(f"Database search error: {e}")
                # Fall through to in-memory search
        
        # Fall back to in-memory search of discovered modules
        if not results:
            results = self._search_in_memory(
                query=query,
                domain=domain,
                category=category,
                tags=tags,
                status=status,
                limit=limit
            )
            logger.debug(f"In-memory search found {len(results)} modules")
        
        # Cache results with shorter TTL for search queries
        self.cache.set(cache_key, results, ttl=300)  # 5 minute cache for searches
        
        return results
    
    async def update_status(
        self,
        name: str,
        status: ModuleStatus,
        session: AsyncSession
    ) -> bool:
        """Update module status in database.
        
        Args:
            name: Module name
            status: New status
            session: Database session
            
        Returns:
            True if updated successfully, False if module not found
        """
        try:
            result = await session.execute(
                select(ModuleRecord).where(ModuleRecord.name == name)
            )
            record = result.scalar_one_or_none()
            
            if not record:
                return False
            
            old_status = record.status
            record.status = status.value
            record.last_updated = datetime.utcnow()
            
            await session.commit()
            
            # Invalidate cache
            self.cache.invalidate(f"module:{name}")
            self.cache.invalidate_pattern("search:*")  # Invalidate search caches
            
            # Update in-memory copy
            if name in self._discovered_modules:
                self._discovered_modules[name].status = status
            
            logger.info(
                f"Updated module {name} status: {old_status} -> {status.value}"
            )
            return True
            
        except Exception as e:
            await session.rollback()
            logger.error(f"Failed to update status for module {name}: {e}")
            raise ModuleManagementError(
                f"Failed to update module status",
                module_name=name
            ) from e
    
    async def rebuild_registry(
        self,
        session: AsyncSession,
        gibson_root: Optional[Path] = None
    ) -> int:
        """Rebuild registry from module files.
        
        Args:
            session: Database session
            gibson_root: Gibson installation root
            
        Returns:
            Number of modules rebuilt
        """
        logger.info("Starting registry rebuild")
        
        try:
            # Clear existing cache
            cleared = self.cache.clear()
            logger.debug(f"Cleared {cleared} cached entries")
            
            # Force module rediscovery
            discovered = await self.discover_modules(
                force_refresh=True,
                gibson_root=gibson_root
            )
            
            # Re-register all discovered modules
            rebuild_count = 0
            for module in discovered:
                await self.register_module(module, session, overwrite=True)
                rebuild_count += 1
            
            logger.info(f"Registry rebuilt with {rebuild_count} modules")
            return rebuild_count
            
        except Exception as e:
            logger.error(f"Registry rebuild failed: {e}")
            raise ModuleRegistryError(
                "Failed to rebuild registry",
                corruption_detected=True
            ) from e
    
    def get_stats(self) -> Dict[str, Any]:
        """Get registry statistics.
        
        Returns:
            Dictionary with registry statistics
        """
        cache_stats = self.cache.get_stats()
        
        # Count modules by domain
        domain_counts = {}
        status_counts = {}
        
        for module in self._discovered_modules.values():
            domain = module.domain.value
            domain_counts[domain] = domain_counts.get(domain, 0) + 1
            
            status = module.status.value
            status_counts[status] = status_counts.get(status, 0) + 1
        
        return {
            "total_modules": len(self._discovered_modules),
            "discovery_completed": self._discovery_completed,
            "discovery_paths": len(self.discovery_paths),
            "domain_distribution": domain_counts,
            "status_distribution": status_counts,
            "cache_stats": cache_stats.to_dict()
        }
    
    # Private helper methods
    
    async def _discover_builtin_modules(
        self,
        gibson_root: Path
    ) -> List[ModuleDefinitionModel]:
        """Discover built-in Gibson modules."""
        modules = []
        
        # Look in gibson/domains/ for domain-specific modules
        domains_path = gibson_root / "gibson" / "domains"
        if domains_path.exists():
            async for domain_path in self._async_iterdir(domains_path):
                if domain_path.is_dir() and not domain_path.name.startswith("."):
                    domain_modules = await self._discover_modules_in_path(
                        domain_path,
                        default_domain=domain_path.name
                    )
                    modules.extend(domain_modules)
        
        # Also check gibson/core/modules/ for additional modules
        core_modules_path = gibson_root / "gibson" / "core" / "modules"
        if core_modules_path.exists():
            core_modules = await self._discover_modules_in_path(core_modules_path)
            modules.extend(core_modules)
        
        return modules
    
    async def _discover_modules_in_path(
        self,
        path: Path,
        default_domain: Optional[str] = None
    ) -> List[ModuleDefinitionModel]:
        """Discover modules in a specific directory path."""
        modules = []
        
        if not path.exists() or not path.is_dir():
            return modules
        
        async for item in self._async_iterdir(path):
            if item.is_file() and item.suffix == ".py" and not item.name.startswith("_"):
                try:
                    module_def = await self._load_module_from_file(
                        item,
                        default_domain=default_domain
                    )
                    if module_def:
                        modules.append(module_def)
                except Exception as e:
                    logger.warning(f"Failed to load module from {item}: {e}")
        
        return modules
    
    async def _load_module_from_file(
        self,
        file_path: Path,
        default_domain: Optional[str] = None
    ) -> Optional[ModuleDefinitionModel]:
        """Load and validate a module from a Python file."""
        try:
            # Load module dynamically
            spec = importlib.util.spec_from_file_location(
                file_path.stem,
                file_path
            )
            if not spec or not spec.loader:
                return None
            
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Find BaseModule subclasses
            module_classes = []
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if (issubclass(obj, BaseModule) and 
                    obj is not BaseModule and
                    obj.__module__ == module.__name__):
                    module_classes.append(obj)
            
            if not module_classes:
                logger.debug(f"No module classes found in {file_path}")
                return None
            
            # Use the first valid module class
            module_class = module_classes[0]
            
            # Extract metadata
            name = getattr(module_class, 'name', file_path.stem)
            version = getattr(module_class, 'version', '1.0.0')
            description = getattr(module_class, 'description', f'Gibson module: {name}')
            category = getattr(module_class, 'category', ModuleCategory.UNSPECIFIED)
            
            # Determine domain from path or metadata
            domain = None
            if hasattr(module_class, 'domain'):
                domain = module_class.domain
            elif default_domain:
                try:
                    domain = AttackDomain(default_domain.upper())
                except ValueError:
                    domain = AttackDomain.PROMPT  # Default fallback
            else:
                domain = AttackDomain.PROMPT  # Default fallback
            
            # Create module definition
            module_def = ModuleDefinitionModel(
                name=name,
                version=version,
                display_name=getattr(module_class, 'display_name', name.replace('_', ' ').title()),
                description=description,
                author=getattr(module_class, 'author', 'Gibson Framework'),
                license=getattr(module_class, 'license', 'Apache-2.0'),
                domain=domain,
                category=category,
                severity=getattr(module_class, 'severity', Severity.MEDIUM),
                owasp_categories=getattr(module_class, 'owasp_categories', []),
                tags=getattr(module_class, 'tags', []),
                dependencies=getattr(module_class, 'dependencies', []),
                file_path=file_path,
                source_url=getattr(module_class, 'source_url', None),
                documentation_url=getattr(module_class, 'documentation_url', None),
                status=ModuleStatus.INSTALLED
            )
            
            logger.debug(f"Loaded module definition: {name} from {file_path}")
            return module_def
            
        except Exception as e:
            logger.error(f"Failed to load module from {file_path}: {e}")
            return None
    
    def _search_in_memory(
        self,
        query: Optional[str] = None,
        domain: Optional[AttackDomain] = None,
        category: Optional[ModuleCategory] = None,
        tags: Optional[List[str]] = None,
        status: Optional[ModuleStatus] = None,
        limit: Optional[int] = None
    ) -> List[ModuleDefinitionModel]:
        """Search modules in memory using discovered modules."""
        results = []
        
        for module in self._discovered_modules.values():
            # Apply filters
            if domain and module.domain != domain:
                continue
            if category and module.category != category:
                continue
            if status and module.status != status:
                continue
            
            # Tag filtering
            if tags:
                module_tags_lower = [tag.lower() for tag in module.tags]
                if not any(tag.lower() in module_tags_lower for tag in tags):
                    continue
            
            # Text search with fuzzy matching
            if query:
                query_lower = query.lower()
                searchable_text = ' '.join([
                    module.name.lower(),
                    module.display_name.lower(),
                    module.description.lower(),
                    ' '.join(module.tags).lower()
                ])
                
                # Simple fuzzy matching - check if query words are in searchable text
                query_words = query_lower.split()
                if not all(word in searchable_text for word in query_words):
                    # Also try wildcard matching for partial matches
                    if not any(
                        fnmatch.fnmatch(searchable_text, f"*{word}*")
                        for word in query_words
                    ):
                        continue
            
            results.append(module)
            
            # Apply limit
            if limit and len(results) >= limit:
                break
        
        # Sort by relevance (name matches first, then others)
        if query:
            def relevance_score(m):
                score = 0
                query_lower = query.lower()
                if query_lower in m.name.lower():
                    score += 10
                if query_lower in m.display_name.lower():
                    score += 5
                if query_lower in m.description.lower():
                    score += 1
                return score
            
            results.sort(key=relevance_score, reverse=True)
        else:
            # Sort alphabetically by name
            results.sort(key=lambda m: m.name.lower())
        
        return results
    
    async def _record_to_model(self, record: ModuleRecord) -> ModuleDefinitionModel:
        """Convert database record to Pydantic model."""
        return ModuleDefinitionModel(
            id=record.id,
            name=record.name,
            version=record.version,
            display_name=record.display_name,
            description=record.description,
            author=record.author,
            license=record.license,
            domain=AttackDomain(record.domain),
            category=ModuleCategory(record.category),
            severity=Severity(record.severity),
            owasp_categories=record.owasp_categories,
            tags=record.tags,
            dependencies=record.dependencies,
            file_path=Path(record.file_path) if record.file_path else None,
            source_url=record.source_url,
            documentation_url=record.documentation_url,
            status=ModuleStatus(record.status),
            installation_date=record.installation_date,
            last_updated=record.last_updated,
            created_at=record.created_at,
            updated_at=record.updated_at
        )
    
    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA-256 hash of file for integrity checking."""
        hash_sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    
    async def _async_iterdir(self, path: Path):
        """Async generator for directory iteration."""
        # For now, use sync iterdir wrapped in executor
        # In production, could use aiofiles or similar for true async I/O
        for item in path.iterdir():
            yield item
            # Allow other tasks to run
            await asyncio.sleep(0)
