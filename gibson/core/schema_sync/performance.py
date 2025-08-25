"""
Performance optimizations for schema synchronization.
"""

import hashlib
import json
import pickle
from pathlib import Path
from typing import Dict, Any, Optional, List, Callable
from datetime import datetime, timedelta
import asyncio
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import functools
import time
import logging

from gibson.models.base import GibsonBaseModel


logger = logging.getLogger(__name__)


class CacheEntry(GibsonBaseModel):
    """Cache entry with TTL support."""

    key: str
    value: Any
    created_at: datetime
    ttl_seconds: int = 3600
    hits: int = 0

    @property
    def is_expired(self) -> bool:
        """Check if cache entry is expired."""
        age = datetime.utcnow() - self.created_at
        return age.total_seconds() > self.ttl_seconds

    def increment_hits(self):
        """Increment hit counter."""
        self.hits += 1


class SchemaCache:
    """Cache for schema-related operations."""

    def __init__(self, cache_dir: Optional[Path] = None, max_size: int = 100):
        """
        Initialize schema cache.

        Args:
            cache_dir: Directory for persistent cache
            max_size: Maximum number of cache entries
        """
        self.cache_dir = cache_dir or Path.home() / ".gibson" / "schema_cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.max_size = max_size
        self.memory_cache: Dict[str, CacheEntry] = {}
        self._load_persistent_cache()

    def get(self, key: str) -> Optional[Any]:
        """
        Get value from cache.

        Args:
            key: Cache key

        Returns:
            Cached value or None if not found/expired
        """
        # Check memory cache first
        if key in self.memory_cache:
            entry = self.memory_cache[key]
            if not entry.is_expired:
                entry.increment_hits()
                logger.debug(f"Cache hit for key: {key}")
                return entry.value
            else:
                # Remove expired entry
                del self.memory_cache[key]

        # Check persistent cache
        cache_file = self.cache_dir / f"{self._hash_key(key)}.cache"
        if cache_file.exists():
            try:
                with open(cache_file, "rb") as f:
                    entry = pickle.load(f)

                if not entry.is_expired:
                    # Load into memory cache
                    self.memory_cache[key] = entry
                    entry.increment_hits()
                    logger.debug(f"Persistent cache hit for key: {key}")
                    return entry.value
                else:
                    # Remove expired file
                    cache_file.unlink()
            except Exception as e:
                logger.warning(f"Failed to load cache entry: {e}")

        logger.debug(f"Cache miss for key: {key}")
        return None

    def set(self, key: str, value: Any, ttl_seconds: int = 3600, persistent: bool = True):
        """
        Set value in cache.

        Args:
            key: Cache key
            value: Value to cache
            ttl_seconds: Time to live in seconds
            persistent: Whether to persist to disk
        """
        entry = CacheEntry(
            key=key, value=value, created_at=datetime.utcnow(), ttl_seconds=ttl_seconds
        )

        # Add to memory cache
        self.memory_cache[key] = entry

        # Enforce size limit
        if len(self.memory_cache) > self.max_size:
            self._evict_lru()

        # Persist if requested
        if persistent:
            cache_file = self.cache_dir / f"{self._hash_key(key)}.cache"
            try:
                with open(cache_file, "wb") as f:
                    pickle.dump(entry, f)
            except Exception as e:
                logger.warning(f"Failed to persist cache entry: {e}")

        logger.debug(f"Cached value for key: {key}")

    def invalidate(self, key: str):
        """Invalidate cache entry."""
        # Remove from memory cache
        if key in self.memory_cache:
            del self.memory_cache[key]

        # Remove persistent cache
        cache_file = self.cache_dir / f"{self._hash_key(key)}.cache"
        if cache_file.exists():
            cache_file.unlink()

    def clear(self):
        """Clear all cache entries."""
        self.memory_cache.clear()

        # Clear persistent cache
        for cache_file in self.cache_dir.glob("*.cache"):
            cache_file.unlink()

    def _hash_key(self, key: str) -> str:
        """Hash key for filesystem safety."""
        return hashlib.md5(key.encode()).hexdigest()

    def _evict_lru(self):
        """Evict least recently used entry."""
        if not self.memory_cache:
            return

        # Find LRU entry (oldest with fewest hits)
        lru_key = min(
            self.memory_cache.keys(),
            key=lambda k: (self.memory_cache[k].hits, self.memory_cache[k].created_at),
        )

        del self.memory_cache[lru_key]
        logger.debug(f"Evicted LRU cache entry: {lru_key}")

    def _load_persistent_cache(self):
        """Load persistent cache entries into memory."""
        for cache_file in self.cache_dir.glob("*.cache"):
            try:
                with open(cache_file, "rb") as f:
                    entry = pickle.load(f)

                if not entry.is_expired:
                    self.memory_cache[entry.key] = entry
                else:
                    cache_file.unlink()
            except Exception as e:
                logger.warning(f"Failed to load cache file {cache_file}: {e}")

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        total_hits = sum(e.hits for e in self.memory_cache.values())
        return {
            "entries": len(self.memory_cache),
            "total_hits": total_hits,
            "average_hits": total_hits / len(self.memory_cache) if self.memory_cache else 0,
            "memory_size_bytes": sum(len(pickle.dumps(e)) for e in self.memory_cache.values()),
            "persistent_files": len(list(self.cache_dir.glob("*.cache"))),
        }


def cached(ttl_seconds: int = 3600):
    """
    Decorator for caching function results.

    Args:
        ttl_seconds: Cache time to live
    """

    def decorator(func: Callable) -> Callable:
        cache = SchemaCache()

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Generate cache key
            key = f"{func.__name__}:{args}:{kwargs}"

            # Check cache
            result = cache.get(key)
            if result is not None:
                return result

            # Call function
            result = func(*args, **kwargs)

            # Cache result
            cache.set(key, result, ttl_seconds)

            return result

        return wrapper

    return decorator


class ParallelProcessor:
    """Parallel processing for schema operations."""

    def __init__(self, max_workers: Optional[int] = None):
        """
        Initialize parallel processor.

        Args:
            max_workers: Maximum number of workers
        """
        self.max_workers = max_workers
        self.thread_executor = ThreadPoolExecutor(max_workers=max_workers)
        self.process_executor = ProcessPoolExecutor(max_workers=max_workers)

    def process_parallel(
        self, items: List[Any], processor: Callable, use_processes: bool = False
    ) -> List[Any]:
        """
        Process items in parallel.

        Args:
            items: Items to process
            processor: Function to process each item
            use_processes: Use processes instead of threads

        Returns:
            List of results
        """
        executor = self.process_executor if use_processes else self.thread_executor

        futures = [executor.submit(processor, item) for item in items]
        results = [future.result() for future in futures]

        return results

    async def process_async(self, items: List[Any], processor: Callable) -> List[Any]:
        """
        Process items asynchronously.

        Args:
            items: Items to process
            processor: Async function to process each item

        Returns:
            List of results
        """
        tasks = [processor(item) for item in items]
        results = await asyncio.gather(*tasks)
        return results

    def shutdown(self):
        """Shutdown executors."""
        self.thread_executor.shutdown(wait=True)
        self.process_executor.shutdown(wait=True)


class ChangeDetectionOptimizer:
    """Optimizations for change detection."""

    def __init__(self):
        """Initialize optimizer."""
        self.cache = SchemaCache()
        self.processor = ParallelProcessor()

    @cached(ttl_seconds=300)
    def compute_schema_hash(self, schema: Dict[str, Any]) -> str:
        """
        Compute schema hash with caching.

        Args:
            schema: Schema dictionary

        Returns:
            Hash string
        """
        # Sort keys for consistent hashing
        # Use default=str to handle any non-serializable types
        normalized = json.dumps(schema, sort_keys=True, default=str)
        return hashlib.sha256(normalized.encode()).hexdigest()

    def detect_changes_optimized(
        self, old_schema: Dict[str, Any], new_schema: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Optimized change detection.

        Args:
            old_schema: Previous schema
            new_schema: Current schema

        Returns:
            Changes dictionary
        """
        # Quick hash comparison
        old_hash = self.compute_schema_hash(old_schema)
        new_hash = self.compute_schema_hash(new_schema)

        if old_hash == new_hash:
            return {"has_changes": False}

        # Parallel field comparison
        old_fields = old_schema.get("properties", {})
        new_fields = new_schema.get("properties", {})

        all_fields = set(old_fields.keys()) | set(new_fields.keys())

        def compare_field(field_name):
            old_field = old_fields.get(field_name)
            new_field = new_fields.get(field_name)

            if old_field is None:
                return ("added", field_name, new_field)
            elif new_field is None:
                return ("removed", field_name, old_field)
            elif old_field != new_field:
                return ("modified", field_name, (old_field, new_field))
            else:
                return ("unchanged", field_name, None)

        # Process fields in parallel
        results = self.processor.process_parallel(list(all_fields), compare_field)

        # Aggregate results
        changes = {"has_changes": True, "added": [], "removed": [], "modified": [], "unchanged": []}

        for change_type, field_name, details in results:
            if change_type != "unchanged":
                changes[change_type].append({"field": field_name, "details": details})

        return changes


class GenerationOptimizer:
    """Optimizations for schema generation."""

    def __init__(self):
        """Initialize optimizer."""
        self.cache = SchemaCache()
        self.processor = ParallelProcessor()

    async def generate_formats_async(self, model: type, formats: List[str]) -> Dict[str, Any]:
        """
        Generate multiple formats asynchronously.

        Args:
            model: Pydantic model
            formats: List of format names

        Returns:
            Dictionary of format results
        """

        async def generate_format(format_name: str):
            # Import generator dynamically
            if format_name == "json":
                from gibson.core.schema_sync.generators.json_generator import JSONSchemaGenerator

                generator = JSONSchemaGenerator()
            elif format_name == "typescript":
                from gibson.core.schema_sync.generators.typescript import TypeScriptGenerator

                generator = TypeScriptGenerator()
            elif format_name == "sqlalchemy":
                from gibson.core.schema_sync.generators.sqlalchemy_generator import (
                    SQLAlchemyGenerator,
                )

                generator = SQLAlchemyGenerator()
            else:
                return None

            # Generate with caching
            cache_key = f"{model.__name__}:{format_name}"
            cached_result = self.cache.get(cache_key)

            if cached_result:
                return cached_result

            result = await asyncio.to_thread(generator.generate, model)
            self.cache.set(cache_key, result, ttl_seconds=3600)

            return result

        # Generate all formats in parallel
        tasks = [generate_format(fmt) for fmt in formats]
        results = await asyncio.gather(*tasks)

        return dict(zip(formats, results))


class PerformanceMonitor:
    """Monitor and report performance metrics."""

    def __init__(self):
        """Initialize monitor."""
        self.metrics: Dict[str, List[float]] = {}

    def measure(self, operation: str):
        """
        Decorator to measure operation performance.

        Args:
            operation: Operation name
        """

        def decorator(func: Callable) -> Callable:
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                start_time = time.time()

                try:
                    result = func(*args, **kwargs)
                    return result
                finally:
                    duration = time.time() - start_time

                    if operation not in self.metrics:
                        self.metrics[operation] = []

                    self.metrics[operation].append(duration)

                    logger.debug(f"{operation} took {duration:.3f}s")

            return wrapper

        return decorator

    def get_stats(self) -> Dict[str, Dict[str, float]]:
        """Get performance statistics."""
        stats = {}

        for operation, durations in self.metrics.items():
            if durations:
                stats[operation] = {
                    "count": len(durations),
                    "total": sum(durations),
                    "average": sum(durations) / len(durations),
                    "min": min(durations),
                    "max": max(durations),
                }

        return stats

    def reset(self):
        """Reset metrics."""
        self.metrics.clear()


# Global instances
_cache = SchemaCache()
_monitor = PerformanceMonitor()


def get_cache() -> SchemaCache:
    """Get global cache instance."""
    return _cache


def get_monitor() -> PerformanceMonitor:
    """Get global monitor instance."""
    return _monitor
