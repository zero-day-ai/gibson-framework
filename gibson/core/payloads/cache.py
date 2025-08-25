"""Memory cache for payload management with LRU and TTL support."""

import asyncio
import hashlib
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple
from collections import OrderedDict

from loguru import logger

from gibson.models.payload import PayloadModel
from .types import PayloadQuery, PayloadMetrics


class CacheEntry:
    """Cache entry with TTL and access tracking."""

    def __init__(self, value: Any, ttl_seconds: Optional[int] = None):
        """Initialize cache entry.

        Args:
            value: Value to cache
            ttl_seconds: Time to live in seconds (None for no expiry)
        """
        self.value = value
        self.created_at = time.time()
        self.last_accessed = self.created_at
        self.access_count = 0
        self.ttl_seconds = ttl_seconds
        self.expires_at = self.created_at + ttl_seconds if ttl_seconds else None

    def is_expired(self) -> bool:
        """Check if entry has expired.

        Returns:
            True if entry has expired
        """
        if self.expires_at is None:
            return False
        return time.time() > self.expires_at

    def touch(self) -> None:
        """Update access time and increment access count."""
        self.last_accessed = time.time()
        self.access_count += 1

    def get_age_seconds(self) -> float:
        """Get age of entry in seconds.

        Returns:
            Age in seconds
        """
        return time.time() - self.created_at

    def get_time_since_access_seconds(self) -> float:
        """Get time since last access in seconds.

        Returns:
            Time since last access in seconds
        """
        return time.time() - self.last_accessed


class PayloadCache:
    """High-performance memory cache for payloads with LRU eviction and TTL.

    Features:
    - LRU (Least Recently Used) eviction policy
    - TTL (Time To Live) support
    - Thread-safe operations
    - Query result caching
    - Statistics tracking
    - Memory usage monitoring
    """

    def __init__(
        self,
        max_size: int = 1000,
        default_ttl_seconds: int = 3600,  # 1 hour
        cleanup_interval_seconds: int = 300,  # 5 minutes
    ):
        """Initialize cache.

        Args:
            max_size: Maximum number of entries
            default_ttl_seconds: Default TTL for entries
            cleanup_interval_seconds: Interval for cleanup task
        """
        self.max_size = max_size
        self.default_ttl_seconds = default_ttl_seconds
        self.cleanup_interval_seconds = cleanup_interval_seconds

        # Cache storage - OrderedDict for LRU behavior
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()

        # Separate caches for different data types
        self._payload_cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._query_cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._metadata_cache: OrderedDict[str, CacheEntry] = OrderedDict()

        # Statistics
        self._stats = {"hits": 0, "misses": 0, "evictions": 0, "expirations": 0, "cleanup_runs": 0}

        # Async cleanup task
        self._cleanup_task: Optional[asyncio.Task] = None
        self._shutdown_event = asyncio.Event()

        # Threading lock for thread safety
        self._lock = asyncio.Lock()

        logger.debug(
            f"Initialized PayloadCache with max_size={max_size}, ttl={default_ttl_seconds}s"
        )

    async def start(self) -> None:
        """Start background cleanup task."""
        if self._cleanup_task is None:
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())
            logger.debug("Started cache cleanup task")

    async def stop(self) -> None:
        """Stop background cleanup task."""
        if self._cleanup_task:
            self._shutdown_event.set()
            try:
                await asyncio.wait_for(self._cleanup_task, timeout=5.0)
            except asyncio.TimeoutError:
                self._cleanup_task.cancel()
            self._cleanup_task = None
            logger.debug("Stopped cache cleanup task")

    async def get_payload(self, payload_id: int) -> Optional[PayloadModel]:
        """Get payload by ID from cache.

        Args:
            payload_id: Payload ID

        Returns:
            Cached payload or None if not found
        """
        key = f"payload:{payload_id}"
        return await self._get_from_cache(key, self._payload_cache)

    async def set_payload(self, payload: PayloadModel, ttl_seconds: Optional[int] = None) -> None:
        """Cache payload.

        Args:
            payload: Payload to cache
            ttl_seconds: Custom TTL (uses default if None)
        """
        if payload.id is None:
            return

        key = f"payload:{payload.id}"
        await self._set_in_cache(key, payload, self._payload_cache, ttl_seconds)

    async def get_payload_by_hash(self, hash_value: str) -> Optional[PayloadModel]:
        """Get payload by hash from cache.

        Args:
            hash_value: Payload hash

        Returns:
            Cached payload or None if not found
        """
        key = f"hash:{hash_value}"
        return await self._get_from_cache(key, self._payload_cache)

    async def set_payload_by_hash(
        self, hash_value: str, payload: PayloadModel, ttl_seconds: Optional[int] = None
    ) -> None:
        """Cache payload by hash.

        Args:
            hash_value: Payload hash
            payload: Payload to cache
            ttl_seconds: Custom TTL (uses default if None)
        """
        key = f"hash:{hash_value}"
        await self._set_in_cache(key, payload, self._payload_cache, ttl_seconds)

    async def get_query_result(
        self, query: PayloadQuery
    ) -> Optional[Tuple[List[PayloadModel], int]]:
        """Get cached query result.

        Args:
            query: Payload query

        Returns:
            Cached (payloads, total_count) or None if not found
        """
        query_key = self._generate_query_key(query)
        return await self._get_from_cache(query_key, self._query_cache)

    async def set_query_result(
        self,
        query: PayloadQuery,
        payloads: List[PayloadModel],
        total_count: int,
        ttl_seconds: Optional[int] = None,
    ) -> None:
        """Cache query result.

        Args:
            query: Payload query
            payloads: Query result payloads
            total_count: Total count from query
            ttl_seconds: Custom TTL (uses default if None)
        """
        query_key = self._generate_query_key(query)
        result = (payloads, total_count)

        # Use shorter TTL for query results (they change more frequently)
        query_ttl = ttl_seconds or (self.default_ttl_seconds // 4)
        await self._set_in_cache(query_key, result, self._query_cache, query_ttl)

    async def get_metadata(self, key: str) -> Optional[Any]:
        """Get cached metadata.

        Args:
            key: Metadata key

        Returns:
            Cached metadata or None if not found
        """
        return await self._get_from_cache(key, self._metadata_cache)

    async def set_metadata(self, key: str, value: Any, ttl_seconds: Optional[int] = None) -> None:
        """Cache metadata.

        Args:
            key: Metadata key
            value: Value to cache
            ttl_seconds: Custom TTL (uses default if None)
        """
        await self._set_in_cache(key, value, self._metadata_cache, ttl_seconds)

    async def invalidate_payload(self, payload_id: int) -> None:
        """Invalidate cached payload.

        Args:
            payload_id: Payload ID to invalidate
        """
        async with self._lock:
            # Remove from payload cache
            payload_key = f"payload:{payload_id}"
            self._payload_cache.pop(payload_key, None)

            # Invalidate related query cache entries
            await self._invalidate_query_cache()

            logger.debug(f"Invalidated cache for payload {payload_id}")

    async def invalidate_query_cache(self) -> None:
        """Invalidate all query cache entries."""
        async with self._lock:
            await self._invalidate_query_cache()

    async def invalidate_all(self) -> None:
        """Invalidate all cache entries."""
        async with self._lock:
            self._payload_cache.clear()
            self._query_cache.clear()
            self._metadata_cache.clear()
            logger.debug("Invalidated all cache entries")

    async def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics.

        Returns:
            Dictionary with cache statistics
        """
        async with self._lock:
            total_entries = (
                len(self._payload_cache) + len(self._query_cache) + len(self._metadata_cache)
            )

            total_requests = self._stats["hits"] + self._stats["misses"]
            hit_rate = self._stats["hits"] / total_requests * 100 if total_requests > 0 else 0

            # Calculate memory usage estimate
            memory_estimate = self._estimate_memory_usage()

            return {
                "total_entries": total_entries,
                "payload_entries": len(self._payload_cache),
                "query_entries": len(self._query_cache),
                "metadata_entries": len(self._metadata_cache),
                "max_size": self.max_size,
                "hit_rate_percent": round(hit_rate, 2),
                "total_requests": total_requests,
                "memory_estimate_bytes": memory_estimate,
                **self._stats,
            }

    async def prune_expired(self) -> int:
        """Remove expired entries from cache.

        Returns:
            Number of entries removed
        """
        async with self._lock:
            return await self._prune_expired_entries()

    async def _get_from_cache(self, key: str, cache: OrderedDict[str, CacheEntry]) -> Optional[Any]:
        """Get value from specific cache.

        Args:
            key: Cache key
            cache: Cache to search

        Returns:
            Cached value or None if not found/expired
        """
        async with self._lock:
            entry = cache.get(key)

            if entry is None:
                self._stats["misses"] += 1
                return None

            if entry.is_expired():
                cache.pop(key, None)
                self._stats["misses"] += 1
                self._stats["expirations"] += 1
                return None

            # Update access time and move to end (most recently used)
            entry.touch()
            cache.move_to_end(key)

            self._stats["hits"] += 1
            return entry.value

    async def _set_in_cache(
        self,
        key: str,
        value: Any,
        cache: OrderedDict[str, CacheEntry],
        ttl_seconds: Optional[int] = None,
    ) -> None:
        """Set value in specific cache.

        Args:
            key: Cache key
            value: Value to cache
            cache: Cache to store in
            ttl_seconds: Custom TTL
        """
        async with self._lock:
            ttl = ttl_seconds or self.default_ttl_seconds
            entry = CacheEntry(value, ttl)

            # Remove existing entry if present
            if key in cache:
                cache.pop(key)

            # Add new entry
            cache[key] = entry

            # Enforce size limit with LRU eviction
            while len(cache) > self.max_size:
                oldest_key, _ = cache.popitem(last=False)
                self._stats["evictions"] += 1
                logger.debug(f"Evicted cache entry: {oldest_key}")

    def _generate_query_key(self, query: PayloadQuery) -> str:
        """Generate cache key for query.

        Args:
            query: Payload query

        Returns:
            Cache key for query
        """
        # Create stable hash of query parameters
        query_dict = query.dict(exclude_none=True)
        query_str = str(sorted(query_dict.items()))
        query_hash = hashlib.md5(query_str.encode()).hexdigest()
        return f"query:{query_hash}"

    async def _invalidate_query_cache(self) -> None:
        """Invalidate all query cache entries (internal method)."""
        self._query_cache.clear()
        logger.debug("Invalidated query cache")

    async def _prune_expired_entries(self) -> int:
        """Remove expired entries from all caches (internal method).

        Returns:
            Number of entries removed
        """
        removed_count = 0

        for cache in [self._payload_cache, self._query_cache, self._metadata_cache]:
            expired_keys = [key for key, entry in cache.items() if entry.is_expired()]

            for key in expired_keys:
                cache.pop(key, None)
                removed_count += 1

        if removed_count > 0:
            self._stats["expirations"] += removed_count
            logger.debug(f"Pruned {removed_count} expired cache entries")

        return removed_count

    def _estimate_memory_usage(self) -> int:
        """Estimate memory usage of cache entries.

        Returns:
            Estimated memory usage in bytes
        """
        total_size = 0

        for cache in [self._payload_cache, self._query_cache, self._metadata_cache]:
            for entry in cache.values():
                # Rough estimate - actual memory usage will be higher
                if isinstance(entry.value, str):
                    total_size += len(entry.value.encode("utf-8"))
                elif isinstance(entry.value, (list, tuple)):
                    total_size += len(entry.value) * 100  # rough estimate
                elif hasattr(entry.value, "__sizeof__"):
                    total_size += entry.value.__sizeof__()
                else:
                    total_size += 100  # default estimate

        return total_size

    async def _cleanup_loop(self) -> None:
        """Background cleanup task loop."""
        logger.debug("Started cache cleanup loop")

        try:
            while not self._shutdown_event.is_set():
                # Wait for cleanup interval or shutdown
                try:
                    await asyncio.wait_for(
                        self._shutdown_event.wait(), timeout=self.cleanup_interval_seconds
                    )
                    break  # Shutdown requested
                except asyncio.TimeoutError:
                    pass  # Continue with cleanup

                # Perform cleanup
                try:
                    removed_count = await self.prune_expired()
                    self._stats["cleanup_runs"] += 1

                    if removed_count > 0:
                        logger.debug(f"Cleanup removed {removed_count} expired entries")

                except Exception as e:
                    logger.error(f"Cache cleanup error: {e}")

        except asyncio.CancelledError:
            logger.debug("Cache cleanup task cancelled")
        except Exception as e:
            logger.error(f"Cache cleanup loop error: {e}")

        logger.debug("Cache cleanup loop ended")

    async def warm_cache(self, payloads: List[PayloadModel]) -> int:
        """Warm cache with payload list.

        Args:
            payloads: List of payloads to cache

        Returns:
            Number of payloads cached
        """
        cached_count = 0

        for payload in payloads:
            try:
                await self.set_payload(payload)

                # Also cache by hash if available
                if payload.hash:
                    await self.set_payload_by_hash(payload.hash, payload)

                cached_count += 1

            except Exception as e:
                logger.warning(f"Failed to cache payload {payload.name}: {e}")

        logger.info(f"Warmed cache with {cached_count} payloads")
        return cached_count

    async def get_hot_payloads(self, limit: int = 10) -> List[Tuple[str, int]]:
        """Get most frequently accessed payloads.

        Args:
            limit: Maximum number of results

        Returns:
            List of (payload_key, access_count) tuples
        """
        async with self._lock:
            payload_access = [
                (key, entry.access_count) for key, entry in self._payload_cache.items()
            ]

            # Sort by access count descending
            payload_access.sort(key=lambda x: x[1], reverse=True)

            return payload_access[:limit]

    async def optimize_cache(self) -> Dict[str, Any]:
        """Optimize cache by removing least valuable entries.

        Returns:
            Optimization results
        """
        async with self._lock:
            optimization_results = {"removed_count": 0, "kept_count": 0, "memory_saved_estimate": 0}

            # Remove entries that haven't been accessed recently
            cutoff_time = time.time() - (self.default_ttl_seconds * 2)

            for cache_name, cache in [
                ("payload", self._payload_cache),
                ("query", self._query_cache),
                ("metadata", self._metadata_cache),
            ]:
                stale_keys = [
                    key
                    for key, entry in cache.items()
                    if entry.last_accessed < cutoff_time and entry.access_count < 2
                ]

                for key in stale_keys:
                    cache.pop(key, None)
                    optimization_results["removed_count"] += 1

            optimization_results["kept_count"] = (
                len(self._payload_cache) + len(self._query_cache) + len(self._metadata_cache)
            )

            logger.info(
                f"Cache optimization removed {optimization_results['removed_count']} stale entries"
            )

            return optimization_results
