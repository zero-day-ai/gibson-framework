"""Thread-safe LRU cache implementation for module metadata.

Provides fast access to frequently used module information with
automated eviction policies, TTL support, and cache statistics.
"""

import threading
import time
from collections import OrderedDict
from typing import Any, Dict, Optional, TypeVar, Union
from dataclasses import dataclass

from loguru import logger

from gibson.models.base import GibsonBaseModel

T = TypeVar("T")


@dataclass
class CacheStats:
    """Cache statistics for monitoring and optimization."""

    hits: int = 0
    misses: int = 0
    evictions: int = 0
    size: int = 0
    max_size: int = 0

    @property
    def hit_rate(self) -> float:
        """Calculate cache hit rate as percentage."""
        total = self.hits + self.misses
        return (self.hits / total * 100) if total > 0 else 0.0

    @property
    def utilization(self) -> float:
        """Calculate cache utilization as percentage."""
        return (self.size / self.max_size * 100) if self.max_size > 0 else 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "hits": self.hits,
            "misses": self.misses,
            "evictions": self.evictions,
            "size": self.size,
            "max_size": self.max_size,
            "hit_rate": round(self.hit_rate, 2),
            "utilization": round(self.utilization, 2),
        }


@dataclass
class CacheEntry:
    """Cache entry with TTL and access tracking."""

    key: str
    value: Any
    created_at: float
    accessed_at: float
    access_count: int = 1
    ttl: Optional[float] = None

    @property
    def is_expired(self) -> bool:
        """Check if entry has expired based on TTL."""
        if self.ttl is None:
            return False
        return time.time() > (self.created_at + self.ttl)

    def touch(self) -> None:
        """Update access time and increment access counter."""
        self.accessed_at = time.time()
        self.access_count += 1


class ModuleCache:
    """Thread-safe LRU cache with TTL support for module metadata.

    Features:
    - Thread-safe operations with fine-grained locking
    - TTL (Time To Live) support for automatic expiration
    - LRU eviction policy for memory management
    - Comprehensive statistics tracking
    - Configurable size limits
    - Bulk operations for efficiency
    """

    def __init__(
        self,
        max_size: int = 1000,
        default_ttl: Optional[float] = 3600,  # 1 hour default
        cleanup_interval: float = 300,  # 5 minutes
    ):
        """Initialize cache with configuration.

        Args:
            max_size: Maximum number of entries to cache
            default_ttl: Default TTL in seconds (None for no expiration)
            cleanup_interval: How often to clean up expired entries
        """
        self._max_size = max_size
        self._default_ttl = default_ttl
        self._cleanup_interval = cleanup_interval

        # Thread-safe storage using OrderedDict for LRU behavior
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._lock = threading.RLock()  # Reentrant lock for nested operations

        # Statistics tracking
        self._stats = CacheStats(max_size=max_size)

        # Last cleanup time for periodic maintenance
        self._last_cleanup = time.time()

        logger.debug(
            f"Initialized ModuleCache: max_size={max_size}, "
            f"default_ttl={default_ttl}, cleanup_interval={cleanup_interval}"
        )

    def get(self, key: str) -> Optional[Any]:
        """Get value from cache with LRU update.

        Args:
            key: Cache key to retrieve

        Returns:
            Cached value or None if not found/expired
        """
        with self._lock:
            self._maybe_cleanup()

            entry = self._cache.get(key)
            if entry is None:
                self._stats.misses += 1
                logger.debug(f"Cache miss for key: {key}")
                return None

            # Check expiration
            if entry.is_expired:
                logger.debug(f"Cache entry expired for key: {key}")
                del self._cache[key]
                self._stats.size -= 1
                self._stats.misses += 1
                return None

            # Update LRU order and access tracking
            entry.touch()
            self._cache.move_to_end(key)  # Move to end (most recent)

            self._stats.hits += 1
            logger.debug(f"Cache hit for key: {key} (accessed {entry.access_count} times)")
            return entry.value

    def set(self, key: str, value: Any, ttl: Optional[float] = None) -> None:
        """Set value in cache with optional TTL override.

        Args:
            key: Cache key
            value: Value to cache
            ttl: TTL override (uses default_ttl if None)
        """
        with self._lock:
            self._maybe_cleanup()

            # Use provided TTL or fall back to default
            effective_ttl = ttl if ttl is not None else self._default_ttl

            # Create cache entry
            now = time.time()
            entry = CacheEntry(
                key=key, value=value, created_at=now, accessed_at=now, ttl=effective_ttl
            )

            # Handle existing key
            if key in self._cache:
                self._cache[key] = entry
                self._cache.move_to_end(key)
                logger.debug(f"Updated cache entry for key: {key}")
            else:
                # Check if we need to evict
                if len(self._cache) >= self._max_size:
                    self._evict_lru()

                self._cache[key] = entry
                self._stats.size += 1
                logger.debug(f"Added new cache entry for key: {key}")

    def invalidate(self, key: str) -> bool:
        """Remove specific key from cache.

        Args:
            key: Cache key to remove

        Returns:
            True if key was found and removed, False otherwise
        """
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                self._stats.size -= 1
                logger.debug(f"Invalidated cache entry for key: {key}")
                return True
            return False

    def clear(self) -> int:
        """Clear all entries from cache.

        Returns:
            Number of entries that were cleared
        """
        with self._lock:
            count = len(self._cache)
            self._cache.clear()
            self._stats.size = 0
            self._stats.evictions += count
            logger.info(f"Cleared cache: {count} entries removed")
            return count

    def get_multi(self, keys: list[str]) -> Dict[str, Any]:
        """Get multiple values efficiently.

        Args:
            keys: List of cache keys to retrieve

        Returns:
            Dictionary mapping keys to values (only includes found keys)
        """
        result = {}
        with self._lock:
            for key in keys:
                value = self.get(key)  # Uses existing get() logic
                if value is not None:
                    result[key] = value
        return result

    def set_multi(self, items: Dict[str, Any], ttl: Optional[float] = None) -> None:
        """Set multiple values efficiently.

        Args:
            items: Dictionary mapping keys to values
            ttl: TTL override for all items
        """
        with self._lock:
            for key, value in items.items():
                self.set(key, value, ttl)  # Uses existing set() logic

    def invalidate_pattern(self, pattern: str) -> int:
        """Invalidate all keys matching a pattern.

        Args:
            pattern: Pattern to match (supports simple wildcards: *)

        Returns:
            Number of keys invalidated
        """
        import fnmatch

        with self._lock:
            keys_to_remove = [key for key in self._cache.keys() if fnmatch.fnmatch(key, pattern)]

            for key in keys_to_remove:
                del self._cache[key]
                self._stats.size -= 1

            logger.debug(f"Invalidated {len(keys_to_remove)} entries matching pattern: {pattern}")
            return len(keys_to_remove)

    def get_stats(self) -> CacheStats:
        """Get current cache statistics.

        Returns:
            Current cache statistics
        """
        with self._lock:
            # Update current size in stats
            self._stats.size = len(self._cache)
            return CacheStats(
                hits=self._stats.hits,
                misses=self._stats.misses,
                evictions=self._stats.evictions,
                size=self._stats.size,
                max_size=self._stats.max_size,
            )

    def reset_stats(self) -> None:
        """Reset cache statistics counters."""
        with self._lock:
            self._stats.hits = 0
            self._stats.misses = 0
            self._stats.evictions = 0
            logger.debug("Reset cache statistics")

    def resize(self, new_max_size: int) -> None:
        """Resize cache maximum capacity.

        Args:
            new_max_size: New maximum cache size
        """
        with self._lock:
            old_size = self._max_size
            self._max_size = new_max_size
            self._stats.max_size = new_max_size

            # Evict entries if new size is smaller
            while len(self._cache) > new_max_size:
                self._evict_lru()

            logger.info(
                f"Resized cache from {old_size} to {new_max_size} "
                f"(current entries: {len(self._cache)})"
            )

    def _evict_lru(self) -> None:
        """Evict least recently used entry (private method)."""
        if self._cache:
            # Remove first item (least recently used)
            key, entry = self._cache.popitem(last=False)
            self._stats.size -= 1
            self._stats.evictions += 1
            logger.debug(f"Evicted LRU entry: {key} " f"(accessed {entry.access_count} times)")

    def _maybe_cleanup(self) -> None:
        """Perform periodic cleanup of expired entries (private method)."""
        now = time.time()
        if now - self._last_cleanup < self._cleanup_interval:
            return

        # Find and remove expired entries
        expired_keys = [key for key, entry in self._cache.items() if entry.is_expired]

        for key in expired_keys:
            del self._cache[key]
            self._stats.size -= 1

        if expired_keys:
            logger.debug(f"Cleaned up {len(expired_keys)} expired cache entries")

        self._last_cleanup = now

    def __len__(self) -> int:
        """Return current cache size."""
        with self._lock:
            return len(self._cache)

    def __contains__(self, key: str) -> bool:
        """Check if key exists in cache (respects TTL)."""
        return self.get(key) is not None

    def __repr__(self) -> str:
        """String representation for debugging."""
        with self._lock:
            return (
                f"ModuleCache(size={len(self._cache)}/{self._max_size}, "
                f"hit_rate={self.get_stats().hit_rate:.1f}%)"
            )
