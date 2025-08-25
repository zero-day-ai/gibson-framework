"""Unit tests for ModuleCache implementation.

Tests cache functionality including hit/miss scenarios, TTL expiration,
size limits, thread safety, and statistics tracking.
"""

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from unittest.mock import patch

import pytest

from gibson.core.module_management.cache import ModuleCache, CacheStats, CacheEntry


class TestCacheEntry:
    """Test CacheEntry functionality."""

    def test_cache_entry_creation(self):
        """Test basic cache entry creation."""
        now = time.time()
        entry = CacheEntry(
            key="test_key", value="test_value", created_at=now, accessed_at=now, ttl=3600
        )

        assert entry.key == "test_key"
        assert entry.value == "test_value"
        assert entry.created_at == now
        assert entry.accessed_at == now
        assert entry.access_count == 1
        assert entry.ttl == 3600

    def test_cache_entry_expiration(self):
        """Test TTL expiration logic."""
        now = time.time()

        # Non-expired entry
        entry = CacheEntry(key="test", value="value", created_at=now, accessed_at=now, ttl=3600)
        assert not entry.is_expired

        # Expired entry
        expired_entry = CacheEntry(
            key="expired",
            value="value",
            created_at=now - 7200,  # 2 hours ago
            accessed_at=now - 7200,
            ttl=3600,  # 1 hour TTL
        )
        assert expired_entry.is_expired

        # Entry without TTL (never expires)
        no_ttl_entry = CacheEntry(
            key="no_ttl",
            value="value",
            created_at=now - 86400,  # 1 day ago
            accessed_at=now - 86400,
            ttl=None,
        )
        assert not no_ttl_entry.is_expired

    def test_cache_entry_touch(self):
        """Test access tracking with touch() method."""
        now = time.time()
        entry = CacheEntry(key="test", value="value", created_at=now, accessed_at=now)

        original_access_time = entry.accessed_at
        original_count = entry.access_count

        # Small delay to ensure time difference
        time.sleep(0.01)
        entry.touch()

        assert entry.accessed_at > original_access_time
        assert entry.access_count == original_count + 1


class TestCacheStats:
    """Test CacheStats functionality."""

    def test_cache_stats_creation(self):
        """Test basic cache stats creation."""
        stats = CacheStats(hits=100, misses=20, evictions=5, size=80, max_size=100)

        assert stats.hits == 100
        assert stats.misses == 20
        assert stats.evictions == 5
        assert stats.size == 80
        assert stats.max_size == 100

    def test_hit_rate_calculation(self):
        """Test hit rate percentage calculation."""
        # Good hit rate
        stats = CacheStats(hits=80, misses=20)
        assert stats.hit_rate == 80.0

        # Perfect hit rate
        perfect_stats = CacheStats(hits=100, misses=0)
        assert perfect_stats.hit_rate == 100.0

        # Zero hit rate
        zero_stats = CacheStats(hits=0, misses=50)
        assert zero_stats.hit_rate == 0.0

        # No data
        empty_stats = CacheStats(hits=0, misses=0)
        assert empty_stats.hit_rate == 0.0

    def test_utilization_calculation(self):
        """Test cache utilization percentage."""
        # Partial utilization
        stats = CacheStats(size=75, max_size=100)
        assert stats.utilization == 75.0

        # Full utilization
        full_stats = CacheStats(size=100, max_size=100)
        assert full_stats.utilization == 100.0

        # Empty cache
        empty_stats = CacheStats(size=0, max_size=100)
        assert empty_stats.utilization == 0.0

        # Zero max size
        zero_max_stats = CacheStats(size=0, max_size=0)
        assert zero_max_stats.utilization == 0.0

    def test_stats_to_dict(self):
        """Test stats dictionary conversion."""
        stats = CacheStats(hits=80, misses=20, evictions=5, size=75, max_size=100)

        stats_dict = stats.to_dict()
        expected = {
            "hits": 80,
            "misses": 20,
            "evictions": 5,
            "size": 75,
            "max_size": 100,
            "hit_rate": 80.0,
            "utilization": 75.0,
        }

        assert stats_dict == expected


class TestModuleCache:
    """Test ModuleCache functionality."""

    def test_cache_initialization(self):
        """Test cache initialization with various parameters."""
        # Default initialization
        cache = ModuleCache()
        assert cache._max_size == 1000
        assert cache._default_ttl == 3600
        assert len(cache) == 0

        # Custom initialization
        custom_cache = ModuleCache(max_size=500, default_ttl=1800, cleanup_interval=600)
        assert custom_cache._max_size == 500
        assert custom_cache._default_ttl == 1800
        assert custom_cache._cleanup_interval == 600

    def test_basic_get_set_operations(self):
        """Test basic cache operations."""
        cache = ModuleCache(max_size=10)

        # Test set and get
        cache.set("key1", "value1")
        assert cache.get("key1") == "value1"
        assert len(cache) == 1

        # Test cache miss
        assert cache.get("nonexistent") is None

        # Test overwrite
        cache.set("key1", "new_value")
        assert cache.get("key1") == "new_value"
        assert len(cache) == 1  # Size shouldn't change

    def test_lru_eviction(self):
        """Test LRU eviction when cache is full."""
        cache = ModuleCache(max_size=3)

        # Fill cache to capacity
        cache.set("key1", "value1")
        cache.set("key2", "value2")
        cache.set("key3", "value3")
        assert len(cache) == 3

        # Access key1 to make it recently used
        cache.get("key1")

        # Add another item, should evict key2 (least recently used)
        cache.set("key4", "value4")
        assert len(cache) == 3
        assert cache.get("key1") == "value1"  # Still present
        assert cache.get("key2") is None  # Evicted
        assert cache.get("key3") == "value3"  # Still present
        assert cache.get("key4") == "value4"  # New item

    def test_ttl_expiration(self):
        """Test TTL-based expiration."""
        cache = ModuleCache(default_ttl=0.1)  # 100ms TTL

        cache.set("key1", "value1")
        assert cache.get("key1") == "value1"

        # Wait for expiration
        time.sleep(0.15)

        # Should be expired and removed
        assert cache.get("key1") is None
        assert len(cache) == 0

    def test_custom_ttl_override(self):
        """Test TTL override for specific entries."""
        cache = ModuleCache(default_ttl=0.1)  # 100ms default

        # Set with longer TTL
        cache.set("key1", "value1", ttl=1.0)  # 1 second
        cache.set("key2", "value2")  # Uses default 100ms

        # Wait for default TTL to expire
        time.sleep(0.15)

        assert cache.get("key1") == "value1"  # Should still exist
        assert cache.get("key2") is None  # Should be expired

    def test_no_ttl_entries(self):
        """Test entries without TTL (never expire)."""
        cache = ModuleCache(default_ttl=None)

        cache.set("permanent", "value")

        # Simulate long time passage
        with patch("time.time", return_value=time.time() + 86400):  # 1 day later
            assert cache.get("permanent") == "value"

    def test_invalidate_operations(self):
        """Test cache invalidation methods."""
        cache = ModuleCache(max_size=10)

        # Setup test data
        cache.set("key1", "value1")
        cache.set("key2", "value2")
        cache.set("module:test1", "data1")
        cache.set("module:test2", "data2")
        assert len(cache) == 4

        # Test single key invalidation
        assert cache.invalidate("key1") is True
        assert cache.invalidate("nonexistent") is False
        assert cache.get("key1") is None
        assert len(cache) == 3

        # Test pattern invalidation
        invalidated = cache.invalidate_pattern("module:*")
        assert invalidated == 2
        assert cache.get("module:test1") is None
        assert cache.get("module:test2") is None
        assert cache.get("key2") == "value2"  # Unaffected
        assert len(cache) == 1

        # Test clear all
        cleared = cache.clear()
        assert cleared == 1
        assert len(cache) == 0

    def test_multi_operations(self):
        """Test bulk get/set operations."""
        cache = ModuleCache(max_size=10)

        # Test multi-set
        items = {"key1": "value1", "key2": "value2", "key3": "value3"}
        cache.set_multi(items)
        assert len(cache) == 3

        # Test multi-get
        results = cache.get_multi(["key1", "key3", "nonexistent"])
        expected = {"key1": "value1", "key3": "value3"}
        assert results == expected

        # Test multi-set with TTL
        cache.set_multi({"temp1": "val1", "temp2": "val2"}, ttl=0.1)
        assert cache.get("temp1") == "val1"

        time.sleep(0.15)
        assert cache.get("temp1") is None

    def test_statistics_tracking(self):
        """Test cache statistics tracking."""
        cache = ModuleCache(max_size=5)

        # Generate some cache activity
        cache.set("key1", "value1")
        cache.set("key2", "value2")

        cache.get("key1")  # Hit
        cache.get("key1")  # Hit
        cache.get("nonexistent")  # Miss

        stats = cache.get_stats()
        assert stats.hits == 2
        assert stats.misses == 1
        assert stats.size == 2
        assert stats.max_size == 5
        assert stats.hit_rate == 66.67  # Rounded

        # Test eviction tracking
        cache.set("key3", "value3")
        cache.set("key4", "value4")
        cache.set("key5", "value5")
        cache.set("key6", "value6")  # Should evict key1

        stats = cache.get_stats()
        assert stats.evictions == 1
        assert stats.size == 5

        # Test stats reset
        cache.reset_stats()
        stats = cache.get_stats()
        assert stats.hits == 0
        assert stats.misses == 0
        assert stats.evictions == 0

    def test_cache_resize(self):
        """Test cache resizing functionality."""
        cache = ModuleCache(max_size=5)

        # Fill cache
        for i in range(5):
            cache.set(f"key{i}", f"value{i}")
        assert len(cache) == 5

        # Shrink cache
        cache.resize(3)
        assert cache._max_size == 3
        assert len(cache) == 3  # Should evict 2 items

        # Grow cache
        cache.resize(10)
        assert cache._max_size == 10
        assert len(cache) == 3  # Size unchanged

        # Can add more items now
        for i in range(5, 10):
            cache.set(f"key{i}", f"value{i}")
        assert len(cache) == 8

    def test_contains_operation(self):
        """Test __contains__ operator."""
        cache = ModuleCache(default_ttl=0.1)

        cache.set("key1", "value1")
        assert "key1" in cache
        assert "nonexistent" not in cache

        # Test with expired entry
        time.sleep(0.15)
        assert "key1" not in cache  # Should respect TTL

    def test_thread_safety(self):
        """Test cache thread safety with concurrent access."""
        cache = ModuleCache(max_size=1000)
        results = []
        errors = []

        def worker(worker_id: int, operations: int):
            """Worker function for concurrent testing."""
            try:
                for i in range(operations):
                    key = f"worker{worker_id}_item{i}"
                    value = f"value_{worker_id}_{i}"

                    # Set value
                    cache.set(key, value)

                    # Get value
                    retrieved = cache.get(key)
                    if retrieved != value:
                        errors.append(f"Worker {worker_id}: Expected {value}, got {retrieved}")

                    # Invalidate some items
                    if i % 10 == 0:
                        cache.invalidate(key)

                    results.append((worker_id, i, retrieved))

            except Exception as e:
                errors.append(f"Worker {worker_id} error: {e}")

        # Run concurrent workers
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(worker, worker_id, 50) for worker_id in range(10)]

            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    errors.append(f"Future error: {e}")

        # Verify no errors occurred
        assert not errors, f"Concurrent access errors: {errors}"

        # Verify cache is in consistent state
        stats = cache.get_stats()
        assert stats.size <= 1000  # Within max size
        assert len(cache) == stats.size  # Consistent size

    def test_cleanup_functionality(self):
        """Test periodic cleanup of expired entries."""
        cache = ModuleCache(
            default_ttl=0.1, cleanup_interval=0.05  # 100ms TTL  # 50ms cleanup interval
        )

        # Add entries that will expire
        cache.set("key1", "value1")
        cache.set("key2", "value2")
        assert len(cache) == 2

        # Wait for expiration
        time.sleep(0.15)

        # Add new entry to trigger cleanup
        cache.set("key3", "value3")

        # Expired entries should be cleaned up
        assert cache.get("key1") is None
        assert cache.get("key2") is None
        assert cache.get("key3") == "value3"

    def test_repr_string(self):
        """Test string representation."""
        cache = ModuleCache(max_size=100)

        # Empty cache
        repr_str = repr(cache)
        assert "ModuleCache" in repr_str
        assert "0/100" in repr_str

        # With data
        cache.set("key1", "value1")
        cache.get("key1")  # Generate hit
        cache.get("missing")  # Generate miss

        repr_str = repr(cache)
        assert "1/100" in repr_str
        assert "hit_rate" in repr_str


@pytest.fixture
def sample_cache():
    """Fixture providing a pre-configured cache for testing."""
    cache = ModuleCache(max_size=10, default_ttl=3600)
    cache.set("module1", {"name": "test_module", "version": "1.0.0"})
    cache.set("module2", {"name": "another_module", "version": "2.1.0"})
    return cache


class TestCacheIntegration:
    """Integration tests for cache with realistic usage patterns."""

    def test_module_metadata_caching(self, sample_cache):
        """Test caching of module metadata."""
        # Retrieve module metadata
        module1 = sample_cache.get("module1")
        assert module1["name"] == "test_module"
        assert module1["version"] == "1.0.0"

        # Update metadata
        updated_metadata = {"name": "test_module", "version": "1.1.0"}
        sample_cache.set("module1", updated_metadata)

        # Verify update
        module1 = sample_cache.get("module1")
        assert module1["version"] == "1.1.0"

    def test_domain_based_invalidation(self, sample_cache):
        """Test invalidating modules by domain pattern."""
        # Add domain-specific entries
        sample_cache.set("prompt:injection", {"domain": "prompt"})
        sample_cache.set("prompt:leakage", {"domain": "prompt"})
        sample_cache.set("data:poisoning", {"domain": "data"})

        # Invalidate all prompt modules
        invalidated = sample_cache.invalidate_pattern("prompt:*")
        assert invalidated == 2

        # Verify selective invalidation
        assert sample_cache.get("prompt:injection") is None
        assert sample_cache.get("prompt:leakage") is None
        assert sample_cache.get("data:poisoning") is not None
        assert sample_cache.get("module1") is not None  # Original data preserved
