"""
Performance tests for GitSync operations.

Tests performance characteristics of Git operations including:
- Clone performance (shallow vs full)
- Update performance
- Memory usage
- Network efficiency
"""

import asyncio
import time
import psutil
import tempfile
from pathlib import Path
from typing import Dict, Any

import pytest
from gibson.core.payloads.git_sync import GitSync
from gibson.core.payloads.git_models import GitURL


# Public repositories of various sizes for testing
TEST_REPOS = {
    "tiny": "https://github.com/octocat/Hello-World.git",  # ~200KB
    "small": "https://github.com/github/gitignore.git",    # ~2MB
    "medium": "https://github.com/facebook/react.git",     # ~200MB (shallow: ~20MB)
}


class TestGitSyncPerformance:
    """Performance tests for GitSync operations."""
    
    @pytest.mark.performance
    @pytest.mark.slow
    @pytest.mark.asyncio
    async def test_shallow_vs_full_clone_performance(self):
        """Compare performance of shallow vs full clones."""
        url = TEST_REPOS["small"]
        git_url = GitURL.from_url(url)
        
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            
            # Measure shallow clone
            shallow_sync = GitSync(workspace / "shallow", shallow=True)
            shallow_start = time.time()
            shallow_result = await shallow_sync.clone_repository(git_url)
            shallow_duration = time.time() - shallow_start
            
            # Measure full clone
            full_sync = GitSync(workspace / "full", shallow=False)
            full_start = time.time()
            full_result = await full_sync.clone_repository(git_url)
            full_duration = time.time() - full_start
            
            # Assertions
            assert shallow_result.success == True
            assert full_result.success == True
            
            # Shallow should be faster
            assert shallow_duration < full_duration * 1.5  # Allow some margin
            
            # Shallow should be smaller
            assert shallow_result.clone_size_mb < full_result.clone_size_mb
            
            # Report results
            print(f"\nShallow clone: {shallow_duration:.2f}s, {shallow_result.clone_size_mb:.2f}MB")
            print(f"Full clone: {full_duration:.2f}s, {full_result.clone_size_mb:.2f}MB")
            print(f"Time ratio: {full_duration/shallow_duration:.2f}x")
            print(f"Size ratio: {full_result.clone_size_mb/shallow_result.clone_size_mb:.2f}x")
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_update_performance(self):
        """Test performance of repository updates."""
        url = TEST_REPOS["tiny"]
        git_url = GitURL.from_url(url)
        
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            git_sync = GitSync(workspace, shallow=True)
            
            # Initial clone
            clone_result = await git_sync.clone_repository(git_url)
            assert clone_result.success == True
            
            # Measure update performance
            update_times = []
            for i in range(3):
                start = time.time()
                update_result = await git_sync.update_repository(clone_result.repo_path)
                duration = time.time() - start
                update_times.append(duration)
                assert update_result.success == True
            
            # Updates should be fast (< 2s for small repo)
            avg_update_time = sum(update_times) / len(update_times)
            assert avg_update_time < 2.0
            
            print(f"\nAverage update time: {avg_update_time:.2f}s")
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_memory_usage(self):
        """Test memory usage during Git operations."""
        url = TEST_REPOS["tiny"]
        git_url = GitURL.from_url(url)
        
        process = psutil.Process()
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            git_sync = GitSync(workspace, shallow=True)
            
            # Clone repository
            result = await git_sync.clone_repository(git_url)
            assert result.success == True
            
            # Measure memory after clone
            peak_memory = process.memory_info().rss / 1024 / 1024  # MB
            memory_increase = peak_memory - initial_memory
            
            # Memory increase should be reasonable (< 100MB for small repo)
            assert memory_increase < 100
            
            print(f"\nMemory increase: {memory_increase:.2f}MB")
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_concurrent_clones(self):
        """Test performance of concurrent clone operations."""
        urls = [TEST_REPOS["tiny"], TEST_REPOS["tiny"], TEST_REPOS["tiny"]]
        
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            
            # Sequential clones
            sequential_start = time.time()
            for i, url in enumerate(urls):
                git_sync = GitSync(workspace / f"seq_{i}", shallow=True)
                git_url = GitURL.from_url(url)
                result = await git_sync.clone_repository(git_url)
                assert result.success == True
            sequential_duration = time.time() - sequential_start
            
            # Concurrent clones
            concurrent_start = time.time()
            tasks = []
            for i, url in enumerate(urls):
                git_sync = GitSync(workspace / f"con_{i}", shallow=True)
                git_url = GitURL.from_url(url)
                tasks.append(git_sync.clone_repository(git_url))
            
            results = await asyncio.gather(*tasks)
            concurrent_duration = time.time() - concurrent_start
            
            # All should succeed
            assert all(r.success for r in results)
            
            # Concurrent should be faster
            assert concurrent_duration < sequential_duration
            
            print(f"\nSequential: {sequential_duration:.2f}s")
            print(f"Concurrent: {concurrent_duration:.2f}s")
            print(f"Speedup: {sequential_duration/concurrent_duration:.2f}x")
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_sparse_checkout_performance(self):
        """Test performance benefits of sparse checkout."""
        url = TEST_REPOS["small"]
        git_url = GitURL.from_url(url)
        
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            
            # Full checkout
            full_sync = GitSync(workspace / "full", shallow=True)
            full_start = time.time()
            full_result = await full_sync.clone_repository(git_url)
            full_duration = time.time() - full_start
            
            # Sparse checkout (only specific files)
            sparse_sync = GitSync(workspace / "sparse", shallow=True)
            sparse_start = time.time()
            sparse_result = await sparse_sync.clone_repository(
                git_url,
                sparse_patterns=["*.md", "*.txt"]
            )
            sparse_duration = time.time() - sparse_start
            
            # Both should succeed
            assert full_result.success == True
            assert sparse_result.success == True
            
            # Sparse should have fewer files
            if sparse_result.sparse_patterns:
                full_file_count = len(list(full_result.repo_path.rglob("*")))
                sparse_file_count = len(list(sparse_result.repo_path.rglob("*")))
                assert sparse_file_count < full_file_count
            
            print(f"\nFull checkout: {full_duration:.2f}s")
            print(f"Sparse checkout: {sparse_duration:.2f}s")


class TestAuthenticationPerformance:
    """Test performance of authentication mechanisms."""
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_auth_escalation_performance(self):
        """Test performance of authentication escalation."""
        # Use a public repo to test auth escalation without actual auth
        url = TEST_REPOS["tiny"]
        git_url = GitURL.from_url(url)
        
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            git_sync = GitSync(workspace, shallow=True)
            
            # Time the entire operation including auth checks
            start = time.time()
            result = await git_sync.clone_repository(git_url)
            duration = time.time() - start
            
            assert result.success == True
            assert result.auth_method_used in ["public", "ssh_key", "token"]
            
            # Should complete quickly for public repo (< 5s)
            assert duration < 5.0
            
            print(f"\nAuth method: {result.auth_method_used}")
            print(f"Total time: {duration:.2f}s")


class BenchmarkResults:
    """Store and compare benchmark results."""
    
    def __init__(self):
        self.results: Dict[str, Any] = {}
    
    def record(self, name: str, value: float, unit: str = "seconds"):
        """Record a benchmark result."""
        self.results[name] = {"value": value, "unit": unit}
    
    def compare(self, baseline: Dict[str, Any]) -> Dict[str, float]:
        """Compare results against baseline."""
        comparison = {}
        for name, data in self.results.items():
            if name in baseline:
                ratio = data["value"] / baseline[name]["value"]
                comparison[name] = ratio
        return comparison
    
    def report(self):
        """Generate performance report."""
        print("\n=== Performance Report ===")
        for name, data in self.results.items():
            print(f"{name}: {data['value']:.2f} {data['unit']}")


@pytest.mark.performance
@pytest.mark.slow
@pytest.mark.asyncio
async def test_full_performance_suite():
    """Run complete performance test suite and generate report."""
    benchmark = BenchmarkResults()
    
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        
        # Test shallow clone performance
        git_sync = GitSync(workspace / "test1", shallow=True)
        git_url = GitURL.from_url(TEST_REPOS["tiny"])
        
        start = time.time()
        result = await git_sync.clone_repository(git_url)
        duration = time.time() - start
        
        benchmark.record("tiny_repo_shallow_clone", duration)
        benchmark.record("tiny_repo_size", result.clone_size_mb, "MB")
        
        # Test update performance
        start = time.time()
        update_result = await git_sync.update_repository(result.repo_path)
        duration = time.time() - start
        
        benchmark.record("tiny_repo_update", duration)
        
    # Generate report
    benchmark.report()
    
    # Define performance thresholds
    assert benchmark.results["tiny_repo_shallow_clone"]["value"] < 10.0
    assert benchmark.results["tiny_repo_update"]["value"] < 5.0