"""Authentication performance benchmarking."""
import time
import asyncio
from typing import Dict, Any, List, Callable
from statistics import mean, median, stdev


class AuthBenchmark:
    """Benchmarks authentication performance."""

    def __init__(self):
        self.results: Dict[str, List[float]] = {}

    async def benchmark_operation(
        self, name: str, operation: Callable, iterations: int = 100, warmup: int = 10
    ) -> Dict[str, Any]:
        """Benchmark an authentication operation."""

        # Warmup
        for _ in range(warmup):
            await operation()

        # Benchmark
        timings = []
        for _ in range(iterations):
            start = time.perf_counter()
            await operation()
            duration = time.perf_counter() - start
            timings.append(duration * 1000)  # Convert to ms

        self.results[name] = timings

        return {
            "operation": name,
            "iterations": iterations,
            "mean_ms": mean(timings),
            "median_ms": median(timings),
            "stdev_ms": stdev(timings) if len(timings) > 1 else 0,
            "min_ms": min(timings),
            "max_ms": max(timings),
            "ops_per_second": 1000 / mean(timings) if mean(timings) > 0 else 0,
        }

    async def run_suite(self) -> Dict[str, Any]:
        """Run complete benchmark suite."""
        results = {}

        # Mock operations for benchmarking
        async def mock_encrypt():
            await asyncio.sleep(0.001)

        async def mock_decrypt():
            await asyncio.sleep(0.001)

        async def mock_validate():
            await asyncio.sleep(0.005)

        async def mock_load():
            await asyncio.sleep(0.002)

        # Run benchmarks
        results["encryption"] = await self.benchmark_operation("encryption", mock_encrypt)
        results["decryption"] = await self.benchmark_operation("decryption", mock_decrypt)
        results["validation"] = await self.benchmark_operation("validation", mock_validate)
        results["credential_load"] = await self.benchmark_operation("load", mock_load)

        return results

    def compare_results(self, baseline: Dict, current: Dict) -> Dict[str, Any]:
        """Compare benchmark results."""
        comparison = {}

        for op in baseline:
            if op in current:
                baseline_mean = baseline[op].get("mean_ms", 0)
                current_mean = current[op].get("mean_ms", 0)

                if baseline_mean > 0:
                    change_pct = ((current_mean - baseline_mean) / baseline_mean) * 100
                    comparison[op] = {
                        "baseline_ms": baseline_mean,
                        "current_ms": current_mean,
                        "change_percent": change_pct,
                        "improved": change_pct < 0,
                    }

        return comparison
