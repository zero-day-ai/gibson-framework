"""
Unit tests for LiteLLM rate limiting.
"""

import asyncio
import pytest
import time
from unittest.mock import MagicMock, AsyncMock

from gibson.core.llm.rate_limiting import (
    RateLimiter,
    TokenBucket,
    RequestQueue,
    BackpressureManager,
    ProviderLimits,
    Priority,
    RateLimitType,
    AlgorithmType,
    BackpressureAction,
    create_rate_limiter,
    PROVIDER_DEFAULTS,
)
from gibson.core.llm.types import LLMProvider


class TestTokenBucket:
    """Test TokenBucket implementation."""
    
    @pytest.mark.asyncio
    async def test_token_bucket_initialization(self):
        """Test TokenBucket initialization."""
        bucket = TokenBucket(capacity=10, refill_rate=2)
        
        assert bucket.capacity == 10
        assert bucket.refill_rate == 2
        assert bucket.tokens == 10
    
    @pytest.mark.asyncio
    async def test_consume_tokens_success(self):
        """Test consuming tokens when available."""
        bucket = TokenBucket(capacity=10, refill_rate=2)
        
        success = await bucket.consume(5)
        assert success is True
        assert bucket.tokens == 5
    
    @pytest.mark.asyncio
    async def test_consume_tokens_failure(self):
        """Test consuming tokens when insufficient."""
        bucket = TokenBucket(capacity=10, refill_rate=2)
        
        success = await bucket.consume(15)
        assert success is False
        assert bucket.tokens == 10
    
    @pytest.mark.asyncio
    async def test_token_refill(self):
        """Test token refill over time."""
        bucket = TokenBucket(capacity=10, refill_rate=10)  # 10 tokens per second
        
        # Consume all tokens
        await bucket.consume(10)
        assert bucket.tokens == 0
        
        # Wait for refill
        await asyncio.sleep(0.5)
        
        # Should have approximately 5 tokens (10 per second * 0.5 seconds)
        # Refill happens on next consume attempt
        success = await bucket.consume(4)
        assert success is True


class TestProviderLimits:
    """Test ProviderLimits configuration."""
    
    def test_provider_limits_creation(self):
        """Test creating provider limits."""
        limits = ProviderLimits(
            provider=LLMProvider.OPENAI,
            requests_per_minute=100,
            tokens_per_minute=10000,
            concurrent_requests=10
        )
        
        assert limits.provider == LLMProvider.OPENAI
        assert limits.requests_per_minute == 100
        assert limits.tokens_per_minute == 10000
        assert limits.concurrent_requests == 10
    
    def test_provider_defaults(self):
        """Test default provider limits."""
        assert LLMProvider.OPENAI in PROVIDER_DEFAULTS
        defaults = PROVIDER_DEFAULTS[LLMProvider.OPENAI]
        
        assert "rpm" in defaults
        assert "tpm" in defaults
        assert "concurrent" in defaults


class TestRateLimiter:
    """Test RateLimiter functionality."""
    
    @pytest.fixture
    def rate_limiter(self):
        """Create RateLimiter with test limits."""
        limits = ProviderLimits(
            provider=LLMProvider.OPENAI,
            requests_per_minute=10,
            tokens_per_minute=1000,
            concurrent_requests=2
        )
        return RateLimiter(provider_limits={LLMProvider.OPENAI: limits})
    
    @pytest.mark.asyncio
    async def test_acquire_success(self, rate_limiter):
        """Test successful rate limit acquisition."""
        success = await rate_limiter.acquire(
            provider=LLMProvider.OPENAI,
            estimated_tokens=100
        )
        assert success is not None
    
    @pytest.mark.asyncio
    async def test_acquire_rate_limited(self, rate_limiter):
        """Test rate limiting when limits exceeded."""
        # Acquire all available requests
        for _ in range(10):
            await rate_limiter.acquire(
                provider=LLMProvider.OPENAI,
                estimated_tokens=50
            )
        
        # Next request should be rate limited
        success = await rate_limiter.acquire(
            provider=LLMProvider.OPENAI,
            estimated_tokens=50,
            timeout=0.1
        )
        assert success is None
    
    @pytest.mark.asyncio
    async def test_release(self, rate_limiter):
        """Test releasing rate limit slot."""
        token = await rate_limiter.acquire(
            provider=LLMProvider.OPENAI,
            estimated_tokens=100
        )
        assert token is not None
        
        await rate_limiter.release(
            provider=LLMProvider.OPENAI,
            success=True,
            actual_tokens=95
        )
        
        # Verify metrics were updated
        metrics = await rate_limiter.get_metrics()
        assert metrics["total_requests"] > 0
    
    @pytest.mark.asyncio
    async def test_concurrent_limit(self, rate_limiter):
        """Test concurrent request limiting."""
        # Acquire max concurrent requests
        token1 = await rate_limiter.acquire(
            provider=LLMProvider.OPENAI,
            estimated_tokens=100
        )
        token2 = await rate_limiter.acquire(
            provider=LLMProvider.OPENAI,
            estimated_tokens=100
        )
        
        assert token1 is not None
        assert token2 is not None
        
        # Third request should be queued
        token3_task = asyncio.create_task(
            rate_limiter.acquire(
                provider=LLMProvider.OPENAI,
                estimated_tokens=100,
                timeout=0.1
            )
        )
        
        await asyncio.sleep(0.05)
        
        # Release one slot
        await rate_limiter.release(LLMProvider.OPENAI, success=True)
        
        # Now third request should succeed
        token3 = await token3_task
        assert token3 is not None
    
    @pytest.mark.asyncio
    async def test_priority_queuing(self, rate_limiter):
        """Test priority-based request queuing."""
        # Fill up concurrent slots
        await rate_limiter.acquire(
            provider=LLMProvider.OPENAI,
            estimated_tokens=100
        )
        await rate_limiter.acquire(
            provider=LLMProvider.OPENAI,
            estimated_tokens=100
        )
        
        # Queue requests with different priorities
        low_priority = asyncio.create_task(
            rate_limiter.acquire(
                provider=LLMProvider.OPENAI,
                estimated_tokens=100,
                priority=Priority.LOW,
                timeout=1.0
            )
        )
        
        high_priority = asyncio.create_task(
            rate_limiter.acquire(
                provider=LLMProvider.OPENAI,
                estimated_tokens=100,
                priority=Priority.HIGH,
                timeout=1.0
            )
        )
        
        # Give tasks time to queue
        await asyncio.sleep(0.1)
        
        # Release a slot
        await rate_limiter.release(LLMProvider.OPENAI, success=True)
        
        # High priority should complete first
        done, pending = await asyncio.wait(
            [low_priority, high_priority],
            return_when=asyncio.FIRST_COMPLETED
        )
        
        completed_task = done.pop()
        assert completed_task == high_priority
        
        # Cancel pending task
        for task in pending:
            task.cancel()
    
    @pytest.mark.asyncio
    async def test_check_availability(self, rate_limiter):
        """Test checking rate limit availability."""
        status = await rate_limiter.check_availability(LLMProvider.OPENAI)
        
        assert status.status in ["available", "limited", "exhausted"]
        assert status.rpm_remaining >= 0
        assert status.tpm_remaining >= 0
        assert status.concurrent_remaining >= 0
    
    @pytest.mark.asyncio
    async def test_module_limits(self, rate_limiter):
        """Test per-module rate limiting."""
        module_limits = ProviderLimits(
            provider=LLMProvider.OPENAI,
            requests_per_minute=5,
            tokens_per_minute=500,
            concurrent_requests=1
        )
        
        await rate_limiter.set_module_limits("test_module", module_limits)
        
        # Module limits should be more restrictive
        success = await rate_limiter.acquire(
            provider=LLMProvider.OPENAI,
            estimated_tokens=100,
            module_name="test_module"
        )
        assert success is not None
        
        # Second request should be blocked by concurrent limit
        success2 = await rate_limiter.acquire(
            provider=LLMProvider.OPENAI,
            estimated_tokens=100,
            module_name="test_module",
            timeout=0.1
        )
        assert success2 is None
    
    @pytest.mark.asyncio
    async def test_get_metrics(self, rate_limiter):
        """Test metrics collection."""
        # Generate some activity
        await rate_limiter.acquire(
            provider=LLMProvider.OPENAI,
            estimated_tokens=100
        )
        await rate_limiter.release(LLMProvider.OPENAI, success=True)
        
        metrics = await rate_limiter.get_metrics()
        
        assert "total_requests" in metrics
        assert "successful_requests" in metrics
        assert "failed_requests" in metrics
        assert "total_tokens" in metrics
        assert metrics["total_requests"] > 0


class TestRequestQueue:
    """Test RequestQueue functionality."""
    
    @pytest.fixture
    def request_queue(self):
        """Create RequestQueue instance."""
        return RequestQueue(max_size=10)
    
    @pytest.mark.asyncio
    async def test_enqueue_dequeue(self, request_queue):
        """Test basic enqueue and dequeue operations."""
        request = MagicMock()
        request.priority = Priority.NORMAL
        
        await request_queue.enqueue(request)
        assert request_queue.size() == 1
        
        dequeued = await request_queue.dequeue()
        assert dequeued == request
        assert request_queue.size() == 0
    
    @pytest.mark.asyncio
    async def test_priority_ordering(self, request_queue):
        """Test priority-based dequeuing."""
        low = MagicMock(priority=Priority.LOW)
        normal = MagicMock(priority=Priority.NORMAL)
        high = MagicMock(priority=Priority.HIGH)
        critical = MagicMock(priority=Priority.CRITICAL)
        
        # Add in random order
        await request_queue.enqueue(normal)
        await request_queue.enqueue(low)
        await request_queue.enqueue(critical)
        await request_queue.enqueue(high)
        
        # Should dequeue in priority order
        assert await request_queue.dequeue() == critical
        assert await request_queue.dequeue() == high
        assert await request_queue.dequeue() == normal
        assert await request_queue.dequeue() == low
    
    @pytest.mark.asyncio
    async def test_max_size(self, request_queue):
        """Test queue max size enforcement."""
        for i in range(10):
            request = MagicMock(priority=Priority.NORMAL)
            await request_queue.enqueue(request)
        
        # Queue is full
        assert request_queue.size() == 10
        
        # Try to add one more
        extra_request = MagicMock(priority=Priority.NORMAL)
        result = await request_queue.enqueue(extra_request)
        assert result is False
        assert request_queue.size() == 10


class TestBackpressureManager:
    """Test BackpressureManager functionality."""
    
    @pytest.fixture
    def backpressure_manager(self):
        """Create BackpressureManager instance."""
        return BackpressureManager(
            threshold_percentage=80,
            critical_percentage=95
        )
    
    def test_calculate_pressure(self, backpressure_manager):
        """Test pressure calculation."""
        pressure = backpressure_manager.calculate_pressure(
            current_load=50,
            max_capacity=100
        )
        assert pressure == 50.0
        
        pressure = backpressure_manager.calculate_pressure(
            current_load=80,
            max_capacity=100
        )
        assert pressure == 80.0
    
    def test_get_action_normal(self, backpressure_manager):
        """Test action for normal pressure."""
        action = backpressure_manager.get_action(50.0)
        assert action == BackpressureAction.ALLOW
    
    def test_get_action_throttle(self, backpressure_manager):
        """Test action for high pressure."""
        action = backpressure_manager.get_action(85.0)
        assert action == BackpressureAction.THROTTLE
    
    def test_get_action_reject(self, backpressure_manager):
        """Test action for critical pressure."""
        action = backpressure_manager.get_action(96.0)
        assert action == BackpressureAction.REJECT
    
    @pytest.mark.asyncio
    async def test_apply_backpressure_allow(self, backpressure_manager):
        """Test applying backpressure - allow case."""
        result = await backpressure_manager.apply_backpressure(
            action=BackpressureAction.ALLOW
        )
        assert result is True
    
    @pytest.mark.asyncio
    async def test_apply_backpressure_throttle(self, backpressure_manager):
        """Test applying backpressure - throttle case."""
        start_time = time.time()
        result = await backpressure_manager.apply_backpressure(
            action=BackpressureAction.THROTTLE,
            delay_ms=100
        )
        elapsed = time.time() - start_time
        
        assert result is True
        assert elapsed >= 0.1  # Should have delayed
    
    @pytest.mark.asyncio
    async def test_apply_backpressure_reject(self, backpressure_manager):
        """Test applying backpressure - reject case."""
        result = await backpressure_manager.apply_backpressure(
            action=BackpressureAction.REJECT
        )
        assert result is False


class TestCreateRateLimiter:
    """Test rate limiter creation helper."""
    
    @pytest.mark.asyncio
    async def test_create_with_defaults(self):
        """Test creating rate limiter with defaults."""
        limiter = create_rate_limiter()
        
        assert limiter is not None
        assert isinstance(limiter, RateLimiter)
        
        # Should have default provider limits
        status = await limiter.check_availability(LLMProvider.OPENAI)
        assert status.rpm_remaining > 0
    
    @pytest.mark.asyncio
    async def test_create_with_custom_limits(self):
        """Test creating rate limiter with custom limits."""
        custom_limits = {
            LLMProvider.OPENAI: ProviderLimits(
                provider=LLMProvider.OPENAI,
                requests_per_minute=50,
                tokens_per_minute=5000,
                concurrent_requests=5
            )
        }
        
        limiter = create_rate_limiter(provider_limits=custom_limits)
        
        status = await limiter.check_availability(LLMProvider.OPENAI)
        assert status.rpm_remaining <= 50