"""
Unit tests for Gibson Framework's usage tracking system.

Tests cover:
- Basic usage tracking functionality
- Cost calculation with different providers
- Budget management and enforcement
- Usage aggregation and reporting
- Data export functionality
"""

import asyncio
import pytest
from datetime import datetime, timedelta
from decimal import Decimal
from unittest.mock import Mock, AsyncMock

from gibson.core.database import DatabaseManager
from gibson.core.llm.usage_tracking import (
    UsageTracker,
    CostCalculator,
    BudgetManager,
    UsageDatabase,
    UsageReporter,
    BudgetType,
    ExportFormat,
    AggregationPeriod,
    create_usage_tracker,
    estimate_request_cost,
)
from gibson.core.llm.types import (
    CompletionRequest,
    CompletionResponse,
    TokenUsage,
    ChatMessage,
    LLMProvider,
)


class TestCostCalculator:
    """Test cost calculation functionality."""

    def test_cost_calculator_initialization(self):
        """Test cost calculator initializes with pricing data."""
        calculator = CostCalculator()
        assert calculator._pricing_cache is not None
        assert len(calculator._pricing_cache) > 0

    def test_get_model_pricing(self):
        """Test retrieving pricing for known models."""
        calculator = CostCalculator()

        # Test OpenAI pricing
        pricing = calculator.get_model_pricing("openai", "gpt-4-turbo")
        if pricing:  # May be None if not in default pricing
            assert "prompt" in pricing
            assert "completion" in pricing
            assert isinstance(pricing["prompt"], Decimal)
            assert isinstance(pricing["completion"], Decimal)

    def test_calculate_cost(self):
        """Test cost calculation for token usage."""
        calculator = CostCalculator()

        usage = TokenUsage(prompt_tokens=1000, completion_tokens=500, total_tokens=1500)

        prompt_cost, completion_cost, total_cost = calculator.calculate_cost(
            usage, "openai", "gpt-3.5-turbo"
        )

        assert isinstance(prompt_cost, Decimal)
        assert isinstance(completion_cost, Decimal)
        assert isinstance(total_cost, Decimal)
        assert total_cost == prompt_cost + completion_cost
        assert prompt_cost >= 0
        assert completion_cost >= 0


@pytest.mark.asyncio
class TestUsageDatabase:
    """Test usage database functionality."""

    async def test_save_usage(self):
        """Test saving usage records to database."""
        # Mock database manager
        db_manager = Mock(spec=DatabaseManager)
        usage_db = UsageDatabase(db_manager)

        # Mock the session context manager
        mock_session = AsyncMock()
        db_manager.get_session.return_value.__aenter__.return_value = mock_session

        usage = TokenUsage(prompt_tokens=100, completion_tokens=50, total_tokens=150)

        # Test saving usage
        record_id = await usage_db.save_usage(
            request_id="test_request",
            provider="openai",
            model="gpt-3.5-turbo",
            usage=usage,
            response_time=1.2,
            module_name="test_module",
        )

        assert record_id is not None
        mock_session.add.assert_called_once()
        mock_session.commit.assert_called_once()


@pytest.mark.asyncio
class TestBudgetManager:
    """Test budget management functionality."""

    async def test_create_budget(self):
        """Test creating budget limits."""
        # Mock database manager
        db_manager = Mock(spec=DatabaseManager)
        budget_manager = BudgetManager(db_manager)

        # Mock the session context manager
        mock_session = AsyncMock()
        db_manager.get_session.return_value.__aenter__.return_value = mock_session

        budget_id = await budget_manager.create_budget(
            name="Test Budget",
            budget_type=BudgetType.DAILY,
            limit_amount=Decimal("10.00"),
            provider="openai",
        )

        assert budget_id is not None
        mock_session.add.assert_called_once()
        mock_session.commit.assert_called_once()

    def test_calculate_period_boundaries(self):
        """Test period boundary calculation for different budget types."""
        db_manager = Mock(spec=DatabaseManager)
        budget_manager = BudgetManager(db_manager)

        now = datetime(2024, 1, 15, 12, 30, 45)  # Monday

        # Test daily boundaries
        start, end = budget_manager._calculate_period_boundaries(BudgetType.DAILY, now)
        assert start == datetime(2024, 1, 15, 0, 0, 0)
        assert end == datetime(2024, 1, 16, 0, 0, 0)

        # Test weekly boundaries (should start on Monday)
        start, end = budget_manager._calculate_period_boundaries(BudgetType.WEEKLY, now)
        assert start == datetime(2024, 1, 15, 0, 0, 0)  # Monday
        assert end == datetime(2024, 1, 22, 0, 0, 0)  # Next Monday

        # Test monthly boundaries
        start, end = budget_manager._calculate_period_boundaries(BudgetType.MONTHLY, now)
        assert start == datetime(2024, 1, 1, 0, 0, 0)
        assert end == datetime(2024, 2, 1, 0, 0, 0)


class TestUsageTracker:
    """Test main usage tracker functionality."""

    def test_estimate_request_cost(self):
        """Test cost estimation function."""
        cost = estimate_request_cost(
            prompt_tokens=1000, completion_tokens=500, provider="openai", model="gpt-3.5-turbo"
        )

        assert isinstance(cost, Decimal)
        assert cost >= 0

    @pytest.mark.asyncio
    async def test_create_usage_tracker(self):
        """Test usage tracker factory function."""
        db_manager = Mock(spec=DatabaseManager)
        tracker = await create_usage_tracker(db_manager)

        assert isinstance(tracker, UsageTracker)
        assert tracker.db_manager == db_manager
        assert isinstance(tracker.cost_calculator, CostCalculator)
        assert isinstance(tracker.budget_manager, BudgetManager)
        assert isinstance(tracker.usage_db, UsageDatabase)
        assert isinstance(tracker.usage_reporter, UsageReporter)


@pytest.mark.asyncio
class TestUsageReporter:
    """Test usage reporting functionality."""

    async def test_export_json(self):
        """Test JSON export functionality."""
        db_manager = Mock(spec=DatabaseManager)
        reporter = UsageReporter(db_manager)

        # Mock usage summary
        from gibson.core.llm.usage_tracking import UsageSummary

        summary = UsageSummary(
            period_start=datetime.utcnow() - timedelta(days=1),
            period_end=datetime.utcnow(),
            total_requests=100,
            successful_requests=95,
            failed_requests=5,
            total_prompt_tokens=10000,
            total_completion_tokens=5000,
            total_tokens=15000,
            total_cost=Decimal("5.25"),
            avg_cost_per_request=Decimal("0.0525"),
            avg_response_time=1.2,
            p95_response_time=2.1,
            error_rate=5.0,
            fallback_rate=2.0,
        )

        json_data = reporter._export_json(summary)

        assert isinstance(json_data, bytes)
        assert len(json_data) > 0

        # Verify it's valid JSON
        import json

        parsed = json.loads(json_data.decode("utf-8"))
        assert parsed["total_requests"] == 100
        assert parsed["total_cost"] == "5.25"


class TestIntegration:
    """Integration tests for the complete usage tracking system."""

    def test_import_all_classes(self):
        """Test that all usage tracking classes can be imported."""
        from gibson.core.llm.usage_tracking import (
            UsageTracker,
            CostCalculator,
            BudgetManager,
            UsageDatabase,
            UsageReporter,
            UsageSummary,
            TrendData,
            BudgetStatus,
            CostBreakdown,
            AggregationPeriod,
            ExportFormat,
            BudgetType,
            AlertLevel,
        )

        # Verify all classes are properly defined
        assert UsageTracker is not None
        assert CostCalculator is not None
        assert BudgetManager is not None
        assert UsageDatabase is not None
        assert UsageReporter is not None
        assert UsageSummary is not None
        assert TrendData is not None
        assert BudgetStatus is not None
        assert CostBreakdown is not None

        # Verify enums
        assert AggregationPeriod.DAILY is not None
        assert ExportFormat.JSON is not None
        assert BudgetType.MONTHLY is not None
        assert AlertLevel.WARNING is not None

    def test_enum_values(self):
        """Test enum value consistency."""
        assert AggregationPeriod.DAILY.value == "daily"
        assert ExportFormat.JSON.value == "json"
        assert BudgetType.MONTHLY.value == "monthly"
        assert AlertLevel.WARNING.value == "warning"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
