"""
Cost tracking and usage monitoring for Gibson Framework's LLM integrations.

This module provides comprehensive usage statistics collection using LiteLLM's cost tracking,
per-module/provider/scan aggregation, cost estimation, budget warning systems, and persistent
storage of usage data. Designed for production deployment with performance optimization.
"""

from __future__ import annotations

import asyncio
import csv
import json
from collections import defaultdict
from datetime import datetime, timedelta
from decimal import Decimal, ROUND_HALF_UP
from enum import Enum
from io import StringIO
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from uuid import UUID, uuid4

from loguru import logger
from pydantic import BaseModel, Field, computed_field, field_validator
from sqlalchemy import (
    Column,
    String,
    Text,
    Integer,
    Boolean,
    DateTime,
    JSON,
    ForeignKey,
    Float,
    Index,
    Numeric,
)
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.sql import func

try:
    import litellm
    from litellm import get_model_cost_map, cost_calculator

    LITELLM_AVAILABLE = True
except ImportError:
    logger.warning("LiteLLM not available - cost tracking will use estimated pricing")
    LITELLM_AVAILABLE = False

from gibson.db import Base
from gibson.db.manager import DatabaseManager
from gibson.core.llm.types import (
    LLMProvider,
    TokenUsage,
    CompletionRequest,
    CompletionResponse,
    UsageRecord as BaseUsageRecord,
)
from gibson.models.base import GibsonBaseModel, TimestampedModel


# =============================================================================
# Enums and Constants
# =============================================================================


class AggregationPeriod(str, Enum):
    """Time periods for usage aggregation."""

    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    YEARLY = "yearly"


class ExportFormat(str, Enum):
    """Export format options."""

    JSON = "json"
    CSV = "csv"
    XLSX = "xlsx"


class BudgetType(str, Enum):
    """Budget types for different scopes."""

    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    YEARLY = "yearly"
    TOTAL = "total"


class AlertLevel(str, Enum):
    """Alert levels for budget warnings."""

    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


# Default pricing data when LiteLLM is not available (per 1K tokens)
DEFAULT_PRICING = {
    LLMProvider.OPENAI: {
        "gpt-4-turbo": {"prompt": Decimal("0.01"), "completion": Decimal("0.03")},
        "gpt-4": {"prompt": Decimal("0.03"), "completion": Decimal("0.06")},
        "gpt-3.5-turbo": {"prompt": Decimal("0.0015"), "completion": Decimal("0.002")},
        "gpt-3.5-turbo-16k": {"prompt": Decimal("0.003"), "completion": Decimal("0.004")},
    },
    LLMProvider.ANTHROPIC: {
        "claude-3-opus": {"prompt": Decimal("0.015"), "completion": Decimal("0.075")},
        "claude-3-sonnet": {"prompt": Decimal("0.003"), "completion": Decimal("0.015")},
        "claude-3-haiku": {"prompt": Decimal("0.00025"), "completion": Decimal("0.00125")},
    },
    LLMProvider.GOOGLE_AI: {
        "gemini-pro": {"prompt": Decimal("0.0005"), "completion": Decimal("0.0015")},
        "gemini-pro-vision": {"prompt": Decimal("0.0005"), "completion": Decimal("0.0015")},
    },
}


# =============================================================================
# Database Models
# =============================================================================


class UsageTrackingRecord(Base):
    """Database model for usage tracking records."""

    __tablename__ = "usage_tracking"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    request_id = Column(String(36), nullable=False, index=True)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=True, index=True)
    module_name = Column(String(100), nullable=True, index=True)
    provider = Column(String(50), nullable=False, index=True)
    model = Column(String(100), nullable=False, index=True)

    # Token usage
    prompt_tokens = Column(Integer, default=0)
    completion_tokens = Column(Integer, default=0)
    total_tokens = Column(Integer, default=0)
    cached_tokens = Column(Integer, default=0)

    # Cost tracking
    prompt_cost = Column(Numeric(10, 6), default=0)
    completion_cost = Column(Numeric(10, 6), default=0)
    total_cost = Column(Numeric(10, 6), default=0)
    currency = Column(String(3), default="USD")

    # Performance metrics
    response_time = Column(Float, default=0.0)
    request_size = Column(Integer, default=0)  # Request payload size
    response_size = Column(Integer, default=0)  # Response payload size

    # Error tracking
    error_type = Column(String(50), nullable=True)
    error_message = Column(Text, nullable=True)
    fallback_used = Column(Boolean, default=False)
    retry_count = Column(Integer, default=0)

    # Metadata
    user_id = Column(String(100), nullable=True, index=True)
    session_id = Column(String(100), nullable=True, index=True)
    tags = Column(JSON, default=list)
    request_metadata = Column(
        JSON, default=dict
    )  # renamed from metadata to avoid SQLAlchemy conflict

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    # Indexes for efficient querying
    __table_args__ = (
        Index("idx_usage_provider_model", "provider", "model"),
        Index("idx_usage_scan_module", "scan_id", "module_name"),
        Index("idx_usage_created_at", "created_at"),
        Index("idx_usage_cost", "total_cost"),
        Index("idx_usage_user_session", "user_id", "session_id"),
    )


class UsageAggregationRecord(Base):
    """Database model for aggregated usage statistics."""

    __tablename__ = "usage_aggregation"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    period = Column(String(20), nullable=False, index=True)  # hourly, daily, weekly, monthly
    period_start = Column(DateTime, nullable=False, index=True)
    period_end = Column(DateTime, nullable=False, index=True)

    # Aggregation dimensions
    provider = Column(String(50), nullable=True, index=True)
    model = Column(String(100), nullable=True, index=True)
    module_name = Column(String(100), nullable=True, index=True)
    scan_id = Column(String(36), nullable=True, index=True)
    user_id = Column(String(100), nullable=True, index=True)

    # Aggregated metrics
    total_requests = Column(Integer, default=0)
    successful_requests = Column(Integer, default=0)
    failed_requests = Column(Integer, default=0)

    total_prompt_tokens = Column(Integer, default=0)
    total_completion_tokens = Column(Integer, default=0)
    total_tokens = Column(Integer, default=0)
    total_cached_tokens = Column(Integer, default=0)

    total_cost = Column(Numeric(10, 6), default=0)
    avg_cost_per_request = Column(Numeric(10, 6), default=0)

    # Performance metrics
    avg_response_time = Column(Float, default=0.0)
    min_response_time = Column(Float, default=0.0)
    max_response_time = Column(Float, default=0.0)
    p95_response_time = Column(Float, default=0.0)

    # Quality metrics
    error_rate = Column(Float, default=0.0)
    fallback_rate = Column(Float, default=0.0)
    avg_retry_count = Column(Float, default=0.0)

    # Metadata
    data_points = Column(Integer, default=0)  # Number of records aggregated
    last_updated = Column(DateTime, default=datetime.utcnow)

    # Unique constraint to prevent duplicate aggregations
    __table_args__ = (
        Index(
            "idx_aggregation_unique",
            "period",
            "period_start",
            "provider",
            "model",
            "module_name",
            "scan_id",
            "user_id",
            unique=True,
        ),
        Index("idx_aggregation_period", "period", "period_start"),
        Index("idx_aggregation_cost", "total_cost"),
    )


class BudgetRecord(Base):
    """Database model for budget limits and tracking."""

    __tablename__ = "budget_limits"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    name = Column(String(100), nullable=False)
    budget_type = Column(
        String(20), nullable=False, index=True
    )  # daily, weekly, monthly, yearly, total
    limit_amount = Column(Numeric(10, 2), nullable=False)
    currency = Column(String(3), default="USD")

    # Scope filters
    provider = Column(String(50), nullable=True, index=True)
    model = Column(String(100), nullable=True, index=True)
    module_name = Column(String(100), nullable=True, index=True)
    user_id = Column(String(100), nullable=True, index=True)

    # Alert configuration
    warning_threshold = Column(Float, default=0.8)  # 80%
    critical_threshold = Column(Float, default=0.9)  # 90%
    emergency_threshold = Column(Float, default=0.95)  # 95%

    # Status
    enabled = Column(Boolean, default=True)
    hard_limit = Column(Boolean, default=False)  # Enforce hard limit vs warning only

    # Tracking
    current_usage = Column(Numeric(10, 6), default=0)
    period_start = Column(DateTime, nullable=True)
    period_end = Column(DateTime, nullable=True)
    last_reset = Column(DateTime, nullable=True)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        Index("idx_budget_type_provider", "budget_type", "provider"),
        Index("idx_budget_enabled", "enabled"),
    )


class AlertRecord(Base):
    """Database model for budget alerts and notifications."""

    __tablename__ = "budget_alerts"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    budget_id = Column(String(36), ForeignKey("budget_limits.id"), nullable=False, index=True)
    alert_level = Column(String(20), nullable=False, index=True)
    message = Column(Text, nullable=False)

    # Alert context
    current_usage = Column(Numeric(10, 6), nullable=False)
    limit_amount = Column(Numeric(10, 6), nullable=False)
    usage_percentage = Column(Float, nullable=False)

    # Status
    acknowledged = Column(Boolean, default=False)
    resolved = Column(Boolean, default=False)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    acknowledged_at = Column(DateTime, nullable=True)
    resolved_at = Column(DateTime, nullable=True)


# =============================================================================
# Pydantic Models
# =============================================================================


class UsageSummary(GibsonBaseModel):
    """Summary of usage statistics for a given period."""

    period_start: datetime = Field(description="Period start timestamp")
    period_end: datetime = Field(description="Period end timestamp")

    # Request metrics
    total_requests: int = Field(description="Total number of requests")
    successful_requests: int = Field(description="Number of successful requests")
    failed_requests: int = Field(description="Number of failed requests")

    # Token metrics
    total_prompt_tokens: int = Field(description="Total prompt tokens")
    total_completion_tokens: int = Field(description="Total completion tokens")
    total_tokens: int = Field(description="Total tokens")
    total_cached_tokens: int = Field(default=0, description="Total cached tokens")

    # Cost metrics
    total_cost: Decimal = Field(description="Total cost")
    avg_cost_per_request: Decimal = Field(description="Average cost per request")
    currency: str = Field(default="USD", description="Currency code")

    # Performance metrics
    avg_response_time: float = Field(description="Average response time in seconds")
    p95_response_time: float = Field(description="95th percentile response time")

    # Quality metrics
    error_rate: float = Field(description="Error rate as percentage")
    fallback_rate: float = Field(description="Fallback usage rate as percentage")

    # Breakdowns
    provider_breakdown: Dict[str, Dict[str, Any]] = Field(
        default_factory=dict, description="Usage breakdown by provider"
    )
    model_breakdown: Dict[str, Dict[str, Any]] = Field(
        default_factory=dict, description="Usage breakdown by model"
    )
    module_breakdown: Dict[str, Dict[str, Any]] = Field(
        default_factory=dict, description="Usage breakdown by module"
    )

    @computed_field
    def success_rate(self) -> float:
        """Calculate success rate percentage."""
        if self.total_requests == 0:
            return 0.0
        return (self.successful_requests / self.total_requests) * 100


class TrendData(GibsonBaseModel):
    """Usage trend data over time."""

    period: AggregationPeriod = Field(description="Aggregation period")
    data_points: List[Dict[str, Any]] = Field(description="Time series data points")

    # Trend analysis
    trend_direction: str = Field(description="Overall trend direction: up, down, stable")
    growth_rate: float = Field(description="Percentage growth rate")
    seasonal_patterns: Dict[str, Any] = Field(
        default_factory=dict, description="Detected seasonal patterns"
    )

    # Forecasting
    predicted_next_period: Dict[str, Any] = Field(
        default_factory=dict, description="Predicted values for next period"
    )


class BudgetStatus(GibsonBaseModel):
    """Current budget status and usage."""

    budget_id: str = Field(description="Budget identifier")
    name: str = Field(description="Budget name")
    budget_type: BudgetType = Field(description="Budget type")
    limit_amount: Decimal = Field(description="Budget limit")
    current_usage: Decimal = Field(description="Current usage amount")
    currency: str = Field(description="Currency code")

    # Status calculations
    usage_percentage: float = Field(description="Usage as percentage of limit")
    remaining_amount: Decimal = Field(description="Remaining budget amount")

    # Alert levels
    warning_threshold: float = Field(description="Warning threshold percentage")
    critical_threshold: float = Field(description="Critical threshold percentage")
    emergency_threshold: float = Field(description="Emergency threshold percentage")

    # Period information
    period_start: Optional[datetime] = Field(default=None, description="Period start")
    period_end: Optional[datetime] = Field(default=None, description="Period end")

    # Status flags
    is_over_budget: bool = Field(description="Whether budget is exceeded")
    alert_level: Optional[AlertLevel] = Field(default=None, description="Current alert level")
    hard_limit_enabled: bool = Field(description="Whether hard limit is enforced")

    @computed_field
    def days_remaining(self) -> Optional[int]:
        """Calculate days remaining in budget period."""
        if not self.period_end:
            return None
        return max(0, (self.period_end - datetime.utcnow()).days)


class CostBreakdown(GibsonBaseModel):
    """Detailed cost breakdown by various dimensions."""

    total_cost: Decimal = Field(description="Total cost")
    currency: str = Field(default="USD", description="Currency")

    # By provider
    by_provider: Dict[str, Decimal] = Field(
        default_factory=dict, description="Cost breakdown by provider"
    )

    # By model
    by_model: Dict[str, Decimal] = Field(
        default_factory=dict, description="Cost breakdown by model"
    )

    # By module
    by_module: Dict[str, Decimal] = Field(
        default_factory=dict, description="Cost breakdown by module"
    )

    # By scan
    by_scan: Dict[str, Decimal] = Field(default_factory=dict, description="Cost breakdown by scan")

    # By time period
    by_period: Dict[str, Decimal] = Field(
        default_factory=dict, description="Cost breakdown by time period"
    )


# =============================================================================
# Core Usage Tracking Classes
# =============================================================================


class CostCalculator:
    """Calculate costs based on provider pricing and usage."""

    def __init__(self):
        """Initialize cost calculator with pricing data."""
        self._pricing_cache: Dict[str, Dict[str, Dict[str, Decimal]]] = {}
        self._last_update: Optional[datetime] = None
        self._update_pricing_cache()

    def _update_pricing_cache(self) -> None:
        """Update pricing cache from LiteLLM or use defaults."""
        try:
            if LITELLM_AVAILABLE:
                # Get pricing from LiteLLM
                cost_map = get_model_cost_map()
                for model, pricing in cost_map.items():
                    if isinstance(pricing, dict):
                        provider = self._extract_provider_from_model(model)
                        if provider not in self._pricing_cache:
                            self._pricing_cache[provider] = {}

                        self._pricing_cache[provider][model] = {
                            "prompt": Decimal(str(pricing.get("input_cost_per_token", 0))),
                            "completion": Decimal(str(pricing.get("output_cost_per_token", 0))),
                        }
            else:
                # Use default pricing
                for provider, models in DEFAULT_PRICING.items():
                    self._pricing_cache[provider.value] = models

            self._last_update = datetime.utcnow()
            logger.debug(f"Updated pricing cache with {len(self._pricing_cache)} providers")

        except Exception as e:
            logger.warning(f"Failed to update pricing cache: {e}")
            # Fallback to default pricing
            for provider, models in DEFAULT_PRICING.items():
                self._pricing_cache[provider.value] = models

    def _extract_provider_from_model(self, model: str) -> str:
        """Extract provider from model string."""
        # Simple heuristic - can be improved
        if "gpt" in model.lower():
            return LLMProvider.OPENAI.value
        elif "claude" in model.lower():
            return LLMProvider.ANTHROPIC.value
        elif "gemini" in model.lower():
            return LLMProvider.GOOGLE_AI.value
        else:
            return "unknown"

    def get_model_pricing(self, provider: str, model: str) -> Optional[Dict[str, Decimal]]:
        """Get pricing for a specific provider and model."""
        # Refresh cache if it's old
        if self._last_update is None or datetime.utcnow() - self._last_update > timedelta(hours=24):
            self._update_pricing_cache()

        return self._pricing_cache.get(provider, {}).get(model)

    def calculate_cost(
        self, usage: TokenUsage, provider: str, model: str
    ) -> Tuple[Decimal, Decimal, Decimal]:
        """
        Calculate cost for token usage.

        Returns:
            Tuple of (prompt_cost, completion_cost, total_cost)
        """
        pricing = self.get_model_pricing(provider, model)

        if not pricing:
            logger.warning(f"No pricing data for {provider}/{model}, using zero cost")
            return Decimal("0"), Decimal("0"), Decimal("0")

        # Calculate costs (pricing is per 1K tokens)
        prompt_cost = (Decimal(str(usage.prompt_tokens)) * pricing["prompt"]) / Decimal("1000")
        completion_cost = (Decimal(str(usage.completion_tokens)) * pricing["completion"]) / Decimal(
            "1000"
        )
        total_cost = prompt_cost + completion_cost

        # Round to 6 decimal places
        prompt_cost = prompt_cost.quantize(Decimal("0.000001"), rounding=ROUND_HALF_UP)
        completion_cost = completion_cost.quantize(Decimal("0.000001"), rounding=ROUND_HALF_UP)
        total_cost = total_cost.quantize(Decimal("0.000001"), rounding=ROUND_HALF_UP)

        return prompt_cost, completion_cost, total_cost


class BudgetManager:
    """Monitor spending and enforce budget limits."""

    def __init__(self, db_manager: DatabaseManager):
        """Initialize budget manager with database connection."""
        self.db_manager = db_manager
        self._budget_cache: Dict[str, BudgetRecord] = {}
        self._last_cache_update: Optional[datetime] = None

    async def _refresh_budget_cache(self) -> None:
        """Refresh budget cache from database."""
        async with self.db_manager.session_factory() as session:
            result = await session.execute(select(BudgetRecord).where(BudgetRecord.enabled == True))
            budgets = result.scalars().all()

            self._budget_cache = {budget.id: budget for budget in budgets}
            self._last_cache_update = datetime.utcnow()

    async def create_budget(
        self,
        name: str,
        budget_type: BudgetType,
        limit_amount: Decimal,
        provider: Optional[str] = None,
        model: Optional[str] = None,
        module_name: Optional[str] = None,
        user_id: Optional[str] = None,
        warning_threshold: float = 0.8,
        critical_threshold: float = 0.9,
        emergency_threshold: float = 0.95,
        hard_limit: bool = False,
    ) -> str:
        """Create a new budget limit."""
        budget_id = str(uuid4())

        # Calculate period boundaries
        now = datetime.utcnow()
        period_start, period_end = self._calculate_period_boundaries(budget_type, now)

        budget = BudgetRecord(
            id=budget_id,
            name=name,
            budget_type=budget_type.value,
            limit_amount=limit_amount,
            provider=provider,
            model=model,
            module_name=module_name,
            user_id=user_id,
            warning_threshold=warning_threshold,
            critical_threshold=critical_threshold,
            emergency_threshold=emergency_threshold,
            hard_limit=hard_limit,
            period_start=period_start,
            period_end=period_end,
            last_reset=now,
        )

        async with self.db_manager.session_factory() as session:
            session.add(budget)
            await session.commit()

        # Update cache
        await self._refresh_budget_cache()

        logger.info(f"Created budget '{name}' with limit {limit_amount}")
        return budget_id

    def _calculate_period_boundaries(
        self, budget_type: BudgetType, reference_time: datetime
    ) -> Tuple[datetime, datetime]:
        """Calculate period start and end for budget type."""
        if budget_type == BudgetType.DAILY:
            start = reference_time.replace(hour=0, minute=0, second=0, microsecond=0)
            end = start + timedelta(days=1)
        elif budget_type == BudgetType.WEEKLY:
            days_since_monday = reference_time.weekday()
            start = (reference_time - timedelta(days=days_since_monday)).replace(
                hour=0, minute=0, second=0, microsecond=0
            )
            end = start + timedelta(weeks=1)
        elif budget_type == BudgetType.MONTHLY:
            start = reference_time.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            if start.month == 12:
                end = start.replace(year=start.year + 1, month=1)
            else:
                end = start.replace(month=start.month + 1)
        elif budget_type == BudgetType.YEARLY:
            start = reference_time.replace(
                month=1, day=1, hour=0, minute=0, second=0, microsecond=0
            )
            end = start.replace(year=start.year + 1)
        else:  # TOTAL
            start = datetime.min
            end = datetime.max

        return start, end

    async def check_budget(
        self,
        amount: Decimal,
        provider: Optional[str] = None,
        model: Optional[str] = None,
        module_name: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> Tuple[bool, List[BudgetStatus]]:
        """
        Check if spending amount would exceed any applicable budgets.

        Returns:
            Tuple of (allowed, list of applicable budget statuses)
        """
        # Refresh cache if needed
        if (
            self._last_cache_update is None
            or datetime.utcnow() - self._last_cache_update > timedelta(minutes=5)
        ):
            await self._refresh_budget_cache()

        applicable_budgets = []
        allowed = True

        for budget in self._budget_cache.values():
            if self._budget_applies(budget, provider, model, module_name, user_id):
                # Reset budget if period has changed
                if self._should_reset_budget(budget):
                    await self._reset_budget_period(budget)

                # Calculate new usage
                new_usage = budget.current_usage + amount
                usage_percentage = float((new_usage / budget.limit_amount) * 100)

                status = BudgetStatus(
                    budget_id=budget.id,
                    name=budget.name,
                    budget_type=BudgetType(budget.budget_type),
                    limit_amount=budget.limit_amount,
                    current_usage=new_usage,
                    currency=budget.currency,
                    usage_percentage=usage_percentage,
                    remaining_amount=budget.limit_amount - new_usage,
                    warning_threshold=budget.warning_threshold * 100,
                    critical_threshold=budget.critical_threshold * 100,
                    emergency_threshold=budget.emergency_threshold * 100,
                    period_start=budget.period_start,
                    period_end=budget.period_end,
                    is_over_budget=new_usage > budget.limit_amount,
                    hard_limit_enabled=budget.hard_limit,
                )

                # Determine alert level
                if usage_percentage >= budget.emergency_threshold * 100:
                    status.alert_level = AlertLevel.EMERGENCY
                elif usage_percentage >= budget.critical_threshold * 100:
                    status.alert_level = AlertLevel.CRITICAL
                elif usage_percentage >= budget.warning_threshold * 100:
                    status.alert_level = AlertLevel.WARNING

                applicable_budgets.append(status)

                # Check if hard limit would be exceeded
                if budget.hard_limit and new_usage > budget.limit_amount:
                    allowed = False

        return allowed, applicable_budgets

    def _budget_applies(
        self,
        budget: BudgetRecord,
        provider: Optional[str],
        model: Optional[str],
        module_name: Optional[str],
        user_id: Optional[str],
    ) -> bool:
        """Check if budget applies to the given context."""
        if budget.provider and budget.provider != provider:
            return False
        if budget.model and budget.model != model:
            return False
        if budget.module_name and budget.module_name != module_name:
            return False
        if budget.user_id and budget.user_id != user_id:
            return False
        return True

    def _should_reset_budget(self, budget: BudgetRecord) -> bool:
        """Check if budget period should be reset."""
        if budget.budget_type == BudgetType.TOTAL.value:
            return False

        now = datetime.utcnow()
        return budget.period_end and now >= budget.period_end

    async def _reset_budget_period(self, budget: BudgetRecord) -> None:
        """Reset budget for new period."""
        now = datetime.utcnow()
        budget_type = BudgetType(budget.budget_type)

        period_start, period_end = self._calculate_period_boundaries(budget_type, now)

        async with self.db_manager.session_factory() as session:
            # Update budget record
            await session.execute(select(BudgetRecord).where(BudgetRecord.id == budget.id))
            budget.current_usage = Decimal("0")
            budget.period_start = period_start
            budget.period_end = period_end
            budget.last_reset = now

            session.add(budget)
            await session.commit()

        # Update cache
        self._budget_cache[budget.id] = budget

        logger.info(f"Reset budget '{budget.name}' for new period")

    async def update_budget_usage(
        self,
        amount: Decimal,
        provider: Optional[str] = None,
        model: Optional[str] = None,
        module_name: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> List[str]:
        """
        Update budget usage and return list of budget IDs that were updated.
        """
        updated_budgets = []

        for budget in self._budget_cache.values():
            if self._budget_applies(budget, provider, model, module_name, user_id):
                # Reset if needed
                if self._should_reset_budget(budget):
                    await self._reset_budget_period(budget)

                # Update usage
                budget.current_usage += amount

                async with self.db_manager.session_factory() as session:
                    await session.execute(select(BudgetRecord).where(BudgetRecord.id == budget.id))
                    session.add(budget)
                    await session.commit()

                updated_budgets.append(budget.id)

                # Check for alerts
                await self._check_and_create_alerts(budget)

        return updated_budgets

    async def _check_and_create_alerts(self, budget: BudgetRecord) -> None:
        """Check budget status and create alerts if needed."""
        usage_percentage = float((budget.current_usage / budget.limit_amount))

        alert_level = None
        if usage_percentage >= budget.emergency_threshold:
            alert_level = AlertLevel.EMERGENCY
        elif usage_percentage >= budget.critical_threshold:
            alert_level = AlertLevel.CRITICAL
        elif usage_percentage >= budget.warning_threshold:
            alert_level = AlertLevel.WARNING

        if alert_level:
            # Check if we already have a recent alert for this level
            async with self.db_manager.session_factory() as session:
                recent_alert = await session.execute(
                    select(AlertRecord)
                    .where(AlertRecord.budget_id == budget.id)
                    .where(AlertRecord.alert_level == alert_level.value)
                    .where(AlertRecord.resolved == False)
                    .where(AlertRecord.created_at > datetime.utcnow() - timedelta(hours=1))
                )

                if not recent_alert.scalar_one_or_none():
                    # Create new alert
                    alert = AlertRecord(
                        budget_id=budget.id,
                        alert_level=alert_level.value,
                        message=f"Budget '{budget.name}' is at {usage_percentage*100:.1f}% of limit",
                        current_usage=budget.current_usage,
                        limit_amount=budget.limit_amount,
                        usage_percentage=usage_percentage * 100,
                    )
                    session.add(alert)
                    await session.commit()

                    logger.warning(f"Budget alert: {alert.message}")


class UsageDatabase:
    """Handle persistent storage of usage data."""

    def __init__(self, db_manager: DatabaseManager):
        """Initialize with database manager."""
        self.db_manager = db_manager

    async def save_usage(
        self,
        request_id: str,
        provider: str,
        model: str,
        usage: TokenUsage,
        response_time: float,
        scan_id: Optional[str] = None,
        module_name: Optional[str] = None,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        error_type: Optional[str] = None,
        error_message: Optional[str] = None,
        fallback_used: bool = False,
        retry_count: int = 0,
        request_size: int = 0,
        response_size: int = 0,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Save usage record to database."""

        # Calculate costs
        cost_calculator = CostCalculator()
        prompt_cost, completion_cost, total_cost = cost_calculator.calculate_cost(
            usage, provider, model
        )

        record = UsageTrackingRecord(
            request_id=request_id,
            scan_id=scan_id,
            module_name=module_name,
            provider=provider,
            model=model,
            prompt_tokens=usage.prompt_tokens,
            completion_tokens=usage.completion_tokens,
            total_tokens=usage.total_tokens,
            cached_tokens=usage.cached_tokens or 0,
            prompt_cost=prompt_cost,
            completion_cost=completion_cost,
            total_cost=total_cost,
            response_time=response_time,
            request_size=request_size,
            response_size=response_size,
            error_type=error_type,
            error_message=error_message,
            fallback_used=fallback_used,
            retry_count=retry_count,
            user_id=user_id,
            session_id=session_id,
            tags=tags or [],
            request_metadata=metadata or {},
        )

        async with self.db_manager.session_factory() as session:
            session.add(record)
            await session.commit()
            await session.refresh(record)

        return record.id

    async def get_usage_summary(
        self,
        period_start: datetime,
        period_end: datetime,
        provider: Optional[str] = None,
        model: Optional[str] = None,
        module_name: Optional[str] = None,
        scan_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> UsageSummary:
        """Get usage summary for specified period and filters."""

        async with self.db_manager.session_factory() as session:
            # Base query
            query = select(UsageTrackingRecord).where(
                UsageTrackingRecord.created_at.between(period_start, period_end)
            )

            # Apply filters
            if provider:
                query = query.where(UsageTrackingRecord.provider == provider)
            if model:
                query = query.where(UsageTrackingRecord.model == model)
            if module_name:
                query = query.where(UsageTrackingRecord.module_name == module_name)
            if scan_id:
                query = query.where(UsageTrackingRecord.scan_id == scan_id)
            if user_id:
                query = query.where(UsageTrackingRecord.user_id == user_id)

            result = await session.execute(query)
            records = result.scalars().all()

            # Calculate aggregates
            total_requests = len(records)
            successful_requests = sum(1 for r in records if not r.error_type)
            failed_requests = total_requests - successful_requests

            total_prompt_tokens = sum(r.prompt_tokens for r in records)
            total_completion_tokens = sum(r.completion_tokens for r in records)
            total_tokens = sum(r.total_tokens for r in records)
            total_cached_tokens = sum(r.cached_tokens for r in records)

            total_cost = sum(r.total_cost for r in records)
            avg_cost_per_request = (
                total_cost / total_requests if total_requests > 0 else Decimal("0")
            )

            response_times = [r.response_time for r in records if r.response_time > 0]
            avg_response_time = sum(response_times) / len(response_times) if response_times else 0.0

            # Calculate p95 response time
            if response_times:
                sorted_times = sorted(response_times)
                p95_index = int(len(sorted_times) * 0.95)
                p95_response_time = (
                    sorted_times[p95_index] if p95_index < len(sorted_times) else sorted_times[-1]
                )
            else:
                p95_response_time = 0.0

            error_rate = (failed_requests / total_requests * 100) if total_requests > 0 else 0.0
            fallback_rate = (
                (sum(1 for r in records if r.fallback_used) / total_requests * 100)
                if total_requests > 0
                else 0.0
            )

            # Build breakdowns
            provider_breakdown = defaultdict(
                lambda: {"requests": 0, "cost": Decimal("0"), "tokens": 0}
            )
            model_breakdown = defaultdict(
                lambda: {"requests": 0, "cost": Decimal("0"), "tokens": 0}
            )
            module_breakdown = defaultdict(
                lambda: {"requests": 0, "cost": Decimal("0"), "tokens": 0}
            )

            for record in records:
                provider_breakdown[record.provider]["requests"] += 1
                provider_breakdown[record.provider]["cost"] += record.total_cost
                provider_breakdown[record.provider]["tokens"] += record.total_tokens

                model_breakdown[record.model]["requests"] += 1
                model_breakdown[record.model]["cost"] += record.total_cost
                model_breakdown[record.model]["tokens"] += record.total_tokens

                if record.module_name:
                    module_breakdown[record.module_name]["requests"] += 1
                    module_breakdown[record.module_name]["cost"] += record.total_cost
                    module_breakdown[record.module_name]["tokens"] += record.total_tokens

            return UsageSummary(
                period_start=period_start,
                period_end=period_end,
                total_requests=total_requests,
                successful_requests=successful_requests,
                failed_requests=failed_requests,
                total_prompt_tokens=total_prompt_tokens,
                total_completion_tokens=total_completion_tokens,
                total_tokens=total_tokens,
                total_cached_tokens=total_cached_tokens,
                total_cost=total_cost,
                avg_cost_per_request=avg_cost_per_request,
                avg_response_time=avg_response_time,
                p95_response_time=p95_response_time,
                error_rate=error_rate,
                fallback_rate=fallback_rate,
                provider_breakdown=dict(provider_breakdown),
                model_breakdown=dict(model_breakdown),
                module_breakdown=dict(module_breakdown),
            )

    async def aggregate_usage(
        self,
        period: AggregationPeriod,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> None:
        """Aggregate usage data for the specified period."""

        if not start_time:
            start_time = datetime.utcnow() - timedelta(days=1)
        if not end_time:
            end_time = datetime.utcnow()

        # Calculate aggregation boundaries based on period
        boundaries = self._calculate_aggregation_boundaries(period, start_time, end_time)

        async with self.db_manager.session_factory() as session:
            for period_start, period_end in boundaries:
                # Query raw usage data for this period
                query = select(UsageTrackingRecord).where(
                    UsageTrackingRecord.created_at.between(period_start, period_end)
                )
                result = await session.execute(query)
                records = result.scalars().all()

                if not records:
                    continue

                # Group by aggregation dimensions
                groups = defaultdict(list)
                for record in records:
                    key = (
                        record.provider,
                        record.model,
                        record.module_name,
                        record.scan_id,
                        record.user_id,
                    )
                    groups[key].append(record)

                # Create aggregation records
                for (
                    provider,
                    model,
                    module_name,
                    scan_id,
                    user_id,
                ), group_records in groups.items():
                    await self._create_aggregation_record(
                        session,
                        period,
                        period_start,
                        period_end,
                        provider,
                        model,
                        module_name,
                        scan_id,
                        user_id,
                        group_records,
                    )

            await session.commit()

    def _calculate_aggregation_boundaries(
        self, period: AggregationPeriod, start_time: datetime, end_time: datetime
    ) -> List[Tuple[datetime, datetime]]:
        """Calculate time boundaries for aggregation periods."""
        boundaries = []
        current = start_time

        while current < end_time:
            if period == AggregationPeriod.HOURLY:
                period_start = current.replace(minute=0, second=0, microsecond=0)
                period_end = period_start + timedelta(hours=1)
            elif period == AggregationPeriod.DAILY:
                period_start = current.replace(hour=0, minute=0, second=0, microsecond=0)
                period_end = period_start + timedelta(days=1)
            elif period == AggregationPeriod.WEEKLY:
                days_since_monday = current.weekday()
                period_start = (current - timedelta(days=days_since_monday)).replace(
                    hour=0, minute=0, second=0, microsecond=0
                )
                period_end = period_start + timedelta(weeks=1)
            elif period == AggregationPeriod.MONTHLY:
                period_start = current.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
                if period_start.month == 12:
                    period_end = period_start.replace(year=period_start.year + 1, month=1)
                else:
                    period_end = period_start.replace(month=period_start.month + 1)
            else:  # YEARLY
                period_start = current.replace(
                    month=1, day=1, hour=0, minute=0, second=0, microsecond=0
                )
                period_end = period_start.replace(year=period_start.year + 1)

            boundaries.append((period_start, min(period_end, end_time)))
            current = period_end

        return boundaries

    async def _create_aggregation_record(
        self,
        session: AsyncSession,
        period: AggregationPeriod,
        period_start: datetime,
        period_end: datetime,
        provider: str,
        model: str,
        module_name: Optional[str],
        scan_id: Optional[str],
        user_id: Optional[str],
        records: List[UsageTrackingRecord],
    ) -> None:
        """Create aggregation record for a group of usage records."""

        # Check if aggregation already exists
        existing = await session.execute(
            select(UsageAggregationRecord).where(
                UsageAggregationRecord.period == period.value,
                UsageAggregationRecord.period_start == period_start,
                UsageAggregationRecord.provider == provider,
                UsageAggregationRecord.model == model,
                UsageAggregationRecord.module_name == module_name,
                UsageAggregationRecord.scan_id == scan_id,
                UsageAggregationRecord.user_id == user_id,
            )
        )

        if existing.scalar_one_or_none():
            return  # Already aggregated

        # Calculate aggregated metrics
        total_requests = len(records)
        successful_requests = sum(1 for r in records if not r.error_type)
        failed_requests = total_requests - successful_requests

        total_prompt_tokens = sum(r.prompt_tokens for r in records)
        total_completion_tokens = sum(r.completion_tokens for r in records)
        total_tokens = sum(r.total_tokens for r in records)
        total_cached_tokens = sum(r.cached_tokens for r in records)

        total_cost = sum(r.total_cost for r in records)
        avg_cost_per_request = total_cost / total_requests if total_requests > 0 else Decimal("0")

        response_times = [r.response_time for r in records if r.response_time > 0]
        avg_response_time = sum(response_times) / len(response_times) if response_times else 0.0
        min_response_time = min(response_times) if response_times else 0.0
        max_response_time = max(response_times) if response_times else 0.0

        # Calculate p95
        if response_times:
            sorted_times = sorted(response_times)
            p95_index = int(len(sorted_times) * 0.95)
            p95_response_time = (
                sorted_times[p95_index] if p95_index < len(sorted_times) else sorted_times[-1]
            )
        else:
            p95_response_time = 0.0

        error_rate = (failed_requests / total_requests) if total_requests > 0 else 0.0
        fallback_rate = (
            (sum(1 for r in records if r.fallback_used) / total_requests)
            if total_requests > 0
            else 0.0
        )
        avg_retry_count = (
            sum(r.retry_count for r in records) / total_requests if total_requests > 0 else 0.0
        )

        # Create aggregation record
        aggregation = UsageAggregationRecord(
            period=period.value,
            period_start=period_start,
            period_end=period_end,
            provider=provider,
            model=model,
            module_name=module_name,
            scan_id=scan_id,
            user_id=user_id,
            total_requests=total_requests,
            successful_requests=successful_requests,
            failed_requests=failed_requests,
            total_prompt_tokens=total_prompt_tokens,
            total_completion_tokens=total_completion_tokens,
            total_tokens=total_tokens,
            total_cached_tokens=total_cached_tokens,
            total_cost=total_cost,
            avg_cost_per_request=avg_cost_per_request,
            avg_response_time=avg_response_time,
            min_response_time=min_response_time,
            max_response_time=max_response_time,
            p95_response_time=p95_response_time,
            error_rate=error_rate,
            fallback_rate=fallback_rate,
            avg_retry_count=avg_retry_count,
            data_points=total_requests,
        )

        session.add(aggregation)


class UsageReporter:
    """Generate usage reports and export data."""

    def __init__(self, db_manager: DatabaseManager):
        """Initialize with database manager."""
        self.db_manager = db_manager
        self.usage_db = UsageDatabase(db_manager)

    async def export_usage(
        self,
        format: ExportFormat,
        period_start: datetime,
        period_end: datetime,
        provider: Optional[str] = None,
        model: Optional[str] = None,
        module_name: Optional[str] = None,
        scan_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> bytes:
        """Export usage data in specified format."""

        # Get usage summary
        summary = await self.usage_db.get_usage_summary(
            period_start, period_end, provider, model, module_name, scan_id, user_id
        )

        if format == ExportFormat.JSON:
            return self._export_json(summary)
        elif format == ExportFormat.CSV:
            return self._export_csv(summary, period_start, period_end)
        elif format == ExportFormat.XLSX:
            return self._export_xlsx(summary)
        else:
            raise ValueError(f"Unsupported export format: {format}")

    def _export_json(self, summary: UsageSummary) -> bytes:
        """Export summary as JSON."""
        data = summary.model_dump(mode="json")
        return json.dumps(data, indent=2, default=str).encode("utf-8")

    def _export_csv(
        self, summary: UsageSummary, period_start: datetime, period_end: datetime
    ) -> bytes:
        """Export summary as CSV."""
        output = StringIO()
        writer = csv.writer(output)

        # Write header
        writer.writerow(["Metric", "Value"])

        # Write summary data
        writer.writerow(["Period Start", period_start.isoformat()])
        writer.writerow(["Period End", period_end.isoformat()])
        writer.writerow(["Total Requests", summary.total_requests])
        writer.writerow(["Successful Requests", summary.successful_requests])
        writer.writerow(["Failed Requests", summary.failed_requests])
        writer.writerow(["Success Rate (%)", f"{summary.success_rate:.2f}"])
        writer.writerow(["Total Tokens", summary.total_tokens])
        writer.writerow(["Total Cost", f"{summary.total_cost:.6f}"])
        writer.writerow(["Average Cost per Request", f"{summary.avg_cost_per_request:.6f}"])
        writer.writerow(["Average Response Time (s)", f"{summary.avg_response_time:.3f}"])
        writer.writerow(["P95 Response Time (s)", f"{summary.p95_response_time:.3f}"])
        writer.writerow(["Error Rate (%)", f"{summary.error_rate:.2f}"])
        writer.writerow(["Fallback Rate (%)", f"{summary.fallback_rate:.2f}"])

        # Provider breakdown
        writer.writerow([])
        writer.writerow(["Provider Breakdown"])
        writer.writerow(["Provider", "Requests", "Cost", "Tokens"])
        for provider, data in summary.provider_breakdown.items():
            writer.writerow([provider, data["requests"], f"{data['cost']:.6f}", data["tokens"]])

        # Model breakdown
        writer.writerow([])
        writer.writerow(["Model Breakdown"])
        writer.writerow(["Model", "Requests", "Cost", "Tokens"])
        for model, data in summary.model_breakdown.items():
            writer.writerow([model, data["requests"], f"{data['cost']:.6f}", data["tokens"]])

        return output.getvalue().encode("utf-8")

    def _export_xlsx(self, summary: UsageSummary) -> bytes:
        """Export summary as Excel file."""
        # This would require openpyxl or xlsxwriter
        # For now, return CSV format
        logger.warning("XLSX export not implemented, returning CSV format")
        return self._export_csv(summary, summary.period_start, summary.period_end)

    async def get_cost_breakdown(
        self,
        period_start: datetime,
        period_end: datetime,
        breakdown_by: List[str] = ["provider", "model", "module"],
    ) -> CostBreakdown:
        """Get detailed cost breakdown by specified dimensions."""

        async with self.db_manager.session_factory() as session:
            query = select(UsageTrackingRecord).where(
                UsageTrackingRecord.created_at.between(period_start, period_end)
            )
            result = await session.execute(query)
            records = result.scalars().all()

            breakdown = CostBreakdown(total_cost=sum(r.total_cost for r in records))

            if "provider" in breakdown_by:
                provider_costs = defaultdict(Decimal)
                for record in records:
                    provider_costs[record.provider] += record.total_cost
                breakdown.by_provider = dict(provider_costs)

            if "model" in breakdown_by:
                model_costs = defaultdict(Decimal)
                for record in records:
                    model_costs[record.model] += record.total_cost
                breakdown.by_model = dict(model_costs)

            if "module" in breakdown_by:
                module_costs = defaultdict(Decimal)
                for record in records:
                    if record.module_name:
                        module_costs[record.module_name] += record.total_cost
                breakdown.by_module = dict(module_costs)

            if "scan" in breakdown_by:
                scan_costs = defaultdict(Decimal)
                for record in records:
                    if record.scan_id:
                        scan_costs[record.scan_id] += record.total_cost
                breakdown.by_scan = dict(scan_costs)

            return breakdown


# =============================================================================
# Main Usage Tracker Class
# =============================================================================


class UsageTracker:
    """Main usage tracker that orchestrates all usage tracking functionality."""

    def __init__(self, db_manager: DatabaseManager):
        """Initialize usage tracker with database manager."""
        self.db_manager = db_manager
        self.cost_calculator = CostCalculator()
        self.budget_manager = BudgetManager(db_manager)
        self.usage_db = UsageDatabase(db_manager)
        self.usage_reporter = UsageReporter(db_manager)

        # Performance optimization
        self._batch_buffer: List[Dict[str, Any]] = []
        self._batch_size = 100
        self._batch_timeout = 30  # seconds
        self._last_flush = datetime.utcnow()
        self._batch_lock = asyncio.Lock()

    async def track_usage(
        self,
        request: CompletionRequest,
        response: CompletionResponse,
        provider: str,
        module_name: Optional[str] = None,
        scan_id: Optional[str] = None,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        error_type: Optional[str] = None,
        error_message: Optional[str] = None,
        fallback_used: bool = False,
        retry_count: int = 0,
        request_size: int = 0,
        response_size: int = 0,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Track usage for a request/response pair."""

        usage_data = {
            "request_id": response.request_id or str(uuid4()),
            "provider": provider,
            "model": response.model,
            "usage": response.usage,
            "response_time": response.response_time or 0.0,
            "scan_id": scan_id,
            "module_name": module_name,
            "user_id": user_id,
            "session_id": session_id,
            "error_type": error_type,
            "error_message": error_message,
            "fallback_used": fallback_used,
            "retry_count": retry_count,
            "request_size": request_size,
            "response_size": response_size,
            "tags": tags,
            "metadata": metadata,
        }

        # Add to batch buffer for performance
        async with self._batch_lock:
            self._batch_buffer.append(usage_data)

            # Flush if batch is full or timeout reached
            if len(
                self._batch_buffer
            ) >= self._batch_size or datetime.utcnow() - self._last_flush > timedelta(
                seconds=self._batch_timeout
            ):
                await self._flush_batch()

        # Update budgets immediately for budget enforcement
        if response.usage and response.usage.total_cost:
            await self.budget_manager.update_budget_usage(
                response.usage.total_cost,
                provider=provider,
                model=response.model,
                module_name=module_name,
                user_id=user_id,
            )

        return usage_data["request_id"]

    async def _flush_batch(self) -> None:
        """Flush buffered usage data to database."""
        if not self._batch_buffer:
            return

        batch = self._batch_buffer.copy()
        self._batch_buffer.clear()
        self._last_flush = datetime.utcnow()

        # Process batch in background to avoid blocking
        asyncio.create_task(self._process_batch(batch))

    async def _process_batch(self, batch: List[Dict[str, Any]]) -> None:
        """Process a batch of usage data."""
        try:
            for usage_data in batch:
                await self.usage_db.save_usage(**usage_data)
        except Exception as e:
            logger.error(f"Failed to process usage batch: {e}")

    async def calculate_cost(
        self, usage: TokenUsage, provider: str, model: str
    ) -> Tuple[Decimal, Decimal, Decimal]:
        """Calculate cost for token usage."""
        return self.cost_calculator.calculate_cost(usage, provider, model)

    async def check_budget(
        self,
        amount: Decimal,
        provider: Optional[str] = None,
        model: Optional[str] = None,
        module_name: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> bool:
        """Check if spending amount would exceed budgets."""
        allowed, _ = await self.budget_manager.check_budget(
            amount, provider, model, module_name, user_id
        )
        return allowed

    async def get_usage_summary(
        self,
        period: str = "today",
        provider: Optional[str] = None,
        model: Optional[str] = None,
        module_name: Optional[str] = None,
        scan_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> UsageSummary:
        """Get usage summary for specified period."""

        # Parse period
        now = datetime.utcnow()
        if period == "today":
            period_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
            period_end = now
        elif period == "yesterday":
            period_start = (now - timedelta(days=1)).replace(
                hour=0, minute=0, second=0, microsecond=0
            )
            period_end = period_start + timedelta(days=1)
        elif period == "week":
            days_since_monday = now.weekday()
            period_start = (now - timedelta(days=days_since_monday)).replace(
                hour=0, minute=0, second=0, microsecond=0
            )
            period_end = now
        elif period == "month":
            period_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            period_end = now
        else:
            # Default to last 24 hours
            period_start = now - timedelta(days=1)
            period_end = now

        return await self.usage_db.get_usage_summary(
            period_start, period_end, provider, model, module_name, scan_id, user_id
        )

    async def export_usage(
        self,
        format: ExportFormat,
        period: str = "today",
        provider: Optional[str] = None,
        model: Optional[str] = None,
        module_name: Optional[str] = None,
        scan_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> bytes:
        """Export usage data in specified format."""

        # Parse period (same logic as get_usage_summary)
        now = datetime.utcnow()
        if period == "today":
            period_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
            period_end = now
        elif period == "yesterday":
            period_start = (now - timedelta(days=1)).replace(
                hour=0, minute=0, second=0, microsecond=0
            )
            period_end = period_start + timedelta(days=1)
        elif period == "week":
            days_since_monday = now.weekday()
            period_start = (now - timedelta(days=days_since_monday)).replace(
                hour=0, minute=0, second=0, microsecond=0
            )
            period_end = now
        elif period == "month":
            period_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            period_end = now
        else:
            period_start = now - timedelta(days=1)
            period_end = now

        return await self.usage_reporter.export_usage(
            format, period_start, period_end, provider, model, module_name, scan_id, user_id
        )

    async def set_budget_limit(
        self,
        name: str,
        budget_type: BudgetType,
        limit_amount: Decimal,
        provider: Optional[str] = None,
        model: Optional[str] = None,
        module_name: Optional[str] = None,
        user_id: Optional[str] = None,
        hard_limit: bool = False,
    ) -> str:
        """Set a budget limit."""
        return await self.budget_manager.create_budget(
            name,
            budget_type,
            limit_amount,
            provider,
            model,
            module_name,
            user_id,
            hard_limit=hard_limit,
        )

    async def get_usage_trends(
        self, period: AggregationPeriod = AggregationPeriod.DAILY, days_back: int = 30
    ) -> TrendData:
        """Get usage trends over time."""

        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=days_back)

        async with self.db_manager.session_factory() as session:
            query = (
                select(UsageAggregationRecord)
                .where(
                    UsageAggregationRecord.period == period.value,
                    UsageAggregationRecord.period_start.between(start_time, end_time),
                )
                .order_by(UsageAggregationRecord.period_start)
            )

            result = await session.execute(query)
            records = result.scalars().all()

            data_points = []
            for record in records:
                data_points.append(
                    {
                        "timestamp": record.period_start.isoformat(),
                        "requests": record.total_requests,
                        "cost": float(record.total_cost),
                        "tokens": record.total_tokens,
                        "error_rate": record.error_rate,
                        "avg_response_time": record.avg_response_time,
                    }
                )

            # Simple trend analysis
            if len(data_points) >= 2:
                first_cost = data_points[0]["cost"]
                last_cost = data_points[-1]["cost"]

                if last_cost > first_cost * 1.1:
                    trend_direction = "up"
                elif last_cost < first_cost * 0.9:
                    trend_direction = "down"
                else:
                    trend_direction = "stable"

                growth_rate = ((last_cost - first_cost) / first_cost * 100) if first_cost > 0 else 0
            else:
                trend_direction = "stable"
                growth_rate = 0.0

            return TrendData(
                period=period,
                data_points=data_points,
                trend_direction=trend_direction,
                growth_rate=growth_rate,
            )

    async def cleanup(self) -> None:
        """Cleanup resources and flush any pending data."""
        async with self._batch_lock:
            await self._flush_batch()


# =============================================================================
# Utility Functions
# =============================================================================


async def create_usage_tracker(db_manager: DatabaseManager) -> UsageTracker:
    """Factory function to create a configured usage tracker."""
    return UsageTracker(db_manager)


def estimate_request_cost(
    prompt_tokens: int, completion_tokens: int, provider: str, model: str
) -> Decimal:
    """Estimate cost for a request without making the actual call."""
    calculator = CostCalculator()

    # Create dummy usage object
    usage = TokenUsage(
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        total_tokens=prompt_tokens + completion_tokens,
    )

    _, _, total_cost = calculator.calculate_cost(usage, provider, model)
    return total_cost


# Export key classes and functions
__all__ = [
    # Enums
    "AggregationPeriod",
    "ExportFormat",
    "BudgetType",
    "AlertLevel",
    # Models
    "UsageSummary",
    "TrendData",
    "BudgetStatus",
    "CostBreakdown",
    # Main classes
    "UsageTracker",
    "CostCalculator",
    "BudgetManager",
    "UsageDatabase",
    "UsageReporter",
    # Utility functions
    "create_usage_tracker",
    "estimate_request_cost",
]
