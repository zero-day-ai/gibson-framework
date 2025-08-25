"""
Table registry for usage tracking tables.

This module ensures that usage tracking tables are imported and registered
with SQLAlchemy's Base metadata when needed.
"""

from loguru import logger


def register_usage_tracking_tables():
    """
    Register usage tracking tables with SQLAlchemy Base metadata.

    This function must be called before database initialization to ensure
    that all usage tracking tables are created.
    """
    try:
        # Import the usage_tracking module to register tables
        from gibson.core.llm.usage_tracking import (
            UsageTrackingRecord,
            UsageAggregationRecord,
            BudgetRecord,
            AlertRecord,
        )

        logger.debug("Successfully registered usage tracking tables")
        return True

    except ImportError as e:
        logger.warning(f"Could not register usage tracking tables: {e}")
        return False


# Auto-register tables when module is imported
register_usage_tracking_tables()
