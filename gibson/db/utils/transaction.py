"""Transaction management utilities for database operations."""

import asyncio
from contextlib import asynccontextmanager
from typing import Any, Callable, Optional, TypeVar
from functools import wraps
import time
import random

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import (
    DBAPIError,
    IntegrityError,
    OperationalError,
    SQLAlchemyError
)
from sqlalchemy.orm import Session
from loguru import logger

T = TypeVar("T")


class TransactionContext:
    """Advanced transaction context manager with savepoints and retry logic."""
    
    def __init__(
        self,
        session: AsyncSession,
        isolation_level: Optional[str] = None,
        read_only: bool = False,
        max_retries: int = 3,
        retry_delay: float = 0.1,
        retry_backoff: float = 2.0
    ):
        """Initialize transaction context.
        
        Args:
            session: Async database session
            isolation_level: Transaction isolation level
            read_only: Whether transaction is read-only
            max_retries: Maximum retry attempts for deadlocks
            retry_delay: Initial retry delay in seconds
            retry_backoff: Retry delay multiplier
        """
        self.session = session
        self.isolation_level = isolation_level
        self.read_only = read_only
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.retry_backoff = retry_backoff
        self._savepoint_counter = 0
        self._active_savepoints = []
    
    @asynccontextmanager
    async def begin(self):
        """Begin transaction with automatic retry on deadlock.
        
        Yields:
            Session within transaction context
        """
        retries = 0
        delay = self.retry_delay
        
        while retries <= self.max_retries:
            try:
                # Set isolation level if specified
                if self.isolation_level:
                    await self.session.execute(
                        f"SET TRANSACTION ISOLATION LEVEL {self.isolation_level}"
                    )
                
                # Set read-only if specified
                if self.read_only:
                    await self.session.execute("SET TRANSACTION READ ONLY")
                
                async with self.session.begin():
                    yield self.session
                    
                # Success - exit retry loop
                break
                
            except OperationalError as e:
                # Check for deadlock or lock timeout
                if retries < self.max_retries and self._is_deadlock(e):
                    retries += 1
                    logger.warning(
                        f"Deadlock detected, retry {retries}/{self.max_retries} "
                        f"after {delay:.2f}s"
                    )
                    
                    # Add jitter to prevent thundering herd
                    jittered_delay = delay * (1 + random.random() * 0.1)
                    await asyncio.sleep(jittered_delay)
                    
                    # Exponential backoff
                    delay *= self.retry_backoff
                else:
                    # Max retries exceeded or not a deadlock
                    logger.error(f"Transaction failed: {str(e)}")
                    raise
                    
            except Exception as e:
                logger.error(f"Transaction error: {str(e)}")
                raise
    
    @asynccontextmanager
    async def savepoint(self, name: Optional[str] = None):
        """Create a savepoint within transaction.
        
        Args:
            name: Optional savepoint name
            
        Yields:
            Savepoint context
        """
        if not name:
            self._savepoint_counter += 1
            name = f"sp_{self._savepoint_counter}"
        
        # Create savepoint
        await self.session.execute(f"SAVEPOINT {name}")
        self._active_savepoints.append(name)
        
        try:
            yield name
            # Success - remove from active list
            self._active_savepoints.remove(name)
            
        except Exception as e:
            # Rollback to savepoint on error
            if name in self._active_savepoints:
                await self.session.execute(f"ROLLBACK TO SAVEPOINT {name}")
                self._active_savepoints.remove(name)
            logger.error(f"Savepoint {name} rolled back: {str(e)}")
            raise
    
    async def release_savepoint(self, name: str):
        """Release a savepoint.
        
        Args:
            name: Savepoint name
        """
        if name in self._active_savepoints:
            await self.session.execute(f"RELEASE SAVEPOINT {name}")
            self._active_savepoints.remove(name)
    
    def _is_deadlock(self, error: Exception) -> bool:
        """Check if error is a deadlock or lock timeout.
        
        Args:
            error: Exception to check
            
        Returns:
            True if deadlock/lock timeout
        """
        error_str = str(error).lower()
        deadlock_indicators = [
            "deadlock",
            "lock wait timeout",
            "lock timeout",
            "could not serialize",
            "concurrent update"
        ]
        return any(indicator in error_str for indicator in deadlock_indicators)


class TransactionManager:
    """Manager for coordinating complex transactions."""
    
    def __init__(self, session: AsyncSession):
        """Initialize transaction manager.
        
        Args:
            session: Async database session
        """
        self.session = session
    
    @asynccontextmanager
    async def atomic(
        self,
        isolation_level: Optional[str] = None,
        read_only: bool = False,
        max_retries: int = 3
    ):
        """Execute operations in atomic transaction.
        
        Args:
            isolation_level: Transaction isolation level
            read_only: Whether transaction is read-only
            max_retries: Maximum retry attempts
            
        Yields:
            Transaction context
        """
        context = TransactionContext(
            self.session,
            isolation_level=isolation_level,
            read_only=read_only,
            max_retries=max_retries
        )
        
        async with context.begin():
            yield context
    
    async def execute_in_transaction(
        self,
        func: Callable,
        *args,
        isolation_level: Optional[str] = None,
        max_retries: int = 3,
        **kwargs
    ) -> Any:
        """Execute function within transaction.
        
        Args:
            func: Async function to execute
            *args: Function arguments
            isolation_level: Transaction isolation level
            max_retries: Maximum retry attempts
            **kwargs: Function keyword arguments
            
        Returns:
            Function result
        """
        async with self.atomic(
            isolation_level=isolation_level,
            max_retries=max_retries
        ):
            return await func(*args, **kwargs)
    
    async def batch_execute(
        self,
        operations: list[tuple[Callable, tuple, dict]],
        stop_on_error: bool = False
    ) -> list[Any]:
        """Execute multiple operations in single transaction.
        
        Args:
            operations: List of (function, args, kwargs) tuples
            stop_on_error: Whether to stop on first error
            
        Returns:
            List of operation results
        """
        results = []
        
        async with self.atomic():
            for func, args, kwargs in operations:
                try:
                    result = await func(*args, **kwargs)
                    results.append(result)
                except Exception as e:
                    if stop_on_error:
                        raise
                    results.append(e)
                    logger.error(f"Batch operation failed: {str(e)}")
        
        return results


def transactional(
    isolation_level: Optional[str] = None,
    read_only: bool = False,
    max_retries: int = 3
):
    """Decorator for transactional methods.
    
    Args:
        isolation_level: Transaction isolation level
        read_only: Whether transaction is read-only
        max_retries: Maximum retry attempts
        
    Returns:
        Decorated function
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(self, *args, **kwargs):
            # Assume self has session attribute
            if not hasattr(self, 'session'):
                # No session, execute without transaction
                return await func(self, *args, **kwargs)
            
            manager = TransactionManager(self.session)
            return await manager.execute_in_transaction(
                func,
                self,
                *args,
                isolation_level=isolation_level,
                max_retries=max_retries,
                **kwargs
            )
        return wrapper
    return decorator


class IsolationLevel:
    """Standard SQL isolation levels."""
    
    READ_UNCOMMITTED = "READ UNCOMMITTED"
    READ_COMMITTED = "READ COMMITTED"
    REPEATABLE_READ = "REPEATABLE READ"
    SERIALIZABLE = "SERIALIZABLE"


class TransactionMonitor:
    """Monitor for tracking transaction metrics."""
    
    def __init__(self):
        """Initialize transaction monitor."""
        self.metrics = {
            "total_transactions": 0,
            "successful_transactions": 0,
            "failed_transactions": 0,
            "deadlocks": 0,
            "retries": 0,
            "total_duration_ms": 0,
            "savepoints_created": 0,
            "savepoints_rolled_back": 0
        }
    
    @asynccontextmanager
    async def track_transaction(self, context: TransactionContext):
        """Track transaction execution.
        
        Args:
            context: Transaction context
            
        Yields:
            Monitored context
        """
        start_time = time.time()
        self.metrics["total_transactions"] += 1
        
        try:
            yield context
            self.metrics["successful_transactions"] += 1
        except Exception as e:
            self.metrics["failed_transactions"] += 1
            if "deadlock" in str(e).lower():
                self.metrics["deadlocks"] += 1
            raise
        finally:
            duration_ms = (time.time() - start_time) * 1000
            self.metrics["total_duration_ms"] += duration_ms
    
    def get_metrics(self) -> dict:
        """Get transaction metrics.
        
        Returns:
            Dictionary of metrics
        """
        metrics = self.metrics.copy()
        
        # Calculate averages
        if metrics["total_transactions"] > 0:
            metrics["success_rate"] = (
                metrics["successful_transactions"] / 
                metrics["total_transactions"]
            )
            metrics["avg_duration_ms"] = (
                metrics["total_duration_ms"] / 
                metrics["total_transactions"]
            )
        else:
            metrics["success_rate"] = 0
            metrics["avg_duration_ms"] = 0
        
        return metrics
    
    def reset(self):
        """Reset metrics."""
        self.metrics = {
            "total_transactions": 0,
            "successful_transactions": 0,
            "failed_transactions": 0,
            "deadlocks": 0,
            "retries": 0,
            "total_duration_ms": 0,
            "savepoints_created": 0,
            "savepoints_rolled_back": 0
        }


# Global transaction monitor instance
transaction_monitor = TransactionMonitor()


# Export main components
__all__ = [
    "TransactionContext",
    "TransactionManager",
    "transactional",
    "IsolationLevel",
    "TransactionMonitor",
    "transaction_monitor"
]