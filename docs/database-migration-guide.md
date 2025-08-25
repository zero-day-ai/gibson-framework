# Database Layer Migration Guide

This guide provides comprehensive instructions for migrating from the old database architecture to the new enhanced database layer with repository patterns, enhanced models, and improved transaction management.

## Overview of Changes

The database layer has been significantly enhanced with the following improvements:

### 1. Enhanced Base Models
- **Audit Fields**: All models now include `created_by`, `updated_by` fields
- **Soft Delete**: Built-in soft delete support with `is_deleted` flag
- **Optimistic Locking**: Version field for concurrent update protection
- **Enhanced Validation**: Comprehensive model validation with error reporting

### 2. Repository Pattern
- **Abstract Repositories**: Consistent CRUD interface across all models
- **Specialized Repositories**: Model-specific business logic and queries
- **Repository Factory**: Dependency injection and repository registration
- **Transaction Support**: Integrated transaction management

### 3. Advanced Transaction Management
- **Automatic Retry**: Deadlock detection and exponential backoff
- **Savepoints**: Nested transaction support
- **Connection Pooling**: Configurable connection pools for performance

### 4. Health Monitoring & Safety
- **Health Checks**: Comprehensive database health monitoring
- **Migration Safety**: Pre-migration validation and backup creation
- **Schema Analysis**: Automated schema drift detection
- **Performance Monitoring**: Query performance tracking

## Migration Steps

### Step 1: Update Your Models

#### Before (Old Pattern)
```python
from gibson.core.database import Base
from sqlalchemy import Column, String, Integer, DateTime

class Target(Base):
    __tablename__ = 'targets'
    
    id = Column(String(36), primary_key=True)
    name = Column(String(200), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
```

#### After (New Pattern)
```python
from gibson.db.base import BaseDBModel, CRUDMixin
from gibson.db.repositories.target import TargetRepository
from sqlalchemy import Column, String, Enum as SQLEnum

class Target(BaseDBModel, CRUDMixin):
    __tablename__ = 'targets'
    
    # Basic fields
    name = Column(String(200), nullable=False, unique=True)
    target_type = Column(SQLEnum(TargetType), nullable=False)
    
    # Audit fields (created_by, updated_by, version, is_deleted) 
    # are automatically added by BaseDBModel
    
    def validate_target(self) -> None:
        """Custom business logic method."""
        self.last_validated = datetime.utcnow()
```

### Step 2: Update Database Manager Usage

#### Before
```python
from gibson.db.manager import DatabaseManager

db = DatabaseManager("sqlite:///gibson.db")
await db.initialize()
session = db.get_session()
```

#### After
```python
from gibson.db.manager import DatabaseManager

# Enhanced initialization with connection pooling
db = DatabaseManager(
    database_url="sqlite:///gibson.db",
    pool_size=5,
    max_overflow=10,
    echo=False  # Set to True for SQL debugging
)

await db.initialize(auto_migrate=True)

# Context manager usage (recommended)
async with db.session() as session:
    # Your database operations
    pass

# Repository access
target_repo = db.get_repository(Target)
```

### Step 3: Update Repository Usage

#### Before (Direct Model Usage)
```python
# Old pattern - direct model queries
from sqlalchemy.future import select

async def get_targets(session):
    query = select(Target).where(Target.enabled == True)
    result = await session.execute(query)
    return result.scalars().all()
```

#### After (Repository Pattern)
```python
# New pattern - use repositories
from gibson.db.repositories.target import TargetRepository

async def get_targets(session):
    repo = TargetRepository(session)
    return await repo.get_active_targets()

# Or using the factory
async def get_targets_with_factory(db_manager):
    async with db_manager.session() as session:
        repo = db_manager.get_repository(Target)
        return await repo.get_active_targets()
```

### Step 4: Update Transaction Handling

#### Before
```python
async def complex_operation(session):
    try:
        async with session.begin():
            # Operations
            await session.commit()
    except Exception:
        await session.rollback()
        raise
```

#### After
```python
# Using enhanced transaction manager
from gibson.db.utils.transaction import TransactionManager

async def complex_operation(session):
    manager = TransactionManager(session)
    
    # Automatic retry with deadlock handling
    async with manager.atomic(max_retries=3):
        # Your operations
        async with manager.savepoint("checkpoint1"):
            # Nested operations with savepoint
            pass

# Or using database manager
async def complex_operation_with_manager(db_manager):
    async with db_manager.transaction() as tx_manager:
        # Operations with automatic retry and rollback
        pass
```

### Step 5: Update Test Code

#### Before
```python
@pytest.fixture
async def db_session():
    engine = create_async_engine('sqlite+aiosqlite:///:memory:')
    # Manual setup...
```

#### After
```python
from tests.unit.db.test_database_utilities import db_session, db_with_data

@pytest.mark.asyncio
async def test_target_operations(db_session):
    # Session with full test setup provided
    repo = TargetRepository(db_session)
    target = await repo.create(Target(name="test", target_type="api"))
    assert target.id is not None

@pytest.mark.asyncio  
async def test_with_data(db_with_data):
    session, test_data = db_with_data
    # Pre-populated test data available
    target = test_data['target']
    assert target.name == "test_target"
```

## Migration Checklist

### Phase 1: Model Migration
- [ ] Update import statements (`gibson.core.database` → `gibson.db.base`)
- [ ] Inherit from `BaseDBModel` and `CRUDMixin`
- [ ] Remove manual audit field definitions (auto-added by base)
- [ ] Add enhanced validation methods if needed
- [ ] Create custom repository classes for complex queries

### Phase 2: Database Manager Updates
- [ ] Update DatabaseManager initialization with new parameters
- [ ] Replace direct session usage with context managers
- [ ] Update connection string format for async drivers
- [ ] Add health check integration

### Phase 3: Repository Integration
- [ ] Replace direct model queries with repository methods
- [ ] Register custom repositories with the factory
- [ ] Update business logic to use repository methods
- [ ] Add transaction management where needed

### Phase 4: Testing Updates
- [ ] Update test fixtures to use new utilities
- [ ] Add repository testing for custom methods
- [ ] Update integration tests for new patterns
- [ ] Add performance testing for critical queries

### Phase 5: CLI & Operations
- [ ] Update CLI commands to use enhanced database manager
- [ ] Add health monitoring to deployment
- [ ] Set up schema analysis in CI/CD
- [ ] Configure backup and recovery procedures

## Common Issues and Solutions

### Issue 1: Import Errors
**Problem**: `ImportError: No module named 'gibson.core.database'`

**Solution**: 
```python
# Change this:
from gibson.core.database import Base

# To this:
from gibson.db.base import Base
```

### Issue 2: Missing Audit Fields
**Problem**: Existing records don't have audit fields

**Solution**:
```bash
# Run migration to add audit fields with defaults
gibson db migrate "Add audit fields with defaults"
```

### Issue 3: Repository Not Found
**Problem**: `Repository not registered for model`

**Solution**:
```python
# Register repository in database manager
from gibson.db.repositories.factory import register_repository

register_repository(YourModel, YourRepository)

# Or use the built-in registration
db_manager = DatabaseManager(database_url)
# Repositories are auto-registered during initialization
```

### Issue 4: Transaction Deadlocks
**Problem**: Frequent deadlock errors in concurrent scenarios

**Solution**:
```python
# Use automatic retry with exponential backoff
async with TransactionManager(session).atomic(max_retries=5):
    # Your operations will be automatically retried on deadlock
    pass
```

### Issue 5: Performance Issues
**Problem**: Slow queries after migration

**Solution**:
```python
# Use performance monitoring
from gibson.db.utils.health_check import PerformanceTestUtils

result, time_taken = await PerformanceTestUtils.time_query(
    session, 
    lambda s: repo.get_active_targets()
)

# Add connection pooling
db = DatabaseManager(
    database_url,
    pool_size=10,
    max_overflow=20
)
```

## Testing Migration

### 1. Schema Validation
```bash
# Check for schema issues before deploying
gibson db analyze-schema

# Run health checks
gibson db health
```

### 2. Performance Validation
```python
# Add performance tests
@pytest.mark.asyncio
async def test_query_performance(db_session):
    repo = TargetRepository(db_session)
    
    # Assert query completes within time limit
    result = await PerformanceTestUtils.assert_query_performance(
        db_session,
        lambda s: repo.get_active_targets(),
        max_time_seconds=0.1
    )
```

### 3. Data Integrity
```python
# Verify audit fields are properly set
@pytest.mark.asyncio
async def test_audit_fields(db_session):
    repo = TargetRepository(db_session)
    target = await repo.create(
        Target(name="test", target_type="api"),
        created_by="test_user"
    )
    
    DatabaseAssertions.assert_audit_fields_set(target, created_by="test_user")
```

## Production Deployment

### 1. Pre-deployment Checklist
- [ ] Backup database: `gibson db backup "pre-migration"`
- [ ] Run schema analysis: `gibson db analyze-schema`
- [ ] Test health checks: `gibson db health`
- [ ] Validate migrations: `gibson db migrate --dry-run`

### 2. Deployment Steps
```bash
# 1. Create backup
gibson db backup "Production migration $(date +%Y%m%d)"

# 2. Run safety checks
gibson db check

# 3. Apply migrations
gibson db migrate

# 4. Verify deployment
gibson db health
gibson db analyze-schema
```

### 3. Post-deployment Verification
- [ ] Verify all tables exist: `gibson db analyze-schema`
- [ ] Check application functionality
- [ ] Monitor performance metrics
- [ ] Validate repository operations
- [ ] Run integration tests

### 4. Rollback Plan (if needed)
```bash
# List available backups
gibson db list-backups

# Rollback to previous version
gibson db rollback --steps 1

# Or restore from backup
gibson db restore <backup-id>
```

## Performance Tuning

### Connection Pool Configuration
```python
# For high-traffic applications
db = DatabaseManager(
    database_url="postgresql+asyncpg://user:pass@localhost/gibson",
    pool_size=20,        # Base connections
    max_overflow=30,     # Additional connections under load
    pool_timeout=30,     # Connection timeout
    echo=False          # Disable SQL logging in production
)
```

### Repository Optimization
```python
class OptimizedTargetRepository(TargetRepository):
    async def get_targets_with_stats(self, limit: int = 100):
        """Optimized query with eager loading."""
        query = select(Target).options(
            selectinload(Target.scans),
            selectinload(Target.findings)
        ).limit(limit)
        
        result = await self.session.execute(query)
        return result.unique().scalars().all()
```

### Query Performance Monitoring
```python
# Add performance monitoring to critical queries
async def monitor_query_performance():
    async with db.session() as session:
        repo = TargetRepository(session)
        
        # Time critical operations
        result, duration = await PerformanceTestUtils.time_query(
            session,
            lambda s: repo.get_active_targets()
        )
        
        if duration > 1.0:  # Log slow queries
            logger.warning(f"Slow query detected: {duration:.3f}s")
```

## Support and Troubleshooting

### Logging Configuration
```python
# Enable detailed database logging for debugging
import logging
logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO)
logging.getLogger('gibson.db').setLevel(logging.DEBUG)
```

### Debug Mode
```python
# Create database manager with debug logging
db = DatabaseManager(
    database_url,
    echo=True,  # Log all SQL statements
    validate_on_init=True  # Validate schema on startup
)
```

### Health Monitoring
```python
# Add health monitoring to your application
async def periodic_health_check():
    """Run health checks periodically."""
    async with db.session() as session:
        health = await db.health_check()
        
        if health["status"] != "healthy":
            logger.error(f"Database health issue: {health}")
            # Alert your monitoring system
```

---

For additional support:
- Check the [Database Architecture Documentation](./attack-taxonomy-architecture.md)
- Review test examples in `tests/unit/db/`
- Run `gibson db --help` for CLI reference
- Enable debug logging for detailed troubleshooting