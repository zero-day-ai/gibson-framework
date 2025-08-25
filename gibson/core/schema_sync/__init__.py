"""
Payload Schema Synchronization Module.

This module provides automated detection, generation, and application of database
schema changes based on PayloadModel modifications. It coordinates JSON schema
generation, TypeScript types, SQLAlchemy models, and Alembic migrations.
"""

# Import with error handling for gradual implementation
try:
    from gibson.core.schema_sync.detector import SchemaChangeDetector
except ImportError:
    SchemaChangeDetector = None

try:
    from gibson.core.schema_sync.analyzer import ChangeAnalyzer
except ImportError:
    ChangeAnalyzer = None

try:
    from gibson.core.schema_sync.generator_hub import SchemaGeneratorHub
except ImportError:
    SchemaGeneratorHub = None

try:
    from gibson.core.schema_sync.migration_generator import AlembicMigrationGenerator
except ImportError:
    AlembicMigrationGenerator = None

try:
    from gibson.core.schema_sync.data_migration import DataMigrationPlanner
except ImportError:
    DataMigrationPlanner = None

try:
    from gibson.core.schema_sync.version_registry import VersionRegistry
except ImportError:
    VersionRegistry = None

try:
    from gibson.core.schema_sync.orchestrator import SchemaOrchestrator
except ImportError:
    SchemaOrchestrator = None

from gibson.core.schema_sync.exceptions import (
    SchemaSyncError,
    BreakingChangeError,
    MigrationGenerationError,
    DataIntegrityError,
    VersionConflictError,
)

from gibson.core.schema_sync.models import (
    ChangeSet,
    ChangeAnalysis,
    SchemaBundle,
    MigrationScript,
    CompatibilityLevel,
)

__all__ = [
    # Core components
    "SchemaChangeDetector",
    "ChangeAnalyzer",
    "SchemaGeneratorHub",
    "AlembicMigrationGenerator",
    "DataMigrationPlanner",
    "VersionRegistry",
    "SchemaOrchestrator",
    # Exceptions
    "SchemaSyncError",
    "BreakingChangeError",
    "MigrationGenerationError",
    "DataIntegrityError",
    "VersionConflictError",
    # Models
    "ChangeSet",
    "ChangeAnalysis",
    "SchemaBundle",
    "MigrationScript",
    "CompatibilityLevel",
]

__version__ = "1.0.0"
