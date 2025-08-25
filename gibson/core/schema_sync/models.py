"""
Data models for schema synchronization.
"""

from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, Field, field_validator

from gibson.models.base import GibsonBaseModel


class CompatibilityLevel(str, Enum):
    """Schema change compatibility levels."""

    COMPATIBLE = "compatible"  # No action required
    MINOR_BREAKING = "minor_breaking"  # May require data updates
    MAJOR_BREAKING = "major_breaking"  # Requires data migration
    DATA_LOSS = "data_loss"  # Will result in data loss


class FieldChangeType(str, Enum):
    """Types of field changes."""

    ADDED = "added"
    REMOVED = "removed"
    TYPE_CHANGED = "type_changed"
    CONSTRAINT_CHANGED = "constraint_changed"
    DEFAULT_CHANGED = "default_changed"
    NULLABLE_CHANGED = "nullable_changed"


class ValidationStatus(str, Enum):
    """Schema validation status."""

    VALID = "valid"
    INVALID = "invalid"
    WARNINGS = "warnings"
    NOT_VALIDATED = "not_validated"


class MigrationStatus(str, Enum):
    """Migration execution status."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class FieldInfo(BaseModel):
    """Information about a field."""

    name: str
    type: str
    nullable: bool = True
    default: Optional[Any] = None
    constraints: Dict[str, Any] = Field(default_factory=dict)
    description: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class FieldModification(BaseModel):
    """Represents a modification to a field."""

    field_name: str
    change_type: FieldChangeType
    old_value: Optional[Any] = None
    new_value: Optional[Any] = None
    details: Dict[str, Any] = Field(default_factory=dict)

    @property
    def is_breaking(self) -> bool:
        """Check if this modification is breaking."""
        breaking_changes = {
            FieldChangeType.REMOVED,
            FieldChangeType.TYPE_CHANGED,
        }
        if self.change_type in breaking_changes:
            return True

        # Nullable to non-nullable is breaking
        if self.change_type == FieldChangeType.NULLABLE_CHANGED:
            return self.new_value is False

        return False


class ConstraintChange(BaseModel):
    """Represents a change to constraints."""

    constraint_type: str  # unique, check, foreign_key, etc.
    table_name: str
    column_name: Optional[str] = None
    old_constraint: Optional[Dict[str, Any]] = None
    new_constraint: Optional[Dict[str, Any]] = None
    action: str  # add, drop, modify


class EnumChange(BaseModel):
    """Represents changes to enum values."""

    enum_name: str
    added_values: List[str] = Field(default_factory=list)
    removed_values: List[str] = Field(default_factory=list)
    renamed_values: Dict[str, str] = Field(default_factory=dict)

    @property
    def has_breaking_changes(self) -> bool:
        """Check if enum changes are breaking."""
        return len(self.removed_values) > 0


class ChangeSet(GibsonBaseModel):
    """Collection of schema changes detected."""

    added_fields: Dict[str, FieldInfo] = Field(default_factory=dict)
    removed_fields: List[str] = Field(default_factory=list)
    modified_fields: Dict[str, FieldModification] = Field(default_factory=dict)
    constraint_changes: List[ConstraintChange] = Field(default_factory=list)
    enum_changes: Dict[str, EnumChange] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    model_hash_before: str
    model_hash_after: str

    @property
    def has_changes(self) -> bool:
        """Check if there are any changes."""
        return (
            len(self.added_fields) > 0
            or len(self.removed_fields) > 0
            or len(self.modified_fields) > 0
            or len(self.constraint_changes) > 0
            or len(self.enum_changes) > 0
        )

    @property
    def change_count(self) -> int:
        """Get total number of changes."""
        return (
            len(self.added_fields)
            + len(self.removed_fields)
            + len(self.modified_fields)
            + len(self.constraint_changes)
            + len(self.enum_changes)
        )


class BreakingChange(BaseModel):
    """Represents a breaking change that requires intervention."""

    change_type: str
    description: str
    affected_table: str
    affected_column: Optional[str] = None
    impact: str
    remediation_required: bool = True
    suggested_remediation: Optional[str] = None
    estimated_affected_rows: Optional[int] = None
    data_transformation_required: bool = False


class DataMigration(BaseModel):
    """Represents a data migration step."""

    step_number: int
    description: str
    sql_statements: List[str]
    validation_query: Optional[str] = None
    rollback_statements: List[str] = Field(default_factory=list)
    estimated_duration: Optional[timedelta] = None


class RollbackPlan(BaseModel):
    """Plan for rolling back a migration."""

    can_rollback: bool = True
    rollback_statements: List[str] = Field(default_factory=list)
    data_backup_required: bool = False
    warnings: List[str] = Field(default_factory=list)
    estimated_rollback_duration: Optional[timedelta] = None


class ChangeAnalysis(GibsonBaseModel):
    """Analysis of detected changes."""

    changeset: ChangeSet
    compatibility: CompatibilityLevel
    breaking_changes: List[BreakingChange] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    migration_required: bool = False
    estimated_affected_rows: Optional[int] = None
    suggested_actions: List[str] = Field(default_factory=list)
    risk_level: str = "low"  # low, medium, high, critical

    @property
    def is_safe(self) -> bool:
        """Check if changes are safe to apply automatically."""
        return (
            self.compatibility == CompatibilityLevel.COMPATIBLE
            and len(self.breaking_changes) == 0
            and self.risk_level == "low"
        )

    def add_warning(self, warning: str) -> None:
        """Add a warning to the analysis."""
        self.warnings.append(warning)

    def add_breaking_change(self, change: BreakingChange) -> None:
        """Add a breaking change to the analysis."""
        self.breaking_changes.append(change)
        self.migration_required = True

        # Update compatibility level
        if change.data_transformation_required:
            self.compatibility = CompatibilityLevel.MAJOR_BREAKING
        elif self.compatibility == CompatibilityLevel.COMPATIBLE:
            self.compatibility = CompatibilityLevel.MINOR_BREAKING


class SchemaBundle(GibsonBaseModel):
    """Bundle of schemas in different formats."""

    version: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    pydantic_schema: Dict[str, Any]
    json_schema: Dict[str, Any]
    typescript_types: str
    sqlalchemy_model: str
    alembic_migration: Optional[str] = None
    validation_status: ValidationStatus = ValidationStatus.NOT_VALIDATED
    validation_errors: List[Dict[str, Any]] = Field(default_factory=list)
    hash: str

    @field_validator("version")
    @classmethod
    def validate_version(cls, v: str) -> str:
        """Validate version format."""
        # Simple semantic version validation
        parts = v.split(".")
        if len(parts) != 3:
            raise ValueError("Version must be in format X.Y.Z")
        for part in parts:
            if not part.isdigit():
                raise ValueError("Version components must be numeric")
        return v

    def mark_validated(
        self, status: ValidationStatus, errors: Optional[List[Dict[str, Any]]] = None
    ) -> None:
        """Mark the bundle as validated."""
        self.validation_status = status
        if errors:
            self.validation_errors = errors


class MigrationScript(GibsonBaseModel):
    """Represents a complete migration script."""

    revision_id: str
    description: str
    depends_on: Optional[str] = None  # Previous revision
    upgrade_sql: List[str]
    downgrade_sql: List[str]
    data_migrations: List[DataMigration] = Field(default_factory=list)
    pre_checks: List[str] = Field(default_factory=list)
    post_checks: List[str] = Field(default_factory=list)
    estimated_duration: Optional[timedelta] = None
    rollback_plan: RollbackPlan
    metadata: Dict[str, Any] = Field(default_factory=dict)
    status: MigrationStatus = MigrationStatus.PENDING

    @property
    def total_statements(self) -> int:
        """Get total number of SQL statements."""
        count = len(self.upgrade_sql) + len(self.pre_checks) + len(self.post_checks)
        for dm in self.data_migrations:
            count += len(dm.sql_statements)
        return count

    def add_data_migration(self, migration: DataMigration) -> None:
        """Add a data migration step."""
        migration.step_number = len(self.data_migrations) + 1
        self.data_migrations.append(migration)

    def to_alembic_format(self) -> str:
        """Convert to Alembic migration file format."""
        # This will be implemented when we create the migration generator
        pass


class SchemaVersion(BaseModel):
    """Represents a schema version entry."""

    version: str
    hash: str
    timestamp: datetime
    model_name: str
    changes_from_previous: Optional[ChangeSet] = None
    migration_id: Optional[str] = None
    applied: bool = False
    applied_at: Optional[datetime] = None


class MigrationHistory(BaseModel):
    """History of applied migrations."""

    migration_id: str
    version: str
    applied_at: datetime
    execution_time: timedelta
    status: MigrationStatus
    error_message: Optional[str] = None
    rolled_back: bool = False
    rolled_back_at: Optional[datetime] = None
