"""
Exception classes for schema synchronization module.
"""

from typing import Any, Dict, List, Optional


class SchemaSyncError(Exception):
    """Base exception for schema synchronization errors."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class BreakingChangeError(SchemaSyncError):
    """Raised when breaking changes are detected that require manual intervention."""

    def __init__(
        self,
        message: str,
        breaking_changes: List[Dict[str, Any]],
        affected_rows: Optional[int] = None,
        remediation_steps: Optional[List[str]] = None,
    ):
        details = {
            "breaking_changes": breaking_changes,
            "affected_rows": affected_rows,
            "remediation_steps": remediation_steps or [],
        }
        super().__init__(message, details)
        self.breaking_changes = breaking_changes
        self.affected_rows = affected_rows
        self.remediation_steps = remediation_steps or []


class MigrationGenerationError(SchemaSyncError):
    """Raised when migration script generation fails."""

    def __init__(
        self, message: str, component: str, error_type: str, traceback: Optional[str] = None
    ):
        details = {"component": component, "error_type": error_type, "traceback": traceback}
        super().__init__(message, details)
        self.component = component
        self.error_type = error_type


class DataIntegrityError(SchemaSyncError):
    """Raised when data integrity violations are detected."""

    def __init__(
        self,
        message: str,
        violations: List[Dict[str, Any]],
        constraint_type: str,
        table_name: Optional[str] = None,
    ):
        details = {
            "violations": violations,
            "constraint_type": constraint_type,
            "table_name": table_name,
        }
        super().__init__(message, details)
        self.violations = violations
        self.constraint_type = constraint_type
        self.table_name = table_name


class VersionConflictError(SchemaSyncError):
    """Raised when schema version conflicts are detected."""

    def __init__(
        self, message: str, current_version: str, expected_version: str, conflict_type: str
    ):
        details = {
            "current_version": current_version,
            "expected_version": expected_version,
            "conflict_type": conflict_type,
        }
        super().__init__(message, details)
        self.current_version = current_version
        self.expected_version = expected_version
        self.conflict_type = conflict_type


class SchemaValidationError(SchemaSyncError):
    """Raised when schema validation fails."""

    def __init__(self, message: str, validation_errors: List[Dict[str, Any]], schema_format: str):
        details = {"validation_errors": validation_errors, "schema_format": schema_format}
        super().__init__(message, details)
        self.validation_errors = validation_errors
        self.schema_format = schema_format


class RollbackError(SchemaSyncError):
    """Raised when migration rollback fails."""

    def __init__(
        self,
        message: str,
        migration_id: str,
        rollback_step: str,
        original_error: Optional[str] = None,
    ):
        details = {
            "migration_id": migration_id,
            "rollback_step": rollback_step,
            "original_error": original_error,
        }
        super().__init__(message, details)
        self.migration_id = migration_id
        self.rollback_step = rollback_step
        self.original_error = original_error
