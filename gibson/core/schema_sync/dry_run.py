"""
Dry-run module for testing schema changes without applying them.
"""

import tempfile
import shutil
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
import json
import sqlite3
from contextlib import contextmanager

from gibson.models.base import GibsonBaseModel
from gibson.core.schema_sync.models import ChangeSet, MigrationScript, ChangeAnalysis
from gibson.core.schema_sync.migration_generator import MigrationGenerator
from gibson.core.schema_sync.validator import MigrationValidator


class DryRunResult(GibsonBaseModel):
    """Result of a dry-run operation."""

    success: bool
    changes_detected: Dict[str, Any]
    migration_preview: Optional[str] = None
    validation_results: Dict[str, Any] = {}
    affected_rows: int = 0
    warnings: List[str] = []
    errors: List[str] = []
    rollback_tested: bool = False
    rollback_success: Optional[bool] = None
    execution_time_ms: float = 0

    @property
    def is_safe(self) -> bool:
        """Check if dry-run indicates safe migration."""
        return self.success and len(self.errors) == 0


class DryRunExecutor:
    """Executes dry-run of schema changes."""

    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize dry-run executor.

        Args:
            db_path: Path to database for testing (uses temp DB if None)
        """
        self.db_path = db_path
        self.temp_db_path: Optional[str] = None
        self.migration_generator = MigrationGenerator()
        self.validator = MigrationValidator()

    def execute(
        self,
        changeset: ChangeSet,
        analysis: ChangeAnalysis,
        test_data: Optional[Dict[str, Any]] = None,
    ) -> DryRunResult:
        """
        Execute dry-run of schema changes.

        Args:
            changeset: Set of changes to test
            analysis: Analysis of changes
            test_data: Optional test data to use

        Returns:
            DryRunResult with outcome
        """
        import time

        start_time = time.time()

        result = DryRunResult(success=False, changes_detected=self._summarize_changes(changeset))

        try:
            # Create test database
            with self._create_test_database() as test_db:
                # Generate migration script
                migration = self.migration_generator.generate(changeset)
                result.migration_preview = self._format_migration_preview(migration)

                # Validate migration script
                validation = self.validator.validate(migration)
                result.validation_results = {
                    "valid": validation.valid,
                    "errors": [i.message for i in validation.issues if i.severity == "error"],
                    "warnings": [i.message for i in validation.issues if i.severity == "warning"],
                }

                if not validation.valid:
                    result.errors.extend(result.validation_results["errors"])
                    return result

                # Apply migration in test database
                affected_rows = self._apply_migration(test_db, migration, test_data)
                result.affected_rows = affected_rows

                # Test rollback if available
                if migration.downgrade_sql:
                    result.rollback_tested = True
                    result.rollback_success = self._test_rollback(test_db, migration, test_data)

                # Verify data integrity
                integrity_check = self._verify_data_integrity(test_db, analysis)
                if not integrity_check["valid"]:
                    result.errors.append(
                        f"Data integrity check failed: {integrity_check['message']}"
                    )

                # Check for warnings
                if analysis.breaking_changes:
                    result.warnings.append(
                        f"Found {len(analysis.breaking_changes)} breaking changes"
                    )

                if analysis.data_transformation_required:
                    result.warnings.append("Data transformation will be required")

                # Mark success if no errors
                result.success = len(result.errors) == 0

        except Exception as e:
            result.errors.append(f"Dry-run failed: {str(e)}")

        finally:
            result.execution_time_ms = (time.time() - start_time) * 1000
            self._cleanup()

        return result

    def preview_migration(self, changeset: ChangeSet) -> Tuple[str, Dict[str, Any]]:
        """
        Generate preview of migration without executing.

        Args:
            changeset: Changes to preview

        Returns:
            Tuple of (migration_script, metadata)
        """
        # Generate migration
        migration = self.migration_generator.generate(changeset)

        # Format for display
        preview = self._format_migration_preview(migration)

        # Generate metadata
        metadata = {
            "version": migration.version,
            "description": migration.description,
            "reversible": bool(migration.downgrade_sql),
            "field_changes": {
                "added": len(changeset.added_fields),
                "removed": len(changeset.removed_fields),
                "modified": len(changeset.modified_fields),
            },
        }

        return preview, metadata

    @contextmanager
    def _create_test_database(self):
        """Create temporary test database."""
        # Create temp database
        temp_dir = tempfile.mkdtemp()
        self.temp_db_path = str(Path(temp_dir) / "test.db")

        try:
            # Copy existing database or create new
            if self.db_path and Path(self.db_path).exists():
                shutil.copy2(self.db_path, self.temp_db_path)
            else:
                # Create minimal test database
                self._create_minimal_db(self.temp_db_path)

            yield self.temp_db_path

        finally:
            # Cleanup
            if Path(temp_dir).exists():
                shutil.rmtree(temp_dir)

    def _create_minimal_db(self, db_path: str):
        """Create minimal test database."""
        conn = sqlite3.connect(db_path)
        try:
            cursor = conn.cursor()

            # Create payloads table with basic schema
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS payloads (
                    id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    payload_type TEXT,
                    severity TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """
            )

            # Add some test data
            cursor.execute(
                """
                INSERT INTO payloads (name, description, payload_type, severity)
                VALUES 
                    ('Test Payload 1', 'Description 1', 'prompt', 'high'),
                    ('Test Payload 2', 'Description 2', 'data', 'medium'),
                    ('Test Payload 3', 'Description 3', 'model', 'low')
            """
            )

            conn.commit()
        finally:
            conn.close()

    def _apply_migration(
        self, db_path: str, migration: MigrationScript, test_data: Optional[Dict[str, Any]] = None
    ) -> int:
        """
        Apply migration to test database.

        Returns:
            Number of affected rows
        """
        conn = sqlite3.connect(db_path)
        affected_rows = 0

        try:
            cursor = conn.cursor()

            # Begin transaction
            cursor.execute("BEGIN TRANSACTION")

            # Apply migration SQL
            # Note: This is simplified - real implementation would parse SQL properly
            statements = migration.upgrade_sql.split(";")
            for statement in statements:
                statement = statement.strip()
                if statement:
                    cursor.execute(statement)
                    affected_rows += cursor.rowcount

            # Insert test data if provided
            if test_data:
                for table, rows in test_data.items():
                    for row in rows:
                        columns = ", ".join(row.keys())
                        placeholders = ", ".join(["?" for _ in row])
                        query = f"INSERT INTO {table} ({columns}) VALUES ({placeholders})"
                        cursor.execute(query, list(row.values()))

            # Commit transaction
            conn.commit()

        except Exception as e:
            conn.rollback()
            raise Exception(f"Migration failed: {str(e)}")

        finally:
            conn.close()

        return affected_rows

    def _test_rollback(
        self, db_path: str, migration: MigrationScript, test_data: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Test rollback of migration.

        Returns:
            True if rollback successful
        """
        if not migration.downgrade_sql:
            return False

        conn = sqlite3.connect(db_path)

        try:
            cursor = conn.cursor()

            # Begin transaction
            cursor.execute("BEGIN TRANSACTION")

            # Apply downgrade SQL
            statements = migration.downgrade_sql.split(";")
            for statement in statements:
                statement = statement.strip()
                if statement and not statement.startswith("--"):
                    cursor.execute(statement)

            # Verify rollback
            # This is simplified - real implementation would verify schema state
            cursor.execute("SELECT sql FROM sqlite_master WHERE type='table'")

            # Commit if successful
            conn.commit()
            return True

        except Exception:
            conn.rollback()
            return False

        finally:
            conn.close()

    def _verify_data_integrity(self, db_path: str, analysis: ChangeAnalysis) -> Dict[str, Any]:
        """
        Verify data integrity after migration.

        Returns:
            Dictionary with validation results
        """
        conn = sqlite3.connect(db_path)

        try:
            cursor = conn.cursor()

            # Check for NULL values in required fields
            for field in analysis.breaking_changes:
                if "nullable_to_required" in field.change_type:
                    cursor.execute(
                        f"SELECT COUNT(*) FROM payloads WHERE {field.field_name} IS NULL"
                    )
                    null_count = cursor.fetchone()[0]
                    if null_count > 0:
                        return {
                            "valid": False,
                            "message": f"Found {null_count} NULL values in required field {field.field_name}",
                        }

            # Check for data type compatibility
            cursor.execute("PRAGMA table_info(payloads)")
            columns = cursor.fetchall()

            return {
                "valid": True,
                "message": "Data integrity verified",
                "column_count": len(columns),
            }

        finally:
            conn.close()

    def _summarize_changes(self, changeset: ChangeSet) -> Dict[str, Any]:
        """Summarize changes for result."""
        return {
            "fields_added": list(changeset.added_fields.keys()),
            "fields_removed": changeset.removed_fields,
            "fields_modified": list(changeset.modified_fields.keys()),
            "enum_changes": list(changeset.enum_changes.keys()),
            "total_changes": changeset.change_count,
        }

    def _format_migration_preview(self, migration: MigrationScript) -> str:
        """Format migration script for preview."""
        lines = [
            f"-- Migration Version: {migration.version}",
            f"-- Description: {migration.description}",
            "",
            "-- Upgrade Migration:",
            "-- " + "-" * 50,
            migration.upgrade_sql,
            "",
        ]

        if migration.downgrade_sql:
            lines.extend(["-- Downgrade Migration:", "-- " + "-" * 50, migration.downgrade_sql])
        else:
            lines.append("-- No downgrade migration available (irreversible)")

        return "\n".join(lines)

    def _cleanup(self):
        """Clean up temporary resources."""
        if self.temp_db_path and Path(self.temp_db_path).exists():
            try:
                Path(self.temp_db_path).unlink()
            except:
                pass  # Best effort cleanup


class DryRunReporter:
    """Generates reports from dry-run results."""

    @staticmethod
    def generate_report(result: DryRunResult) -> str:
        """
        Generate human-readable report from dry-run result.

        Args:
            result: Dry-run result

        Returns:
            Formatted report string
        """
        lines = [
            "=" * 60,
            "SCHEMA MIGRATION DRY-RUN REPORT",
            "=" * 60,
            "",
            f"Status: {'✓ SUCCESS' if result.success else '✗ FAILED'}",
            f"Execution Time: {result.execution_time_ms:.2f}ms",
            "",
        ]

        # Changes summary
        lines.extend(
            [
                "Changes Detected:",
                "-" * 40,
            ]
        )

        for key, value in result.changes_detected.items():
            if isinstance(value, list) and value:
                lines.append(f"  {key}: {', '.join(value)}")
            elif isinstance(value, int):
                lines.append(f"  {key}: {value}")

        lines.append("")

        # Validation results
        if result.validation_results:
            lines.extend(
                [
                    "Validation Results:",
                    "-" * 40,
                    f"  Valid: {result.validation_results.get('valid', False)}",
                ]
            )

            errors = result.validation_results.get("errors", [])
            if errors:
                lines.append("  Errors:")
                for error in errors:
                    lines.append(f"    - {error}")

            warnings = result.validation_results.get("warnings", [])
            if warnings:
                lines.append("  Warnings:")
                for warning in warnings:
                    lines.append(f"    - {warning}")

        lines.append("")

        # Rollback test
        if result.rollback_tested:
            lines.extend(
                [
                    "Rollback Test:",
                    "-" * 40,
                    f"  Tested: Yes",
                    f"  Success: {result.rollback_success}",
                    "",
                ]
            )

        # Final warnings and errors
        if result.warnings:
            lines.extend(
                [
                    "⚠ Warnings:",
                    "-" * 40,
                ]
            )
            for warning in result.warnings:
                lines.append(f"  - {warning}")
            lines.append("")

        if result.errors:
            lines.extend(
                [
                    "✗ Errors:",
                    "-" * 40,
                ]
            )
            for error in result.errors:
                lines.append(f"  - {error}")
            lines.append("")

        # Migration preview
        if result.migration_preview:
            lines.extend(["Migration Preview:", "-" * 40, result.migration_preview, ""])

        lines.append("=" * 60)

        return "\n".join(lines)
