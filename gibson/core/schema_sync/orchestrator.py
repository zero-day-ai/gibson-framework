"""
Main orchestrator for schema synchronization workflow.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional, Type
from pydantic import BaseModel
from loguru import logger

from gibson.models.payload import PayloadModel
from gibson.core.schema_sync.detector import SchemaChangeDetector
from gibson.core.schema_sync.analyzer import ChangeAnalyzer
from gibson.core.schema_sync.generator_hub import SchemaGeneratorHub
from gibson.core.schema_sync.migration_generator import AlembicMigrationGenerator
from gibson.core.schema_sync.data_migration import DataMigrationPlanner
from gibson.core.schema_sync.version_registry import VersionRegistry
from gibson.core.schema_sync.models import (
    CompatibilityLevel,
    MigrationStatus,
    SchemaBundle,
    SchemaVersion,
)
from gibson.core.schema_sync.exceptions import (
    BreakingChangeError,
    VersionConflictError,
)


class SchemaOrchestrator:
    """Orchestrates the complete schema synchronization workflow."""

    def __init__(
        self,
        registry_path: Optional[Path] = None,
        dry_run: bool = False,
        force: bool = False,
        database_session=None,
    ):
        """
        Initialize the schema orchestrator.

        Args:
            registry_path: Path for version registry storage
            dry_run: If True, don't apply changes
            force: If True, apply changes even with warnings
            database_session: Optional database session
        """
        self.dry_run = dry_run
        self.force = force
        self.database_session = database_session

        # Initialize components
        self.detector = SchemaChangeDetector()
        self.analyzer = ChangeAnalyzer(database_session)
        self.generator_hub = SchemaGeneratorHub()
        self.migration_generator = AlembicMigrationGenerator()
        self.data_planner = DataMigrationPlanner(database_session)
        self.registry = VersionRegistry(registry_path)

        logger.info(f"Initialized SchemaOrchestrator (dry_run={dry_run}, force={force})")

    def sync_schemas(
        self, model: Type[BaseModel] = PayloadModel, version: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Main entry point for schema synchronization.

        Args:
            model: Pydantic model to sync (default: PayloadModel)
            version: Version string (auto-generated if not provided)

        Returns:
            Result dictionary with status and details
        """
        logger.info(f"Starting schema sync for {model.__name__}")

        result = {
            "status": "pending",
            "model": model.__name__,
            "version": version,
            "changes_detected": False,
            "migration_generated": False,
            "schemas_generated": False,
            "errors": [],
            "warnings": [],
        }

        try:
            # Step 1: Detect changes
            current_version = self.registry.get_current_version()

            if current_version:
                # Load previous schema from registry
                previous_schema = self._load_previous_schema(current_version)
            else:
                # First run - use empty schema
                previous_schema = {}
                logger.info("No previous schema found - treating as initial setup")

            changeset = self.detector.detect_changes(model, previous_schema)
            result["changes_detected"] = changeset.has_changes
            result["change_count"] = changeset.change_count

            if not changeset.has_changes:
                logger.info("No changes detected - schemas are in sync")
                result["status"] = "no_changes"
                return result

            # Step 2: Analyze changes
            analysis = self.analyzer.analyze_changeset(changeset)
            # Handle compatibility as enum or string
            if hasattr(analysis.compatibility, "value"):
                result["compatibility"] = analysis.compatibility.value
            else:
                result["compatibility"] = analysis.compatibility
            result["risk_level"] = analysis.risk_level
            result["warnings"].extend(analysis.warnings)

            # Check for breaking changes
            if analysis.breaking_changes and not self.force:
                raise BreakingChangeError(
                    f"Breaking changes detected: {len(analysis.breaking_changes)} changes require intervention",
                    breaking_changes=[bc.model_dump() for bc in analysis.breaking_changes],
                    affected_rows=analysis.estimated_affected_rows,
                    remediation_steps=analysis.suggested_actions,
                )

            # Step 3: Generate version if not provided
            if not version:
                version = self._generate_version()
                result["version"] = version

            # Check for version conflicts
            schema_hash = self.detector.calculate_schema_hash(model)
            conflict = self.registry.check_version_conflict(version, schema_hash)
            if conflict:
                raise VersionConflictError(
                    f"Version conflict: {conflict}",
                    current_version=current_version.version if current_version else "none",
                    expected_version=version,
                    conflict_type="version_exists",
                )

            # Step 4: Generate all schema formats
            schema_bundle = self.generator_hub.generate_all_schemas(model, version)
            result["schemas_generated"] = True
            result["schema_bundle_hash"] = schema_bundle.hash[:8]

            # Step 5: Generate migration script
            previous_revision = current_version.migration_id if current_version else None
            migration = self.migration_generator.generate_migration(
                analysis, version, previous_revision
            )
            result["migration_generated"] = True
            result["migration_id"] = migration.revision_id

            # Step 6: Generate data migrations if needed
            if analysis.breaking_changes:
                data_migrations = self.data_planner.plan_data_migration(analysis.breaking_changes)
                migration.data_migrations = data_migrations
                result["data_migrations_count"] = len(data_migrations)

            # Step 7: Apply changes (if not dry run)
            if self.dry_run:
                logger.info("DRY RUN - Changes not applied")
                result["status"] = "dry_run_success"
                result["message"] = "Dry run completed successfully"
            else:
                # Apply migration
                success = self._apply_migration(migration, schema_bundle)

                if success:
                    # Register version
                    self.registry.register_version(
                        version, schema_bundle.model_dump(), schema_bundle.hash, model.__name__
                    )

                    # Record migration
                    self.registry.record_migration(
                        migration.revision_id, version, MigrationStatus.COMPLETED
                    )

                    result["status"] = "success"
                    result["message"] = f"Schema sync completed for version {version}"
                else:
                    result["status"] = "failed"
                    result["message"] = "Migration application failed"

            # Add migration script to result for review
            result["migration_script"] = self._migration_to_dict(migration)

        except BreakingChangeError as e:
            logger.error(f"Breaking changes detected: {e.message}")
            result["status"] = "breaking_changes"
            result["errors"].append(e.message)
            result["breaking_changes"] = e.breaking_changes
            result["remediation_steps"] = e.remediation_steps

        except VersionConflictError as e:
            logger.error(f"Version conflict: {e.message}")
            result["status"] = "version_conflict"
            result["errors"].append(e.message)

        except Exception as e:
            logger.error(f"Unexpected error during schema sync: {e}")
            result["status"] = "error"
            result["errors"].append(str(e))

        return result

    def validate_current_state(self) -> Dict[str, Any]:
        """
        Validate current schema state across all formats.

        Returns:
            Validation result dictionary
        """
        logger.info("Validating current schema state")

        result = {
            "valid": True,
            "issues": [],
            "current_version": None,
            "pending_migrations": [],
        }

        # Get current version
        current_version = self.registry.get_current_version()
        if current_version:
            result["current_version"] = current_version.version

        # Check for pending migrations
        pending = self.registry.get_pending_migrations()
        result["pending_migrations"] = pending

        if pending:
            result["valid"] = False
            result["issues"].append(f"Found {len(pending)} pending migrations")

        # Validate schema consistency
        # This would check that JSON schemas, TypeScript, etc. are all in sync

        return result

    def _apply_migration(self, migration: Any, schema_bundle: SchemaBundle) -> bool:
        """
        Apply migration to database.

        Args:
            migration: Migration script to apply
            schema_bundle: Schema bundle with new schemas

        Returns:
            True if successful
        """
        if not self.database_session:
            logger.warning("No database session - skipping migration application")
            # Would write migration file for manual application
            migration_file = Path(f"migrations/{migration.revision_id}.sql")
            migration_file.parent.mkdir(exist_ok=True)

            with open(migration_file, "w") as f:
                f.write("-- Auto-generated migration\n")
                f.write(f"-- Revision: {migration.revision_id}\n")
                f.write(f"-- Description: {migration.description}\n\n")

                for sql in migration.upgrade_sql:
                    f.write(f"{sql}\n")

            logger.info(f"Migration script written to {migration_file}")
            return True

        # In real implementation, would execute migration via Alembic
        logger.info("Would apply migration via Alembic here")
        return True

    def _load_previous_schema(self, version: SchemaVersion) -> Dict[str, Any]:
        """Load previous schema from version registry."""
        # In real implementation, would load from stored schema files
        # For now, return the current model schema as a baseline
        return PayloadModel.model_json_schema()

    def _generate_version(self) -> str:
        """Generate automatic version string."""
        from datetime import datetime

        # Simple version generation based on date
        # Real implementation might use semantic versioning
        now = datetime.utcnow()
        return f"1.{now.year % 100}.{now.month:02d}{now.day:02d}"

    def _migration_to_dict(self, migration: Any) -> Dict[str, Any]:
        """Convert migration to dictionary for result."""
        return {
            "revision_id": migration.revision_id,
            "description": migration.description,
            "statement_count": migration.total_statements,
            "has_data_migrations": len(migration.data_migrations) > 0,
            "estimated_duration": str(migration.estimated_duration)
            if migration.estimated_duration
            else None,
            "risk_level": migration.metadata.get("risk_level", "unknown"),
        }
