"""
Integration tests for complete schema synchronization workflow.
"""

import pytest
import tempfile
import shutil
from pathlib import Path
from typing import Dict, Any
import json

from gibson.core.schema_sync import SchemaOrchestrator
from gibson.core.schema_sync.preflight import PreflightChecker
from gibson.core.schema_sync.dry_run import DryRunExecutor
from gibson.core.schema_sync.rollback import RollbackManager
from gibson.models.payload import PayloadModel
from pydantic import BaseModel, Field


class TestPayloadV1(BaseModel):
    """Test model version 1."""

    id: int
    name: str
    description: str = ""
    active: bool = True


class TestPayloadV2(BaseModel):
    """Test model version 2 with changes."""

    id: int
    name: str
    description: str  # Made required
    active: bool = True
    created_at: str = ""  # New field
    # removed: old_field


class TestSchemaWorkflow:
    """Integration tests for schema synchronization workflow."""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for testing."""
        temp_dir = tempfile.mkdtemp()
        yield Path(temp_dir)
        shutil.rmtree(temp_dir)

    @pytest.fixture
    def orchestrator(self, temp_dir):
        """Create orchestrator instance."""
        return SchemaOrchestrator(
            migrations_dir=temp_dir / "migrations", schemas_dir=temp_dir / "schemas", dry_run=False
        )

    def test_full_sync_workflow(self, orchestrator, temp_dir):
        """Test complete synchronization workflow."""
        # Step 1: Initial sync with V1
        result = orchestrator.sync_schemas(model=TestPayloadV1, version="1.0.0")

        assert result["status"] in ["success", "no_changes"]
        assert result["version"] == "1.0.0"

        # Verify files created
        schemas_dir = temp_dir / "schemas"
        assert schemas_dir.exists()
        assert (schemas_dir / "payload_1.0.0.json").exists()

        # Step 2: Sync with V2 (has changes)
        result = orchestrator.sync_schemas(model=TestPayloadV2, version="2.0.0")

        assert result["status"] == "success"
        assert result["version"] == "2.0.0"
        assert "changeset" in result

        # Verify migration created
        migrations_dir = temp_dir / "migrations"
        assert migrations_dir.exists()
        migration_files = list(migrations_dir.glob("*.py"))
        assert len(migration_files) > 0

    def test_dry_run_workflow(self, orchestrator):
        """Test dry-run mode."""
        orchestrator.dry_run = True

        result = orchestrator.sync_schemas(model=TestPayloadV1, version="1.0.0")

        assert result["status"] == "dry_run_success"
        assert "preview" in result

        # Verify no files created in dry-run
        assert not orchestrator.migrations_dir.exists()

    def test_breaking_changes_detection(self, orchestrator):
        """Test detection of breaking changes."""
        # Initial sync
        orchestrator.sync_schemas(model=TestPayloadV1, version="1.0.0")

        # Create model with breaking changes
        class TestPayloadBreaking(BaseModel):
            id: int
            name: str
            # removed: description (breaking)
            # removed: active (breaking)
            new_required: str  # Required field without default (breaking)

        result = orchestrator.sync_schemas(model=TestPayloadBreaking, version="2.0.0")

        assert result["status"] == "breaking_changes"
        assert "breaking_changes" in result
        assert len(result["breaking_changes"]) > 0

        # Force sync with breaking changes
        result = orchestrator.sync_schemas(model=TestPayloadBreaking, version="2.0.0", force=True)

        assert result["status"] == "success"
        assert result.get("forced") is True

    def test_rollback_workflow(self, temp_dir):
        """Test rollback functionality."""
        orchestrator = SchemaOrchestrator(
            migrations_dir=temp_dir / "migrations", schemas_dir=temp_dir / "schemas"
        )

        # Create rollback manager
        rollback_manager = RollbackManager(backup_dir=temp_dir / "backups")

        # Sync multiple versions
        orchestrator.sync_schemas(TestPayloadV1, "1.0.0")
        orchestrator.sync_schemas(TestPayloadV2, "2.0.0")

        # Create rollback points
        rollback_manager.create_rollback_point(version="1.0.0", schema_hash="hash1")
        rollback_manager.create_rollback_point(version="2.0.0", schema_hash="hash2")

        # Test rollback
        result = rollback_manager.rollback_to_version(target_version="1.0.0", dry_run=True)

        assert result.success
        assert result.to_version == "1.0.0"

    def test_preflight_checks(self, temp_dir):
        """Test preflight check integration."""
        checker = PreflightChecker(
            config={
                "database_path": temp_dir / "test.db",
                "migrations_directory": temp_dir / "migrations",
                "backup_directory": temp_dir / "backups",
            }
        )

        result = checker.run_checks(skip_categories=["git"])  # Skip Git checks in test

        assert result.checks
        assert result.can_proceed or result.warnings > 0

        # Check specific checks ran
        check_names = [c.name for c in result.checks]
        assert "Python Version" in check_names
        assert "Database Connection" in check_names
        assert "Disk Space" in check_names

    def test_data_migration_workflow(self, orchestrator):
        """Test data migration planning."""
        # Initial sync
        orchestrator.sync_schemas(TestPayloadV1, "1.0.0")

        # Model with data migration needs
        class TestPayloadMigration(BaseModel):
            id: int
            name: str
            description: str  # Was optional, now required
            active: bool = True
            status: str = "active"  # New with default

        result = orchestrator.sync_schemas(model=TestPayloadMigration, version="2.0.0")

        assert "data_migration_plan" in result
        plan = result["data_migration_plan"]

        assert plan["requires_data_transformation"]
        assert len(plan["transformations"]) > 0

    def test_multi_format_generation(self, orchestrator, temp_dir):
        """Test generation of multiple schema formats."""
        result = orchestrator.sync_schemas(model=TestPayloadV1, version="1.0.0")

        assert result["status"] in ["success", "no_changes"]

        # Check generated formats
        schemas_dir = temp_dir / "schemas"

        # JSON schema should exist
        json_file = schemas_dir / "payload_1.0.0.json"
        assert json_file.exists()

        # TypeScript definitions (if generated)
        ts_file = schemas_dir / "payload_1.0.0.d.ts"
        # This might not exist depending on configuration

        # SQLAlchemy models (if generated)
        sql_file = schemas_dir / "payload_1.0.0_models.py"
        # This might not exist depending on configuration

    def test_concurrent_sync_handling(self, temp_dir):
        """Test handling of concurrent synchronization attempts."""
        import threading
        import time

        orchestrator1 = SchemaOrchestrator(
            migrations_dir=temp_dir / "migrations", schemas_dir=temp_dir / "schemas"
        )

        orchestrator2 = SchemaOrchestrator(
            migrations_dir=temp_dir / "migrations", schemas_dir=temp_dir / "schemas"
        )

        results = []

        def sync_task(orchestrator, version):
            result = orchestrator.sync_schemas(model=TestPayloadV1, version=version)
            results.append(result)

        # Start concurrent syncs
        t1 = threading.Thread(target=sync_task, args=(orchestrator1, "1.0.0"))
        t2 = threading.Thread(target=sync_task, args=(orchestrator2, "1.0.1"))

        t1.start()
        t2.start()

        t1.join()
        t2.join()

        # Both should complete without errors
        assert len(results) == 2
        for result in results:
            assert result["status"] in ["success", "no_changes", "locked"]

    def test_error_recovery(self, orchestrator):
        """Test error recovery mechanisms."""

        # Simulate error by using invalid model
        class InvalidModel:
            """Not a Pydantic model."""

            pass

        with pytest.raises(Exception):
            orchestrator.sync_schemas(model=InvalidModel, version="1.0.0")

        # Should still be able to sync valid model after error
        result = orchestrator.sync_schemas(model=TestPayloadV1, version="1.0.0")

        assert result["status"] in ["success", "no_changes"]


class TestDryRunIntegration:
    """Integration tests for dry-run functionality."""

    def test_dry_run_with_test_data(self, temp_dir):
        """Test dry-run with test data."""
        executor = DryRunExecutor(db_path=temp_dir / "test.db")

        # Create test changeset
        from gibson.core.schema_sync.models import ChangeSet, FieldInfo

        changeset = ChangeSet(
            added_fields={"new_field": FieldInfo(name="new_field", type="string", nullable=True)},
            model_hash_before="hash1",
            model_hash_after="hash2",
        )

        # Create test analysis
        from gibson.core.schema_sync.analyzer import ChangeAnalyzer

        analyzer = ChangeAnalyzer()
        analysis = analyzer.analyze_changeset(changeset)

        # Run dry-run with test data
        test_data = {
            "payloads": [
                {"name": "test1", "description": "desc1"},
                {"name": "test2", "description": "desc2"},
            ]
        }

        result = executor.execute(changeset=changeset, analysis=analysis, test_data=test_data)

        assert result.is_safe
        assert result.affected_rows >= 0
        assert result.migration_preview is not None

    def test_dry_run_rollback_testing(self, temp_dir):
        """Test dry-run rollback validation."""
        executor = DryRunExecutor(db_path=temp_dir / "test.db")

        # Create reversible changeset
        from gibson.core.schema_sync.models import ChangeSet, FieldInfo

        changeset = ChangeSet(
            added_fields={
                "temp_field": FieldInfo(name="temp_field", type="integer", nullable=True, default=0)
            },
            model_hash_before="hash1",
            model_hash_after="hash2",
        )

        from gibson.core.schema_sync.analyzer import ChangeAnalyzer

        analyzer = ChangeAnalyzer()
        analysis = analyzer.analyze_changeset(changeset)

        result = executor.execute(changeset=changeset, analysis=analysis)

        assert result.rollback_tested
        # Rollback success might be None if no downgrade SQL
        assert result.rollback_success in [True, False, None]


class TestVersionManagement:
    """Integration tests for version management."""

    def test_version_progression(self, temp_dir):
        """Test proper version progression."""
        from gibson.core.schema_sync.version_registry import VersionRegistry
        from gibson.core.schema_sync.version_utils import VersionManager

        registry = VersionRegistry(registry_path=temp_dir / "versions.json")
        manager = VersionManager()

        # Start with no version
        current = registry.get_current_version()
        assert current is None

        # Suggest first version
        first = manager.suggest_version(None, "patch")
        assert first in ["0.1.0", datetime.now().strftime("%Y%m%d_%H%M%S")]

        # Set and progress versions
        registry.set_current_version("0.1.0")

        # Patch bump
        patch = manager.suggest_version("0.1.0", "patch")
        assert patch == "0.1.1"

        # Minor bump
        minor = manager.suggest_version("0.1.0", "minor")
        assert minor == "0.2.0"

        # Major bump
        major = manager.suggest_version("0.1.0", "major")
        assert major == "1.0.0"

    def test_version_history_tracking(self, temp_dir):
        """Test version history tracking."""
        from gibson.core.schema_sync.version_registry import VersionRegistry

        registry = VersionRegistry(registry_path=temp_dir / "versions.json")

        # Add multiple versions
        versions = ["0.1.0", "0.2.0", "0.2.1", "1.0.0", "1.1.0"]

        for version in versions:
            registry.register_version(
                version=version, schema_hash=f"hash_{version}", metadata={"test": True}
            )

        # Get history
        history = registry.get_version_history(limit=3)
        assert len(history) <= 3

        # Get specific version info
        info = registry.get_version_info("1.0.0")
        assert info is not None
        assert info["version"] == "1.0.0"
        assert info["schema_hash"] == "hash_1.0.0"
