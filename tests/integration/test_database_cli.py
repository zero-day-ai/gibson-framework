"""Integration tests for database CLI commands."""

import asyncio
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import pytest
from typer.testing import CliRunner

from gibson.cli.commands.database import app
from gibson.core.migrations import MigrationInfo, MigrationStatus


@pytest.fixture
def runner():
    """Create a CLI test runner."""
    return CliRunner()


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    yield db_path
    Path(db_path).unlink(missing_ok=True)


def test_database_init_command(runner):
    """Test database init command."""
    with patch("gibson.cli.commands.database.DatabaseManager") as mock_manager:
        mock_db = Mock()
        mock_db.init_db = AsyncMock()
        mock_manager.return_value = mock_db

        result = runner.invoke(app, ["init"])

        assert result.exit_code == 0
        assert "Database initialized successfully" in result.output


def test_database_init_with_force(runner):
    """Test database init with force flag."""
    with patch("gibson.cli.commands.database.DatabaseManager") as mock_manager:
        mock_db = Mock()
        mock_db.init_db = AsyncMock()
        mock_manager.return_value = mock_db

        result = runner.invoke(app, ["init", "--force"])

        assert result.exit_code == 0
        mock_db.init_db.assert_called()


def test_database_init_failure(runner):
    """Test database init when it fails."""
    with patch("gibson.cli.commands.database.DatabaseManager") as mock_manager:
        mock_db = Mock()
        mock_db.init_db = AsyncMock(side_effect=Exception("Init failed"))
        mock_manager.return_value = mock_db

        result = runner.invoke(app, ["init"])

        assert result.exit_code == 1
        assert "Failed to initialize database" in result.output


def test_database_migrate_create_new(runner):
    """Test creating a new migration."""
    with patch("gibson.cli.commands.database.MigrationManager") as mock_manager:
        mock_mgr = Mock()
        mock_mgr.create_migration = AsyncMock(return_value="abc123")
        mock_manager.return_value = mock_mgr

        result = runner.invoke(app, ["migrate", "Add new feature"])

        assert result.exit_code == 0
        assert "Creating migration: Add new feature" in result.output
        assert "Created migration: abc123" in result.output
        mock_mgr.create_migration.assert_called_once()


def test_database_migrate_apply_pending(runner):
    """Test applying pending migrations."""
    with patch("gibson.cli.commands.database.MigrationManager") as mock_manager:
        mock_mgr = Mock()

        # Mock status with pending migrations
        pending_migration = MigrationInfo(
            revision="def456", description="Add user table", is_head=True, is_current=False
        )
        mock_status = MigrationStatus(
            current_revision="abc123",
            head_revision="def456",
            pending_migrations=[pending_migration],
            applied_migrations=[],
            needs_migration=True,
        )
        mock_mgr.get_status = AsyncMock(return_value=mock_status)
        mock_mgr.upgrade = AsyncMock()
        mock_manager.return_value = mock_mgr

        with patch("gibson.cli.commands.database.MigrationSafety") as mock_safety:
            mock_safety_inst = Mock()
            mock_safety_inst.run_safety_checks = Mock(return_value=(True, []))
            mock_safety_inst.create_backup = Mock(return_value=Mock(backup_id="backup_123"))
            mock_safety.return_value = mock_safety_inst

            result = runner.invoke(app, ["migrate"])

            assert result.exit_code == 0
            assert "Found 1 pending migration(s)" in result.output
            assert "Migrations applied successfully" in result.output


def test_database_migrate_dry_run(runner):
    """Test migration in dry-run mode."""
    with patch("gibson.cli.commands.database.MigrationManager") as mock_manager:
        mock_mgr = Mock()
        mock_status = MigrationStatus(
            current_revision="abc123",
            head_revision="def456",
            pending_migrations=[
                MigrationInfo(
                    revision="def456", description="Test migration", is_head=True, is_current=False
                )
            ],
            applied_migrations=[],
            needs_migration=True,
        )
        mock_mgr.get_status = AsyncMock(return_value=mock_status)
        mock_manager.return_value = mock_mgr

        result = runner.invoke(app, ["migrate", "--dry-run"])

        assert result.exit_code == 0
        assert "Dry run - no migrations applied" in result.output


def test_database_status(runner):
    """Test database status command."""
    with patch("gibson.cli.commands.database.MigrationManager") as mock_manager:
        mock_mgr = Mock()

        # Create mock migrations
        pending = MigrationInfo(
            revision="def456789",
            description="Add indexes",
            is_head=True,
            is_current=False,
            create_date=None,
        )
        applied = MigrationInfo(
            revision="abc123456",
            description="Initial schema",
            is_head=False,
            is_current=True,
            create_date=None,
        )

        mock_status = MigrationStatus(
            current_revision="abc123456",
            head_revision="def456789",
            pending_migrations=[pending],
            applied_migrations=[applied],
            is_up_to_date=False,
            needs_migration=True,
        )
        mock_mgr.get_status = AsyncMock(return_value=mock_status)
        mock_manager.return_value = mock_mgr

        result = runner.invoke(app, ["status"])

        assert result.exit_code == 0
        assert "Migration Status" in result.output
        assert "abc12345" in result.output  # Truncated revision
        assert "def45678" in result.output  # Truncated revision
        assert "Migrations pending" in result.output


def test_database_status_up_to_date(runner):
    """Test status when database is up to date."""
    with patch("gibson.cli.commands.database.MigrationManager") as mock_manager:
        mock_mgr = Mock()
        mock_status = MigrationStatus(
            current_revision="xyz789",
            head_revision="xyz789",
            pending_migrations=[],
            applied_migrations=[],
            is_up_to_date=True,
            needs_migration=False,
        )
        mock_mgr.get_status = AsyncMock(return_value=mock_status)
        mock_manager.return_value = mock_mgr

        result = runner.invoke(app, ["status"])

        assert result.exit_code == 0
        assert "Up to date" in result.output


def test_database_rollback(runner):
    """Test database rollback command."""
    with patch("gibson.cli.commands.database.MigrationManager") as mock_manager:
        mock_mgr = Mock()
        mock_status = MigrationStatus(
            current_revision="def456",
            head_revision="def456",
            pending_migrations=[],
            applied_migrations=[],
            is_up_to_date=True,
            needs_migration=False,
        )
        mock_mgr.get_status = AsyncMock(return_value=mock_status)
        mock_mgr.downgrade = AsyncMock()
        mock_manager.return_value = mock_mgr

        with patch("gibson.cli.commands.database.MigrationSafety") as mock_safety:
            mock_safety_inst = Mock()
            mock_safety_inst.create_backup = Mock(return_value=Mock(backup_id="backup_456"))
            mock_safety.return_value = mock_safety_inst

            # Use --force to skip confirmation
            result = runner.invoke(app, ["rollback", "1", "--force"])

            assert result.exit_code == 0
            assert "Rollback completed successfully" in result.output


def test_database_rollback_dry_run(runner):
    """Test rollback in dry-run mode."""
    with patch("gibson.cli.commands.database.MigrationManager") as mock_manager:
        mock_mgr = Mock()
        mock_status = MigrationStatus(
            current_revision="def456",
            head_revision="def456",
            pending_migrations=[],
            applied_migrations=[],
            is_up_to_date=True,
            needs_migration=False,
        )
        mock_mgr.get_status = AsyncMock(return_value=mock_status)
        mock_manager.return_value = mock_mgr

        result = runner.invoke(app, ["rollback", "2", "--dry-run"])

        assert result.exit_code == 0
        assert "Dry run - no rollback performed" in result.output


def test_database_history(runner):
    """Test migration history command."""
    with patch("gibson.cli.commands.database.MigrationManager") as mock_manager:
        mock_mgr = Mock()

        # Create mock history
        from datetime import datetime

        migrations = [
            MigrationInfo(
                revision="abc123456",
                description="Initial migration",
                is_head=False,
                is_current=False,
                create_date=datetime.now(),
            ),
            MigrationInfo(
                revision="def456789",
                description="Add indexes",
                is_head=False,
                is_current=True,
                create_date=datetime.now(),
            ),
        ]
        mock_mgr.get_migration_history = AsyncMock(return_value=migrations)
        mock_manager.return_value = mock_mgr

        result = runner.invoke(app, ["history"])

        assert result.exit_code == 0
        assert "Migration History" in result.output
        assert "abc12345" in result.output
        assert "def45678" in result.output


def test_database_history_with_limit(runner):
    """Test migration history with limit."""
    with patch("gibson.cli.commands.database.MigrationManager") as mock_manager:
        mock_mgr = Mock()

        # Create many migrations
        migrations = [
            MigrationInfo(
                revision=f"rev{i:06d}",
                description=f"Migration {i}",
                is_head=False,
                is_current=(i == 0),
            )
            for i in range(20)
        ]
        mock_mgr.get_migration_history = AsyncMock(return_value=migrations)
        mock_manager.return_value = mock_mgr

        result = runner.invoke(app, ["history", "--limit", "5"])

        assert result.exit_code == 0
        assert "Showing 5 of 20 total migrations" in result.output


def test_database_backup(runner):
    """Test database backup command."""
    with patch("gibson.cli.commands.database.MigrationSafety") as mock_safety:
        mock_safety_inst = Mock()
        mock_backup = Mock(
            backup_id="backup_20240101_120000",
            backup_path=Path("/backups/backup_20240101_120000.db"),
            size_bytes=1024 * 1024 * 5,  # 5MB
        )
        mock_safety_inst.create_backup = Mock(return_value=mock_backup)
        mock_safety.return_value = mock_safety_inst

        result = runner.invoke(app, ["backup", "Test backup"])

        assert result.exit_code == 0
        assert "Backup created successfully" in result.output
        assert "backup_20240101_120000" in result.output
        assert "5.00 MB" in result.output


def test_database_list_backups(runner):
    """Test listing database backups."""
    with patch("gibson.cli.commands.database.MigrationSafety") as mock_safety:
        mock_safety_inst = Mock()

        from datetime import datetime

        backups = [
            Mock(
                backup_id="backup_20240101_120000",
                created_at=datetime(2024, 1, 1, 12, 0, 0),
                size_bytes=1024 * 1024 * 10,
                migration_revision="abc123def",
            ),
            Mock(
                backup_id="backup_20240102_130000",
                created_at=datetime(2024, 1, 2, 13, 0, 0),
                size_bytes=1024 * 1024 * 12,
                migration_revision=None,
            ),
        ]
        mock_safety_inst.list_backups = Mock(return_value=backups)
        mock_safety.return_value = mock_safety_inst

        result = runner.invoke(app, ["list-backups"])

        assert result.exit_code == 0
        assert "Database Backups" in result.output
        assert "backup_20240101_120000" in result.output
        assert "10.00 MB" in result.output
        assert "abc123de" in result.output  # Truncated revision


def test_database_restore(runner):
    """Test database restore command."""
    with patch("gibson.cli.commands.database.MigrationSafety") as mock_safety:
        mock_safety_inst = Mock()
        mock_safety_inst.restore_backup = Mock()
        mock_safety.return_value = mock_safety_inst

        result = runner.invoke(app, ["restore", "backup_20240101_120000", "--force"])

        assert result.exit_code == 0
        assert "Database restored successfully" in result.output
        assert "backup_20240101_120000" in result.output


def test_database_check(runner):
    """Test database safety checks command."""
    with patch("gibson.cli.commands.database.MigrationSafety") as mock_safety:
        mock_safety_inst = Mock()

        checks = [
            Mock(
                check_name="database_exists", passed=True, message="Database found", severity="info"
            ),
            Mock(
                check_name="disk_space",
                passed=True,
                message="Sufficient disk space: 100.0 MB free",
                severity="info",
            ),
            Mock(
                check_name="alembic_installed",
                passed=False,
                message="Alembic not installed",
                severity="error",
            ),
        ]
        mock_safety_inst.run_safety_checks = Mock(return_value=(False, checks))
        mock_safety.return_value = mock_safety_inst

        result = runner.invoke(app, ["check"])

        assert result.exit_code == 1
        assert "Database Safety Checks" in result.output
        assert "database_exists" in result.output
        assert "Some safety checks failed" in result.output


def test_database_check_all_pass(runner):
    """Test safety checks when all pass."""
    with patch("gibson.cli.commands.database.MigrationSafety") as mock_safety:
        mock_safety_inst = Mock()

        checks = [
            Mock(
                check_name="database_exists", passed=True, message="Database found", severity="info"
            ),
            Mock(check_name="all_good", passed=True, message="Everything is fine", severity="info"),
        ]
        mock_safety_inst.run_safety_checks = Mock(return_value=(True, checks))
        mock_safety.return_value = mock_safety_inst

        result = runner.invoke(app, ["check"])

        assert result.exit_code == 0
        assert "All safety checks passed" in result.output
