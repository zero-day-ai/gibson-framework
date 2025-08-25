"""Unit tests for migration safety utilities."""

import shutil
import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from gibson.core.migrations.safety import (
    BackupInfo,
    MigrationSafety,
    MigrationSafetyCheck,
)


@pytest.fixture
def temp_db():
    """Create a temporary database file for testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        f.write(b"fake database content")
        db_path = Path(f.name)
    yield db_path
    db_path.unlink(missing_ok=True)


@pytest.fixture
def temp_backup_dir():
    """Create a temporary backup directory."""
    backup_dir = Path(tempfile.mkdtemp())
    yield backup_dir
    shutil.rmtree(backup_dir, ignore_errors=True)


@pytest.fixture
def migration_safety(temp_db, temp_backup_dir):
    """Create a MigrationSafety instance for testing."""
    safety = MigrationSafety(db_path=temp_db)
    safety.backup_dir = temp_backup_dir
    return safety


def test_migration_safety_init():
    """Test MigrationSafety initialization."""
    safety = MigrationSafety()
    assert safety.db_path == Path("./gibson.db")
    assert safety.backup_dir.name == "backups"
    assert safety.max_backups == 10
    
    # Test with custom path
    custom_path = Path("/tmp/test.db")
    safety = MigrationSafety(db_path=custom_path)
    assert safety.db_path == custom_path


def test_create_backup(migration_safety, temp_db):
    """Test database backup creation."""
    backup = migration_safety.create_backup(
        migration_revision="abc123def456",
        description="Test backup"
    )
    
    assert isinstance(backup, BackupInfo)
    assert backup.backup_path.exists()
    assert backup.original_path == temp_db
    assert backup.migration_revision == "abc123def456"
    assert backup.description == "Test backup"
    assert backup.size_bytes > 0
    assert "abc123" in backup.backup_id
    
    # Verify content was copied
    with open(backup.backup_path, "rb") as f:
        content = f.read()
    assert content == b"fake database content"


def test_create_backup_no_database(migration_safety):
    """Test backup creation when database doesn't exist."""
    migration_safety.db_path = Path("/nonexistent/database.db")
    
    with pytest.raises(FileNotFoundError, match="Database not found"):
        migration_safety.create_backup()


def test_restore_backup(migration_safety, temp_db):
    """Test database restoration from backup."""
    # Create a backup first
    backup = migration_safety.create_backup(description="Pre-restore backup")
    backup_id = backup.backup_id
    
    # Modify the original database
    with open(temp_db, "wb") as f:
        f.write(b"modified content")
    
    # Restore from backup
    migration_safety.restore_backup(backup_id)
    
    # Verify restoration
    with open(temp_db, "rb") as f:
        content = f.read()
    assert content == b"fake database content"
    
    # Verify safety copy was created
    safety_copy = temp_db.with_suffix(".db.safety")
    assert safety_copy.exists()
    with open(safety_copy, "rb") as f:
        safety_content = f.read()
    assert safety_content == b"modified content"
    
    # Cleanup
    safety_copy.unlink()


def test_restore_backup_not_found(migration_safety):
    """Test restore with non-existent backup."""
    with pytest.raises(FileNotFoundError, match="Backup not found"):
        migration_safety.restore_backup("nonexistent_backup")


def test_list_backups(migration_safety):
    """Test listing available backups."""
    # Create multiple backups
    backup1 = migration_safety.create_backup(description="Backup 1")
    backup2 = migration_safety.create_backup(
        migration_revision="xyz789",
        description="Backup 2"
    )
    
    backups = migration_safety.list_backups()
    
    assert len(backups) == 2
    assert all(isinstance(b, BackupInfo) for b in backups)
    # Should be sorted in reverse order (newest first)
    assert backups[0].backup_id == backup2.backup_id
    assert backups[1].backup_id == backup1.backup_id


def test_cleanup_old_backups(migration_safety):
    """Test automatic cleanup of old backups."""
    migration_safety.max_backups = 3
    
    # Create more backups than the limit
    backups_created = []
    for i in range(5):
        backup = migration_safety.create_backup(description=f"Backup {i}")
        backups_created.append(backup)
    
    # Check that only max_backups remain
    remaining_backups = migration_safety.list_backups()
    assert len(remaining_backups) == 3
    
    # Verify oldest backups were deleted
    remaining_ids = {b.backup_id for b in remaining_backups}
    assert backups_created[-1].backup_id in remaining_ids
    assert backups_created[-2].backup_id in remaining_ids
    assert backups_created[-3].backup_id in remaining_ids
    assert backups_created[0].backup_id not in remaining_ids
    assert backups_created[1].backup_id not in remaining_ids


def test_run_safety_checks_all_pass(migration_safety, temp_db):
    """Test safety checks when all pass."""
    with patch("shutil.disk_usage") as mock_disk:
        mock_disk.return_value = Mock(free=1024 * 1024 * 1024)  # 1GB free
        
        with patch("subprocess.run") as mock_run:
            # Alembic version check
            mock_run.return_value = Mock(
                returncode=0,
                stdout="alembic 1.13.0"
            )
            
            passed, checks = migration_safety.run_safety_checks()
            
            assert passed is True
            assert len(checks) >= 4
            
            # Check specific checks
            db_exists = next(c for c in checks if c.check_name == "database_exists")
            assert db_exists.passed is True
            
            db_readable = next(c for c in checks if c.check_name == "database_readable")
            assert db_readable.passed is True
            
            backup_writable = next(c for c in checks if c.check_name == "backup_directory_writable")
            assert backup_writable.passed is True
            
            disk_space = next(c for c in checks if c.check_name == "disk_space")
            assert disk_space.passed is True


def test_run_safety_checks_database_missing(migration_safety):
    """Test safety checks when database is missing."""
    migration_safety.db_path = Path("/nonexistent/database.db")
    
    passed, checks = migration_safety.run_safety_checks()
    
    # Should still pass overall (database missing is a warning)
    db_exists = next(c for c in checks if c.check_name == "database_exists")
    assert db_exists.passed is False
    assert db_exists.severity == "warning"


def test_run_safety_checks_insufficient_disk_space(migration_safety, temp_db):
    """Test safety checks with insufficient disk space."""
    db_size = temp_db.stat().st_size
    
    with patch("shutil.disk_usage") as mock_disk:
        mock_disk.return_value = Mock(free=db_size)  # Less than 2x database size
        
        passed, checks = migration_safety.run_safety_checks()
        
        disk_space = next(c for c in checks if c.check_name == "disk_space")
        assert disk_space.passed is False
        assert disk_space.severity == "warning"


def test_run_safety_checks_alembic_not_installed(migration_safety, temp_db):
    """Test safety checks when Alembic is not installed."""
    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = FileNotFoundError()
        
        passed, checks = migration_safety.run_safety_checks()
        
        alembic_check = next(
            (c for c in checks if c.check_name == "alembic_installed"),
            None
        )
        assert alembic_check is not None
        assert alembic_check.passed is False
        assert alembic_check.severity == "critical"


def test_run_safety_checks_git_status(migration_safety, temp_db):
    """Test safety checks with Git repository status."""
    with patch("subprocess.run") as mock_run:
        # Simulate uncommitted changes
        mock_run.return_value = Mock(
            returncode=0,
            stdout="M  file1.py\nA  file2.py"
        )
        
        passed, checks = migration_safety.run_safety_checks()
        
        git_check = next(
            (c for c in checks if c.check_name == "git_status"),
            None
        )
        if git_check:
            assert git_check.passed is True
            assert git_check.severity == "warning"
            assert "Uncommitted changes" in git_check.message


def test_validate_migration_script(migration_safety, tmp_path):
    """Test migration script validation."""
    # Create a valid migration script
    script_path = tmp_path / "migration.py"
    script_path.write_text("""
def upgrade():
    pass

def downgrade():
    pass
""")
    
    is_valid, issues = migration_safety.validate_migration_script(script_path)
    assert is_valid is True
    assert len(issues) == 0


def test_validate_migration_script_missing_functions(migration_safety, tmp_path):
    """Test validation with missing upgrade/downgrade functions."""
    script_path = tmp_path / "migration.py"
    script_path.write_text("""
# Missing upgrade and downgrade functions
pass
""")
    
    is_valid, issues = migration_safety.validate_migration_script(script_path)
    assert is_valid is False
    assert "Missing upgrade() function" in issues
    assert "Missing downgrade() function" in issues


def test_validate_migration_script_dangerous_operations(migration_safety, tmp_path):
    """Test validation detecting dangerous operations."""
    script_path = tmp_path / "migration.py"
    script_path.write_text("""
def upgrade():
    op.execute("DROP TABLE users")
    op.execute("TRUNCATE logs")
    op.execute("DELETE FROM sessions")

def downgrade():
    pass
""")
    
    is_valid, issues = migration_safety.validate_migration_script(script_path)
    assert is_valid is False
    assert any("DROP TABLE without IF EXISTS" in issue for issue in issues)
    assert any("TRUNCATE statement detected" in issue for issue in issues)
    assert any("DELETE without WHERE" in issue for issue in issues)


def test_validate_migration_script_syntax_error(migration_safety, tmp_path):
    """Test validation with syntax errors."""
    script_path = tmp_path / "migration.py"
    script_path.write_text("""
def upgrade():
    this is not valid python
    
def downgrade():
    pass
""")
    
    is_valid, issues = migration_safety.validate_migration_script(script_path)
    assert is_valid is False
    assert any("Syntax error" in issue for issue in issues)


def test_validate_migration_script_not_found(migration_safety):
    """Test validation with non-existent script."""
    is_valid, issues = migration_safety.validate_migration_script(
        Path("/nonexistent/script.py")
    )
    assert is_valid is False
    assert "Migration script not found" in issues[0]


def test_create_rollback_plan(migration_safety):
    """Test creating a rollback plan."""
    plan = migration_safety.create_rollback_plan(
        from_revision="abc123",
        to_revision="def456"
    )
    
    assert isinstance(plan, dict)
    assert plan["from_revision"] == "abc123"
    assert plan["to_revision"] == "def456"
    assert len(plan["steps"]) > 0
    assert len(plan["warnings"]) > 0
    assert plan["backup_required"] is True
    
    # Check for specific steps
    assert any("backup" in step.lower() for step in plan["steps"])
    assert any("downgrade" in step.lower() for step in plan["steps"])
    assert any("verify" in step.lower() for step in plan["steps"])


def test_create_rollback_plan_to_base(migration_safety):
    """Test rollback plan when rolling back to base."""
    plan = migration_safety.create_rollback_plan(
        from_revision="xyz789",
        to_revision="base"
    )
    
    # Should have warning about rolling back to base
    assert any("base" in warning.lower() for warning in plan["warnings"])
    assert any("all migrations" in warning.lower() for warning in plan["warnings"])