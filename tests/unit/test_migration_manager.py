"""Unit tests for MigrationManager."""

import asyncio
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest
from sqlalchemy.ext.asyncio import create_async_engine

from gibson.core.migrations import MigrationManager, MigrationInfo, MigrationStatus


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    yield db_path
    Path(db_path).unlink(missing_ok=True)


@pytest.fixture
def migration_manager():
    """Create a MigrationManager instance for testing."""
    manager = MigrationManager()
    return manager


@pytest.mark.asyncio
async def test_migration_manager_init(migration_manager):
    """Test MigrationManager initialization."""
    assert migration_manager.db_manager is None
    assert migration_manager.project_root.exists()
    assert migration_manager.alembic_ini.name == "alembic.ini"
    assert migration_manager.alembic_dir.name == "alembic"


@pytest.mark.asyncio
async def test_get_config(migration_manager):
    """Test Alembic config retrieval."""
    config = migration_manager.config
    assert config is not None
    assert hasattr(config, "get_main_option")
    # Config should be cached
    assert migration_manager.config is config


@pytest.mark.asyncio
async def test_get_engine(migration_manager, temp_db, monkeypatch):
    """Test async engine creation."""
    monkeypatch.setenv("GIBSON_DATABASE_URL", f"sqlite+aiosqlite:///{temp_db}")
    engine = await migration_manager.get_engine()
    assert engine is not None
    # Engine should be cached
    assert await migration_manager.get_engine() is engine
    await engine.dispose()


@pytest.mark.asyncio
async def test_init_creates_alembic_dir(migration_manager, tmp_path, monkeypatch):
    """Test that init creates alembic directory if missing."""
    # Create a temporary alembic directory path that doesn't exist
    fake_alembic = tmp_path / "alembic"
    migration_manager.alembic_dir = fake_alembic

    with patch("alembic.command.init") as mock_init:
        await migration_manager.init()
        # Should not call init if directory exists
        if fake_alembic.exists():
            mock_init.assert_not_called()


@pytest.mark.asyncio
async def test_create_migration(migration_manager):
    """Test migration creation."""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = Mock(
            returncode=0, stdout="Generating /path/to/abc123_test_migration.py ... done", stderr=""
        )

        revision = await migration_manager.create_migration(
            message="Test migration", autogenerate=True, sql=False
        )

        assert revision == "abc123"
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert "alembic" in args
        assert "revision" in args
        assert "-m" in args
        assert "Test migration" in args
        assert "--autogenerate" in args


@pytest.mark.asyncio
async def test_create_migration_with_sql(migration_manager):
    """Test migration creation with SQL output."""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = Mock(returncode=0, stdout="Generating SQL script...", stderr="")

        await migration_manager.create_migration(
            message="SQL migration", autogenerate=False, sql=True
        )

        args = mock_run.call_args[0][0]
        assert "--sql" in args
        assert "--autogenerate" not in args


@pytest.mark.asyncio
async def test_create_migration_failure(migration_manager):
    """Test migration creation failure."""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = Mock(returncode=1, stdout="", stderr="Error creating migration")

        with pytest.raises(RuntimeError, match="Failed to create migration"):
            await migration_manager.create_migration("Failed migration")


@pytest.mark.asyncio
async def test_upgrade(migration_manager):
    """Test database upgrade."""
    with patch.object(migration_manager, "get_current_revision") as mock_current:
        mock_current.return_value = "abc123"

        with patch.object(migration_manager, "_log_migration_audit") as mock_audit:
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(returncode=0, stdout="Upgrade complete", stderr="")

                await migration_manager.upgrade()

                mock_run.assert_called_once()
                args = mock_run.call_args[0][0]
                assert "alembic" in args
                assert "upgrade" in args
                assert "head" in args

                # Check audit logging
                mock_audit.assert_called_once()
                audit_kwargs = mock_audit.call_args[1]
                assert audit_kwargs["operation"] == "upgrade"
                assert audit_kwargs["from_revision"] == "abc123"
                assert audit_kwargs["to_revision"] == "head"
                assert audit_kwargs["status"] == "success"


@pytest.mark.asyncio
async def test_upgrade_failure(migration_manager):
    """Test database upgrade failure."""
    with patch.object(migration_manager, "get_current_revision") as mock_current:
        mock_current.return_value = "abc123"

        with patch.object(migration_manager, "_log_migration_audit"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(returncode=1, stdout="", stderr="Migration failed")

                with pytest.raises(RuntimeError, match="Failed to upgrade database"):
                    await migration_manager.upgrade()


@pytest.mark.asyncio
async def test_downgrade(migration_manager):
    """Test database downgrade."""
    with patch.object(migration_manager, "get_current_revision") as mock_current:
        mock_current.return_value = "def456"

        with patch.object(migration_manager, "_log_migration_audit") as mock_audit:
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(returncode=0, stdout="Downgrade complete", stderr="")

                await migration_manager.downgrade("-1")

                mock_run.assert_called_once()
                args = mock_run.call_args[0][0]
                assert "alembic" in args
                assert "downgrade" in args
                assert "-1" in args

                # Check audit logging
                mock_audit.assert_called_once()
                audit_kwargs = mock_audit.call_args[1]
                assert audit_kwargs["operation"] == "downgrade"
                assert audit_kwargs["from_revision"] == "def456"


@pytest.mark.asyncio
async def test_get_current_revision(migration_manager, temp_db, monkeypatch):
    """Test getting current database revision."""
    monkeypatch.setenv("GIBSON_DATABASE_URL", f"sqlite+aiosqlite:///{temp_db}")

    with patch("alembic.runtime.migration.MigrationContext.configure") as mock_context:
        mock_ctx = Mock()
        mock_ctx.get_current_revision.return_value = "abc123"
        mock_context.return_value = mock_ctx

        # Need to mock the engine connection
        engine = await migration_manager.get_engine()
        with patch.object(engine, "connect") as mock_connect:
            mock_conn = AsyncMock()
            mock_conn.run_sync = AsyncMock(return_value="abc123")
            mock_connect.return_value.__aenter__.return_value = mock_conn

            revision = await migration_manager.get_current_revision()
            assert revision == "abc123"

        await engine.dispose()


@pytest.mark.asyncio
async def test_get_head_revision(migration_manager):
    """Test getting head revision from scripts."""
    with patch("alembic.script.ScriptDirectory.from_config") as mock_script:
        mock_dir = Mock()
        mock_dir.get_current_head.return_value = "xyz789"
        mock_script.return_value = mock_dir

        head = await migration_manager.get_head_revision()
        assert head == "xyz789"


@pytest.mark.asyncio
async def test_get_status(migration_manager):
    """Test getting comprehensive migration status."""
    with patch.object(migration_manager, "get_current_revision") as mock_current:
        mock_current.return_value = "abc123"

        with patch.object(migration_manager, "get_head_revision") as mock_head:
            mock_head.return_value = "xyz789"

            with patch.object(migration_manager, "get_pending_migrations") as mock_pending:
                pending_migration = MigrationInfo(
                    revision="def456", description="Test migration", is_head=False, is_current=False
                )
                mock_pending.return_value = [pending_migration]

                with patch.object(migration_manager, "get_migration_history") as mock_history:
                    history_migration = MigrationInfo(
                        revision="abc123",
                        description="Previous migration",
                        is_head=False,
                        is_current=True,
                    )
                    mock_history.return_value = [history_migration]

                    status = await migration_manager.get_status()

                    assert isinstance(status, MigrationStatus)
                    assert status.current_revision == "abc123"
                    assert status.head_revision == "xyz789"
                    assert len(status.pending_migrations) == 1
                    assert len(status.applied_migrations) == 1
                    assert status.needs_migration is True
                    assert status.is_up_to_date is False


@pytest.mark.asyncio
async def test_check_migration_needed(migration_manager):
    """Test checking if migration is needed."""
    with patch.object(migration_manager, "get_status") as mock_status:
        # Test when migration is needed
        mock_status.return_value = MigrationStatus(
            current_revision="abc123", head_revision="xyz789", needs_migration=True
        )
        assert await migration_manager.check_migration_needed() is True

        # Test when migration is not needed
        mock_status.return_value = MigrationStatus(
            current_revision="xyz789", head_revision="xyz789", needs_migration=False
        )
        assert await migration_manager.check_migration_needed() is False


@pytest.mark.asyncio
async def test_auto_upgrade(migration_manager):
    """Test automatic upgrade to latest migration."""
    with patch.object(migration_manager, "check_migration_needed") as mock_check:
        with patch.object(migration_manager, "upgrade") as mock_upgrade:
            # Test when migration is needed
            mock_check.return_value = True
            await migration_manager.auto_upgrade()
            mock_upgrade.assert_called_once()

            # Reset mock
            mock_upgrade.reset_mock()

            # Test when migration is not needed
            mock_check.return_value = False
            await migration_manager.auto_upgrade()
            mock_upgrade.assert_not_called()


@pytest.mark.asyncio
async def test_stamp(migration_manager):
    """Test stamping database with revision."""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = Mock(returncode=0, stdout="Stamped to head", stderr="")

        await migration_manager.stamp("head")

        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert "alembic" in args
        assert "stamp" in args
        assert "head" in args


@pytest.mark.asyncio
async def test_stamp_failure(migration_manager):
    """Test stamp failure."""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = Mock(returncode=1, stdout="", stderr="Stamp failed")

        with pytest.raises(RuntimeError, match="Failed to stamp database"):
            await migration_manager.stamp("bad_revision")


@pytest.mark.asyncio
async def test_verify_migrations(migration_manager):
    """Test migration verification."""
    # Test when alembic directory doesn't exist
    with patch.object(migration_manager.alembic_dir, "exists") as mock_exists:
        mock_exists.return_value = False
        success, issues = await migration_manager.verify_migrations()
        assert success is False
        assert "Alembic directory not found" in issues[0]

    # Test successful verification
    with patch.object(migration_manager.alembic_dir, "exists") as mock_exists:
        mock_exists.return_value = True

        with patch.object(migration_manager, "get_current_revision") as mock_current:
            mock_current.return_value = "abc123"

            with patch.object(migration_manager, "get_head_revision") as mock_head:
                mock_head.return_value = "xyz789"

                with patch.object(migration_manager, "get_pending_migrations") as mock_pending:
                    mock_pending.return_value = []

                    success, issues = await migration_manager.verify_migrations()
                    assert success is True
                    assert len(issues) == 0


@pytest.mark.asyncio
async def test_log_migration_audit(migration_manager, temp_db, monkeypatch):
    """Test migration audit logging."""
    monkeypatch.setenv("GIBSON_DATABASE_URL", f"sqlite+aiosqlite:///{temp_db}")

    with patch.object(migration_manager, "get_engine") as mock_engine:
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock()
        mock_conn.commit = AsyncMock()

        mock_engine_obj = AsyncMock()
        mock_engine_obj.connect.return_value.__aenter__.return_value = mock_conn
        mock_engine.return_value = mock_engine_obj

        with patch("getpass.getuser") as mock_user:
            mock_user.return_value = "testuser"

            await migration_manager._log_migration_audit(
                operation="upgrade",
                from_revision="abc123",
                to_revision="def456",
                duration_ms=1500,
                status="success",
            )

            # Verify audit was logged
            mock_conn.execute.assert_called_once()
            call_args = mock_conn.execute.call_args[0]
            assert "INSERT INTO migration_audit" in str(call_args[0])


@pytest.mark.asyncio
async def test_log_migration_audit_failure(migration_manager, temp_db, monkeypatch):
    """Test that audit logging failure doesn't break migration."""
    monkeypatch.setenv("GIBSON_DATABASE_URL", f"sqlite+aiosqlite:///{temp_db}")

    with patch.object(migration_manager, "get_engine") as mock_engine:
        # Make engine.connect() raise an exception
        mock_engine.side_effect = Exception("Database error")

        # Should not raise, just log warning
        await migration_manager._log_migration_audit(
            operation="upgrade", from_revision="abc123", to_revision="def456"
        )
        # No exception should be raised
