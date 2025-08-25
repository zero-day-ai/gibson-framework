"""Unit tests for GitSync class."""

import asyncio
import tempfile
from pathlib import Path
from unittest.mock import Mock, AsyncMock, patch, MagicMock

import pytest
from git import Repo, GitCommandError

from gibson.core.payloads.git_sync import GitSync
from gibson.core.payloads.git_models import GitURL, GitPlatform
from gibson.core.payloads.models.git_sync import (
    AuthMethod,
    CloneResult,
    UpdateResult,
    RepositoryInfo,
    GitSyncConfig,
    AuthenticationError,
    GitOperationError,
)


@pytest.fixture
def git_sync():
    """Create GitSync instance with temporary workspace."""
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        yield GitSync(workspace, shallow=True)


@pytest.fixture
def sample_git_url():
    """Create sample GitURL for testing."""
    return GitURL(
        platform=GitPlatform.GITHUB,
        protocol="https",
        host="github.com",
        owner="test-owner",
        repo="test-repo",
        branch="main",
    )


class TestGitSyncInit:
    """Test GitSync initialization."""

    def test_init_creates_workspace(self):
        """Test that GitSync creates workspace directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir) / "test_workspace"
            assert not workspace.exists()

            git_sync = GitSync(workspace)
            assert workspace.exists()
            assert workspace.is_dir()

    def test_init_with_config(self):
        """Test GitSync initialization with custom config."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = GitSyncConfig(
                default_shallow=False, max_clone_depth=50, enable_sparse_checkout=False
            )

            git_sync = GitSync(Path(tmpdir), shallow=False, config=config)
            assert git_sync.shallow == False
            assert git_sync.config.default_shallow == False
            assert git_sync.config.max_clone_depth == 50


class TestCloneRepository:
    """Test clone_repository method."""

    @pytest.mark.asyncio
    async def test_clone_public_repository_success(self, git_sync, sample_git_url):
        """Test successful clone of public repository."""
        mock_repo = Mock(spec=Repo)
        mock_repo.head.commit.hexsha = "abc123def456"
        mock_repo.active_branch.name = "main"

        with patch.object(git_sync, "_try_operation_with_auth_escalation") as mock_try:
            mock_try.return_value = (mock_repo, AuthMethod.PUBLIC)

            with patch.object(git_sync, "_calculate_directory_size", return_value=10.5):
                result = await git_sync.clone_repository(sample_git_url)

        assert result.success == True
        assert result.auth_method_used == AuthMethod.PUBLIC
        assert result.commit_hash == "abc123def456"
        assert result.branch == "main"
        assert result.clone_size_mb == 10.5
        assert result.is_shallow == True

    @pytest.mark.asyncio
    async def test_clone_with_ssh_authentication(self, git_sync, sample_git_url):
        """Test clone with SSH key authentication."""
        mock_repo = Mock(spec=Repo)
        mock_repo.head.commit.hexsha = "def789ghi012"
        mock_repo.active_branch.name = "develop"

        with patch.object(git_sync, "_try_operation_with_auth_escalation") as mock_try:
            mock_try.return_value = (mock_repo, AuthMethod.SSH_KEY)

            with patch.object(git_sync, "_calculate_directory_size", return_value=25.0):
                result = await git_sync.clone_repository(sample_git_url, branch="develop")

        assert result.success == True
        assert result.auth_method_used == AuthMethod.SSH_KEY
        assert result.branch == "develop"

    @pytest.mark.asyncio
    async def test_clone_with_token_authentication(self, git_sync, sample_git_url):
        """Test clone with token authentication."""
        mock_repo = Mock(spec=Repo)
        mock_repo.head.commit.hexsha = "xyz789abc123"
        mock_repo.active_branch.name = "main"

        with patch.object(git_sync, "_try_operation_with_auth_escalation") as mock_try:
            mock_try.return_value = (mock_repo, AuthMethod.TOKEN)

            with patch.object(git_sync, "_calculate_directory_size", return_value=15.0):
                result = await git_sync.clone_repository(sample_git_url)

        assert result.success == True
        assert result.auth_method_used == AuthMethod.TOKEN

    @pytest.mark.asyncio
    async def test_clone_failure(self, git_sync, sample_git_url):
        """Test clone failure handling."""
        with patch.object(git_sync, "_try_operation_with_auth_escalation") as mock_try:
            mock_try.side_effect = GitOperationError("Clone failed")

            result = await git_sync.clone_repository(sample_git_url)

        assert result.success == False
        assert result.auth_method_used == AuthMethod.FAILED
        assert "Clone failed" in result.error_message


class TestUpdateRepository:
    """Test update_repository method."""

    @pytest.mark.asyncio
    async def test_update_repository_success(self, git_sync):
        """Test successful repository update."""
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_path = Path(tmpdir) / "test_repo"
            repo_path.mkdir()

            mock_repo = Mock(spec=Repo)
            mock_repo.head.commit.hexsha = "old123"
            mock_repo.active_branch.name = "main"
            mock_repo.remotes.origin.url = "https://github.com/test/repo.git"

            updated_repo = Mock(spec=Repo)
            updated_repo.head.commit.hexsha = "new456"
            updated_repo.git.diff.return_value = "file1.txt\nfile2.txt"

            with patch("gibson.core.payloads.git_sync.Repo", return_value=mock_repo):
                with patch.object(git_sync, "_try_operation_with_auth_escalation") as mock_try:
                    mock_try.return_value = (updated_repo, AuthMethod.PUBLIC)

                    result = await git_sync.update_repository(repo_path)

            assert result.success == True
            assert result.updated == True
            assert result.old_commit == "old123"
            assert result.new_commit == "new456"
            assert result.files_changed == 2

    @pytest.mark.asyncio
    async def test_update_repository_no_changes(self, git_sync):
        """Test update when repository is already up to date."""
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_path = Path(tmpdir) / "test_repo"
            repo_path.mkdir()

            mock_repo = Mock(spec=Repo)
            mock_repo.head.commit.hexsha = "same123"
            mock_repo.active_branch.name = "main"
            mock_repo.remotes.origin.url = "https://github.com/test/repo.git"

            with patch("gibson.core.payloads.git_sync.Repo", return_value=mock_repo):
                with patch.object(git_sync, "_try_operation_with_auth_escalation") as mock_try:
                    mock_try.return_value = (mock_repo, AuthMethod.PUBLIC)

                    result = await git_sync.update_repository(repo_path)

            assert result.success == True
            assert result.updated == False
            assert result.old_commit == "same123"
            assert result.new_commit == "same123"


class TestAuthenticationEscalation:
    """Test authentication escalation logic."""

    @pytest.mark.asyncio
    async def test_auth_escalation_public_success(self, git_sync, sample_git_url):
        """Test auth escalation stops at public access if successful."""
        mock_operation = AsyncMock(return_value="success")

        with patch.object(git_sync, "_has_ssh_keys", return_value=True):
            result, auth_method = await git_sync._try_operation_with_auth_escalation(
                mock_operation, sample_git_url
            )

        assert result == "success"
        assert auth_method == AuthMethod.PUBLIC
        mock_operation.assert_called_once()

    @pytest.mark.asyncio
    async def test_auth_escalation_ssh_fallback(self, git_sync, sample_git_url):
        """Test auth escalation falls back to SSH after public fails."""
        mock_operation = AsyncMock()
        mock_operation.side_effect = [
            GitCommandError("git", "authentication failed"),  # Public fails
            "success",  # SSH succeeds
        ]

        with patch.object(git_sync, "_has_ssh_keys", return_value=True):
            with patch.object(git_sync, "_is_auth_error", return_value=True):
                result, auth_method = await git_sync._try_operation_with_auth_escalation(
                    mock_operation, sample_git_url
                )

        assert result == "success"
        assert auth_method == AuthMethod.SSH_KEY
        assert mock_operation.call_count == 2

    @pytest.mark.asyncio
    async def test_auth_escalation_token_fallback(self, git_sync, sample_git_url):
        """Test auth escalation falls back to token after SSH fails."""
        mock_operation = AsyncMock()
        mock_operation.side_effect = [
            GitCommandError("git", "authentication failed"),  # Public fails
            GitCommandError("git", "authentication failed"),  # SSH fails
            "success",  # Token succeeds
        ]

        with patch.object(git_sync, "_has_ssh_keys", return_value=True):
            with patch.object(git_sync, "_is_auth_error", return_value=True):
                with patch.object(
                    git_sync.token_prompter, "prompt_for_token", return_value="test-token"
                ):
                    result, auth_method = await git_sync._try_operation_with_auth_escalation(
                        mock_operation, sample_git_url
                    )

        assert result == "success"
        assert auth_method == AuthMethod.TOKEN
        assert mock_operation.call_count == 3

    @pytest.mark.asyncio
    async def test_auth_escalation_all_fail(self, git_sync, sample_git_url):
        """Test auth escalation when all methods fail."""
        mock_operation = AsyncMock()
        mock_operation.side_effect = GitCommandError("git", "authentication failed")

        with patch.object(git_sync, "_has_ssh_keys", return_value=True):
            with patch.object(git_sync, "_is_auth_error", return_value=True):
                with patch.object(
                    git_sync.token_prompter, "prompt_for_token", return_value="test-token"
                ):
                    with pytest.raises(AuthenticationError) as exc_info:
                        await git_sync._try_operation_with_auth_escalation(
                            mock_operation, sample_git_url
                        )

        assert "All authentication methods failed" in str(exc_info.value)


class TestHelperMethods:
    """Test helper methods."""

    def test_has_ssh_keys_found(self, git_sync):
        """Test SSH key detection when keys exist."""
        with patch("pathlib.Path.exists") as mock_exists:
            with patch("pathlib.Path.stat") as mock_stat:
                mock_exists.return_value = True
                mock_stat.return_value = Mock(st_size=1000)

                assert git_sync._has_ssh_keys() == True

    def test_has_ssh_keys_not_found(self, git_sync):
        """Test SSH key detection when no keys exist."""
        with patch("pathlib.Path.exists", return_value=False):
            assert git_sync._has_ssh_keys() == False

    def test_is_auth_error_positive(self, git_sync):
        """Test authentication error detection."""
        errors = [
            Exception("authentication failed"),
            Exception("Permission denied"),
            Exception("Invalid credentials"),
            Exception("401 Unauthorized"),
        ]

        for error in errors:
            assert git_sync._is_auth_error(error) == True

    def test_is_auth_error_negative(self, git_sync):
        """Test non-authentication error detection."""
        errors = [
            Exception("Network error"),
            Exception("File not found"),
            Exception("Timeout occurred"),
        ]

        for error in errors:
            assert git_sync._is_auth_error(error) == False

    def test_calculate_directory_size(self, git_sync):
        """Test directory size calculation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_dir = Path(tmpdir)

            # Create some test files
            (test_dir / "file1.txt").write_text("a" * 1024)  # 1KB
            (test_dir / "file2.txt").write_text("b" * 2048)  # 2KB

            size = git_sync._calculate_directory_size(test_dir)

            # Size should be approximately 3KB (0.003 MB)
            assert 0.002 < size < 0.004

    def test_count_files(self, git_sync):
        """Test file counting."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_dir = Path(tmpdir)

            # Create test files
            (test_dir / "file1.txt").touch()
            (test_dir / "file2.txt").touch()
            subdir = test_dir / "subdir"
            subdir.mkdir()
            (subdir / "file3.txt").touch()

            # Create .git directory (should be excluded)
            git_dir = test_dir / ".git"
            git_dir.mkdir()
            (git_dir / "config").touch()

            count = git_sync._count_files(test_dir)
            assert count == 3  # Should not count .git files


class TestRepositoryInfo:
    """Test get_repository_info method."""

    @pytest.mark.asyncio
    async def test_get_repository_info(self, git_sync):
        """Test getting repository information."""
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_path = Path(tmpdir) / "test_repo"
            repo_path.mkdir()

            mock_repo = Mock(spec=Repo)
            mock_repo.head.commit.hexsha = "abc123"
            mock_repo.active_branch.name = "main"
            mock_repo.remotes.origin.url = "https://github.com/test/repo.git"
            mock_repo.git.rev_parse.return_value = "false"  # Not shallow
            mock_repo.tags = [Mock(name="v1.0"), Mock(name="v2.0")]
            mock_repo.head.commit.committed_datetime = "2024-01-01"

            with patch("gibson.core.payloads.git_sync.Repo", return_value=mock_repo):
                with patch.object(git_sync, "_calculate_directory_size", return_value=50.0):
                    with patch.object(git_sync, "_count_files", return_value=100):
                        info = await git_sync.get_repository_info(repo_path)

            assert info.commit_hash == "abc123"
            assert info.branch == "main"
            assert info.remote_url == "https://github.com/test/repo.git"
            assert info.is_shallow == False
            assert len(info.tags) == 2
            assert info.size_mb == 50.0
            assert info.file_count == 100
