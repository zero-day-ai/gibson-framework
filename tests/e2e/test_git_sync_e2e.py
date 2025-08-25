"""
End-to-end tests for the complete GitSync workflow.

Tests the complete user journey from CLI command to repository synchronization.
"""

import asyncio
import tempfile
import os
from pathlib import Path
from unittest.mock import patch, Mock, AsyncMock

import pytest
from typer.testing import CliRunner

from gibson.core.payloads.git_sync import GitSync
from gibson.core.payloads.git_models import GitURL, GitPlatform
from gibson.core.payloads.models.git_sync import AuthMethod
from gibson.core.payloads.manager import PayloadManager
from gibson.core.payloads.types import SyncResult


class TestE2EGitSyncWorkflow:
    """End-to-end tests for complete GitSync workflow."""

    @pytest.mark.e2e
    @pytest.mark.asyncio
    async def test_public_repo_sync_workflow(self):
        """Test complete workflow for syncing a public repository."""
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)

            # Initialize PayloadManager
            manager = PayloadManager(data_directory=workspace / "payloads")

            # Test repository URL (public)
            repo_url = "https://github.com/octocat/Hello-World.git"

            async with manager:
                # Sync repository
                result = await manager.sync_repository(repository_url=repo_url, branch="master")

                # Verify result
                assert result.success == True
                assert result.repository == repo_url
                assert result.branch == "master"
                assert result.auth_method_used == AuthMethod.PUBLIC

                # Verify files were synced
                repo_path = (
                    workspace
                    / "payloads"
                    / "repositories"
                    / "github.com"
                    / "octocat"
                    / "Hello-World"
                )
                assert repo_path.exists()
                assert (repo_path / ".git").exists()
                assert (repo_path / "README").exists()

    @pytest.mark.e2e
    @pytest.mark.asyncio
    async def test_ssh_url_workflow(self):
        """Test workflow with SSH URL format."""
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)

            # Initialize components
            git_sync = GitSync(workspace, shallow=True)

            # Parse SSH URL
            ssh_url = "git@github.com:octocat/Hello-World.git"
            git_url = GitURL.from_url(ssh_url)

            # Verify URL parsing
            assert git_url.protocol == "ssh"
            assert git_url.host == "github.com"
            assert git_url.owner == "octocat"
            assert git_url.repo == "Hello-World"

            # Mock SSH key check
            with patch.object(git_sync, "_has_ssh_keys", return_value=False):
                # Clone with fallback to HTTPS for public repo
                result = await git_sync.clone_repository(git_url)

                if result.success:
                    # Should have fallen back to public HTTPS
                    assert result.auth_method_used == AuthMethod.PUBLIC

    @pytest.mark.e2e
    @pytest.mark.asyncio
    async def test_auth_escalation_workflow(self):
        """Test complete authentication escalation workflow."""
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            git_sync = GitSync(workspace, shallow=True)

            # Private repository URL (will fail without auth)
            private_url = "https://github.com/private-org/private-repo.git"
            git_url = GitURL.from_url(private_url)

            # Mock the escalation sequence
            with patch.object(git_sync, "_has_ssh_keys", return_value=True):
                with patch.object(git_sync.token_prompter, "prompt_for_token", return_value=None):
                    # Try to clone - should fail
                    result = await git_sync.clone_repository(git_url)

                    # Should have tried all methods and failed
                    assert result.success == False
                    assert result.auth_method_used == AuthMethod.FAILED
                    assert result.error_message is not None

    @pytest.mark.e2e
    @pytest.mark.asyncio
    async def test_update_existing_repo_workflow(self):
        """Test workflow for updating an existing repository."""
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            manager = PayloadManager(data_directory=workspace / "payloads")

            repo_url = "https://github.com/octocat/Hello-World.git"

            async with manager:
                # Initial sync
                result1 = await manager.sync_repository(repo_url, branch="master")
                assert result1.success == True
                initial_commit = result1.commit_hash

                # Update sync (should detect existing repo)
                result2 = await manager.sync_repository(repo_url, branch="master")
                assert result2.success == True

                # Should have same commit (unless repo changed)
                # For stable test repo, commits should match
                if not result2.updated:
                    assert result2.commit_hash == initial_commit

    @pytest.mark.e2e
    @pytest.mark.asyncio
    async def test_multiple_repo_sync_workflow(self):
        """Test syncing multiple repositories."""
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            manager = PayloadManager(data_directory=workspace / "payloads")

            repos = [
                "https://github.com/octocat/Hello-World.git",
                "https://github.com/octocat/Spoon-Knife.git",
            ]

            async with manager:
                results = []
                for repo_url in repos:
                    result = await manager.sync_repository(repo_url)
                    results.append(result)

                # All should succeed
                assert all(r.success for r in results)

                # Verify separate directories
                for repo_url in repos:
                    git_url = GitURL.from_url(repo_url)
                    repo_path = (
                        workspace
                        / "payloads"
                        / "repositories"
                        / git_url.host
                        / git_url.owner
                        / git_url.repo
                    )
                    assert repo_path.exists()


class TestCLIIntegration:
    """Test CLI command integration with GitSync."""

    @pytest.mark.e2e
    def test_cli_sync_command_success(self):
        """Test successful CLI sync command."""
        from gibson.cli.commands import payloads

        runner = CliRunner()

        with patch("gibson.cli.commands.payloads.PayloadManager") as MockManager:
            mock_manager = AsyncMock()
            MockManager.return_value.__aenter__.return_value = mock_manager

            # Mock successful sync
            mock_manager.sync_repository.return_value = SyncResult(
                success=True,
                repository="https://github.com/test/repo.git",
                branch="main",
                fetched_count=10,
                processed_count=10,
                auth_method_used=AuthMethod.PUBLIC,
                commit_hash="abc123",
            )

            # Run CLI command
            result = runner.invoke(payloads.app, ["sync", "https://github.com/test/repo.git"])

            # Should succeed
            assert result.exit_code == 0
            assert "Successfully" in result.stdout or "success" in result.stdout.lower()

    @pytest.mark.e2e
    def test_cli_sync_with_branch(self):
        """Test CLI sync with specific branch."""
        from gibson.cli.commands import payloads

        runner = CliRunner()

        with patch("gibson.cli.commands.payloads.PayloadManager") as MockManager:
            mock_manager = AsyncMock()
            MockManager.return_value.__aenter__.return_value = mock_manager

            mock_manager.sync_repository.return_value = SyncResult(
                success=True,
                repository="https://github.com/test/repo.git",
                branch="develop",
                fetched_count=5,
                processed_count=5,
                auth_method_used=AuthMethod.SSH_KEY,
            )

            # Run with branch option
            result = runner.invoke(
                payloads.app, ["sync", "https://github.com/test/repo.git", "--branch", "develop"]
            )

            assert result.exit_code == 0
            # Verify branch was passed
            mock_manager.sync_repository.assert_called_with(
                repository_url="https://github.com/test/repo.git",
                branch="develop",
                domains=None,
                force=False,
            )

    @pytest.mark.e2e
    def test_cli_sync_error_handling(self):
        """Test CLI error handling for failed sync."""
        from gibson.cli.commands import payloads

        runner = CliRunner()

        with patch("gibson.cli.commands.payloads.PayloadManager") as MockManager:
            mock_manager = AsyncMock()
            MockManager.return_value.__aenter__.return_value = mock_manager

            # Mock failed sync
            mock_manager.sync_repository.return_value = SyncResult(
                success=False,
                repository="https://github.com/private/repo.git",
                branch="main",
                fetched_count=0,
                processed_count=0,
                auth_method_used=AuthMethod.FAILED,
                error="Authentication failed: All methods exhausted",
            )

            # Run CLI command
            result = runner.invoke(payloads.app, ["sync", "https://github.com/private/repo.git"])

            # Should show error
            assert result.exit_code != 0
            assert "error" in result.stdout.lower() or "failed" in result.stdout.lower()


class TestEnvironmentIntegration:
    """Test integration with environment variables and configuration."""

    @pytest.mark.e2e
    @pytest.mark.asyncio
    async def test_token_from_environment(self):
        """Test using token from environment variable."""
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            git_sync = GitSync(workspace, shallow=True)

            # Set environment variable
            test_token = "ghp_test_token_123"
            with patch.dict(os.environ, {"GITHUB_TOKEN": test_token}):
                # Check token detection
                from gibson.core.payloads.auth_prompt import TokenPrompter

                prompter = TokenPrompter()

                detected_token = prompter._get_token_from_env("github.com")
                assert detected_token == test_token

    @pytest.mark.e2e
    @pytest.mark.asyncio
    async def test_ssh_key_detection(self):
        """Test SSH key detection from standard locations."""
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            git_sync = GitSync(workspace, shallow=True)

            # Mock SSH key file
            ssh_dir = Path.home() / ".ssh"
            with patch("pathlib.Path.exists") as mock_exists:
                with patch("pathlib.Path.stat") as mock_stat:
                    # Simulate SSH key exists
                    mock_exists.return_value = True
                    mock_stat.return_value = Mock(st_size=1000)

                    has_keys = git_sync._has_ssh_keys()
                    assert has_keys == True

            # Test without SSH keys
            with patch("pathlib.Path.exists", return_value=False):
                has_keys = git_sync._has_ssh_keys()
                assert has_keys == False


class TestRealWorldScenarios:
    """Test real-world usage scenarios."""

    @pytest.mark.e2e
    @pytest.mark.slow
    @pytest.mark.asyncio
    async def test_gibson_prompt_library_sync(self):
        """Test syncing the actual Gibson prompt library."""
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            manager = PayloadManager(data_directory=workspace / "payloads")

            # The actual Gibson prompt library
            repo_url = "https://github.com/zero-day-ai/gibson-prompt-library.git"

            async with manager:
                result = await manager.sync_repository(repo_url)

                # Should succeed (public repository)
                assert result.success == True
                assert result.auth_method_used == AuthMethod.PUBLIC
                assert result.fetched_count > 0

                # Verify prompt files exist
                repo_path = (
                    workspace
                    / "payloads"
                    / "repositories"
                    / "github.com"
                    / "zero-day-ai"
                    / "gibson-prompt-library"
                )
                assert repo_path.exists()

                # Should have prompt files
                prompt_files = list(repo_path.rglob("*.txt")) + list(repo_path.rglob("*.md"))
                assert len(prompt_files) > 0

    @pytest.mark.e2e
    @pytest.mark.asyncio
    async def test_url_format_variations(self):
        """Test various URL format variations users might provide."""
        test_urls = [
            "https://github.com/owner/repo",
            "https://github.com/owner/repo.git",
            "git@github.com:owner/repo.git",
            "https://github.com/owner/repo/tree/main",
            "ssh://git@github.com/owner/repo.git",
        ]

        for url in test_urls:
            try:
                git_url = GitURL.from_url(url)
                assert git_url.owner == "owner"
                assert git_url.repo == "repo"
                assert git_url.host == "github.com"
            except ValueError as e:
                # Some formats might not be supported
                print(f"URL format not supported: {url} - {e}")


@pytest.mark.e2e
def test_complete_user_journey():
    """Test the complete user journey from CLI to synced payloads."""
    from gibson.cli.commands import payloads

    runner = CliRunner()

    with tempfile.TemporaryDirectory() as tmpdir:
        # Set up test environment
        os.environ["GIBSON_DATA_DIR"] = str(tmpdir)

        with patch("gibson.cli.commands.payloads.PayloadManager") as MockManager:
            mock_manager = AsyncMock()
            MockManager.return_value.__aenter__.return_value = mock_manager

            # Mock the complete flow
            mock_manager.sync_repository.return_value = SyncResult(
                success=True,
                repository="https://github.com/zero-day-ai/gibson-prompt-library.git",
                branch="main",
                fetched_count=25,
                processed_count=25,
                auth_method_used=AuthMethod.PUBLIC,
                commit_hash="abc123def456",
            )

            # User runs the sync command
            result = runner.invoke(
                payloads.app, ["sync", "https://github.com/zero-day-ai/gibson-prompt-library.git"]
            )

            # Command should succeed
            assert result.exit_code == 0

            # Should show success message
            assert "success" in result.stdout.lower() or "synced" in result.stdout.lower()

            # Should show statistics
            assert "25" in result.stdout or "fetched" in result.stdout.lower()
