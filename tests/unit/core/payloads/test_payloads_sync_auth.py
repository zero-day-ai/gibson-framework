"""
Unit tests for payloads sync command with authentication handling.

Tests that the sync command:
1. Automatically attempts to pull with existing SSH keys or HTTPS
2. Prompts for credentials on authentication errors
3. Handles both SSH and HTTPS URLs correctly
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, Mock, patch
from pathlib import Path
from typing import Optional
import tempfile

from gibson.core.payloads.git_sync import GitSync
from gibson.core.payloads.git_models import GitPlatform, GitURL
from gibson.core.payloads.models.git_sync import (
    AuthMethod, 
    CloneResult, 
    UpdateResult,
    AuthenticationError,
    GitOperationError
)
from gibson.core.payloads.types import SyncResult
from gibson.core.payloads.url_parser import URLParser
from git import GitCommandError, Repo


class TestPayloadsSyncAuthentication:
    """Test authentication handling in payloads sync command."""

    @pytest.fixture
    def mock_git_url_ssh(self):
        """Create a mock GitURL for SSH."""
        return GitURL(
            platform=GitPlatform.GITHUB,
            protocol="ssh",
            host="github.com",
            owner="zero-day-ai",
            repo="gibson-prompt-library",
            branch="main"
        )

    @pytest.fixture
    def mock_git_url_https(self):
        """Create a mock GitURL for HTTPS."""
        return GitURL(
            platform=GitPlatform.GITHUB,
            protocol="https",
            host="github.com",
            owner="zero-day-ai",
            repo="gibson-prompt-library",
            branch="main"
        )

    @pytest.fixture
    def git_sync(self):
        """Create GitSync instance with temporary workspace."""
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            yield GitSync(workspace, shallow=True)

    @pytest.mark.asyncio
    async def test_sync_ssh_auto_pull_success(self, git_sync, mock_git_url_ssh):
        """Test that SSH sync automatically attempts to pull when keys are set up."""
        # Arrange
        mock_repo = Mock(spec=Repo)
        mock_repo.head.commit.hexsha = "abc123"
        mock_repo.active_branch.name = "main"
        
        with patch.object(git_sync, '_try_operation_with_auth_escalation') as mock_try:
            mock_try.return_value = (mock_repo, AuthMethod.SSH_KEY)
            
            with patch.object(git_sync, '_calculate_directory_size', return_value=10.5):
                # Act
                result = await git_sync.clone_repository(mock_git_url_ssh)
                
                # Assert
                assert result.success is True
                assert result.auth_method_used == AuthMethod.SSH_KEY
                assert result.commit_hash == "abc123"
                # Should have used SSH without prompting

    @pytest.mark.asyncio
    async def test_sync_https_public_repo_auto_pull(self, git_sync, mock_git_url_https):
        """Test that HTTPS sync automatically pulls from public repositories."""
        # Arrange
        mock_repo = Mock(spec=Repo)
        mock_repo.head.commit.hexsha = "def456"
        mock_repo.active_branch.name = "main"
        
        with patch.object(git_sync, '_try_operation_with_auth_escalation') as mock_try:
            mock_try.return_value = (mock_repo, AuthMethod.PUBLIC)
            
            with patch.object(git_sync, '_calculate_directory_size', return_value=10.5):
                # Act
                result = await git_sync.clone_repository(mock_git_url_https)
                
                # Assert
                assert result.success is True
                assert result.auth_method_used == AuthMethod.PUBLIC
                # No authentication needed for public repo

    @pytest.mark.asyncio
    async def test_sync_ssh_auth_error_prompts_credentials(self, git_sync, mock_git_url_ssh):
        """Test that SSH auth errors trigger token prompting."""
        # Arrange
        mock_repo = Mock(spec=Repo)
        mock_repo.head.commit.hexsha = "ghi789"
        mock_repo.active_branch.name = "main"
        
        # Mock auth escalation: SSH fails, token succeeds
        with patch.object(git_sync, '_has_ssh_keys', return_value=True):
            with patch.object(git_sync, '_is_auth_error', return_value=True):
                with patch.object(git_sync.token_prompter, 'prompt_for_token', return_value="test-token"):
                    with patch('gibson.core.payloads.git_sync.Repo.clone_from') as mock_clone:
                        # SSH fails, token succeeds
                        mock_clone.side_effect = [
                            GitCommandError("git", "authentication failed"),  # Public fails
                            GitCommandError("git", "authentication failed"),  # SSH fails
                            mock_repo  # Token succeeds
                        ]
                        
                        with patch.object(git_sync, '_calculate_directory_size', return_value=10.5):
                            # Act
                            result = await git_sync.clone_repository(mock_git_url_ssh)
                            
                            # Assert
                            assert result.success is True
                            assert result.auth_method_used == AuthMethod.TOKEN
                            git_sync.token_prompter.prompt_for_token.assert_called_once()

    @pytest.mark.asyncio
    async def test_sync_https_auth_error_prompts_credentials(self, git_sync, mock_git_url_https):
        """Test that HTTPS auth errors (private repo) trigger credential prompting."""
        # Arrange
        mock_git_url_https.owner = "private-org"
        mock_git_url_https.repo = "private-repo"
        
        mock_repo = Mock(spec=Repo)
        mock_repo.head.commit.hexsha = "jkl012"
        mock_repo.active_branch.name = "main"
        
        with patch.object(git_sync, '_has_ssh_keys', return_value=False):
            with patch.object(git_sync, '_is_auth_error', return_value=True):
                with patch.object(git_sync.token_prompter, 'prompt_for_token', return_value="personal-access-token"):
                    with patch('gibson.core.payloads.git_sync.Repo.clone_from') as mock_clone:
                        # Public fails, no SSH keys, token succeeds
                        mock_clone.side_effect = [
                            GitCommandError("git", "authentication failed"),  # Public fails
                            mock_repo  # Token succeeds
                        ]
                        
                        with patch.object(git_sync, '_calculate_directory_size', return_value=10.5):
                            # Act
                            result = await git_sync.clone_repository(mock_git_url_https)
                            
                            # Assert
                            assert result.success is True
                            assert result.auth_method_used == AuthMethod.TOKEN
                            git_sync.token_prompter.prompt_for_token.assert_called_once()

    @pytest.mark.asyncio
    async def test_sync_handles_all_auth_failures(self, git_sync, mock_git_url_https):
        """Test that sync handles case where all auth methods fail."""
        # Arrange
        with patch.object(git_sync, '_has_ssh_keys', return_value=True):
            with patch.object(git_sync, '_is_auth_error', return_value=True):
                with patch.object(git_sync.token_prompter, 'prompt_for_token', return_value="bad-token"):
                    with patch('gibson.core.payloads.git_sync.Repo.clone_from') as mock_clone:
                        # All attempts fail
                        mock_clone.side_effect = GitCommandError("git", "authentication failed")
                        
                        # Act
                        result = await git_sync.clone_repository(mock_git_url_https)
                        
                        # Assert
                        assert result.success is False
                        assert result.auth_method_used == AuthMethod.FAILED
                        assert result.error_message is not None

    @pytest.mark.asyncio
    async def test_sync_validates_url_format(self, git_sync):
        """Test that sync validates URL format before attempting connection."""
        # Act
        with pytest.raises(ValueError, match="Invalid URL"):
            GitURL.from_url("not-a-valid-git-url")

    @pytest.mark.asyncio
    async def test_sync_handles_network_errors_gracefully(self, git_sync, mock_git_url_https):
        """Test that sync handles network errors gracefully."""
        # Arrange
        with patch('gibson.core.payloads.git_sync.Repo.clone_from') as mock_clone:
            mock_clone.side_effect = Exception("Network error: Connection failed")
            
            # Act
            result = await git_sync.clone_repository(mock_git_url_https)
            
            # Assert
            assert result.success is False
            assert "network" in result.error_message.lower() or "connection" in result.error_message.lower()


class TestPayloadsSyncCLI:
    """Test the CLI interface for payloads sync command."""

    @pytest.mark.asyncio
    async def test_cli_sync_command_with_ssh_url(self):
        """Test CLI sync command with SSH URL."""
        from gibson.cli.commands.payloads import sync_repository
        
        with patch('gibson.cli.commands.payloads.PayloadManager') as MockManager:
            mock_manager = AsyncMock()
            MockManager.return_value.__aenter__.return_value = mock_manager
            
            mock_manager.sync_repository.return_value = SyncResult(
                success=True,
                repository="git@github.com:zero-day-ai/gibson-prompt-library.git",
                branch="main",
                fetched_count=10,
                processed_count=10,
                auth_method_used=AuthMethod.SSH_KEY
            )
            
            with patch('gibson.cli.commands.payloads.render_success') as mock_success:
                with patch('asyncio.run') as mock_run:
                    mock_run.return_value = None
                    
                    # Act - simulate CLI command
                    sync_repository(
                        repository_url="git@github.com:zero-day-ai/gibson-prompt-library.git",
                        branch="main",
                        domains=None,
                        force=False
                    )
                    
                    # Assert
                    mock_run.assert_called_once()
                    # Success should be rendered after successful sync

    @pytest.mark.asyncio
    async def test_cli_sync_validates_url_before_sync(self):
        """Test that CLI validates URL format before attempting sync."""
        from gibson.cli.commands.payloads import sync_repository
        
        with patch('gibson.cli.commands.payloads.URLParser') as MockParser:
            mock_parser = Mock()
            MockParser.return_value = mock_parser
            mock_parser.validate_url.return_value = (False, "Invalid URL format")
            
            with patch('gibson.cli.commands.payloads.render_error') as mock_error:
                with patch('asyncio.run') as mock_run:
                    mock_run.return_value = None
                    
                    # Act
                    sync_repository(
                        repository_url="invalid-url",
                        branch="main",
                        domains=None,
                        force=False
                    )
                    
                    # Assert
                    mock_parser.validate_url.assert_called_once_with("invalid-url")
                    mock_error.assert_called()


class TestAuthenticationEscalation:
    """Test the three-tier authentication escalation."""
    
    @pytest.mark.asyncio
    async def test_auth_escalation_sequence(self):
        """Test the complete auth escalation sequence."""
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            git_sync = GitSync(workspace, shallow=True)
            
            git_url = GitURL(
                platform=GitPlatform.GITHUB,
                protocol="https",
                host="github.com",
                owner="private-org",
                repo="private-repo",
                branch="main"
            )
            
            mock_operation = AsyncMock()
            mock_operation.side_effect = [
                GitCommandError("git", "authentication failed"),  # Public fails
                GitCommandError("git", "authentication failed"),  # SSH fails
                "success"  # Token succeeds
            ]
            
            with patch.object(git_sync, '_has_ssh_keys', return_value=True):
                with patch.object(git_sync, '_is_auth_error', return_value=True):
                    with patch.object(git_sync.token_prompter, 'prompt_for_token', return_value="test-token"):
                        result, auth_method = await git_sync._try_operation_with_auth_escalation(
                            mock_operation,
                            git_url
                        )
            
            assert result == "success"
            assert auth_method == AuthMethod.TOKEN
            assert mock_operation.call_count == 3  # All three tiers attempted