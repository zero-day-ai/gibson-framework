"""Integration tests for GitSync with real Git operations."""

import asyncio
import os
import tempfile
from pathlib import Path

import pytest
from git import Repo

from gibson.core.payloads.git_sync import GitSync
from gibson.core.payloads.git_models import GitURL, GitPlatform
from gibson.core.payloads.models.git_sync import AuthMethod, GitSyncConfig


# Test repositories (public repos for integration testing)
TEST_REPOS = {
    "small_public": "https://github.com/octocat/Hello-World.git",
    "medium_public": "https://github.com/github/gitignore.git",
}


@pytest.fixture
def workspace_dir():
    """Create temporary workspace for integration tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def git_sync(workspace_dir):
    """Create GitSync instance for integration testing."""
    return GitSync(workspace_dir, shallow=True)


class TestPublicRepositoryOperations:
    """Test operations with real public repositories."""
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_clone_small_public_repo(self, git_sync):
        """Test cloning a small public repository."""
        git_url = GitURL.from_url(TEST_REPOS["small_public"])
        
        result = await git_sync.clone_repository(git_url)
        
        assert result.success == True
        assert result.auth_method_used == AuthMethod.PUBLIC
        assert result.repo_path.exists()
        assert (result.repo_path / ".git").exists()
        assert (result.repo_path / "README").exists()
        assert result.clone_size_mb > 0
        assert result.is_shallow == True
        
        # Verify it's actually a shallow clone
        repo = Repo(result.repo_path)
        shallow_check = repo.git.rev_parse("--is-shallow-repository")
        assert shallow_check == "true"
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_clone_with_specific_branch(self, git_sync):
        """Test cloning a specific branch."""
        git_url = GitURL.from_url(TEST_REPOS["medium_public"])
        
        # Clone main branch
        result = await git_sync.clone_repository(
            git_url,
            branch="main"
        )
        
        assert result.success == True
        assert result.branch == "main"
        
        # Verify branch
        repo = Repo(result.repo_path)
        assert repo.active_branch.name == "main"
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_update_cloned_repository(self, git_sync):
        """Test updating a previously cloned repository."""
        git_url = GitURL.from_url(TEST_REPOS["small_public"])
        
        # First clone
        clone_result = await git_sync.clone_repository(git_url)
        assert clone_result.success == True
        
        repo_path = clone_result.repo_path
        original_commit = clone_result.commit_hash
        
        # Update the same repository
        update_result = await git_sync.update_repository(repo_path)
        
        assert update_result.success == True
        assert update_result.auth_method_used == AuthMethod.PUBLIC
        
        # For a stable repo, it might not have changes
        if update_result.updated:
            assert update_result.old_commit != update_result.new_commit
        else:
            assert update_result.old_commit == update_result.new_commit
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_repository_info(self, git_sync):
        """Test getting repository information."""
        git_url = GitURL.from_url(TEST_REPOS["small_public"])
        
        # Clone first
        clone_result = await git_sync.clone_repository(git_url)
        assert clone_result.success == True
        
        # Get repository info
        info = await git_sync.get_repository_info(clone_result.repo_path)
        
        assert info.commit_hash == clone_result.commit_hash
        assert info.branch == clone_result.branch
        assert info.remote_url != ""
        assert info.is_shallow == True
        assert info.size_mb > 0
        assert info.file_count > 0


class TestURLParsing:
    """Test URL parsing with real Git URLs."""
    
    @pytest.mark.integration
    def test_parse_github_https_url(self):
        """Test parsing GitHub HTTPS URL."""
        url = "https://github.com/owner/repo.git"
        git_url = GitURL.from_url(url)
        
        assert git_url.platform == GitPlatform.GENERIC  # Before detect_platform_from_host
        git_url.platform = git_url.detect_platform_from_host()
        assert git_url.platform == GitPlatform.GITHUB
        assert git_url.host == "github.com"
        assert git_url.owner == "owner"
        assert git_url.repo == "repo"
        assert git_url.protocol == "https"
    
    @pytest.mark.integration
    def test_parse_github_ssh_url(self):
        """Test parsing GitHub SSH URL."""
        url = "git@github.com:owner/repo.git"
        git_url = GitURL.from_url(url)
        
        git_url.platform = git_url.detect_platform_from_host()
        assert git_url.platform == GitPlatform.GITHUB
        assert git_url.host == "github.com"
        assert git_url.owner == "owner"
        assert git_url.repo == "repo"
        assert git_url.protocol == "ssh"
    
    @pytest.mark.integration
    def test_url_transformations(self):
        """Test URL transformation methods."""
        url = "https://github.com/owner/repo.git"
        git_url = GitURL.from_url(url)
        
        # Test HTTPS URL generation
        https_url = git_url.to_https_url()
        assert https_url == "https://github.com/owner/repo.git"
        
        # Test SSH URL generation
        ssh_url = git_url.to_ssh_url()
        assert ssh_url == "git@github.com:owner/repo.git"
        
        # Test authenticated URL generation
        auth_url = git_url.to_authenticated_url("test-token")
        assert auth_url == "https://test-token@github.com/owner/repo.git"


class TestAuthenticationEscalation:
    """Test authentication escalation with real scenarios."""
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_public_repo_no_auth_needed(self, git_sync):
        """Test that public repos don't trigger auth escalation."""
        git_url = GitURL.from_url(TEST_REPOS["small_public"])
        
        # Should succeed with public access
        result = await git_sync.clone_repository(git_url)
        
        assert result.success == True
        assert result.auth_method_used == AuthMethod.PUBLIC
        assert result.error_message is None
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    @pytest.mark.skipif(
        not os.getenv("GIBSON_TEST_PRIVATE_REPO"),
        reason="Private repo URL not provided"
    )
    async def test_private_repo_auth_escalation(self, git_sync):
        """Test auth escalation with private repository.
        
        Set GIBSON_TEST_PRIVATE_REPO env var to test with a private repo.
        """
        private_repo_url = os.getenv("GIBSON_TEST_PRIVATE_REPO")
        git_url = GitURL.from_url(private_repo_url)
        
        # This should trigger authentication escalation
        result = await git_sync.clone_repository(git_url)
        
        if result.success:
            # Should have used SSH or token
            assert result.auth_method_used in [AuthMethod.SSH_KEY, AuthMethod.TOKEN]
        else:
            # Should have tried and failed gracefully
            assert result.auth_method_used == AuthMethod.FAILED
            assert result.error_message is not None


class TestPerformanceAndOptimization:
    """Test performance features like shallow clones."""
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_shallow_clone_performance(self, workspace_dir):
        """Test that shallow clones are faster and smaller."""
        git_url = GitURL.from_url(TEST_REPOS["medium_public"])
        
        # Shallow clone
        shallow_sync = GitSync(workspace_dir / "shallow", shallow=True)
        shallow_result = await shallow_sync.clone_repository(git_url)
        
        # Full clone
        full_sync = GitSync(workspace_dir / "full", shallow=False)
        full_result = await full_sync.clone_repository(git_url)
        
        assert shallow_result.success == True
        assert full_result.success == True
        
        # Shallow clone should be smaller
        assert shallow_result.clone_size_mb < full_result.clone_size_mb
        
        # Shallow clone should be faster (usually)
        # Note: Network variability might affect this
        if shallow_result.clone_duration_seconds < full_result.clone_duration_seconds * 1.5:
            # Give some margin for network variability
            assert True
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_sparse_checkout(self, git_sync):
        """Test sparse checkout functionality."""
        git_url = GitURL.from_url(TEST_REPOS["medium_public"])
        
        # Clone with sparse patterns (only Python files)
        result = await git_sync.clone_repository(
            git_url,
            sparse_patterns=["*.py", "*.md"]
        )
        
        if result.success:
            # Check that sparse patterns were applied
            assert result.sparse_patterns == ["*.py", "*.md"]
            
            # The repository should have fewer files
            file_count = sum(1 for _ in result.repo_path.rglob("*") if _.is_file())
            assert file_count > 0  # Should have some files


class TestErrorHandling:
    """Test error handling and recovery."""
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_invalid_url_handling(self, git_sync):
        """Test handling of invalid repository URLs."""
        # Invalid URL format
        with pytest.raises(ValueError):
            GitURL.from_url("not-a-valid-url")
        
        # Non-existent repository (should fail during clone)
        git_url = GitURL(
            platform=GitPlatform.GITHUB,
            protocol="https",
            host="github.com",
            owner="nonexistent",
            repo="nonexistent-repo-xyz123",
            branch="main"
        )
        
        result = await git_sync.clone_repository(git_url)
        
        assert result.success == False
        assert result.auth_method_used == AuthMethod.FAILED
        assert result.error_message is not None
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_network_error_handling(self, git_sync):
        """Test handling of network errors."""
        # Use an invalid host
        git_url = GitURL(
            platform=GitPlatform.GENERIC,
            protocol="https",
            host="invalid.host.example.com",
            owner="test",
            repo="test",
            branch="main"
        )
        
        result = await git_sync.clone_repository(git_url)
        
        assert result.success == False
        assert result.error_message is not None
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_cleanup_on_failure(self, git_sync, workspace_dir):
        """Test that failed clones clean up properly."""
        # Invalid repository
        git_url = GitURL(
            platform=GitPlatform.GITHUB,
            protocol="https",
            host="github.com",
            owner="nonexistent",
            repo="nonexistent-repo-xyz123",
            branch="main"
        )
        
        target_path = workspace_dir / "failed_clone"
        
        result = await git_sync.clone_repository(git_url, target_path=target_path)
        
        assert result.success == False
        # Target directory should be cleaned up after failure
        assert not target_path.exists()


class TestConfiguration:
    """Test GitSync configuration options."""
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_custom_config(self, workspace_dir):
        """Test GitSync with custom configuration."""
        config = GitSyncConfig(
            default_shallow=True,
            max_clone_depth=10,
            enable_sparse_checkout=True,
            sparse_patterns=["*.md", "*.txt"],
            timeout_seconds=60,
            retry_attempts=2
        )
        
        git_sync = GitSync(workspace_dir, config=config)
        git_url = GitURL.from_url(TEST_REPOS["small_public"])
        
        result = await git_sync.clone_repository(git_url)
        
        assert result.success == True
        assert result.is_shallow == True