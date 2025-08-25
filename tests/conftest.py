"""
Shared pytest fixtures for all tests.

This file is automatically discovered by pytest and makes fixtures
available to all test files without explicit imports.
"""

import pytest
from pathlib import Path
from typing import List, Dict, Any
from unittest.mock import Mock, AsyncMock

# Import the components we'll be testing
from gibson.core.payloads.url_parser import URLParser
from gibson.core.payloads.git_models import GitURL, GitPlatform, GitCredentials
from gibson.core.payloads.git_sync import GitSync
from gibson.core.payloads.models.git_sync import CloneResult, UpdateResult, AuthMethod
from gibson.core.payloads.types import SyncResult, PayloadDomain


# ========================================
# URL Parser Fixtures
# ========================================

@pytest.fixture
def url_parser():
    """Provides a fresh URLParser instance for each test."""
    return URLParser()


@pytest.fixture
def github_urls():
    """Collection of valid GitHub URLs in different formats."""
    return [
        "https://github.com/zero-day-ai/gibson-prompt-library",
        "https://github.com/zero-day-ai/gibson-prompt-library.git",
        "git@github.com:zero-day-ai/gibson-prompt-library.git",
        "https://github.com/owner/repo/tree/main",
        "ssh://git@github.com/owner/repo.git",
    ]


@pytest.fixture
def gitlab_urls():
    """Collection of valid GitLab URLs."""
    return [
        "https://gitlab.com/owner/repo",
        "https://gitlab.com/owner/repo.git",
        "git@gitlab.com:owner/repo.git",
        "https://gitlab.com/group/subgroup/repo.git",
    ]


@pytest.fixture
def all_platform_urls():
    """URLs from all supported platforms for comprehensive testing."""
    return {
        GitPlatform.GITHUB: [
            "https://github.com/owner/repo.git",
            "git@github.com:owner/repo.git",
        ],
        GitPlatform.GITLAB: [
            "https://gitlab.com/owner/repo.git",
            "git@gitlab.com:owner/repo.git",
        ],
        GitPlatform.BITBUCKET: [
            "https://bitbucket.org/owner/repo.git",
            "git@bitbucket.org:owner/repo.git",
        ],
        GitPlatform.GITEA: [
            "https://gitea.example.com/owner/repo.git",
        ],
        GitPlatform.GOGS: [
            "https://gogs.example.com/owner/repo.git",
        ],
        GitPlatform.GENERIC: [
            "https://git.company.com/owner/repo.git",
            "https://custom-git.org/team/project.git",
        ],
    }


@pytest.fixture
def problematic_urls():
    """URLs that might cause platform detection issues."""
    return [
        # Contains 'gogs' but is GitHub
        ("https://github.com/gogs-team/repo.git", GitPlatform.GITHUB),
        # Contains 'github' but is GitLab
        ("https://gitlab.com/github-migration/repo.git", GitPlatform.GITLAB),
        # Subdomain confusion
        ("https://github.company.com/repo.git", GitPlatform.GENERIC),
        ("https://gitlab.github.io/repo.git", GitPlatform.GENERIC),
    ]


# ========================================
# Authentication Fixtures
# ========================================

@pytest.fixture
def mock_git_sync(tmp_path):
    """Provides a mock GitSync instance."""
    mock_sync = Mock(spec=GitSync)
    mock_sync.workspace = tmp_path
    mock_sync.shallow = True
    return mock_sync


@pytest.fixture
def mock_github_credentials():
    """Mock GitHub credentials for testing."""
    return GitCredentials(
        host="github.com",
        auth_type="token",
        username="testuser",
        token="ghp_testtokenABCD1234567890"
    )


@pytest.fixture
def mock_gitlab_credentials():
    """Mock GitLab credentials for testing."""
    return GitCredentials(
        host="gitlab.com",
        auth_type="token",
        token="glpat-testtoken1234567890"
    )


# ========================================
# Git URL Model Fixtures
# ========================================

@pytest.fixture
def github_git_url():
    """A pre-parsed GitHub GitURL object."""
    return GitURL(
        protocol="https",
        host="github.com",
        owner="zero-day-ai",
        repo="gibson-prompt-library",
        branch="main"
    )


@pytest.fixture
def gitlab_git_url():
    """A pre-parsed GitLab GitURL object."""
    return GitURL(
        protocol="https",
        host="gitlab.com",
        owner="security-team",
        repo="test-payloads",
        branch="main"
    )


# ========================================
# Mock HTTP Response Fixtures
# ========================================

@pytest.fixture
def mock_github_api_response():
    """Mock successful GitHub API response."""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "login": "testuser",
        "name": "Test User",
        "id": 12345
    }
    return mock_response


@pytest.fixture
def mock_github_tree_response():
    """Mock GitHub repository tree API response."""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "tree": [
            {
                "path": "prompts/injection.txt",
                "type": "blob",
                "sha": "abc123",
                "size": 1024
            },
            {
                "path": "README.md",
                "type": "blob",
                "sha": "def456",
                "size": 512
            }
        ]
    }
    return mock_response


# ========================================
# Async Fixtures
# ========================================

@pytest.fixture
async def mock_async_session():
    """Mock async HTTP session for testing fetchers."""
    session = AsyncMock()
    return session


@pytest.fixture
def mock_payload_manager():
    """Mock PayloadManager for integration tests."""
    manager = AsyncMock()
    manager.sync_repository = AsyncMock(return_value={
        "success": True,
        "fetched_count": 10,
        "processed_count": 10
    })
    return manager


# ========================================
# File System Fixtures
# ========================================

@pytest.fixture
def temp_git_repo(tmp_path):
    """Creates a temporary directory structure mimicking a git repo."""
    repo_path = tmp_path / "test-repo"
    repo_path.mkdir()
    
    # Create structure
    (repo_path / "prompts").mkdir()
    (repo_path / "prompts" / "injection.txt").write_text("test payload")
    (repo_path / "data").mkdir()
    (repo_path / "data" / "poisoning.json").write_text('{"test": "data"}')
    (repo_path / "README.md").write_text("# Test Repo")
    
    return repo_path


# ========================================
# Test Data Fixtures
# ========================================

@pytest.fixture
def invalid_urls():
    """URLs that should fail validation."""
    return [
        "owner/repo",  # Shorthand format
        "github.com/owner/repo",  # Missing protocol
        "https://",  # Incomplete URL
        "not-a-url",  # Invalid format
        "",  # Empty string
    ]


@pytest.fixture
def edge_case_urls():
    """Edge cases for URL parsing."""
    return [
        # URL with port
        ("https://git.company.com:8080/owner/repo.git", 8080),
        # URL with special characters
        ("https://github.com/owner-with-dash/repo_with_underscore.git", "owner-with-dash", "repo_with_underscore"),
        # URL with numbers
        ("https://github.com/User123/Repo456.git", "User123", "Repo456"),
    ]


# ========================================
# Git Operation Fixtures
# ========================================

@pytest.fixture
def mock_clone_result():
    """Mock successful CloneResult."""
    return CloneResult(
        success=True,
        repo_path=Path("/tmp/test-repo"),
        commit_hash="abc123def456",
        branch="main",
        auth_method_used=AuthMethod.PUBLIC,
        clone_size_mb=10.5,
        clone_duration_seconds=2.5,
        is_shallow=True,
        error_message=None
    )


@pytest.fixture
def mock_update_result():
    """Mock successful UpdateResult."""
    return UpdateResult(
        success=True,
        updated=True,
        old_commit="old123",
        new_commit="new456",
        files_changed=5,
        auth_method_used=AuthMethod.SSH_KEY,
        error_message=None
    )


@pytest.fixture
def mock_ssh_git_url():
    """Mock SSH Git URL."""
    return GitURL(
        protocol="ssh",
        host="github.com",
        owner="zero-day-ai",
        repo="gibson-prompt-library",
        branch="main"
    )


@pytest.fixture
def mock_https_git_url():
    """Mock HTTPS Git URL."""
    return GitURL(
        protocol="https",
        host="github.com",
        owner="zero-day-ai",
        repo="gibson-prompt-library",
        branch="main"
    )


@pytest.fixture
def mock_git_credentials():
    """Mock Git credentials for testing."""
    return GitCredentials(
        host="github.com",
        auth_type="token",
        username="testuser",
        token="test_token_123"
    )


@pytest.fixture
def mock_sync_result_success():
    """Mock successful sync result."""
    return SyncResult(
        success=True,
        repository="git@github.com:zero-day-ai/gibson-prompt-library.git",
        branch="main",
        fetched_count=15,
        processed_count=15,
        error=None
    )


@pytest.fixture
def mock_sync_result_auth_error():
    """Mock sync result with auth error."""
    return SyncResult(
        success=False,
        repository="git@github.com:private/repo.git",
        branch="main",
        fetched_count=0,
        processed_count=0,
        error="Authentication failed: Please check your credentials"
    )


@pytest.fixture
def mock_httpx_responses():
    """Mock httpx responses for different scenarios."""
    return {
        "auth_success": AsyncMock(
            status_code=200,
            json=AsyncMock(return_value={"message": "Authenticated"})
        ),
        "auth_failure": AsyncMock(
            status_code=401,
            json=AsyncMock(return_value={"message": "Bad credentials"})
        ),
        "rate_limit": AsyncMock(
            status_code=429,
            headers={"X-RateLimit-Reset": "1234567890"},
            json=AsyncMock(return_value={"message": "Rate limited"})
        ),
        "not_found": AsyncMock(
            status_code=404,
            json=AsyncMock(return_value={"message": "Not Found"})
        )
    }


@pytest.fixture
def mock_prompt_for_credentials():
    """Mock credential prompt function."""
    def prompt(host: str = "github.com"):
        return ("testuser", "test_token_123")
    return Mock(side_effect=prompt)


# ========================================
# Pytest Configuration
# ========================================

def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers", "unit: Unit tests that test individual components"
    )
    config.addinivalue_line(
        "markers", "integration: Integration tests that test component interactions"
    )
    config.addinivalue_line(
        "markers", "e2e: End-to-end tests that test complete workflows"
    )
    config.addinivalue_line(
        "markers", "slow: Tests that take longer to run"
    )
    config.addinivalue_line(
        "markers", "network: Tests that require network access"
    )