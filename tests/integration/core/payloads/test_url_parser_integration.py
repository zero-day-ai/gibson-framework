"""
Integration tests for URL parser with real parsing logic.

These tests verify the complete URL parsing flow without mocking internal components.
Only external services are mocked when necessary.
"""

import pytest
from gibson.core.payloads.url_parser import URLParser
from gibson.core.payloads.git_models import GitURL, GitPlatform


class TestURLParserIntegration:
    """Integration tests for URL parser with platform detection."""

    @pytest.fixture
    def parser(self):
        """Create a real URLParser instance."""
        return URLParser()

    def test_parse_github_ssh_url_complete_flow(self, parser):
        """Test parsing GitHub SSH URL through complete flow."""
        # Test validation first
        is_valid, error = parser.validate_url(
            "git@github.com:zero-day-ai/gibson-prompt-library.git"
        )
        assert is_valid is True
        assert error is None

        # Test parsing
        git_url = parser.parse("git@github.com:zero-day-ai/gibson-prompt-library.git")

        # Verify all attributes are correctly set
        assert isinstance(git_url, GitURL)
        assert isinstance(git_url.platform, GitPlatform)  # Must be enum, not string!
        assert git_url.platform == GitPlatform.GITHUB
        assert git_url.protocol == "ssh"
        assert git_url.host == "github.com"
        assert git_url.owner == "zero-day-ai"
        assert git_url.repo == "gibson-prompt-library"

        # Verify the platform enum has .value attribute
        assert hasattr(git_url.platform, "value")
        assert git_url.platform.value == "github"

    def test_parse_github_https_url_complete_flow(self, parser):
        """Test parsing GitHub HTTPS URL through complete flow."""
        url = "https://github.com/zero-day-ai/gibson-prompt-library.git"

        # Test validation
        is_valid, error = parser.validate_url(url)
        assert is_valid is True

        # Test parsing
        git_url = parser.parse(url)

        assert isinstance(git_url.platform, GitPlatform)
        assert git_url.platform == GitPlatform.GITHUB
        assert git_url.protocol == "https"
        assert git_url.host == "github.com"
        assert git_url.owner == "zero-day-ai"
        assert git_url.repo == "gibson-prompt-library"

    def test_parse_gitlab_urls(self, parser):
        """Test parsing GitLab URLs."""
        test_cases = [
            ("https://gitlab.com/group/project.git", GitPlatform.GITLAB),
            ("git@gitlab.com:group/project.git", GitPlatform.GITLAB),
        ]

        for url, expected_platform in test_cases:
            git_url = parser.parse(url)
            assert isinstance(git_url.platform, GitPlatform)
            assert git_url.platform == expected_platform
            assert hasattr(git_url.platform, "value")

    def test_parse_bitbucket_urls(self, parser):
        """Test parsing Bitbucket URLs."""
        test_cases = [
            ("https://bitbucket.org/team/repo.git", GitPlatform.BITBUCKET),
            ("git@bitbucket.org:team/repo.git", GitPlatform.BITBUCKET),
        ]

        for url, expected_platform in test_cases:
            git_url = parser.parse(url)
            assert isinstance(git_url.platform, GitPlatform)
            assert git_url.platform == expected_platform

    def test_parse_gogs_url(self, parser):
        """Test parsing GOGS URL."""
        url = "https://gogs.example.com/user/repo.git"

        git_url = parser.parse(url)
        assert isinstance(git_url.platform, GitPlatform)
        assert git_url.platform == GitPlatform.GOGS
        assert git_url.host == "gogs.example.com"

    def test_parse_gitea_url(self, parser):
        """Test parsing Gitea URL."""
        url = "https://gitea.example.com/org/project.git"

        git_url = parser.parse(url)
        assert isinstance(git_url.platform, GitPlatform)
        assert git_url.platform == GitPlatform.GITEA
        assert git_url.host == "gitea.example.com"

    def test_parse_generic_git_url(self, parser):
        """Test parsing generic Git server URL."""
        url = "https://git.internal.company.com/team/project.git"

        git_url = parser.parse(url)
        assert isinstance(git_url.platform, GitPlatform)
        assert git_url.platform == GitPlatform.GENERIC
        assert git_url.host == "git.internal.company.com"

    def test_validation_rejects_shorthand(self, parser):
        """Test that validation properly rejects shorthand format."""
        is_valid, error = parser.validate_url("owner/repo")
        assert is_valid is False
        assert "shorthand" in error.lower() or "full" in error.lower()

    def test_validation_rejects_invalid_urls(self, parser):
        """Test validation rejects invalid URLs."""
        invalid_urls = [
            "",
            "not-a-url",
            "http://",
            "git@",
            "https://github.com",  # No repo
        ]

        for url in invalid_urls:
            is_valid, error = parser.validate_url(url)
            assert is_valid is False
            assert error is not None

    def test_parse_preserves_branch_info(self, parser):
        """Test that branch information is preserved during parsing."""
        # GitHub tree URL
        url = "https://github.com/owner/repo/tree/feature-branch"
        git_url = parser.parse(url)
        assert git_url.branch == "feature-branch"

        # Default branch when not specified
        url = "https://github.com/owner/repo.git"
        git_url = parser.parse(url)
        assert git_url.branch == "main"

    def test_parse_handles_subpaths(self, parser):
        """Test parsing URLs with subpaths."""
        url = "https://github.com/owner/repo/tree/main/src/components"
        git_url = parser.parse(url)
        assert git_url.path == "src/components"
        assert git_url.branch == "main"

    def test_platform_enum_regression(self, parser):
        """Regression test for platform being string instead of enum.

        This test ensures that the platform field is always a GitPlatform enum,
        not a string, which was causing AttributeError when accessing .value.
        Bug: 'str' object has no attribute 'value' in logger.debug line.
        """
        # Test SSH URL that was originally failing
        url = "git@github.com:zero-day-ai/gibson-prompt-library.git"

        # Parse should succeed without AttributeError
        git_url = parser.parse(url)

        # Platform MUST be an enum instance
        assert isinstance(
            git_url.platform, GitPlatform
        ), f"Platform should be GitPlatform enum, got {type(git_url.platform)}"

        # Should be able to access .value attribute
        assert hasattr(git_url.platform, "value"), "Platform enum should have .value attribute"

        # Value should be correct
        assert (
            git_url.platform.value == "github"
        ), f"Expected 'github' value, got {git_url.platform.value}"

        # Enum should be the correct one
        assert (
            git_url.platform == GitPlatform.GITHUB
        ), f"Expected GITHUB platform, got {git_url.platform}"

    def test_platform_detection_consistency(self, parser):
        """Test that platform detection is consistent between detect_platform and parse."""
        test_urls = [
            "https://github.com/owner/repo.git",
            "https://gitlab.com/group/project.git",
            "https://bitbucket.org/team/repo.git",
            "https://gogs.example.com/user/repo.git",
        ]

        for url in test_urls:
            # Detect platform directly
            detected_platform = parser.detect_platform(url)

            # Parse and get platform
            git_url = parser.parse(url)

            # They should match and both be enums
            assert isinstance(detected_platform, GitPlatform)
            assert isinstance(git_url.platform, GitPlatform)
            assert detected_platform == git_url.platform

    def test_parse_handles_ports(self, parser):
        """Test parsing URLs with custom ports."""
        url = "https://git.example.com:8080/team/project.git"
        git_url = parser.parse(url)
        assert git_url.port == 8080
        assert git_url.host == "git.example.com"

    def test_parse_strips_git_extension(self, parser):
        """Test that .git extension is properly handled."""
        urls_with_git = [
            "https://github.com/owner/repo.git",
            "git@github.com:owner/repo.git",
        ]

        urls_without_git = [
            "https://github.com/owner/repo",
            "git@github.com:owner/repo",
        ]

        for url_with, url_without in zip(urls_with_git, urls_without_git):
            git_url_with = parser.parse(url_with)
            git_url_without = parser.parse(url_without)

            # Both should parse to the same repo name
            assert git_url_with.repo == "repo"
            assert git_url_without.repo == "repo"
            assert git_url_with.repo == git_url_without.repo
