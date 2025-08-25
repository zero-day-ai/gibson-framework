"""
Unit tests for URL platform detection - TDD approach to fix the GOGS bug.

This test file follows TDD principles:
1. Write failing tests first (Red)
2. Make tests pass (Green)  
3. Refactor if needed (Refactor)

The bug: GitHub URLs are being detected as GOGS platform.
"""

import pytest
from gibson.core.payloads.git_models import GitPlatform


class TestPlatformDetectionBug:
    """Tests specifically targeting the platform detection bug."""
    
    @pytest.mark.unit
    def test_github_url_not_detected_as_gogs(self, url_parser):
        """
        FAILING TEST (Red phase): GitHub URL should be detected as GITHUB, not GOGS.
        
        This is the exact URL that's failing in production.
        """
        url = "https://github.com/zero-day-ai/gibson-prompt-library"
        
        # Act
        git_url = url_parser.parse(url)
        
        # Assert - This should FAIL with current bug
        assert git_url.platform == GitPlatform.GITHUB, \
            f"Expected GITHUB but got {git_url.platform.value}"
        assert git_url.platform != GitPlatform.GOGS, \
            "GitHub URL incorrectly detected as GOGS"
    
    @pytest.mark.unit
    def test_github_urls_with_git_extension(self, url_parser):
        """Test GitHub URLs with .git extension are correctly detected."""
        url = "https://github.com/zero-day-ai/gibson-prompt-library.git"
        
        git_url = url_parser.parse(url)
        
        assert git_url.platform == GitPlatform.GITHUB
        assert git_url.owner == "zero-day-ai"
        assert git_url.repo == "gibson-prompt-library"
    
    @pytest.mark.unit
    @pytest.mark.parametrize("url", [
        "https://github.com/owner/repo",
        "https://github.com/owner/repo.git",
        "https://www.github.com/owner/repo",
        "http://github.com/owner/repo",
        "git@github.com:owner/repo.git",
        "ssh://git@github.com/owner/repo.git",
    ])
    def test_all_github_url_formats(self, url_parser, url):
        """Comprehensive test for all GitHub URL formats."""
        git_url = url_parser.parse(url)
        
        assert git_url.platform == GitPlatform.GITHUB, \
            f"URL {url} should be detected as GITHUB, got {git_url.platform.value}"


class TestPlatformDetectionOrder:
    """Test that platform detection happens in correct order."""
    
    @pytest.mark.unit
    def test_platform_detection_priority(self, url_parser):
        """
        Test that platform detection checks happen in the right order.
        GitHub should be checked before GOGS.
        """
        # URLs that might confuse the detector
        test_cases = [
            # GitHub should win even with 'gogs' in path
            ("https://github.com/gogs/repo", GitPlatform.GITHUB),
            ("https://github.com/user/gogs-clone", GitPlatform.GITHUB),
            
            # GOGS should only match actual GOGS domains
            ("https://gogs.example.com/user/repo", GitPlatform.GOGS),
            ("https://gogs.company.org/user/repo", GitPlatform.GOGS),
            
            # GitLab should win even with 'github' in path
            ("https://gitlab.com/github-backup/repo", GitPlatform.GITLAB),
        ]
        
        for url, expected_platform in test_cases:
            git_url = url_parser.parse(url)
            assert git_url.platform == expected_platform, \
                f"URL {url} should be {expected_platform.value}, got {git_url.platform.value}"


class TestRobustPlatformDetection:
    """Ensure platform detection is robust against edge cases."""
    
    @pytest.mark.unit
    def test_subdomain_does_not_affect_detection(self, url_parser):
        """Subdomains should not confuse platform detection."""
        test_cases = [
            # GitHub with subdomain
            ("https://api.github.com/owner/repo", GitPlatform.GITHUB),
            ("https://raw.github.com/owner/repo", GitPlatform.GITHUB),
            
            # Not GitHub despite having 'github' in subdomain
            ("https://github.internal.company.com/repo", GitPlatform.GENERIC),
            ("https://github.gitlab.com/repo", GitPlatform.GITLAB),
        ]
        
        for url, expected in test_cases:
            git_url = url_parser.parse(url)
            assert git_url.platform == expected, \
                f"URL {url} should be {expected.value}, got {git_url.platform.value}"
    
    @pytest.mark.unit
    def test_case_insensitive_detection(self, url_parser):
        """Platform detection should be case-insensitive."""
        test_cases = [
            "https://GitHub.com/owner/repo",
            "https://GITHUB.COM/owner/repo",
            "https://github.COM/owner/repo",
        ]
        
        for url in test_cases:
            git_url = url_parser.parse(url)
            assert git_url.platform == GitPlatform.GITHUB, \
                f"Case variation {url} should still be detected as GITHUB"
    
    @pytest.mark.unit
    def test_problematic_url_combinations(self, url_parser, problematic_urls):
        """Test URLs that might cause platform confusion."""
        for url, expected_platform in problematic_urls:
            git_url = url_parser.parse(url)
            assert git_url.platform == expected_platform, \
                f"URL {url} should be {expected_platform.value}, got {git_url.platform.value}"


class TestPlatformDetectionMethod:
    """Test the internal platform detection method if it exists."""
    
    @pytest.mark.unit
    def test_detect_platform_method(self, url_parser):
        """Test the detect_platform method directly."""
        test_cases = [
            ("https://github.com/owner/repo", GitPlatform.GITHUB),
            ("https://gitlab.com/owner/repo", GitPlatform.GITLAB),
            ("https://bitbucket.org/owner/repo", GitPlatform.BITBUCKET),
            ("https://gogs.example.com/owner/repo", GitPlatform.GOGS),
            ("https://gitea.example.com/owner/repo", GitPlatform.GITEA),
            ("https://random-git.com/owner/repo", GitPlatform.GENERIC),
        ]
        
        for url, expected in test_cases:
            detected = url_parser.detect_platform(url)
            assert detected == expected, \
                f"detect_platform({url}) should return {expected.value}, got {detected.value}"


# ========================================
# Debugging Helper Test
# ========================================

@pytest.mark.unit
def test_debug_platform_detection(url_parser):
    """
    Debug test to understand exactly what's happening with platform detection.
    Run with: pytest -s to see print output
    """
    url = "https://github.com/zero-day-ai/gibson-prompt-library"
    
    print(f"\n=== DEBUGGING PLATFORM DETECTION ===")
    print(f"URL: {url}")
    
    # Parse the URL
    git_url = url_parser.parse(url)
    
    print(f"Detected Platform: {git_url.platform.value}")
    print(f"Expected Platform: {GitPlatform.GITHUB.value}")
    print(f"Host: {git_url.host}")
    print(f"Owner: {git_url.owner}")
    print(f"Repo: {git_url.repo}")
    
    # Check string containment
    print(f"\nString checks:")
    print(f"  'github' in url.lower(): {'github' in url.lower()}")
    print(f"  'gogs' in url.lower(): {'gogs' in url.lower()}")
    print(f"  'gitlab' in url.lower(): {'gitlab' in url.lower()}")
    
    # This assertion will fail if bug exists
    assert git_url.platform == GitPlatform.GITHUB, \
        f"BUG CONFIRMED: Platform is {git_url.platform.value}, should be GITHUB"