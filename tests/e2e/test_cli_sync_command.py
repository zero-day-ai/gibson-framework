"""
End-to-end tests for the CLI sync command.

These tests reproduce the exact command-line usage that's failing.
"""

import pytest
import asyncio
from unittest.mock import patch, Mock, AsyncMock
from io import StringIO
import sys


class TestCLISyncCommand:
    """Test the actual CLI sync command as users would run it."""
    
    @pytest.mark.e2e
    def test_exact_failing_command(self):
        """
        Reproduce the exact failing command:
        python3 -m gibson.main payloads sync https://github.com/zero-day-ai/gibson-prompt-library
        
        This test should FAIL with the current bug (Red phase of TDD).
        """
        from gibson.cli.commands.payloads import sync_repository
        from gibson.core.payloads.url_parser import URLParser
        from gibson.core.payloads.git_models import GitPlatform
        
        # The exact URL that's failing
        url = "https://github.com/zero-day-ai/gibson-prompt-library"
        
        # First, test URL parsing in isolation
        parser = URLParser()
        git_url = parser.parse(url)
        
        # This assertion should pass now that we handle enums properly
        assert git_url.platform == GitPlatform.GITHUB, \
            f"URL detected as {git_url.platform} instead of GitPlatform.GITHUB"
    
    @pytest.mark.e2e
    @pytest.mark.asyncio
    async def test_full_cli_sync_flow(self):
        """Test the complete CLI sync flow with mocked network calls."""
        # Import here to avoid import errors if module structure changes
        from gibson.core.payloads.manager import PayloadManager
        
        url = "https://github.com/zero-day-ai/gibson-prompt-library"
        
        # Mock the entire flow with GitSync
        with patch('gibson.core.payloads.manager.GitSync') as MockGitSync:
            mock_git_sync = AsyncMock()
            MockGitSync.return_value = mock_git_sync
            
            # Mock successful clone
            from gibson.core.payloads.models.git_sync import CloneResult, AuthMethod
            from pathlib import Path
            
            mock_git_sync.clone_repository = AsyncMock(return_value=CloneResult(
                success=True,
                repo_path=Path("/tmp/test-repo"),
                commit_hash="abc123",
                branch="main",
                auth_method_used=AuthMethod.PUBLIC,
                clone_size_mb=10.5,
                clone_duration_seconds=2.5,
                is_shallow=True,
                error_message=None
            ))
            
            # Run the sync
            manager = PayloadManager()
            async with manager:
                result = await manager.sync_repository(url)
            
            # Verify the clone was attempted
            assert mock_git_sync.clone_repository.called
            # Result should be successful
            assert result.success is True
    
    @pytest.mark.e2e
    def test_cli_error_messages(self):
        """Test that CLI provides helpful error messages."""
        from gibson.core.payloads.url_parser import URLParser
        
        parser = URLParser()
        
        # Test shorthand format error
        is_valid, error_msg = parser.validate_url("owner/repo")
        assert not is_valid
        assert "full" in error_msg.lower() or "shorthand" in error_msg.lower()
        
        # Error message should include examples
        assert "example" in error_msg.lower() or "https://" in error_msg.lower()


class TestCLIErrorReproduction:
    """Specific tests to reproduce and diagnose the GOGS error."""
    
    @pytest.mark.e2e
    def test_diagnose_gogs_error(self, capsys):
        """
        Diagnostic test to understand why GitHub is detected as GOGS.
        Run with: pytest -s tests/e2e/test_cli_sync_command.py::TestCLIErrorReproduction::test_diagnose_gogs_error
        """
        from gibson.core.payloads.url_parser import URLParser
        from gibson.core.payloads.git_models import GitPlatform, GitURL
        
        url = "https://github.com/zero-day-ai/gibson-prompt-library"
        parser = URLParser()
        
        print("\n" + "="*70)
        print("DIAGNOSING GOGS ERROR")
        print("="*70)
        print(f"URL: {url}")
        print()
        
        # Test detection method directly
        detected_platform = parser.detect_platform(url)
        print(f"detect_platform() returned: {detected_platform.value}")
        print(f"Expected: {GitPlatform.GITHUB.value}")
        print()
        
        # Parse the URL
        try:
            git_url = parser.parse(url)
            print(f"parse() returned platform: {git_url.platform.value}")
            print(f"parse() returned host: {git_url.host}")
            print(f"parse() returned owner: {git_url.owner}")
            print(f"parse() returned repo: {git_url.repo}")
        except Exception as e:
            print(f"parse() raised exception: {e}")
        
        print()
        print("Platform enum values:")
        for platform in GitPlatform:
            print(f"  {platform.name} = {platform.value}")
        
        print()
        print("URL string checks:")
        print(f"  'github.com' in url: {'github.com' in url}")
        print(f"  'gogs' in url.lower(): {'gogs' in url.lower()}")
        print(f"  url.startswith('https://github.com'): {url.startswith('https://github.com')}")
        
        print("="*70)
        
        # The actual assertion that should fail if bug exists
        assert git_url.platform == GitPlatform.GITHUB, \
            f"BUG CONFIRMED: {git_url.platform.value} != github"
    
    @pytest.mark.e2e
    def test_all_platforms_not_confused(self):
        """Ensure no platform is confused with another."""
        from gibson.core.payloads.url_parser import URLParser
        from gibson.core.payloads.git_models import GitPlatform
        
        parser = URLParser()
        
        # Test URLs for each platform
        platform_urls = {
            GitPlatform.GITHUB: "https://github.com/owner/repo",
            GitPlatform.GITLAB: "https://gitlab.com/owner/repo",
            GitPlatform.BITBUCKET: "https://bitbucket.org/owner/repo",
            GitPlatform.GITEA: "https://gitea.example.com/owner/repo",
            GitPlatform.GOGS: "https://gogs.example.com/owner/repo",
        }
        
        errors = []
        for expected_platform, url in platform_urls.items():
            git_url = parser.parse(url)
            if git_url.platform != expected_platform:
                errors.append(
                    f"{url} detected as {git_url.platform.value} "
                    f"instead of {expected_platform.value}"
                )
        
        assert not errors, f"Platform detection errors:\n" + "\n".join(errors)


class TestTDDWorkflow:
    """
    Demonstrate TDD workflow for fixing the bug.
    
    TDD Steps:
    1. Write test that fails (Red)
    2. Fix code to make test pass (Green)
    3. Refactor if needed (Refactor)
    """
    
    @pytest.mark.e2e
    def test_step1_red_phase(self):
        """
        Step 1 (RED): Write a test that demonstrates the bug.
        This test should FAIL with the current implementation.
        """
        from gibson.core.payloads.url_parser import URLParser
        from gibson.core.payloads.git_models import GitPlatform
        
        parser = URLParser()
        url = "https://github.com/zero-day-ai/gibson-prompt-library"
        
        git_url = parser.parse(url)
        
        # This should fail if bug exists (RED phase)
        assert git_url.platform == GitPlatform.GITHUB, \
            "RED PHASE: Test fails, bug confirmed"
    
    @pytest.mark.e2e
    @pytest.mark.skip(reason="Only run after fixing the bug")
    def test_step2_green_phase(self):
        """
        Step 2 (GREEN): After fixing the bug, this test should pass.
        
        The fix should be in URLParser.detect_platform() or parse() method.
        Ensure GitHub detection happens before GOGS detection.
        """
        from gibson.core.payloads.url_parser import URLParser
        from gibson.core.payloads.git_models import GitPlatform
        
        parser = URLParser()
        
        # All these should now work correctly
        test_urls = [
            "https://github.com/zero-day-ai/gibson-prompt-library",
            "https://github.com/owner/repo",
            "https://github.com/owner/repo.git",
        ]
        
        for url in test_urls:
            git_url = parser.parse(url)
            assert git_url.platform == GitPlatform.GITHUB, \
                f"GREEN PHASE: {url} should be GitHub after fix"
    
    @pytest.mark.e2e
    @pytest.mark.skip(reason="Only run after implementing the fix")
    def test_step3_refactor_phase(self):
        """
        Step 3 (REFACTOR): Ensure the fix doesn't break other platforms.
        
        After fixing GitHub detection, verify all platforms still work.
        """
        from gibson.core.payloads.url_parser import URLParser
        from gibson.core.payloads.git_models import GitPlatform
        
        parser = URLParser()
        
        # Comprehensive platform test after refactoring
        all_platforms = {
            "https://github.com/owner/repo": GitPlatform.GITHUB,
            "https://gitlab.com/owner/repo": GitPlatform.GITLAB,
            "https://bitbucket.org/owner/repo": GitPlatform.BITBUCKET,
            "https://gitea.example.com/owner/repo": GitPlatform.GITEA,
            "https://gogs.example.com/owner/repo": GitPlatform.GOGS,
            "https://custom-git.com/owner/repo": GitPlatform.GENERIC,
        }
        
        for url, expected_platform in all_platforms.items():
            git_url = parser.parse(url)
            assert git_url.platform == expected_platform, \
                f"REFACTOR PHASE: {url} should be {expected_platform.value}"