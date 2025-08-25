"""URL parser utility for Git repository URLs."""

import re
from typing import Optional, Tuple
from urllib.parse import urlparse

from loguru import logger

from gibson.core.payloads.git_models import GitPlatform, GitURL


class URLParser:
    """Simplified parser for Git repository URLs.

    This parser is now a thin wrapper around GitURL.from_url() and focuses
    on validation and platform detection. HTTP-specific logic has been removed
    as GitSync handles all Git operations natively.
    """

    def __init__(self):
        """Initialize URL parser."""
        pass

    @staticmethod
    def get_platform_value(platform: GitPlatform | str) -> str:
        """Safely get platform value string.

        Args:
            platform: Platform enum or string

        Returns:
            Platform value string
        """
        if isinstance(platform, GitPlatform):
            return platform.value
        return str(platform)

    def parse(self, url: str) -> GitURL:
        """Parse any Git URL format into GitURL model.

        Args:
            url: Git repository URL in any common format

        Returns:
            Parsed GitURL instance

        Raises:
            ValueError: If URL format is invalid
        """
        if not url:
            raise ValueError("URL cannot be empty")

        # Clean the URL
        url = url.strip()

        # Reject shorthand format (e.g., "owner/repo")
        if "/" in url and not any(prefix in url for prefix in ["://", "@", ".git"]):
            if url.count("/") == 1:  # Looks like owner/repo
                raise ValueError(
                    f"Full Git URL required. Use: https://github.com/{url}.git instead of {url}"
                )

        # Parse using GitURL model
        try:
            git_url = GitURL.from_url(url)
            # Auto-detect platform from host
            git_url.platform = git_url.detect_platform_from_host()

            platform_value = self.get_platform_value(git_url.platform)
            logger.debug(f"Successfully parsed URL: {url} -> {platform_value} platform")

            return git_url
        except ValueError as e:
            logger.error(f"Failed to parse URL {url}: {e}")
            raise

    def validate_url(self, url: str) -> Tuple[bool, Optional[str]]:
        """Validate a Git repository URL.

        Args:
            url: URL to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            self.parse(url)
            return True, None
        except ValueError as e:
            return False, str(e)

    def normalize_url(self, url: str) -> str:
        """Normalize a Git URL to a standard format.

        Args:
            url: URL to normalize

        Returns:
            Normalized URL string
        """
        try:
            git_url = self.parse(url)
            return git_url.clone_url
        except ValueError:
            return url

    def get_example_urls(self, platform: Optional[GitPlatform] = None) -> list:
        """Get example URLs for specified platform or all platforms.

        Args:
            platform: Specific platform to get examples for (None for all)

        Returns:
            List of example URL strings
        """
        examples = {
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
            GitPlatform.GENERIC: [
                "https://git.company.com/owner/repo.git",
                "ssh://git@git.company.com:2222/owner/repo.git",
            ],
        }

        if platform:
            return examples.get(platform, [])

        # Return all examples
        all_examples = []
        for platform_examples in examples.values():
            all_examples.extend(platform_examples)
        return all_examples
