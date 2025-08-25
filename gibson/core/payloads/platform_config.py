"""Platform detection configuration for Git URL parsing."""

import re
from re import Pattern

from gibson.core.payloads.git_models import GitPlatform

# Known domain to platform mapping for exact matches
KNOWN_DOMAINS: dict[str, GitPlatform] = {
    "github.com": GitPlatform.GITHUB,
    "gitlab.com": GitPlatform.GITLAB,
    "bitbucket.org": GitPlatform.BITBUCKET,
    # GOGS and Gitea typically use custom domains, not fixed ones
}

# URL pattern matching for platform detection
# Patterns are checked in order, first match wins
URL_PATTERNS: list[tuple[Pattern, GitPlatform]] = [
    (re.compile(r"github\.(com|io)", re.IGNORECASE), GitPlatform.GITHUB),
    (re.compile(r"gitlab\.(com|io)", re.IGNORECASE), GitPlatform.GITLAB),
    (re.compile(r"bitbucket\.(org|com)", re.IGNORECASE), GitPlatform.BITBUCKET),
    (re.compile(r"gogs\.", re.IGNORECASE), GitPlatform.GOGS),
    (re.compile(r"gitea\.", re.IGNORECASE), GitPlatform.GITEA),
]

# Platform detection priority order for resolving conflicts
# When multiple patterns match, this order determines which platform is selected
PLATFORM_PRIORITY: list[GitPlatform] = [
    GitPlatform.GITHUB,  # Check first (most common)
    GitPlatform.GITLAB,  # Second most common
    GitPlatform.BITBUCKET,  # Third
    GitPlatform.GOGS,  # Self-hosted platforms
    GitPlatform.GITEA,  # Self-hosted platforms
    GitPlatform.GENERIC,  # Fallback
]

# API endpoint patterns for platform detection via API probing
# These are relative paths that are checked to identify the platform
API_DETECTION_ENDPOINTS: dict[GitPlatform, str] = {
    GitPlatform.GITHUB: "/api/v3/meta",  # GitHub Enterprise endpoint
    GitPlatform.GITLAB: "/api/v4/version",
    GitPlatform.BITBUCKET: "/rest/api/1.0/application-properties",
    GitPlatform.GOGS: "/api/v1/version",
    GitPlatform.GITEA: "/api/v1/version",
}

# Subdomain prefixes that should be ignored when detecting platform
IGNORED_SUBDOMAINS = [
    "api",
    "raw",
    "gist",
    "www",
    "ssh",
    "git",
]
