"""Git repository URL models and enums for multi-platform support."""

from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional, List
from urllib.parse import parse_qs, urlparse

from pydantic import Field, field_validator, ConfigDict

from gibson.models.base import GibsonBaseModel


class GitPlatform(str, Enum):
    """Supported Git platforms."""
    GITHUB = "github"
    GITLAB = "gitlab"
    BITBUCKET = "bitbucket"
    GOGS = "gogs"
    GITEA = "gitea"
    GENERIC = "generic"  # Self-hosted or unknown


class GitURL(GibsonBaseModel):
    """Parsed Git repository URL with platform detection."""
    
    model_config = ConfigDict(use_enum_values=False)  # Keep enums as enums

    platform: GitPlatform = Field(GitPlatform.GENERIC, description="Git hosting platform")
    protocol: str = Field(..., description="URL protocol (https, ssh, git)")
    host: str = Field(..., description="Git host domain")
    owner: str = Field(..., description="Repository owner/organization")
    repo: str = Field(..., description="Repository name")
    branch: Optional[str] = Field("main", description="Branch or tag reference")
    path: Optional[str] = Field(None, description="Subpath within repository")
    port: Optional[int] = Field(None, description="Port for self-hosted Git servers")
    
    @field_validator('platform', mode='before')
    @classmethod
    def ensure_platform_enum(cls, v):
        """Ensure platform is always a GitPlatform enum."""
        if isinstance(v, str):
            # Convert string to enum if needed
            return GitPlatform(v)
        return v

    @classmethod
    def from_url(cls, url: str) -> "GitURL":
        """Parse a Git URL string into GitURL model.

        Args:
            url: Git repository URL in any common format

        Returns:
            Parsed GitURL instance

        Raises:
            ValueError: If URL format is invalid
        """
        # Remove trailing slashes and whitespace
        url = url.strip().rstrip('/')

        # Check for shorthand format (should be rejected)
        if '/' in url and not any(prefix in url for prefix in ['://', '@']):
            if url.count('/') == 1:  # Looks like owner/repo format
                raise ValueError(
                    f"Full Git URL required. Use: https://github.com/{url}.git instead of {url}"
                )

        # Handle SSH format (git@host:owner/repo.git)
        if url.startswith('git@'):
            return cls._parse_ssh_url(url)

        # Parse standard URL formats
        parsed = urlparse(url)

        if not parsed.scheme:
            raise ValueError(f"Invalid Git URL: {url}. Must include protocol (https://, git://, ssh://)")

        if not parsed.hostname:
            raise ValueError(f"Invalid Git URL: {url}. No hostname found")

        # Extract path components
        path_parts = parsed.path.strip('/').split('/')

        # Handle case where URL might be missing components for custom domains
        if len(path_parts) < 2 or not path_parts[0] or (len(path_parts) > 1 and not path_parts[1]):
            # For URLs like https://github.internal.company.com/repo (missing owner)
            if len(path_parts) == 1 and path_parts[0]:
                # Try to construct with unknown owner
                owner = "unknown"
                repo = path_parts[0].removesuffix('.git')
            else:
                raise ValueError(f"Invalid Git URL: {url}. Expected format: https://host/owner/repo")
        else:
            owner = path_parts[0]
            repo_with_suffix = path_parts[1]
            # Remove .git suffix if present
            repo = repo_with_suffix.removesuffix('.git')

        # Extract branch from path or fragment
        branch = None
        subpath = None

        if len(path_parts) > 2:
            # Check for tree/blob pattern (GitHub/GitLab style)
            if path_parts[2] in ['tree', 'blob', '-/tree', '-/blob']:
                if len(path_parts) > 3:
                    branch = path_parts[3]
                if len(path_parts) > 4:
                    subpath = '/'.join(path_parts[4:])
            else:
                # Might be a direct path reference
                subpath = '/'.join(path_parts[2:])

        # Check fragment for branch reference
        if parsed.fragment and not branch:
            if parsed.fragment.startswith('branch='):
                branch = parsed.fragment[7:]

        # Check query params for ref
        if parsed.query:
            params = parse_qs(parsed.query)
            if 'ref' in params and not branch:
                branch = params['ref'][0]

        return cls(
            protocol=parsed.scheme,
            host=parsed.hostname,
            owner=owner,
            repo=repo,
            branch=branch or "main",
            path=subpath,
            port=parsed.port
        )

    @classmethod
    def _parse_ssh_url(cls, url: str) -> "GitURL":
        """Parse SSH format URLs (git@host:owner/repo.git).

        Args:
            url: SSH format Git URL

        Returns:
            Parsed GitURL instance
        """
        # Remove git@ prefix
        url_without_prefix = url[4:]

        # Split host and path
        if ':' not in url_without_prefix:
            raise ValueError(f"Invalid SSH Git URL: {url}")

        host, path = url_without_prefix.split(':', 1)

        # Parse path components
        path_parts = path.strip('/').split('/')
        if len(path_parts) < 2:
            raise ValueError(f"Invalid SSH Git URL: {url}. Expected git@host:owner/repo")

        owner = path_parts[0]
        repo = path_parts[1].removesuffix('.git')

        # SSH URLs typically don't include branch in URL
        return cls(
            protocol="ssh",
            host=host,
            owner=owner,
            repo=repo,
            branch="main",
            path=None,
            port=None
        )

    def detect_platform_from_host(self) -> GitPlatform:
        """Detect Git platform from host.

        Returns:
            Detected Git platform enum value
        """
        host_lower = self.host.lower()

        # Exact domain matches first
        if host_lower == 'github.com' or host_lower.endswith('.github.com'):
            return GitPlatform.GITHUB
        elif host_lower == 'gitlab.com' or host_lower.endswith('.gitlab.com'):
            return GitPlatform.GITLAB
        elif host_lower == 'bitbucket.org' or host_lower.endswith('.bitbucket.org'):
            return GitPlatform.BITBUCKET
        # Check for GitHub Pages (github.io) - these are not Git repos
        elif host_lower.endswith('.github.io'):
            return GitPlatform.GENERIC
        # Pattern matches for self-hosted platforms
        elif host_lower.startswith('gogs.'):
            return GitPlatform.GOGS
        elif host_lower.startswith('gitea.'):
            return GitPlatform.GITEA
        # Check for GitHub Enterprise (but not false positives)
        elif host_lower.startswith('github.') and not any(x in host_lower for x in ['.internal.', '.local.', '.company.', '.corp.']):
            return GitPlatform.GITHUB
        elif host_lower.startswith('gitlab.') and not any(x in host_lower for x in ['.internal.', '.local.', '.company.', '.corp.']):
            return GitPlatform.GITLAB
        elif host_lower.startswith('bitbucket.') and not any(x in host_lower for x in ['.internal.', '.local.', '.company.', '.corp.']):
            return GitPlatform.BITBUCKET
        else:
            return GitPlatform.GENERIC

    @property
    def api_base(self) -> str:
        """Get API base URL for platform.

        Returns:
            API base URL string
        """
        if self.platform == GitPlatform.GITHUB:
            if self.host == "github.com":
                return "https://api.github.com"
            else:
                # GitHub Enterprise
                return f"https://{self.host}/api/v3"
        elif self.platform == GitPlatform.GITLAB:
            return f"https://{self.host}/api/v4"
        elif self.platform == GitPlatform.BITBUCKET:
            if self.host == "bitbucket.org":
                return "https://api.bitbucket.org/2.0"
            else:
                # Bitbucket Server
                return f"https://{self.host}/rest/api/1.0"
        elif self.platform == GitPlatform.GOGS:
            return f"https://{self.host}/api/v1"
        elif self.platform == GitPlatform.GITEA:
            return f"https://{self.host}/api/v1"
        else:
            # Generic - no standard API
            return f"https://{self.host}"

    @property
    def clone_url(self) -> str:
        """Get the URL suitable for git clone operations.

        Returns:
            Clone URL string
        """
        if self.protocol == "ssh":
            return f"git@{self.host}:{self.owner}/{self.repo}.git"
        else:
            port_str = f":{self.port}" if self.port else ""
            return f"{self.protocol}://{self.host}{port_str}/{self.owner}/{self.repo}.git"

    def validate(self) -> bool:
        """Validate that the URL components are valid.

        Returns:
            True if valid, raises ValueError if not
        """
        if not self.protocol:
            raise ValueError("Protocol is required")
        if not self.host:
            raise ValueError("Host is required")
        if not self.owner:
            raise ValueError("Repository owner is required")
        if not self.repo:
            raise ValueError("Repository name is required")

        # Validate protocol
        valid_protocols = ['https', 'http', 'ssh', 'git']
        if self.protocol not in valid_protocols:
            raise ValueError(f"Invalid protocol: {self.protocol}. Must be one of {valid_protocols}")

        return True

    def to_https_url(self) -> str:
        """Convert to HTTPS URL for public access.
        
        Returns:
            HTTPS URL string for public access
        """
        port_str = f":{self.port}" if self.port else ""
        return f"https://{self.host}{port_str}/{self.owner}/{self.repo}.git"
    
    def to_ssh_url(self) -> str:
        """Convert to SSH URL for key-based authentication.
        
        Returns:
            SSH URL string for key-based access
        """
        return f"git@{self.host}:{self.owner}/{self.repo}.git"
    
    def to_authenticated_url(self, token: str) -> str:
        """Convert to token-authenticated HTTPS URL.
        
        Args:
            token: Authentication token
            
        Returns:
            HTTPS URL with embedded token authentication
        """
        port_str = f":{self.port}" if self.port else ""
        # For GitHub/GitLab, token can be used as username with empty password
        return f"https://{token}@{self.host}{port_str}/{self.owner}/{self.repo}.git"
    
    def get_clone_url_candidates(self) -> List[str]:
        """Get ordered list of URLs to try for authentication escalation.
        
        Returns:
            List of URLs in order of preference (public, SSH, then token)
        """
        candidates = [
            self.to_https_url(),  # Try public access first
            self.to_ssh_url(),    # Try SSH key authentication
        ]
        return candidates

    def __str__(self) -> str:
        """String representation of the Git URL."""
        return self.clone_url


class GitCredentials(GibsonBaseModel):
    """Per-host Git credentials storage model."""

    host: str = Field(..., description="Git host domain")
    auth_type: str = Field(..., description="Authentication type (token, oauth, ssh, basic)")
    username: Optional[str] = Field(None, description="Username for authentication")
    token: Optional[str] = Field(None, description="Authentication token (encrypted)")
    ssh_key_path: Optional[Path] = Field(None, description="Path to SSH private key")
    expires_at: Optional[datetime] = Field(None, description="Token expiration time")

    @field_validator('auth_type')
    @classmethod
    def validate_auth_type(cls, v: str) -> str:
        """Validate authentication type."""
        valid_types = ['token', 'oauth', 'ssh', 'basic']
        if v not in valid_types:
            raise ValueError(f"Invalid auth_type: {v}. Must be one of {valid_types}")
        return v

    @field_validator('ssh_key_path')
    @classmethod
    def validate_ssh_key_path(cls, v: Optional[Path]) -> Optional[Path]:
        """Validate SSH key path exists if provided."""
        if v and not v.exists():
            raise ValueError(f"SSH key file not found: {v}")
        return v

    @property
    def is_expired(self) -> bool:
        """Check if credentials have expired.

        Returns:
            True if expired, False otherwise
        """
        if not self.expires_at:
            return False
        return datetime.utcnow() > self.expires_at

    def get_auth_headers(self) -> dict:
        """Get authentication headers for HTTP requests.

        Returns:
            Dictionary of HTTP headers
        """
        if self.auth_type == 'token':
            if self.host.endswith('github.com'):
                return {'Authorization': f'Bearer {self.token}'}
            elif self.host.endswith('gitlab.com'):
                return {'PRIVATE-TOKEN': self.token}
            else:
                return {'Authorization': f'Bearer {self.token}'}
        elif self.auth_type == 'basic':
            import base64
            credentials = base64.b64encode(f"{self.username}:{self.token}".encode()).decode()
            return {'Authorization': f'Basic {credentials}'}
        elif self.auth_type == 'oauth':
            return {'Authorization': f'Bearer {self.token}'}
        else:
            return {}
