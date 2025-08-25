"""Interactive token prompting for Git authentication."""

import getpass
import os
import sys
from typing import Optional, Dict, Tuple

from loguru import logger

from gibson.core.payloads.git_models import GitPlatform, GitURL


class TokenPrompter:
    """Interactive token prompting with platform-specific guidance."""
    
    def __init__(self, interactive: bool = True):
        """Initialize token prompter.
        
        Args:
            interactive: Whether to allow interactive prompting
        """
        self.interactive = interactive
        self._platform_guidance = {
            GitPlatform.GITHUB: {
                'token_name': 'Personal Access Token',
                'token_url': 'https://github.com/settings/tokens',
                'scopes': ['repo', 'read:org'],
                'format_hint': 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
                'prefixes': ['ghp_', 'github_pat_']
            },
            GitPlatform.GITLAB: {
                'token_name': 'Personal Access Token',
                'token_url': 'https://gitlab.com/-/profile/personal_access_tokens',
                'scopes': ['read_repository', 'write_repository'],
                'format_hint': 'glpat-xxxxxxxxxxxxxxxxxxxx',
                'prefixes': ['glpat-']
            },
            GitPlatform.BITBUCKET: {
                'token_name': 'App Password',
                'token_url': 'https://bitbucket.org/account/settings/app-passwords/',
                'scopes': ['Repositories: Read', 'Repositories: Write'],
                'format_hint': 'ATBBxxxxxxxxxxxxxxxx',
                'prefixes': ['ATBB']
            },
            GitPlatform.GENERIC: {
                'token_name': 'Access Token or Password',
                'token_url': 'Check your Git platform\'s documentation',
                'scopes': ['Repository access'],
                'format_hint': 'Platform-specific token format',
                'prefixes': []
            }
        }
    
    def prompt_for_token(self, git_url: GitURL) -> Optional[str]:
        """Prompt user for authentication token.
        
        Args:
            git_url: Git URL that needs authentication
            
        Returns:
            Authentication token or None if cancelled/failed
        """
        if not self.interactive:
            logger.error("Token required but running in non-interactive mode")
            return None
        
        # Check if running in non-TTY environment
        if not sys.stdin.isatty():
            logger.error("Cannot prompt for token: not running in interactive terminal")
            return None
        
        platform = git_url.platform
        guidance = self._platform_guidance.get(platform, self._platform_guidance[GitPlatform.GENERIC])
        
        # Display platform-specific guidance
        self._display_token_guidance(git_url.host, platform, guidance)
        
        # Prompt for token
        try:
            token = getpass.getpass(f"Enter {guidance['token_name']} for {git_url.host}: ")
            
            if not token:
                logger.info("Token entry cancelled")
                return None
            
            # Basic validation
            if not self._validate_token_format(token, platform, guidance):
                logger.warning("Token format may be invalid, but will attempt authentication")
            
            return token.strip()
            
        except KeyboardInterrupt:
            print("\nToken entry cancelled by user")
            return None
        except Exception as e:
            logger.error(f"Failed to prompt for token: {e}")
            return None
    
    def prompt_for_credentials(self, git_url: GitURL) -> Optional[Tuple[str, str]]:
        """Prompt user for username and password/token.
        
        Args:
            git_url: Git URL that needs authentication
            
        Returns:
            Tuple of (username, password) or None if cancelled/failed
        """
        if not self.interactive or not sys.stdin.isatty():
            return None
        
        try:
            print(f"\nAuthentication required for {git_url.host}")
            username = input(f"Username for {git_url.host}: ")
            
            if not username:
                logger.info("Username entry cancelled")
                return None
            
            password = getpass.getpass(f"Password/Token for {username}@{git_url.host}: ")
            
            if not password:
                logger.info("Password entry cancelled")
                return None
            
            return username.strip(), password.strip()
            
        except KeyboardInterrupt:
            print("\nCredential entry cancelled by user")
            return None
        except Exception as e:
            logger.error(f"Failed to prompt for credentials: {e}")
            return None
    
    def _display_token_guidance(self, host: str, platform: GitPlatform, guidance: Dict) -> None:
        """Display platform-specific token guidance.
        
        Args:
            host: Git host domain
            platform: Git platform type
            guidance: Platform-specific guidance dictionary
        """
        print(f"\n🔐 Authentication required for {host}")
        print(f"Platform: {platform.value.title()}")
        print()
        
        if platform != GitPlatform.GENERIC:
            print(f"You need a {guidance['token_name']} to access this repository.")
            print(f"Create one at: {guidance['token_url']}")
            print()
            
            if guidance.get('scopes'):
                print("Required scopes/permissions:")
                for scope in guidance['scopes']:
                    print(f"  • {scope}")
                print()
        
        if guidance.get('format_hint'):
            print(f"Token format: {guidance['format_hint']}")
            print()
    
    def _validate_token_format(self, token: str, platform: GitPlatform, guidance: Dict) -> bool:
        """Validate token format for platform.
        
        Args:
            token: Authentication token
            platform: Git platform type
            guidance: Platform-specific guidance
            
        Returns:
            True if token format appears valid
        """
        if not token or len(token) < 8:
            return False
        
        prefixes = guidance.get('prefixes', [])
        if prefixes:
            # Check if token starts with any expected prefix
            return any(token.startswith(prefix) for prefix in prefixes)
        
        # Generic validation - just check it's not obviously wrong
        return len(token) >= 8
    
    def check_environment_token(self, git_url: GitURL) -> Optional[str]:
        """Check for authentication token in environment variables.
        
        Args:
            git_url: Git URL to find token for
            
        Returns:
            Token from environment or None
        """
        # Platform-specific environment variable patterns
        env_patterns = []
        
        if git_url.platform == GitPlatform.GITHUB:
            env_patterns = [
                'GITHUB_TOKEN',
                'GITHUB_PAT', 
                'GH_TOKEN',
                f'GITHUB_TOKEN_{git_url.host.upper().replace(".", "_")}'
            ]
        elif git_url.platform == GitPlatform.GITLAB:
            env_patterns = [
                'GITLAB_TOKEN',
                'GITLAB_PAT',
                'GL_TOKEN',
                f'GITLAB_TOKEN_{git_url.host.upper().replace(".", "_")}'
            ]
        elif git_url.platform == GitPlatform.BITBUCKET:
            env_patterns = [
                'BITBUCKET_TOKEN',
                'BITBUCKET_PASSWORD',
                'BB_TOKEN',
                f'BITBUCKET_TOKEN_{git_url.host.upper().replace(".", "_")}'
            ]
        
        # Generic patterns
        host_clean = git_url.host.upper().replace(".", "_").replace("-", "_")
        env_patterns.extend([
            f'GIT_TOKEN_{host_clean}',
            f'TOKEN_{host_clean}',
            'GIT_TOKEN',
            'SCM_TOKEN'
        ])
        
        # Check each pattern
        for pattern in env_patterns:
            token = os.getenv(pattern)
            if token:
                logger.debug(f"Found authentication token in environment variable: {pattern}")
                return token
        
        return None
    
    def is_interactive_available(self) -> bool:
        """Check if interactive prompting is available.
        
        Returns:
            True if can prompt interactively
        """
        return (
            self.interactive and
            sys.stdin.isatty() and
            sys.stdout.isatty()
        )
    
    def get_auth_instructions(self, git_url: GitURL) -> str:
        """Get human-readable authentication instructions.
        
        Args:
            git_url: Git URL that needs authentication
            
        Returns:
            Formatted authentication instructions
        """
        platform = git_url.platform
        guidance = self._platform_guidance.get(platform, self._platform_guidance[GitPlatform.GENERIC])
        
        instructions = [
            f"Authentication required for {git_url.host}",
            f"Platform: {platform.value.title()}",
            ""
        ]
        
        if platform != GitPlatform.GENERIC:
            instructions.extend([
                f"Create a {guidance['token_name']} at:",
                f"  {guidance['token_url']}",
                ""
            ])
            
            if guidance.get('scopes'):
                instructions.append("Required permissions:")
                for scope in guidance['scopes']:
                    instructions.append(f"  • {scope}")
                instructions.append("")
        
        instructions.extend([
            "You can provide authentication via:",
            "1. Interactive prompt (when available)",
            "2. Environment variables:",
            f"   - GITHUB_TOKEN (for GitHub)",
            f"   - GITLAB_TOKEN (for GitLab)", 
            f"   - BITBUCKET_TOKEN (for Bitbucket)",
            f"   - GIT_TOKEN_{git_url.host.upper().replace('.', '_')} (host-specific)",
            "3. SSH keys (automatic detection)"
        ])
        
        return "\n".join(instructions)


def prompt_for_token(git_url: GitURL, interactive: bool = True) -> Optional[str]:
    """Convenience function to prompt for authentication token.
    
    Args:
        git_url: Git URL that needs authentication
        interactive: Whether to allow interactive prompting
        
    Returns:
        Authentication token or None
    """
    prompter = TokenPrompter(interactive=interactive)
    
    # First check environment variables
    env_token = prompter.check_environment_token(git_url)
    if env_token:
        return env_token
    
    # Then try interactive prompting
    return prompter.prompt_for_token(git_url)


def get_auth_instructions(git_url: GitURL) -> str:
    """Get authentication instructions for a Git URL.
    
    Args:
        git_url: Git URL that needs authentication
        
    Returns:
        Formatted authentication instructions
    """
    prompter = TokenPrompter()
    return prompter.get_auth_instructions(git_url)