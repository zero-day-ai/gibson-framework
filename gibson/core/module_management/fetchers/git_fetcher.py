"""Git repository fetcher for modules."""

import asyncio
import re
import shutil
from pathlib import Path
from typing import Dict, Optional, Any
from urllib.parse import urlparse
from loguru import logger

from gibson.core.module_management.fetchers.base_fetcher import BaseFetcher
from gibson.core.module_management.exceptions import ModuleInstallationError


class GitFetcher(BaseFetcher):
    """Fetches modules from Git repositories."""
    
    # Pattern for GitHub/GitLab shorthand (owner/repo)
    SHORTHAND_PATTERN = re.compile(r'^[\w\-]+/[\w\-]+$')
    
    # Git URL patterns
    GIT_URL_PATTERNS = [
        re.compile(r'^https?://.*\.git$'),
        re.compile(r'^git@.*:.*\.git$'),
        re.compile(r'^git://.*'),
        re.compile(r'^ssh://.*'),
        re.compile(r'^https?://github\.com/.*'),
        re.compile(r'^https?://gitlab\.com/.*'),
        re.compile(r'^https?://bitbucket\.org/.*')
    ]
    
    async def fetch(
        self,
        source: str,
        target_dir: Path,
        options: Optional[Dict[str, Any]] = None
    ) -> Path:
        """
        Fetch module from Git repository.
        
        Args:
            source: Git URL or shorthand (e.g., "owner/repo")
            target_dir: Directory to clone repository to
            options: Additional options (branch, tag, commit)
            
        Returns:
            Path to the cloned repository
        """
        options = options or {}
        
        # Convert shorthand to full URL
        if self.SHORTHAND_PATTERN.match(source):
            source = f"https://github.com/{source}.git"
        
        # Ensure target directory exists
        self._ensure_target_dir(target_dir)
        
        # Generate unique directory name
        repo_name = self._get_repo_name(source)
        repo_path = target_dir / repo_name
        
        # Remove if exists
        if repo_path.exists():
            shutil.rmtree(repo_path)
        
        try:
            # Build git clone command
            cmd = ["git", "clone"]
            
            # Add branch/tag if specified
            if "branch" in options:
                cmd.extend(["-b", options["branch"]])
            elif "tag" in options:
                cmd.extend(["-b", options["tag"]])
            
            # Add depth for faster cloning
            if options.get("shallow", True):
                cmd.extend(["--depth", "1"])
            
            cmd.extend([source, str(repo_path)])
            
            logger.info(f"Cloning repository: {source}")
            
            # Run git clone
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                error_msg = stderr.decode() if stderr else stdout.decode()
                raise ModuleInstallationError(
                    f"Failed to clone repository: {error_msg}"
                )
            
            # Checkout specific commit if specified
            if "commit" in options:
                await self._checkout_commit(repo_path, options["commit"])
            
            # Find module directory (might be in subdirectory)
            module_path = await self._find_module_directory(repo_path)
            
            logger.info(f"Successfully fetched module from {source}")
            return module_path
            
        except Exception as e:
            logger.error(f"Failed to fetch from Git: {e}")
            if repo_path.exists():
                shutil.rmtree(repo_path)
            raise ModuleInstallationError(f"Git fetch failed: {e}")
    
    async def validate_source(self, source: str) -> bool:
        """Check if source is a valid Git repository."""
        # Check shorthand pattern
        if self.SHORTHAND_PATTERN.match(source):
            return True
        
        # Check Git URL patterns
        for pattern in self.GIT_URL_PATTERNS:
            if pattern.match(source):
                return True
        
        return False
    
    def _get_repo_name(self, url: str) -> str:
        """Extract repository name from URL."""
        if self.SHORTHAND_PATTERN.match(url):
            return url.split("/")[-1]
        
        # Parse URL
        parsed = urlparse(url)
        path = parsed.path.rstrip("/")
        
        # Remove .git extension
        if path.endswith(".git"):
            path = path[:-4]
        
        # Get last part of path
        return path.split("/")[-1] or "module"
    
    async def _checkout_commit(self, repo_path: Path, commit: str) -> None:
        """Checkout specific commit."""
        cmd = ["git", "checkout", commit]
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=repo_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            error_msg = stderr.decode() if stderr else stdout.decode()
            raise ModuleInstallationError(
                f"Failed to checkout commit {commit}: {error_msg}"
            )
    
    async def _find_module_directory(self, repo_path: Path) -> Path:
        """
        Find the actual module directory within the repository.
        
        Looks for:
        1. gibson/ subdirectory
        2. module/ subdirectory
        3. src/ subdirectory
        4. Root directory if module files are present
        """
        # Check for common module directories
        for subdir in ["gibson", "module", "src"]:
            module_dir = repo_path / subdir
            if module_dir.exists() and module_dir.is_dir():
                # Check if it contains module files
                if self._is_module_directory(module_dir):
                    return module_dir
        
        # Check root directory
        if self._is_module_directory(repo_path):
            return repo_path
        
        # Default to root
        return repo_path
    
    def _is_module_directory(self, path: Path) -> bool:
        """Check if directory contains module files."""
        # Look for indicators of a Gibson module
        indicators = [
            "__init__.py",
            "module.py",
            "module.json",
            "module.yaml",
            "gibson.json",
            "gibson.yaml"
        ]
        
        for indicator in indicators:
            if (path / indicator).exists():
                return True
        
        return False