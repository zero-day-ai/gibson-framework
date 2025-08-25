"""GitSync - GitPython-based Git repository operations."""

import asyncio
import os
import shutil
import time
from pathlib import Path
from typing import Optional, List, Callable, Any, Dict

import git
from git import Repo, GitCommandError
from loguru import logger

from gibson.core.payloads.auth_prompt import TokenPrompter
from gibson.core.payloads.git_models import GitURL, GitPlatform
from gibson.core.payloads.models.git_sync import (
    AuthMethod,
    CloneResult,
    UpdateResult,
    RepositoryInfo,
    GitSyncError,
    GitOperationError,
    AuthenticationError,
    RepositoryAccessError,
    NetworkError,
    GitSyncConfig,
)


class GitSync:
    """GitPython-based Git operations with authentication escalation."""

    def __init__(
        self, workspace_dir: Path, shallow: bool = True, config: Optional[GitSyncConfig] = None
    ):
        """Initialize GitSync with workspace configuration.

        Args:
            workspace_dir: Directory for Git operations
            shallow: Use shallow clones by default
            config: GitSync configuration options
        """
        self.workspace_dir = Path(workspace_dir)
        self.shallow = shallow
        self.config = config or GitSyncConfig()
        self.token_prompter = TokenPrompter(interactive=True)

        # Ensure workspace directory exists
        self.workspace_dir.mkdir(parents=True, exist_ok=True)

        logger.debug(f"GitSync initialized with workspace: {self.workspace_dir}")

    async def clone_repository(
        self,
        git_url: GitURL,
        target_path: Optional[Path] = None,
        branch: Optional[str] = None,
        tag: Optional[str] = None,
        sparse_patterns: Optional[List[str]] = None,
    ) -> CloneResult:
        """Clone a Git repository with authentication escalation.

        Args:
            git_url: Git URL to clone
            target_path: Target directory (defaults to workspace/repo_name)
            branch: Specific branch to clone
            tag: Specific tag to clone
            sparse_patterns: Sparse checkout patterns

        Returns:
            CloneResult with operation details
        """
        start_time = time.time()

        # Determine target path
        if not target_path:
            target_path = self.workspace_dir / git_url.repo

        # Ensure parent directory exists
        target_path.parent.mkdir(parents=True, exist_ok=True)

        logger.info(f"Cloning repository: {git_url} to {target_path}")

        # Use branch or tag if specified, otherwise use URL's branch
        ref = tag or branch or git_url.branch or "main"

        try:
            # Attempt clone with authentication escalation
            repo, auth_method = await self._try_operation_with_auth_escalation(
                self._clone_operation,
                git_url,
                target_path=target_path,
                ref=ref,
                sparse_patterns=sparse_patterns,
            )

            # Get repository info
            commit_hash = repo.head.commit.hexsha
            current_branch = repo.active_branch.name if repo.active_branch else ref

            # Calculate repository size
            repo_size = self._calculate_directory_size(target_path)

            duration = time.time() - start_time

            logger.info(
                f"Successfully cloned {git_url.repo} in {duration:.2f}s using {auth_method.value}"
            )

            return CloneResult(
                success=True,
                repo_path=target_path,
                commit_hash=commit_hash,
                branch=current_branch,
                auth_method_used=auth_method,
                clone_size_mb=repo_size,
                clone_duration_seconds=duration,
                is_shallow=self.shallow,
                sparse_patterns=sparse_patterns,
            )

        except Exception as e:
            duration = time.time() - start_time
            error_msg = str(e)

            logger.error(f"Failed to clone {git_url}: {error_msg}")

            # Clean up failed clone attempt
            if target_path.exists():
                try:
                    shutil.rmtree(target_path)
                except Exception as cleanup_error:
                    logger.warning(f"Failed to cleanup after failed clone: {cleanup_error}")

            return CloneResult(
                success=False,
                repo_path=target_path,
                commit_hash="",
                branch=ref,
                auth_method_used=AuthMethod.FAILED,
                clone_size_mb=0.0,
                clone_duration_seconds=duration,
                is_shallow=self.shallow,
                sparse_patterns=sparse_patterns,
                error_message=error_msg,
            )

    async def update_repository(
        self, repo_path: Path, branch: Optional[str] = None, tag: Optional[str] = None
    ) -> UpdateResult:
        """Update an existing Git repository.

        Args:
            repo_path: Path to existing repository
            branch: Branch to update to
            tag: Tag to update to

        Returns:
            UpdateResult with operation details
        """
        start_time = time.time()

        if not repo_path.exists():
            raise GitOperationError(f"Repository path does not exist: {repo_path}")

        try:
            repo = Repo(repo_path)

            # Get current commit
            old_commit = repo.head.commit.hexsha

            # Determine target ref
            target_ref = tag or branch
            current_branch = repo.active_branch.name if repo.active_branch else "HEAD"

            logger.info(f"Updating repository: {repo_path}")

            # Get remote URL for authentication
            remote_url = repo.remotes.origin.url
            git_url = GitURL.from_url(remote_url)

            # Try update with authentication escalation
            updated_repo, auth_method = await self._try_operation_with_auth_escalation(
                self._update_operation, git_url, repo=repo, target_ref=target_ref
            )

            # Get new commit
            new_commit = updated_repo.head.commit.hexsha
            updated = old_commit != new_commit

            # Count changed files if updated
            files_changed = None
            if updated:
                try:
                    diff = updated_repo.git.diff(f"{old_commit}..{new_commit}", name_only=True)
                    files_changed = len(diff.splitlines()) if diff else 0
                except Exception:
                    files_changed = None

            duration = time.time() - start_time

            if updated:
                logger.info(
                    f"Repository updated: {old_commit[:8]} -> {new_commit[:8]} in {duration:.2f}s"
                )
            else:
                logger.info(f"Repository already up to date: {new_commit[:8]} in {duration:.2f}s")

            return UpdateResult(
                success=True,
                updated=updated,
                old_commit=old_commit,
                new_commit=new_commit,
                branch=current_branch,
                auth_method_used=auth_method,
                files_changed=files_changed,
                update_duration_seconds=duration,
            )

        except Exception as e:
            duration = time.time() - start_time
            error_msg = str(e)

            logger.error(f"Failed to update repository {repo_path}: {error_msg}")

            return UpdateResult(
                success=False,
                updated=False,
                old_commit="",
                new_commit="",
                branch="",
                auth_method_used=AuthMethod.FAILED,
                files_changed=None,
                update_duration_seconds=duration,
                error_message=error_msg,
            )

    async def get_repository_info(self, repo_path: Path) -> RepositoryInfo:
        """Get information about a Git repository.

        Args:
            repo_path: Path to repository

        Returns:
            RepositoryInfo with repository metadata
        """
        if not repo_path.exists():
            raise GitOperationError(f"Repository path does not exist: {repo_path}")

        try:
            repo = Repo(repo_path)

            # Get current commit and branch
            commit_hash = repo.head.commit.hexsha
            branch = repo.active_branch.name if repo.active_branch else "HEAD"

            # Get remote URL
            remote_url = repo.remotes.origin.url if repo.remotes else ""

            # Check if shallow
            is_shallow = repo.git.rev_parse("--is-shallow-repository").strip() == "true"

            # Get tags
            tags = [tag.name for tag in repo.tags]

            # Calculate size and file count
            size_mb = self._calculate_directory_size(repo_path)
            file_count = self._count_files(repo_path)

            # Get last commit date as proxy for last updated
            last_updated = repo.head.commit.committed_datetime

            return RepositoryInfo(
                commit_hash=commit_hash,
                branch=branch,
                remote_url=remote_url,
                is_shallow=is_shallow,
                last_updated=last_updated,
                size_mb=size_mb,
                file_count=file_count,
                tags=tags,
            )

        except Exception as e:
            raise GitOperationError(f"Failed to get repository info: {e}")

    async def _try_operation_with_auth_escalation(
        self, operation: Callable, git_url: GitURL, **operation_kwargs
    ) -> tuple[Any, AuthMethod]:
        """Try Git operation with authentication escalation.

        Args:
            operation: Git operation function to call
            git_url: Git URL for the operation
            **operation_kwargs: Additional arguments for operation

        Returns:
            Tuple of (operation_result, auth_method_used)

        Raises:
            GitSyncError: If all authentication methods fail
        """
        # Tier 1: Try public access
        try:
            logger.debug(f"Trying public access for {git_url.host}")
            result = await operation(git_url.to_https_url(), **operation_kwargs)
            return result, AuthMethod.PUBLIC
        except GitCommandError as e:
            if self._is_auth_error(e):
                logger.debug(f"Public access failed for {git_url.host}: authentication required")
            else:
                # Non-auth error, don't try other methods
                raise GitOperationError(f"Git operation failed: {e}")
        except Exception as e:
            if "authentication" in str(e).lower() or "permission" in str(e).lower():
                logger.debug(f"Public access failed for {git_url.host}: {e}")
            else:
                raise GitOperationError(f"Git operation failed: {e}")

        # Tier 2: Try SSH keys
        if self._has_ssh_keys():
            try:
                logger.debug(f"Trying SSH key authentication for {git_url.host}")
                result = await operation(git_url.to_ssh_url(), **operation_kwargs)
                return result, AuthMethod.SSH_KEY
            except GitCommandError as e:
                if self._is_auth_error(e):
                    logger.debug(f"SSH authentication failed for {git_url.host}")
                else:
                    raise GitOperationError(f"Git operation failed: {e}")
            except Exception as e:
                if "authentication" in str(e).lower() or "permission" in str(e).lower():
                    logger.debug(f"SSH authentication failed for {git_url.host}: {e}")
                else:
                    raise GitOperationError(f"Git operation failed: {e}")
        else:
            logger.debug("No SSH keys available, skipping SSH authentication")

        # Tier 3: Prompt for token
        token = self.token_prompter.prompt_for_token(git_url)
        if token:
            try:
                logger.debug(f"Trying token authentication for {git_url.host}")
                auth_url = git_url.to_authenticated_url(token)
                result = await operation(auth_url, **operation_kwargs)
                return result, AuthMethod.TOKEN
            except GitCommandError as e:
                if self._is_auth_error(e):
                    logger.error(f"Token authentication failed for {git_url.host}: invalid token")
                    raise AuthenticationError("Invalid authentication token", AuthMethod.FAILED)
                else:
                    raise GitOperationError(f"Git operation failed: {e}")
            except Exception as e:
                if "authentication" in str(e).lower() or "permission" in str(e).lower():
                    raise AuthenticationError(
                        f"Token authentication failed: {e}", AuthMethod.FAILED
                    )
                else:
                    raise GitOperationError(f"Git operation failed: {e}")
        else:
            logger.error("No authentication token provided")

        # All authentication methods exhausted
        instructions = self.token_prompter.get_auth_instructions(git_url)
        raise AuthenticationError(
            f"All authentication methods failed for {git_url.host}. {instructions}",
            AuthMethod.FAILED,
        )

    def _has_ssh_keys(self) -> bool:
        """Check if SSH keys are available.

        Returns:
            True if SSH keys are likely available
        """
        ssh_dir = Path.home() / ".ssh"
        if not ssh_dir.exists():
            return False

        # Common SSH key names
        key_names = ["id_rsa", "id_ed25519", "id_ecdsa", "github_rsa", "gitlab_rsa"]

        for key_name in key_names:
            key_path = ssh_dir / key_name
            if key_path.exists() and key_path.stat().st_size > 0:
                return True

        return False

    def _is_auth_error(self, error: Exception) -> bool:
        """Check if error is authentication-related.

        Args:
            error: Exception to check

        Returns:
            True if error is authentication-related
        """
        error_str = str(error).lower()
        auth_indicators = [
            "authentication failed",
            "permission denied",
            "access denied",
            "not authorized",
            "unauthorized",
            "invalid credentials",
            "bad credentials",
            "could not read username",
            "repository not found",  # Often means private repo without access
            "fatal: authentication failed",
        ]

        return any(indicator in error_str for indicator in auth_indicators)

    async def _clone_operation(
        self,
        clone_url: str,
        target_path: Path,
        ref: str,
        sparse_patterns: Optional[List[str]] = None,
    ) -> Repo:
        """Perform the actual clone operation.

        Args:
            clone_url: URL to clone from
            target_path: Target directory
            ref: Branch/tag reference
            sparse_patterns: Sparse checkout patterns

        Returns:
            Cloned repository
        """
        clone_kwargs = {
            "to_path": str(target_path),
            "branch": ref,
        }

        # Add shallow clone if enabled
        if self.shallow:
            clone_kwargs["depth"] = 1

        # Clone repository
        repo = Repo.clone_from(clone_url, **clone_kwargs)

        # Set up sparse checkout if patterns provided
        if sparse_patterns and self.config.enable_sparse_checkout:
            await self._setup_sparse_checkout(repo, sparse_patterns)

        return repo

    async def _update_operation(
        self, remote_url: str, repo: Repo, target_ref: Optional[str] = None
    ) -> Repo:
        """Perform the actual update operation.

        Args:
            remote_url: Remote URL (used for auth, but repo already has remote)
            repo: Repository to update
            target_ref: Target reference to update to

        Returns:
            Updated repository
        """
        # Update remote URL if it has changed (for auth)
        origin = repo.remotes.origin
        if origin.url != remote_url:
            origin.set_url(remote_url)

        # Fetch updates
        origin.fetch()

        # Checkout target ref if specified
        if target_ref:
            # Check if it's a tag or branch
            try:
                # Try as branch first
                origin_ref = getattr(origin.refs, target_ref, None)
                if origin_ref:
                    repo.git.checkout(target_ref)
                    repo.git.pull()
                else:
                    # Try as tag
                    repo.git.checkout(target_ref)
            except GitCommandError:
                # Fall back to current branch
                repo.git.pull()
        else:
            # Update current branch
            repo.git.pull()

        return repo

    async def _setup_sparse_checkout(self, repo: Repo, patterns: List[str]) -> None:
        """Set up sparse checkout for repository.

        Args:
            repo: Repository to configure
            patterns: Sparse checkout patterns
        """
        try:
            # Enable sparse checkout
            repo.git.config("core.sparseCheckout", "true")

            # Write sparse checkout patterns
            sparse_checkout_file = Path(repo.git_dir) / "info" / "sparse-checkout"
            sparse_checkout_file.parent.mkdir(exist_ok=True)

            with open(sparse_checkout_file, "w") as f:
                for pattern in patterns:
                    f.write(f"{pattern}\n")

            # Apply sparse checkout
            repo.git.read_tree("-m", "-u", "HEAD")

            logger.debug(f"Sparse checkout configured with {len(patterns)} patterns")

        except Exception as e:
            logger.warning(f"Failed to setup sparse checkout: {e}")

    def _calculate_directory_size(self, path: Path) -> float:
        """Calculate directory size in MB.

        Args:
            path: Directory path

        Returns:
            Size in MB
        """
        try:
            total_size = 0
            for dirpath, dirnames, filenames in os.walk(path):
                for filename in filenames:
                    filepath = os.path.join(dirpath, filename)
                    try:
                        total_size += os.path.getsize(filepath)
                    except (OSError, FileNotFoundError):
                        pass
            return round(total_size / (1024 * 1024), 2)
        except Exception:
            return 0.0

    def _count_files(self, path: Path) -> int:
        """Count files in directory.

        Args:
            path: Directory path

        Returns:
            Number of files
        """
        try:
            file_count = 0
            for dirpath, dirnames, filenames in os.walk(path):
                # Skip .git directory
                if ".git" in dirpath:
                    continue
                file_count += len(filenames)
            return file_count
        except Exception:
            return 0
