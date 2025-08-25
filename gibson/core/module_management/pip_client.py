"""
Async pip client for managing Python package dependencies.

Provides async wrapper around pip operations for installing,
updating, and managing Python packages.
"""

import asyncio
import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from loguru import logger

from gibson.core.module_management.exceptions import DependencyError


class PipClient:
    """Async client for pip operations."""

    def __init__(self, python_executable: Optional[str] = None):
        """
        Initialize pip client.

        Args:
            python_executable: Path to Python executable (defaults to sys.executable)
        """
        self.python_executable = python_executable or sys.executable
        self._installed_cache: Dict[str, str] = {}
        self._last_cache_update = 0
        self._cache_ttl = 300  # 5 minutes

    async def install_package(
        self,
        package: str,
        version_spec: Optional[str] = None,
        upgrade: bool = False,
        force_reinstall: bool = False,
        extra_args: Optional[List[str]] = None,
    ) -> bool:
        """
        Install a Python package.

        Args:
            package: Package name
            version_spec: Version specification (e.g., ">=1.0.0")
            upgrade: Whether to upgrade if already installed
            force_reinstall: Force reinstallation
            extra_args: Additional pip arguments

        Returns:
            True if installation successful

        Raises:
            DependencyError: If installation fails
        """
        # Build package specification
        if version_spec and version_spec != "*":
            package_spec = f"{package}{version_spec}"
        else:
            package_spec = package

        # Build pip command
        cmd = [self.python_executable, "-m", "pip", "install"]

        if upgrade:
            cmd.append("--upgrade")

        if force_reinstall:
            cmd.append("--force-reinstall")

        if extra_args:
            cmd.extend(extra_args)

        cmd.append(package_spec)

        try:
            logger.info(f"Installing package: {package_spec}")

            # Run pip install
            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                logger.info(f"Successfully installed {package_spec}")
                # Invalidate cache
                self._installed_cache.clear()
                return True
            else:
                error_msg = stderr.decode() if stderr else stdout.decode()
                raise DependencyError(f"Failed to install {package_spec}: {error_msg}")

        except Exception as e:
            logger.error(f"Failed to install {package_spec}: {e}")
            raise DependencyError(f"Installation failed: {e}")

    async def install_packages(
        self, packages: List[str], upgrade: bool = False, continue_on_error: bool = False
    ) -> Dict[str, bool]:
        """
        Install multiple packages.

        Args:
            packages: List of package specifications
            upgrade: Whether to upgrade existing packages
            continue_on_error: Continue if a package fails

        Returns:
            Dictionary mapping package to installation success
        """
        results = {}

        for package_spec in packages:
            try:
                success = await self.install_package(package_spec, upgrade=upgrade)
                results[package_spec] = success
            except Exception as e:
                logger.error(f"Failed to install {package_spec}: {e}")
                results[package_spec] = False

                if not continue_on_error:
                    break

        return results

    async def uninstall_package(self, package: str, auto_confirm: bool = True) -> bool:
        """
        Uninstall a Python package.

        Args:
            package: Package name
            auto_confirm: Auto-confirm uninstallation

        Returns:
            True if uninstallation successful
        """
        cmd = [self.python_executable, "-m", "pip", "uninstall"]

        if auto_confirm:
            cmd.append("-y")

        cmd.append(package)

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                logger.info(f"Successfully uninstalled {package}")
                # Invalidate cache
                self._installed_cache.clear()
                return True
            else:
                logger.warning(f"Failed to uninstall {package}")
                return False

        except Exception as e:
            logger.error(f"Failed to uninstall {package}: {e}")
            return False

    async def get_installed_packages(self, force_refresh: bool = False) -> Dict[str, str]:
        """
        Get list of installed packages with versions.

        Args:
            force_refresh: Force cache refresh

        Returns:
            Dictionary mapping package name to version
        """
        import time

        current_time = time.time()

        # Check cache
        if (
            not force_refresh
            and self._installed_cache
            and current_time - self._last_cache_update < self._cache_ttl
        ):
            return self._installed_cache.copy()

        try:
            cmd = [self.python_executable, "-m", "pip", "list", "--format", "json"]

            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                packages = json.loads(stdout.decode())
                self._installed_cache = {pkg["name"].lower(): pkg["version"] for pkg in packages}
                self._last_cache_update = current_time
                return self._installed_cache.copy()
            else:
                logger.error(f"Failed to list packages: {stderr.decode()}")
                return {}

        except Exception as e:
            logger.error(f"Failed to get installed packages: {e}")
            return {}

    async def check_package_installed(
        self, package: str, version_spec: Optional[str] = None
    ) -> bool:
        """
        Check if a package is installed.

        Args:
            package: Package name
            version_spec: Optional version specification to check

        Returns:
            True if package is installed (and meets version spec)
        """
        installed = await self.get_installed_packages()
        package_lower = package.lower()

        if package_lower not in installed:
            return False

        if not version_spec or version_spec == "*":
            return True

        # Check version specification
        try:
            from packaging import version
            from packaging.specifiers import SpecifierSet

            installed_version = version.parse(installed[package_lower])
            specifier = SpecifierSet(version_spec)

            return installed_version in specifier
        except Exception as e:
            logger.warning(f"Failed to check version spec: {e}")
            return True  # Assume it's okay if we can't parse

    async def get_package_info(self, package: str) -> Optional[Dict]:
        """
        Get detailed information about a package.

        Args:
            package: Package name

        Returns:
            Package information dictionary or None
        """
        try:
            cmd = [self.python_executable, "-m", "pip", "show", package, "--json"]

            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                # pip show doesn't support --json, parse text output
                lines = stdout.decode().split("\n")
                info = {}

                for line in lines:
                    if ":" in line:
                        key, value = line.split(":", 1)
                        info[key.strip().lower().replace("-", "_")] = value.strip()

                return info
            else:
                return None

        except Exception as e:
            logger.error(f"Failed to get package info: {e}")
            return None

    async def check_for_updates(
        self, packages: Optional[List[str]] = None
    ) -> Dict[str, Tuple[str, str]]:
        """
        Check for available updates.

        Args:
            packages: Specific packages to check (None for all)

        Returns:
            Dictionary mapping package to (current_version, latest_version)
        """
        try:
            cmd = [self.python_executable, "-m", "pip", "list", "--outdated", "--format", "json"]

            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                outdated = json.loads(stdout.decode())
                updates = {}

                for pkg in outdated:
                    name = pkg["name"].lower()
                    if packages is None or name in [p.lower() for p in packages]:
                        updates[name] = (pkg["version"], pkg["latest_version"])

                return updates
            else:
                logger.error(f"Failed to check for updates: {stderr.decode()}")
                return {}

        except Exception as e:
            logger.error(f"Failed to check for updates: {e}")
            return {}

    async def freeze_requirements(self, output_file: Optional[Path] = None) -> List[str]:
        """
        Get frozen requirements list.

        Args:
            output_file: Optional file to write requirements to

        Returns:
            List of requirement specifications
        """
        try:
            cmd = [self.python_executable, "-m", "pip", "freeze"]

            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                requirements = stdout.decode().strip().split("\n")

                if output_file:
                    output_file.write_text("\n".join(requirements))
                    logger.info(f"Wrote requirements to {output_file}")

                return requirements
            else:
                logger.error(f"Failed to freeze requirements: {stderr.decode()}")
                return []

        except Exception as e:
            logger.error(f"Failed to freeze requirements: {e}")
            return []

    async def install_from_requirements(
        self, requirements_file: Path, upgrade: bool = False
    ) -> bool:
        """
        Install packages from requirements file.

        Args:
            requirements_file: Path to requirements.txt
            upgrade: Whether to upgrade packages

        Returns:
            True if installation successful
        """
        if not requirements_file.exists():
            raise DependencyError(f"Requirements file not found: {requirements_file}")

        try:
            cmd = [self.python_executable, "-m", "pip", "install", "-r", str(requirements_file)]

            if upgrade:
                cmd.append("--upgrade")

            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                logger.info(f"Successfully installed from {requirements_file}")
                # Invalidate cache
                self._installed_cache.clear()
                return True
            else:
                error_msg = stderr.decode() if stderr else stdout.decode()
                raise DependencyError(f"Failed to install from requirements: {error_msg}")

        except Exception as e:
            logger.error(f"Failed to install from requirements: {e}")
            raise DependencyError(f"Installation failed: {e}")
