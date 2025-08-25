"""Local file system fetcher for modules."""

import shutil
import tarfile
import zipfile
from pathlib import Path
from typing import Dict, Optional, Any
from loguru import logger

from gibson.core.module_management.fetchers.base_fetcher import BaseFetcher
from gibson.core.module_management.exceptions import ModuleInstallationError


class LocalFetcher(BaseFetcher):
    """Fetches modules from local file system."""
    
    async def fetch(
        self,
        source: str,
        target_dir: Path,
        options: Optional[Dict[str, Any]] = None
    ) -> Path:
        """
        Fetch module from local file system.
        
        Args:
            source: Path to local module (directory or archive)
            target_dir: Directory to copy module to
            options: Additional options (symlink, etc.)
            
        Returns:
            Path to the fetched module
        """
        options = options or {}
        source_path = Path(source).expanduser().resolve()
        
        # Validate source exists
        if not source_path.exists():
            raise ModuleInstallationError(
                f"Local source not found: {source_path}"
            )
        
        # Ensure target directory exists
        self._ensure_target_dir(target_dir)
        
        try:
            if source_path.is_dir():
                # Copy directory
                module_path = await self._copy_directory(
                    source_path,
                    target_dir,
                    options
                )
            elif source_path.is_file():
                # Handle archive files
                if self._is_archive(source_path):
                    module_path = await self._extract_archive(
                        source_path,
                        target_dir
                    )
                else:
                    raise ModuleInstallationError(
                        f"File is not a supported archive format: {source_path}"
                    )
            else:
                raise ModuleInstallationError(
                    f"Source is neither file nor directory: {source_path}"
                )
            
            logger.info(f"Successfully fetched module from {source_path}")
            return module_path
            
        except Exception as e:
            logger.error(f"Failed to fetch from local source: {e}")
            raise ModuleInstallationError(f"Local fetch failed: {e}")
    
    async def validate_source(self, source: str) -> bool:
        """Check if source is a valid local path."""
        try:
            path = Path(source).expanduser()
            # Check if it's a local path (not URL-like)
            if "://" in source:
                return False
            # Accept absolute or relative paths
            return True
        except Exception:
            return False
    
    async def _copy_directory(
        self,
        source_path: Path,
        target_dir: Path,
        options: Dict[str, Any]
    ) -> Path:
        """Copy directory to target location."""
        # Generate target path
        module_name = source_path.name
        target_path = target_dir / module_name
        
        # Remove if exists
        if target_path.exists():
            if options.get("overwrite", True):
                shutil.rmtree(target_path)
            else:
                raise ModuleInstallationError(
                    f"Target already exists: {target_path}"
                )
        
        if options.get("symlink", False):
            # Create symlink instead of copying
            target_path.symlink_to(source_path)
            logger.info(f"Created symlink from {target_path} to {source_path}")
        else:
            # Copy directory
            shutil.copytree(
                source_path,
                target_path,
                ignore=shutil.ignore_patterns(
                    "*.pyc",
                    "__pycache__",
                    ".git",
                    ".pytest_cache",
                    "*.egg-info"
                )
            )
            logger.info(f"Copied module from {source_path} to {target_path}")
        
        return target_path
    
    async def _extract_archive(
        self,
        archive_path: Path,
        target_dir: Path
    ) -> Path:
        """Extract archive to target location."""
        # Determine archive type and extract
        extract_dir = target_dir / archive_path.stem
        
        # Remove if exists
        if extract_dir.exists():
            shutil.rmtree(extract_dir)
        
        try:
            if archive_path.suffix == ".gz" and archive_path.stem.endswith(".tar"):
                # tar.gz archive
                with tarfile.open(archive_path, "r:gz") as tar:
                    tar.extractall(extract_dir)
                    logger.info(f"Extracted tar.gz archive to {extract_dir}")
            elif archive_path.suffix == ".tar":
                # tar archive
                with tarfile.open(archive_path, "r") as tar:
                    tar.extractall(extract_dir)
                    logger.info(f"Extracted tar archive to {extract_dir}")
            elif archive_path.suffix == ".zip":
                # zip archive
                with zipfile.ZipFile(archive_path, "r") as zip_file:
                    zip_file.extractall(extract_dir)
                    logger.info(f"Extracted zip archive to {extract_dir}")
            else:
                raise ModuleInstallationError(
                    f"Unsupported archive format: {archive_path.suffix}"
                )
            
            # Find module directory within extracted content
            module_dir = self._find_module_directory(extract_dir)
            
            # If module is in a subdirectory, move it up
            if module_dir != extract_dir:
                # Move contents to extract_dir
                temp_dir = target_dir / f"{archive_path.stem}_temp"
                shutil.move(str(module_dir), str(temp_dir))
                shutil.rmtree(extract_dir)
                shutil.move(str(temp_dir), str(extract_dir))
                module_dir = extract_dir
            
            return module_dir
            
        except Exception as e:
            if extract_dir.exists():
                shutil.rmtree(extract_dir)
            raise ModuleInstallationError(f"Failed to extract archive: {e}")
    
    def _is_archive(self, path: Path) -> bool:
        """Check if file is a supported archive format."""
        supported_extensions = {
            ".tar", ".tar.gz", ".tgz",
            ".zip",
            ".tar.bz2", ".tbz2"
        }
        
        # Check single extension
        if path.suffix in supported_extensions:
            return True
        
        # Check double extension (e.g., .tar.gz)
        if len(path.suffixes) >= 2:
            double_ext = "".join(path.suffixes[-2:])
            if double_ext in supported_extensions:
                return True
        
        return False
    
    def _find_module_directory(self, extract_dir: Path) -> Path:
        """Find the actual module directory within extracted content."""
        # Check if extract_dir itself is the module
        if self._is_module_directory(extract_dir):
            return extract_dir
        
        # Check immediate subdirectories
        for item in extract_dir.iterdir():
            if item.is_dir() and self._is_module_directory(item):
                return item
        
        # Check one level deeper (common in archives)
        for item in extract_dir.iterdir():
            if item.is_dir():
                for subitem in item.iterdir():
                    if subitem.is_dir() and self._is_module_directory(subitem):
                        return subitem
        
        # Default to extract_dir
        return extract_dir
    
    def _is_module_directory(self, path: Path) -> bool:
        """Check if directory contains module files."""
        indicators = [
            "__init__.py",
            "module.py",
            "module.json",
            "module.yaml",
            "gibson.json",
            "gibson.yaml",
            "setup.py",
            "pyproject.toml"
        ]
        
        for indicator in indicators:
            if (path / indicator).exists():
                return True
        
        # Check for Python files
        if list(path.glob("*.py")):
            return True
        
        return False