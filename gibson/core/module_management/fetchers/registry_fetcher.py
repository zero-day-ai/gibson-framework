"""Registry fetcher for official Gibson modules."""

import asyncio
import json
import shutil
import tarfile
import zipfile
from pathlib import Path
from typing import Dict, Optional, Any
from urllib.parse import urljoin
from loguru import logger

try:
    import aiohttp
except ImportError:
    aiohttp = None

from gibson.core.module_management.fetchers.base_fetcher import BaseFetcher
from gibson.core.module_management.exceptions import ModuleInstallationError


class RegistryFetcher(BaseFetcher):
    """Fetches modules from Gibson module registry."""
    
    DEFAULT_REGISTRY_URL = "https://registry.gibson.ai/api/v1"
    
    def __init__(self, registry_url: Optional[str] = None):
        """
        Initialize registry fetcher.
        
        Args:
            registry_url: Custom registry URL (uses default if not provided)
        """
        self.registry_url = registry_url or self.DEFAULT_REGISTRY_URL
        self._session: Optional[aiohttp.ClientSession] = None
    
    async def fetch(
        self,
        source: str,
        target_dir: Path,
        options: Optional[Dict[str, Any]] = None
    ) -> Path:
        """
        Fetch module from registry.
        
        Args:
            source: Module name or name@version
            target_dir: Directory to download module to
            options: Additional options (auth token, etc.)
            
        Returns:
            Path to the downloaded module
        """
        if aiohttp is None:
            raise ModuleInstallationError(
                "aiohttp is required for registry fetching. Install with: pip install aiohttp"
            )
        
        options = options or {}
        
        # Parse module name and version
        if "@" in source:
            module_name, version = source.split("@", 1)
        else:
            module_name = source
            version = "latest"
        
        # Ensure target directory exists
        self._ensure_target_dir(target_dir)
        
        try:
            # Get module metadata from registry
            metadata = await self._get_module_metadata(module_name, version, options)
            
            if not metadata:
                raise ModuleInstallationError(
                    f"Module '{module_name}' not found in registry"
                )
            
            # Download module archive
            download_url = metadata.get("download_url")
            if not download_url:
                raise ModuleInstallationError(
                    f"No download URL for module '{module_name}'"
                )
            
            archive_path = await self._download_module(
                download_url,
                target_dir,
                module_name,
                options
            )
            
            # Extract archive
            module_path = await self._extract_archive(archive_path, target_dir)
            
            # Clean up archive
            archive_path.unlink()
            
            logger.info(f"Successfully fetched {module_name}@{version} from registry")
            return module_path
            
        except Exception as e:
            logger.error(f"Failed to fetch from registry: {e}")
            raise ModuleInstallationError(f"Registry fetch failed: {e}")
        finally:
            await self._cleanup_session()
    
    async def validate_source(self, source: str) -> bool:
        """Check if source is a valid registry module name."""
        # Simple validation - module names should be alphanumeric with hyphens
        if "@" in source:
            name, version = source.split("@", 1)
        else:
            name = source
        
        # Check name format
        import re
        pattern = r'^[a-zA-Z][a-zA-Z0-9\-_]*$'
        return bool(re.match(pattern, name))
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session
    
    async def _cleanup_session(self) -> None:
        """Clean up aiohttp session."""
        if self._session and not self._session.closed:
            await self._session.close()
    
    async def _get_module_metadata(
        self,
        module_name: str,
        version: str,
        options: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Get module metadata from registry."""
        session = await self._get_session()
        
        # Build metadata URL
        metadata_url = urljoin(
            self.registry_url,
            f"/modules/{module_name}/versions/{version}"
        )
        
        headers = {}
        if "auth_token" in options:
            headers["Authorization"] = f"Bearer {options['auth_token']}"
        
        try:
            async with session.get(metadata_url, headers=headers) as response:
                if response.status == 200:
                    return await response.json()
                elif response.status == 404:
                    return None
                else:
                    text = await response.text()
                    raise ModuleInstallationError(
                        f"Registry returned {response.status}: {text}"
                    )
        except aiohttp.ClientError as e:
            raise ModuleInstallationError(f"Registry connection failed: {e}")
    
    async def _download_module(
        self,
        download_url: str,
        target_dir: Path,
        module_name: str,
        options: Dict[str, Any]
    ) -> Path:
        """Download module archive from registry."""
        session = await self._get_session()
        
        headers = {}
        if "auth_token" in options:
            headers["Authorization"] = f"Bearer {options['auth_token']}"
        
        # Determine archive filename
        if download_url.endswith(".tar.gz"):
            archive_name = f"{module_name}.tar.gz"
        elif download_url.endswith(".zip"):
            archive_name = f"{module_name}.zip"
        else:
            archive_name = f"{module_name}.archive"
        
        archive_path = target_dir / archive_name
        
        try:
            async with session.get(download_url, headers=headers) as response:
                if response.status != 200:
                    text = await response.text()
                    raise ModuleInstallationError(
                        f"Download failed ({response.status}): {text}"
                    )
                
                # Stream download to file
                with open(archive_path, "wb") as f:
                    async for chunk in response.content.iter_chunked(8192):
                        f.write(chunk)
                
                logger.info(f"Downloaded module archive to {archive_path}")
                return archive_path
                
        except aiohttp.ClientError as e:
            if archive_path.exists():
                archive_path.unlink()
            raise ModuleInstallationError(f"Download failed: {e}")
    
    async def _extract_archive(self, archive_path: Path, target_dir: Path) -> Path:
        """Extract module archive."""
        extract_dir = target_dir / archive_path.stem
        
        # Remove if exists
        if extract_dir.exists():
            shutil.rmtree(extract_dir)
        
        try:
            if archive_path.suffix == ".gz" and archive_path.stem.endswith(".tar"):
                # tar.gz archive
                with tarfile.open(archive_path, "r:gz") as tar:
                    tar.extractall(extract_dir)
            elif archive_path.suffix == ".zip":
                # zip archive
                with zipfile.ZipFile(archive_path, "r") as zip_file:
                    zip_file.extractall(extract_dir)
            else:
                raise ModuleInstallationError(
                    f"Unsupported archive format: {archive_path.suffix}"
                )
            
            # Find module directory (might be nested)
            module_dir = self._find_module_directory(extract_dir)
            
            return module_dir
            
        except Exception as e:
            if extract_dir.exists():
                shutil.rmtree(extract_dir)
            raise ModuleInstallationError(f"Failed to extract archive: {e}")
    
    def _find_module_directory(self, extract_dir: Path) -> Path:
        """Find the actual module directory within extracted archive."""
        # Check if extract_dir itself is the module
        if (extract_dir / "__init__.py").exists() or (extract_dir / "module.py").exists():
            return extract_dir
        
        # Check subdirectories
        for item in extract_dir.iterdir():
            if item.is_dir():
                if (item / "__init__.py").exists() or (item / "module.py").exists():
                    return item
        
        # Default to extract_dir
        return extract_dir