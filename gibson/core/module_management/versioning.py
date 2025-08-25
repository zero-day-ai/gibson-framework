"""Module versioning and update management."""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from packaging import version
from loguru import logger

try:
    import aiohttp
except ImportError:
    aiohttp = None

from gibson.core.module_management.models import ModuleUpdateInfo
from gibson.models.module import ModuleDefinitionModel


class VersionManager:
    """Manages module versions and updates."""
    
    def __init__(
        self,
        registry_url: str = "https://registry.gibson.ai/api/v1",
        cache_dir: Optional[Path] = None
    ):
        """
        Initialize version manager.
        
        Args:
            registry_url: URL of module registry
            cache_dir: Directory for version cache
        """
        self.registry_url = registry_url
        self.cache_dir = cache_dir or Path.home() / ".gibson" / "cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        self.version_cache_file = self.cache_dir / "versions.json"
        self._version_cache: Dict[str, Dict] = {}
        self._load_cache()
    
    def parse_version(self, version_str: str) -> version.Version:
        """
        Parse version string.
        
        Args:
            version_str: Version string to parse
            
        Returns:
            Parsed Version object
        """
        try:
            return version.parse(version_str)
        except version.InvalidVersion:
            # Try to clean up common version formats
            cleaned = version_str.replace("v", "").replace("V", "")
            try:
                return version.parse(cleaned)
            except version.InvalidVersion:
                # Default to 0.0.0 for invalid versions
                logger.warning(f"Invalid version string: {version_str}, using 0.0.0")
                return version.parse("0.0.0")
    
    def compare_versions(
        self,
        version1: str,
        version2: str
    ) -> int:
        """
        Compare two version strings.
        
        Args:
            version1: First version
            version2: Second version
            
        Returns:
            -1 if version1 < version2, 0 if equal, 1 if version1 > version2
        """
        v1 = self.parse_version(version1)
        v2 = self.parse_version(version2)
        
        if v1 < v2:
            return -1
        elif v1 > v2:
            return 1
        else:
            return 0
    
    def is_compatible(
        self,
        current_version: str,
        required_version: str
    ) -> bool:
        """
        Check if current version satisfies requirement.
        
        Args:
            current_version: Currently installed version
            required_version: Required version specification
            
        Returns:
            True if compatible
        """
        from packaging.specifiers import SpecifierSet
        
        try:
            current = self.parse_version(current_version)
            
            # Handle different requirement formats
            if required_version.startswith("^"):
                # Caret requirement (compatible with)
                base = self.parse_version(required_version[1:])
                return current >= base and current.major == base.major
            elif required_version.startswith("~"):
                # Tilde requirement (approximately)
                base = self.parse_version(required_version[1:])
                return (current >= base and 
                        current.major == base.major and 
                        current.minor == base.minor)
            else:
                # Standard specifier
                spec = SpecifierSet(required_version)
                return current in spec
                
        except Exception as e:
            logger.warning(f"Failed to check compatibility: {e}")
            return True  # Assume compatible if can't parse
    
    async def check_for_updates(
        self,
        installed_modules: Dict[str, ModuleDefinitionModel]
    ) -> List[ModuleUpdateInfo]:
        """
        Check for available updates.
        
        Args:
            installed_modules: Dictionary of installed modules
            
        Returns:
            List of available updates
        """
        updates = []
        
        for module_name, module_def in installed_modules.items():
            latest_version = await self.get_latest_version(module_name)
            
            if latest_version and self.compare_versions(
                module_def.version,
                latest_version
            ) < 0:
                # Update available
                changelog = await self.get_changelog(
                    module_name,
                    module_def.version,
                    latest_version
                )
                
                update_info = ModuleUpdateInfo(
                    module_name=module_name,
                    current_version=module_def.version,
                    latest_version=latest_version,
                    changelog=changelog,
                    breaking_changes=self._has_breaking_changes(
                        module_def.version,
                        latest_version
                    ),
                    update_size=0,  # Would need to query registry
                    dependencies_changed=False  # Would need to compare
                )
                
                updates.append(update_info)
        
        return updates
    
    async def get_latest_version(self, module_name: str) -> Optional[str]:
        """
        Get latest version of a module.
        
        Args:
            module_name: Name of module
            
        Returns:
            Latest version string or None
        """
        # Check cache first
        if module_name in self._version_cache:
            cache_entry = self._version_cache[module_name]
            cache_time = datetime.fromisoformat(cache_entry["timestamp"])
            cache_age = (datetime.utcnow() - cache_time).total_seconds()
            
            # Use cache if less than 1 hour old
            if cache_age < 3600:
                return cache_entry.get("latest_version")
        
        # Query registry
        if aiohttp is None:
            logger.warning("aiohttp not available - cannot check for updates")
            return None
        
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.registry_url}/modules/{module_name}/latest"
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        latest_version = data.get("version")
                        
                        # Update cache
                        self._version_cache[module_name] = {
                            "latest_version": latest_version,
                            "timestamp": datetime.utcnow().isoformat()
                        }
                        self._save_cache()
                        
                        return latest_version
                    else:
                        logger.warning(
                            f"Failed to get latest version for {module_name}: "
                            f"HTTP {response.status}"
                        )
                        return None
                        
        except Exception as e:
            logger.error(f"Failed to check latest version: {e}")
            return None
    
    async def get_changelog(
        self,
        module_name: str,
        from_version: str,
        to_version: str
    ) -> Optional[str]:
        """
        Get changelog between versions.
        
        Args:
            module_name: Name of module
            from_version: Starting version
            to_version: Target version
            
        Returns:
            Changelog text or None
        """
        if aiohttp is None:
            return None
        
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.registry_url}/modules/{module_name}/changelog"
                params = {
                    "from": from_version,
                    "to": to_version
                }
                
                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data.get("changelog")
                    else:
                        return None
                        
        except Exception as e:
            logger.error(f"Failed to get changelog: {e}")
            return None
    
    def _has_breaking_changes(
        self,
        current_version: str,
        target_version: str
    ) -> bool:
        """
        Check if update has breaking changes.
        
        Uses semantic versioning rules:
        - Major version change = breaking changes
        - Minor/patch = no breaking changes
        
        Args:
            current_version: Current version
            target_version: Target version
            
        Returns:
            True if breaking changes likely
        """
        current = self.parse_version(current_version)
        target = self.parse_version(target_version)
        
        # Check for major version change
        if hasattr(current, 'major') and hasattr(target, 'major'):
            return target.major > current.major
        
        # Can't determine - assume no breaking changes
        return False
    
    def get_version_history(
        self,
        module_name: str
    ) -> List[str]:
        """
        Get version history for a module.
        
        Args:
            module_name: Name of module
            
        Returns:
            List of versions in chronological order
        """
        history_file = self.cache_dir / f"{module_name}_history.json"
        
        if history_file.exists():
            with open(history_file) as f:
                data = json.load(f)
                return data.get("versions", [])
        
        return []
    
    def record_version(
        self,
        module_name: str,
        version: str
    ) -> None:
        """
        Record a version in history.
        
        Args:
            module_name: Name of module
            version: Version to record
        """
        history_file = self.cache_dir / f"{module_name}_history.json"
        
        if history_file.exists():
            with open(history_file) as f:
                data = json.load(f)
        else:
            data = {"versions": [], "installations": []}
        
        # Add version if not already present
        if version not in data["versions"]:
            data["versions"].append(version)
            data["versions"].sort(key=lambda v: self.parse_version(v))
        
        # Record installation
        data["installations"].append({
            "version": version,
            "timestamp": datetime.utcnow().isoformat()
        })
        
        # Keep only last 100 installations
        data["installations"] = data["installations"][-100:]
        
        with open(history_file, "w") as f:
            json.dump(data, f, indent=2)
    
    def _load_cache(self) -> None:
        """Load version cache from disk."""
        if self.version_cache_file.exists():
            try:
                with open(self.version_cache_file) as f:
                    self._version_cache = json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load version cache: {e}")
                self._version_cache = {}
        else:
            self._version_cache = {}
    
    def _save_cache(self) -> None:
        """Save version cache to disk."""
        try:
            with open(self.version_cache_file, "w") as f:
                json.dump(self._version_cache, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to save version cache: {e}")
    
    async def get_version_metadata(
        self,
        module_name: str,
        version: str
    ) -> Optional[Dict]:
        """
        Get metadata for a specific version.
        
        Args:
            module_name: Name of module
            version: Version to query
            
        Returns:
            Version metadata or None
        """
        if aiohttp is None:
            return None
        
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.registry_url}/modules/{module_name}/versions/{version}"
                
                async with session.get(url) as response:
                    if response.status == 200:
                        return await response.json()
                    else:
                        return None
                        
        except Exception as e:
            logger.error(f"Failed to get version metadata: {e}")
            return None
    
    def suggest_upgrade_path(
        self,
        module_name: str,
        current_version: str,
        target_version: Optional[str] = None
    ) -> List[str]:
        """
        Suggest upgrade path between versions.
        
        Args:
            module_name: Name of module
            current_version: Current version
            target_version: Target version (latest if None)
            
        Returns:
            List of versions to upgrade through
        """
        history = self.get_version_history(module_name)
        
        if not history:
            # No history - direct upgrade
            if target_version:
                return [target_version]
            return []
        
        current = self.parse_version(current_version)
        
        # Filter to versions newer than current
        upgrade_candidates = [
            v for v in history
            if self.parse_version(v) > current
        ]
        
        if not upgrade_candidates:
            return []
        
        # Sort by version
        upgrade_candidates.sort(key=lambda v: self.parse_version(v))
        
        if target_version:
            target = self.parse_version(target_version)
            # Filter to versions up to target
            upgrade_candidates = [
                v for v in upgrade_candidates
                if self.parse_version(v) <= target
            ]
        
        # For major version changes, include intermediate major versions
        path = []
        last_major = current.major if hasattr(current, 'major') else 0
        
        for v_str in upgrade_candidates:
            v = self.parse_version(v_str)
            if hasattr(v, 'major') and v.major > last_major:
                # Include last version of previous major
                prev_major_versions = [
                    c for c in upgrade_candidates
                    if hasattr(self.parse_version(c), 'major') and
                    self.parse_version(c).major == last_major
                ]
                if prev_major_versions:
                    path.append(prev_major_versions[-1])
                
                last_major = v.major
        
        # Add target version
        if target_version and target_version not in path:
            path.append(target_version)
        elif upgrade_candidates and upgrade_candidates[-1] not in path:
            path.append(upgrade_candidates[-1])
        
        return path