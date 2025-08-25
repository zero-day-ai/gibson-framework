"""Main module manager orchestrating all module operations."""

import asyncio
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Any
from uuid import uuid4
from loguru import logger

from gibson.core.module_management.dependencies import DependencyResolver
from gibson.core.module_management.installer import ModuleInstaller
from gibson.core.module_management.executor import ModuleExecutor
from gibson.core.module_management.versioning import VersionManager
from gibson.core.module_management.metrics import MetricsCollector
from gibson.core.module_management.models import (
    ModuleInstallOptions,
    InstallationResult,
    DependencyResolutionResult,
    ModuleUpdateInfo
)
from gibson.core.module_management.exceptions import (
    ModuleNotFoundError,
    ModuleExecutionError,
    DependencyConflictError
)
from gibson.models.module import (
    ModuleDefinitionModel,
    ModuleExecutionContextModel,
    ModuleResultModel,
    ExecutionStatus
)
from gibson.models.domain import TargetModel
# Database integration disabled for now
# from gibson.models.database import Module as ModuleDB
# from gibson.core.database import get_session
# from sqlalchemy.ext.asyncio import AsyncSession
# from sqlalchemy import select
import yaml


class ModuleManager:
    """Orchestrates all module management operations."""
    
    def __init__(
        self,
        config_path: Optional[Path] = None,
        modules_dir: Optional[Path] = None
    ):
        """
        Initialize module manager.
        
        Args:
            config_path: Path to configuration file
            modules_dir: Directory for modules
        """
        # Load configuration
        self.config = self._load_config(config_path)
        
        # Set modules directory
        self.modules_dir = modules_dir or Path(
            self.config["module_management"]["installation"]["base_dir"]
        ).expanduser()
        self.modules_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize components
        self.dependency_resolver = DependencyResolver()
        self.installer = ModuleInstaller(
            install_dir=self.modules_dir
        )
        self.executor = ModuleExecutor(
            modules_dir=self.modules_dir,
            max_execution_time=self.config["module_management"]["execution"]["max_execution_time"],
            max_memory_mb=self.config["module_management"]["execution"]["max_memory_mb"],
            max_cpu_percent=self.config["module_management"]["execution"]["max_cpu_percent"]
        )
        self.version_manager = VersionManager(
            registry_url=self.config["module_management"]["registry"]["url"],
            cache_dir=Path(self.config["module_management"]["cache"]["directory"]).expanduser()
        )
        self.metrics_collector = MetricsCollector(
            metrics_dir=Path(self.config["module_management"]["metrics"]["metrics_dir"]).expanduser(),
            persist_interval=self.config["module_management"]["metrics"]["persist_interval"]
        )
        
        # Module registry cache
        self._module_cache: Dict[str, ModuleDefinitionModel] = {}
        self._discovery_task: Optional[asyncio.Task] = None
    
    def _load_config(self, config_path: Optional[Path] = None) -> Dict:
        """Load configuration from file."""
        if not config_path:
            # Try default locations
            for path in [
                Path("gibson/config/module_management.yaml"),
                Path.home() / ".gibson" / "config" / "module_management.yaml",
                Path("/etc/gibson/module_management.yaml")
            ]:
                if path.exists():
                    config_path = path
                    break
        
        if config_path and config_path.exists():
            with open(config_path) as f:
                return yaml.safe_load(f)
        else:
            # Return default configuration
            return {
                "module_management": {
                    "installation": {
                        "base_dir": "~/.gibson/modules",
                        "backup_dir": "~/.gibson/modules/.backups"
                    },
                    "execution": {
                        "max_execution_time": 300,
                        "max_memory_mb": 512,
                        "max_cpu_percent": 80
                    },
                    "registry": {
                        "url": "https://registry.gibson.ai/api/v1"
                    },
                    "cache": {
                        "directory": "~/.gibson/cache"
                    },
                    "metrics": {
                        "metrics_dir": "~/.gibson/metrics",
                        "persist_interval": 300
                    },
                    "discovery": {
                        "auto_discover": True,
                        "discovery_interval": 3600,
                        "scan_paths": [
                            "~/.gibson/modules",
                            "./gibson/core/modules"
                        ]
                    }
                }
            }
    
    async def initialize(self) -> None:
        """Initialize module manager and discover modules."""
        logger.info("Initializing module manager")
        
        # Discover installed modules
        await self.discover_modules()
        
        # Start auto-discovery if enabled
        if self.config["module_management"]["discovery"]["auto_discover"]:
            self._start_auto_discovery()
        
        logger.info(f"Module manager initialized with {len(self._module_cache)} modules")
    
    async def discover_modules(self) -> Dict[str, ModuleDefinitionModel]:
        """
        Discover all available modules.
        
        Returns:
            Dictionary of module definitions
        """
        logger.debug("Discovering modules")
        discovered = {}
        
        # Scan module directories
        scan_paths = self.config["module_management"]["discovery"]["scan_paths"]
        for path_str in scan_paths:
            scan_path = Path(path_str).expanduser()
            if scan_path.exists():
                modules = await self._scan_directory(scan_path)
                discovered.update(modules)
        
        # Update cache
        self._module_cache = discovered
        
        # Update database (disabled for now)
        # await self._update_module_database(discovered)
        
        return discovered
    
    async def _scan_directory(self, directory: Path) -> Dict[str, ModuleDefinitionModel]:
        """Scan directory for modules."""
        modules = {}
        
        for item in directory.iterdir():
            if item.is_dir():
                # Look for module.yaml or module.json
                for config_name in ["module.yaml", "module.json", "metadata.yaml"]:
                    config_file = item / config_name
                    if config_file.exists():
                        try:
                            module_def = await self._load_module_definition(config_file)
                            if module_def:
                                modules[module_def.name] = module_def
                                logger.debug(f"Discovered module: {module_def.name}")
                            break
                        except Exception as e:
                            logger.warning(f"Failed to load module from {config_file}: {e}")
        
        return modules
    
    async def _load_module_definition(self, config_file: Path) -> Optional[ModuleDefinitionModel]:
        """Load module definition from config file."""
        try:
            with open(config_file) as f:
                if config_file.suffix == ".yaml":
                    data = yaml.safe_load(f)
                else:
                    import json
                    data = json.load(f)
            
            # Add file path to metadata
            data["metadata"] = data.get("metadata", {})
            data["metadata"]["config_path"] = str(config_file)
            data["metadata"]["module_dir"] = str(config_file.parent)
            
            return ModuleDefinitionModel(**data)
        except Exception as e:
            logger.error(f"Failed to parse module definition: {e}")
            return None
    
    async def _update_module_database(self, modules: Dict[str, ModuleDefinitionModel]) -> None:
        """Update module database with discovered modules (disabled for now)."""
        # Database integration disabled until database models are ready
        pass
    
    def _start_auto_discovery(self) -> None:
        """Start auto-discovery background task."""
        if self._discovery_task and not self._discovery_task.done():
            return
        
        async def auto_discover():
            interval = self.config["module_management"]["discovery"]["discovery_interval"]
            while True:
                await asyncio.sleep(interval)
                try:
                    await self.discover_modules()
                    logger.debug("Auto-discovery completed")
                except Exception as e:
                    logger.error(f"Auto-discovery failed: {e}")
        
        self._discovery_task = asyncio.create_task(auto_discover())
    
    async def install(
        self,
        source: str,
        options: Optional[ModuleInstallOptions] = None
    ) -> InstallationResult:
        """
        Install a module from source.
        
        Args:
            source: Module source (git URL, registry name, or local path)
            options: Installation options
            
        Returns:
            Installation result
        """
        logger.info(f"Installing module from: {source}")
        
        # Install module
        result = await self.installer.install_module(source, options)
        
        if result.success:
            # Rediscover modules to update cache
            await self.discover_modules()
            
            # Record version
            if result.module_name:
                self.version_manager.record_version(
                    result.module_name,
                    result.installed_version or "unknown"
                )
        
        return result
    
    async def uninstall(self, module_name: str) -> bool:
        """
        Uninstall a module.
        
        Args:
            module_name: Name of module to uninstall
            
        Returns:
            True if successful
        """
        logger.info(f"Uninstalling module: {module_name}")
        
        if module_name not in self._module_cache:
            raise ModuleNotFoundError(f"Module not found: {module_name}")
        
        module_def = self._module_cache[module_name]
        module_dir = Path(module_def.metadata.get("module_dir", ""))
        
        if module_dir.exists():
            # Backup before removal
            backup_dir = Path(self.config["module_management"]["installation"]["backup_dir"]).expanduser()
            backup_path = backup_dir / f"{module_name}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
            
            import shutil
            shutil.move(str(module_dir), str(backup_path))
            logger.info(f"Module backed up to: {backup_path}")
            
            # Update database (disabled for now)
            # Database integration disabled until database models are ready
            
            # Remove from cache
            del self._module_cache[module_name]
            
            return True
        
        return False
    
    async def execute(
        self,
        module_name: str,
        target: TargetModel,
        parameters: Optional[Dict[str, Any]] = None
    ) -> ModuleResultModel:
        """
        Execute a module.
        
        Args:
            module_name: Name of module to execute
            target: Target for module
            parameters: Module parameters
            
        Returns:
            Execution result
        """
        if module_name not in self._module_cache:
            raise ModuleNotFoundError(f"Module not found: {module_name}")
        
        # Create execution context
        context = ModuleExecutionContextModel(
            execution_id=uuid4(),
            target=target,
            parameters=parameters or {},
            dry_run=False,
            timeout=self.config["module_management"]["execution"]["max_execution_time"]
        )
        
        # Execute module
        result = await self.executor.execute(
            module_name,
            context,
            self._module_cache[module_name]
        )
        
        # Record metrics
        self.metrics_collector.record_execution(
            module_name,
            result,
            {"target": target.model_dump()}
        )
        
        return result
    
    async def list_modules(self) -> List[ModuleDefinitionModel]:
        """
        List all available modules.
        
        Returns:
            List of module definitions
        """
        return list(self._module_cache.values())
    
    async def get_module(self, module_name: str) -> Optional[ModuleDefinitionModel]:
        """
        Get a specific module definition.
        
        Args:
            module_name: Name of module
            
        Returns:
            Module definition or None
        """
        return self._module_cache.get(module_name)
    
    async def check_updates(self) -> List[ModuleUpdateInfo]:
        """
        Check for module updates.
        
        Returns:
            List of available updates
        """
        return await self.version_manager.check_for_updates(self._module_cache)
    
    async def update_module(
        self,
        module_name: str,
        target_version: Optional[str] = None
    ) -> InstallationResult:
        """
        Update a module to latest or specific version.
        
        Args:
            module_name: Name of module to update
            target_version: Target version (latest if None)
            
        Returns:
            Installation result
        """
        if module_name not in self._module_cache:
            raise ModuleNotFoundError(f"Module not found: {module_name}")
        
        # Get update info
        updates = await self.check_updates()
        update_info = next((u for u in updates if u.module_name == module_name), None)
        
        if not update_info and not target_version:
            return InstallationResult(
                success=False,
                module_name=module_name,
                error_message="No updates available"
            )
        
        # Determine target version
        version = target_version or (update_info.latest_version if update_info else None)
        if not version:
            return InstallationResult(
                success=False,
                module_name=module_name,
                error_message="Could not determine target version"
            )
        
        # Install new version
        source = f"registry://{module_name}@{version}"
        options = ModuleInstallOptions(
            force_overwrite=True,
            backup_existing=True
        )
        
        return await self.install(source, options)
    
    async def resolve_dependencies(
        self,
        module_name: str
    ) -> DependencyResolutionResult:
        """
        Resolve dependencies for a module.
        
        Args:
            module_name: Name of module
            
        Returns:
            Dependency resolution result
        """
        if module_name not in self._module_cache:
            raise ModuleNotFoundError(f"Module not found: {module_name}")
        
        module_def = self._module_cache[module_name]
        dependencies = module_def.metadata.get("dependencies", [])
        dev_dependencies = module_def.metadata.get("dev_dependencies", [])
        
        return await self.dependency_resolver.resolve_dependencies(
            module_name,
            dependencies,
            dev_dependencies
        )
    
    async def get_metrics_report(
        self,
        module_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get metrics report.
        
        Args:
            module_name: Specific module or None for global
            
        Returns:
            Metrics report
        """
        return self.metrics_collector.generate_report(module_name)
    
    async def validate_module(self, module_name: str) -> bool:
        """
        Validate a module.
        
        Args:
            module_name: Name of module to validate
            
        Returns:
            True if valid
        """
        return await self.executor.validate_module(module_name)
    
    async def cleanup(self) -> None:
        """Cleanup resources and persist data."""
        logger.info("Cleaning up module manager")
        
        # Cancel auto-discovery
        if self._discovery_task:
            self._discovery_task.cancel()
        
        # Persist metrics
        self.metrics_collector.persist_metrics()
        
        # Cleanup old logs
        self.metrics_collector.cleanup_old_logs()
        
        logger.info("Module manager cleanup completed")


# Make ModuleManager available at package level
__all__ = ["ModuleManager"]