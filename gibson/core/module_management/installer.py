"""Module installer orchestrating the installation process."""

import shutil
from pathlib import Path
from typing import Dict, Optional, Any, Type
from loguru import logger

from gibson.core.module_management.fetchers import (
    GitFetcher,
    RegistryFetcher,
    LocalFetcher
)
from gibson.core.module_management.fetchers.base_fetcher import BaseFetcher
from gibson.core.module_management.validator import ModuleValidator
from gibson.core.module_management.dependencies import DependencyResolver
from gibson.core.module_management.pip_client import PipClient
from gibson.core.module_management.models import (
    ModuleInstallOptions,
    InstallationResult,
    ValidationResult,
    DependencyResolutionResult
)
from gibson.core.module_management.exceptions import (
    ModuleInstallationError,
    ModuleValidationError,
    DependencyError
)
from gibson.models.module import ModuleDefinitionModel


class ModuleInstaller:
    """Orchestrates module installation from various sources."""
    
    def __init__(
        self,
        install_dir: Optional[Path] = None,
        validator: Optional[ModuleValidator] = None,
        dependency_resolver: Optional[DependencyResolver] = None,
        pip_client: Optional[PipClient] = None
    ):
        """
        Initialize module installer.
        
        Args:
            install_dir: Base directory for module installations
            validator: Module validator instance
            dependency_resolver: Dependency resolver instance
            pip_client: Pip client for Python packages
        """
        self.install_dir = install_dir or Path.home() / ".gibson" / "modules"
        self.install_dir.mkdir(parents=True, exist_ok=True)
        
        self.validator = validator or ModuleValidator()
        self.dependency_resolver = dependency_resolver or DependencyResolver()
        self.pip_client = pip_client or PipClient()
        
        # Initialize fetchers
        self.fetchers: Dict[str, BaseFetcher] = {
            "git": GitFetcher(),
            "registry": RegistryFetcher(),
            "local": LocalFetcher()
        }
        
        # Backup directory for rollback
        self.backup_dir = self.install_dir / ".backups"
        self.backup_dir.mkdir(exist_ok=True)
    
    async def install_module(
        self,
        source: str,
        options: Optional[ModuleInstallOptions] = None
    ) -> InstallationResult:
        """
        Install a module from any supported source.
        
        Args:
            source: Module source (git URL, registry name, local path)
            options: Installation options
            
        Returns:
            InstallationResult with installation details
        """
        options = options or ModuleInstallOptions()
        temp_dir = self.install_dir / ".temp"
        temp_dir.mkdir(exist_ok=True)
        
        try:
            # Determine fetcher based on source
            fetcher = await self._get_fetcher(source)
            if not fetcher:
                raise ModuleInstallationError(
                    f"No suitable fetcher found for source: {source}",
                    source=source
                )
            
            logger.info(f"Installing module from {source}")
            
            # Fetch module to temp directory
            module_path = await fetcher.fetch(
                source,
                temp_dir,
                options.model_dump()
            )
            
            # Extract metadata
            metadata = await fetcher.extract_metadata(module_path)
            if not metadata:
                # Try to create minimal metadata
                metadata = ModuleDefinitionModel(
                    name=module_path.name,
                    version="0.0.0",
                    display_name=module_path.name,
                    description="No description available",
                    author="Unknown",
                    domain="prompt",  # Default domain
                    category="custom"
                )
            
            # Validate module
            if not options.skip_validation:
                validation_result = await self.validator.validate_module(module_path)
                if not validation_result.valid and not options.force:
                    raise ModuleValidationError(
                        f"Module validation failed: {', '.join(validation_result.errors)}",
                        module_name=metadata.name,
                        validation_type="complete",
                        errors=validation_result.errors,
                        warnings=validation_result.warnings,
                        security_issues=validation_result.security_issues
                    )
            else:
                validation_result = ValidationResult(
                    valid=True,
                    errors=[],
                    warnings=["Validation skipped"],
                    security_issues=[],
                    required_permissions=[],
                    risk_level="unknown"
                )
            
            # Resolve dependencies
            dependency_result = None
            if not options.skip_deps and metadata.dependencies:
                dependency_result = await self.dependency_resolver.resolve_dependencies(
                    metadata.name,
                    metadata.dependencies
                )
                
                if not dependency_result.success and not options.force:
                    raise DependencyError(
                        f"Dependency resolution failed: {dependency_result.error}",
                        module_name=metadata.name
                    )
                
                # Install Python dependencies
                if dependency_result.python_packages:
                    logger.info(f"Installing {len(dependency_result.python_packages)} Python dependencies")
                    install_results = await self.pip_client.install_packages(
                        dependency_result.python_packages,
                        continue_on_error=options.force
                    )
                    
                    failed = [pkg for pkg, success in install_results.items() if not success]
                    if failed and not options.force:
                        raise DependencyError(
                            f"Failed to install Python dependencies: {', '.join(failed)}",
                            module_name=metadata.name,
                            missing_deps=failed
                        )
            
            # Move module to final location
            final_path = self.install_dir / metadata.name
            
            # Backup existing module if updating
            backup_path = None
            if final_path.exists():
                if not options.force:
                    raise ModuleInstallationError(
                        f"Module '{metadata.name}' already exists. Use --force to overwrite",
                        module_name=metadata.name
                    )
                backup_path = await self._backup_module(metadata.name)
            
            # Move module to final location
            try:
                if final_path.exists():
                    shutil.rmtree(final_path)
                shutil.move(str(module_path), str(final_path))
            except Exception as e:
                # Restore backup if move failed
                if backup_path:
                    await self._restore_backup(metadata.name, backup_path)
                raise ModuleInstallationError(
                    f"Failed to install module: {e}",
                    module_name=metadata.name,
                    rollback_available=True
                )
            
            # Clean up temp directory
            shutil.rmtree(temp_dir, ignore_errors=True)
            
            # Create installation result
            result = InstallationResult(
                success=True,
                module_name=metadata.name,
                module_version=metadata.version,
                install_path=final_path,
                source=source,
                validation_result=validation_result,
                dependency_result=dependency_result,
                warnings=validation_result.warnings,
                metadata=metadata
            )
            
            logger.info(f"Successfully installed module '{metadata.name}' to {final_path}")
            return result
            
        except Exception as e:
            # Clean up temp directory on failure
            shutil.rmtree(temp_dir, ignore_errors=True)
            
            logger.error(f"Module installation failed: {e}")
            
            # Return failure result
            return InstallationResult(
                success=False,
                module_name="unknown",
                module_version="",
                install_path=Path(),
                source=source,
                validation_result=None,
                dependency_result=None,
                warnings=[],
                error=str(e)
            )
    
    async def uninstall_module(
        self,
        module_name: str,
        remove_deps: bool = False
    ) -> bool:
        """
        Uninstall a module.
        
        Args:
            module_name: Name of module to uninstall
            remove_deps: Whether to remove dependencies
            
        Returns:
            True if uninstallation successful
        """
        module_path = self.install_dir / module_name
        
        if not module_path.exists():
            raise ModuleInstallationError(
                f"Module '{module_name}' not found",
                module_name=module_name
            )
        
        try:
            # Create backup before removal
            backup_path = await self._backup_module(module_name)
            
            # Remove module directory
            shutil.rmtree(module_path)
            
            # Remove dependencies if requested
            if remove_deps:
                # This would need to check if dependencies are used by other modules
                logger.warning("Dependency removal not yet implemented")
            
            logger.info(f"Successfully uninstalled module '{module_name}'")
            return True
            
        except Exception as e:
            logger.error(f"Failed to uninstall module: {e}")
            return False
    
    async def update_module(
        self,
        module_name: str,
        source: Optional[str] = None,
        options: Optional[ModuleInstallOptions] = None
    ) -> InstallationResult:
        """
        Update an installed module.
        
        Args:
            module_name: Name of module to update
            source: Source to update from (uses original if not provided)
            options: Installation options
            
        Returns:
            InstallationResult with update details
        """
        module_path = self.install_dir / module_name
        
        if not module_path.exists():
            raise ModuleInstallationError(
                f"Module '{module_name}' not found",
                module_name=module_name
            )
        
        # Get current module metadata
        metadata_file = module_path / "module.json"
        if metadata_file.exists():
            import json
            with open(metadata_file) as f:
                current_metadata = json.load(f)
                current_version = current_metadata.get("version", "unknown")
        else:
            current_version = "unknown"
        
        # Create backup
        backup_path = await self._backup_module(module_name)
        
        try:
            # Install new version
            options = options or ModuleInstallOptions()
            options.force = True  # Force overwrite
            
            result = await self.install_module(source or module_name, options)
            
            if result.success:
                logger.info(
                    f"Successfully updated '{module_name}' "
                    f"from {current_version} to {result.module_version}"
                )
                # Remove backup
                if backup_path.exists():
                    shutil.rmtree(backup_path)
            else:
                # Restore backup on failure
                await self._restore_backup(module_name, backup_path)
                logger.error(f"Update failed, restored previous version")
            
            return result
            
        except Exception as e:
            # Restore backup on error
            await self._restore_backup(module_name, backup_path)
            logger.error(f"Update failed: {e}, restored previous version")
            raise
    
    async def _get_fetcher(self, source: str) -> Optional[BaseFetcher]:
        """Determine appropriate fetcher for source."""
        # Check each fetcher
        for name, fetcher in self.fetchers.items():
            if await fetcher.validate_source(source):
                logger.debug(f"Using {name} fetcher for source: {source}")
                return fetcher
        
        return None
    
    async def _backup_module(self, module_name: str) -> Path:
        """Create backup of existing module."""
        import time
        
        module_path = self.install_dir / module_name
        backup_name = f"{module_name}_{int(time.time())}"
        backup_path = self.backup_dir / backup_name
        
        if module_path.exists():
            shutil.copytree(module_path, backup_path)
            logger.debug(f"Created backup of '{module_name}' at {backup_path}")
        
        return backup_path
    
    async def _restore_backup(self, module_name: str, backup_path: Path) -> None:
        """Restore module from backup."""
        if not backup_path.exists():
            logger.warning(f"Backup not found: {backup_path}")
            return
        
        module_path = self.install_dir / module_name
        
        # Remove current version
        if module_path.exists():
            shutil.rmtree(module_path)
        
        # Restore from backup
        shutil.copytree(backup_path, module_path)
        logger.info(f"Restored '{module_name}' from backup")
        
        # Remove backup after restore
        shutil.rmtree(backup_path)