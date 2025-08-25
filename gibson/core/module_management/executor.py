"""Module executor for managing module lifecycle and execution."""

import asyncio
import importlib.util
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional, Type
from uuid import UUID, uuid4
from loguru import logger

from gibson.core.modules.base import BaseModule
from gibson.models.module import (
    ModuleExecutionContextModel,
    ModuleResultModel,
    ExecutionStatus,
    ModuleDefinitionModel
)
from gibson.models.domain import FindingModel, TargetModel
from gibson.core.module_management.exceptions import ModuleExecutionError


class ResourceMonitor:
    """Monitor resource usage during module execution."""
    
    def __init__(self, max_memory_mb: int = 512, max_cpu_percent: int = 80):
        """
        Initialize resource monitor.
        
        Args:
            max_memory_mb: Maximum memory usage in MB
            max_cpu_percent: Maximum CPU usage percentage
        """
        self.max_memory_mb = max_memory_mb
        self.max_cpu_percent = max_cpu_percent
        self.start_time = None
        self.start_memory = None
    
    def start(self):
        """Start monitoring."""
        self.start_time = time.time()
        try:
            import psutil
            process = psutil.Process()
            self.start_memory = process.memory_info().rss / 1024 / 1024  # MB
        except ImportError:
            logger.warning("psutil not available - resource monitoring limited")
            self.start_memory = 0
    
    def check_limits(self) -> Optional[str]:
        """
        Check if resource limits are exceeded.
        
        Returns:
            Violation message if limits exceeded, None otherwise
        """
        try:
            import psutil
            process = psutil.Process()
            
            # Check memory
            current_memory = process.memory_info().rss / 1024 / 1024  # MB
            memory_used = current_memory - (self.start_memory or 0)
            if memory_used > self.max_memory_mb:
                return f"Memory limit exceeded: {memory_used:.1f}MB > {self.max_memory_mb}MB"
            
            # Check CPU
            cpu_percent = process.cpu_percent(interval=0.1)
            if cpu_percent > self.max_cpu_percent:
                return f"CPU limit exceeded: {cpu_percent:.1f}% > {self.max_cpu_percent}%"
            
        except ImportError:
            pass  # Can't check without psutil
        
        return None
    
    def get_usage(self) -> Dict[str, Any]:
        """Get current resource usage."""
        elapsed = time.time() - (self.start_time or time.time())
        
        try:
            import psutil
            process = psutil.Process()
            current_memory = process.memory_info().rss / 1024 / 1024  # MB
            memory_used = current_memory - (self.start_memory or 0)
            cpu_percent = process.cpu_percent(interval=0.1)
            
            return {
                "elapsed_seconds": elapsed,
                "memory_mb": memory_used,
                "cpu_percent": cpu_percent
            }
        except ImportError:
            return {
                "elapsed_seconds": elapsed,
                "memory_mb": 0,
                "cpu_percent": 0
            }


class ModuleExecutor:
    """Manages module execution lifecycle."""
    
    def __init__(
        self,
        modules_dir: Optional[Path] = None,
        max_execution_time: int = 300,
        max_memory_mb: int = 512,
        max_cpu_percent: int = 80
    ):
        """
        Initialize module executor.
        
        Args:
            modules_dir: Directory containing modules
            max_execution_time: Maximum execution time in seconds
            max_memory_mb: Maximum memory usage in MB
            max_cpu_percent: Maximum CPU usage percentage
        """
        self.modules_dir = modules_dir or Path.home() / ".gibson" / "modules"
        self.max_execution_time = max_execution_time
        self.resource_monitor = ResourceMonitor(max_memory_mb, max_cpu_percent)
        self._loaded_modules: Dict[str, Type[BaseModule]] = {}
    
    async def execute(
        self,
        module_name: str,
        context: ModuleExecutionContextModel,
        module_metadata: Optional[ModuleDefinitionModel] = None
    ) -> ModuleResultModel:
        """
        Execute a module with full lifecycle management.
        
        Args:
            module_name: Name of module to execute
            context: Execution context with target and parameters
            module_metadata: Optional module metadata
            
        Returns:
            ModuleResultModel with execution results
        """
        execution_id = context.execution_id or uuid4()
        result = ModuleResultModel(
            execution_id=execution_id,
            module_name=module_name,
            status=ExecutionStatus.PENDING,
            findings=[],
            metadata={}
        )
        
        try:
            # Load module
            module_class = await self._load_module(module_name)
            if not module_class:
                raise ModuleExecutionError(
                    f"Failed to load module: {module_name}",
                    module_name=module_name,
                    execution_stage="load"
                )
            
            # Instantiate module
            module_instance = module_class()
            
            # Validate target
            if not await self._validate_target(module_instance, context.target):
                raise ModuleExecutionError(
                    f"Target validation failed for module: {module_name}",
                    module_name=module_name,
                    execution_stage="validation"
                )
            
            # Setup execution environment
            env = await self._setup_environment(context)
            
            # Execute with lifecycle management
            result.status = ExecutionStatus.RUNNING
            result.add_log(f"Starting execution of {module_name}")
            
            # Run with timeout and resource monitoring
            findings = await self._execute_with_limits(
                module_instance,
                context,
                result
            )
            
            # Process results
            result.findings = findings
            result.mark_completed()
            result.add_log(f"Module {module_name} completed successfully")
            
            # Add resource usage to metadata
            result.metadata["resource_usage"] = self.resource_monitor.get_usage()
            
        except asyncio.TimeoutError:
            result.mark_timeout()
            logger.error(f"Module {module_name} execution timed out")
            
        except ModuleExecutionError as e:
            result.mark_failed(str(e))
            logger.error(f"Module {module_name} execution failed: {e}")
            
        except Exception as e:
            result.mark_failed(f"Unexpected error: {e}")
            logger.error(f"Unexpected error executing {module_name}: {e}")
        
        finally:
            # Cleanup
            await self._cleanup_environment(context.execution_id)
        
        return result
    
    async def _load_module(self, module_name: str) -> Optional[Type[BaseModule]]:
        """
        Load a module class.
        
        Args:
            module_name: Name of module to load
            
        Returns:
            Module class or None if not found
        """
        # Check cache
        if module_name in self._loaded_modules:
            return self._loaded_modules[module_name]
        
        # Find module file
        module_path = self._find_module_file(module_name)
        if not module_path:
            logger.error(f"Module file not found: {module_name}")
            return None
        
        try:
            # Load module dynamically
            spec = importlib.util.spec_from_file_location(
                f"gibson.modules.{module_name}",
                module_path
            )
            
            if not spec or not spec.loader:
                logger.error(f"Failed to create module spec for {module_name}")
                return None
            
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
            
            # Find module class (should inherit from BaseModule)
            module_class = None
            for name in dir(module):
                obj = getattr(module, name)
                if (isinstance(obj, type) and 
                    issubclass(obj, BaseModule) and 
                    obj is not BaseModule):
                    module_class = obj
                    break
            
            if module_class:
                self._loaded_modules[module_name] = module_class
                logger.debug(f"Loaded module class: {module_class.__name__}")
                return module_class
            else:
                logger.error(f"No BaseModule subclass found in {module_name}")
                return None
                
        except Exception as e:
            logger.error(f"Failed to load module {module_name}: {e}")
            return None
    
    def _find_module_file(self, module_name: str) -> Optional[Path]:
        """Find module file in modules directory."""
        # Check direct path
        module_dir = self.modules_dir / module_name
        if module_dir.exists():
            # Look for module.py or __init__.py
            for filename in ["module.py", "__init__.py", f"{module_name}.py"]:
                module_file = module_dir / filename
                if module_file.exists():
                    return module_file
        
        # Check in domain directories
        for domain_dir in self.modules_dir.iterdir():
            if domain_dir.is_dir():
                module_file = domain_dir / f"{module_name}.py"
                if module_file.exists():
                    return module_file
                
                # Check subdirectory
                module_subdir = domain_dir / module_name
                if module_subdir.exists():
                    for filename in ["module.py", "__init__.py"]:
                        module_file = module_subdir / filename
                        if module_file.exists():
                            return module_file
        
        return None
    
    async def _validate_target(
        self,
        module: BaseModule,
        target: TargetModel
    ) -> bool:
        """
        Validate target for module.
        
        Args:
            module: Module instance
            target: Target to validate
            
        Returns:
            True if target is valid
        """
        try:
            return await module.validate_target(target)
        except Exception as e:
            logger.warning(f"Target validation failed: {e}")
            return False
    
    async def _setup_environment(
        self,
        context: ModuleExecutionContextModel
    ) -> Dict[str, Any]:
        """
        Setup execution environment.
        
        Args:
            context: Execution context
            
        Returns:
            Environment dictionary
        """
        env = {
            "execution_id": str(context.execution_id),
            "target": context.target.model_dump(),
            "parameters": context.parameters,
            "dry_run": context.dry_run,
            "timeout": context.timeout
        }
        
        # Add execution metadata
        if context.execution_environment:
            env.update(context.execution_environment)
        
        return env
    
    async def _execute_with_limits(
        self,
        module: BaseModule,
        context: ModuleExecutionContextModel,
        result: ModuleResultModel
    ) -> List[FindingModel]:
        """
        Execute module with resource limits.
        
        Args:
            module: Module instance
            context: Execution context
            result: Result model to update
            
        Returns:
            List of findings
        """
        # Start resource monitoring
        self.resource_monitor.start()
        
        # Create task for module execution
        async def run_module():
            # Setup phase
            result.add_log("Running module setup")
            await module.setup()
            
            # Run phase
            result.add_log("Executing module")
            findings = await module.run(
                context.target,
                context.parameters
            )
            
            # Teardown phase
            result.add_log("Running module teardown")
            await module.teardown()
            
            return findings
        
        # Create monitoring task
        async def monitor_resources():
            while True:
                await asyncio.sleep(1)
                violation = self.resource_monitor.check_limits()
                if violation:
                    raise ModuleExecutionError(
                        violation,
                        module_name=module.__class__.__name__,
                        resource_limit=violation
                    )
        
        # Run with timeout
        timeout = context.timeout or self.max_execution_time
        
        try:
            # Create tasks
            module_task = asyncio.create_task(run_module())
            monitor_task = asyncio.create_task(monitor_resources())
            
            # Wait for module to complete or timeout
            findings = await asyncio.wait_for(
                module_task,
                timeout=timeout
            )
            
            # Cancel monitor task
            monitor_task.cancel()
            
            return findings
            
        except asyncio.TimeoutError:
            # Cancel both tasks
            module_task.cancel()
            monitor_task.cancel()
            raise
        
        except Exception:
            # Cancel both tasks on any error
            module_task.cancel()
            monitor_task.cancel()
            raise
    
    async def _cleanup_environment(self, execution_id: UUID) -> None:
        """
        Cleanup execution environment.
        
        Args:
            execution_id: Execution ID to cleanup
        """
        # Cleanup any temporary files or resources
        logger.debug(f"Cleaning up environment for execution {execution_id}")
        
        # Reset resource monitor
        self.resource_monitor.start_time = None
        self.resource_monitor.start_memory = None
    
    async def validate_module(self, module_name: str) -> bool:
        """
        Validate that a module can be loaded and instantiated.
        
        Args:
            module_name: Name of module to validate
            
        Returns:
            True if module is valid
        """
        try:
            module_class = await self._load_module(module_name)
            if not module_class:
                return False
            
            # Try to instantiate
            module_instance = module_class()
            
            # Check required methods
            if not hasattr(module_instance, 'run'):
                logger.error(f"Module {module_name} missing 'run' method")
                return False
            
            if not hasattr(module_instance, 'get_config_schema'):
                logger.error(f"Module {module_name} missing 'get_config_schema' method")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Module validation failed for {module_name}: {e}")
            return False
    
    @asynccontextmanager
    async def module_context(self, module_name: str):
        """
        Context manager for module execution.
        
        Args:
            module_name: Name of module
            
        Yields:
            Module instance
        """
        module_class = await self._load_module(module_name)
        if not module_class:
            raise ModuleExecutionError(
                f"Failed to load module: {module_name}",
                module_name=module_name
            )
        
        module = module_class()
        
        try:
            # Setup
            await module.setup()
            yield module
        finally:
            # Teardown
            await module.teardown()