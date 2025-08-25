"""
Scan executor that integrates with the new LiteLLM system.
"""

import asyncio
import uuid
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from datetime import datetime
from loguru import logger

from gibson.core.orchestrator.llm_integration import get_llm_orchestrator
from gibson.core.modules.base import BaseModule
from gibson.core.llm import create_llm_client_factory
from gibson.models.scan import ScanConfig, ScanResult, ScanStatus
from gibson.models.target import Target
from gibson.models.findings import Finding, Severity


@dataclass
class ExecutionContext:
    """Context for scan execution."""
    
    scan_id: str
    scan_config: ScanConfig
    target: Target
    modules: List[BaseModule]
    start_time: datetime = field(default_factory=datetime.now)
    llm_orchestrator: Optional[Any] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ExecutionResult:
    """Result of scan execution."""
    
    scan_id: str
    status: ScanStatus
    findings: List[Finding]
    errors: List[str]
    duration_seconds: float
    llm_usage: Dict[str, Any]
    metadata: Dict[str, Any] = field(default_factory=dict)


class ScanExecutor:
    """Executes security scans with LiteLLM integration."""
    
    def __init__(self):
        """Initialize scan executor."""
        self.active_scans: Dict[str, ExecutionContext] = {}
        self.completed_scans: Dict[str, ExecutionResult] = {}
    
    async def execute_scan(
        self,
        scan_config: ScanConfig,
        target: Target,
        modules: List[BaseModule],
    ) -> ExecutionResult:
        """Execute a security scan.
        
        Args:
            scan_config: Scan configuration
            target: Target to scan
            modules: Modules to execute
        
        Returns:
            Execution result
        """
        scan_id = str(uuid.uuid4())
        logger.info(f"Starting scan {scan_id} on target {target.url}")
        
        # Create execution context
        context = ExecutionContext(
            scan_id=scan_id,
            scan_config=scan_config,
            target=target,
            modules=modules,
        )
        
        self.active_scans[scan_id] = context
        
        try:
            # Get LLM orchestrator
            llm_orchestrator = await get_llm_orchestrator()
            context.llm_orchestrator = llm_orchestrator
            
            # Prepare LLM for scan
            await llm_orchestrator.prepare_for_scan(
                scan_id=scan_id,
                scan_config=scan_config,
                target=target,
            )
            
            # Create LLM client factory for modules
            llm_client_factory = await create_llm_client_factory()
            
            # Execute modules
            findings = []
            errors = []
            
            for module in modules:
                try:
                    logger.info(f"Executing module {module.name} for scan {scan_id}")
                    
                    # Inject LLM client factory into module
                    module.llm_client_factory = llm_client_factory
                    
                    # Setup module
                    await module.setup()
                    
                    # Execute module
                    module_findings = await module.run(target)
                    
                    # Process findings
                    if module_findings:
                        if isinstance(module_findings, list):
                            findings.extend(module_findings)
                        else:
                            findings.append(module_findings)
                    
                    # Teardown module
                    await module.teardown()
                    
                    logger.info(
                        f"Module {module.name} completed with "
                        f"{len(module_findings) if isinstance(module_findings, list) else 1} findings"
                    )
                    
                except Exception as e:
                    error_msg = f"Module {module.name} failed: {str(e)}"
                    logger.error(error_msg)
                    errors.append(error_msg)
            
            # Get LLM usage statistics
            llm_usage = await llm_orchestrator.get_scan_usage(scan_id)
            
            # Complete scan in orchestrator
            await llm_orchestrator.complete_scan(scan_id)
            
            # Calculate duration
            duration = (datetime.now() - context.start_time).total_seconds()
            
            # Determine status
            if errors and not findings:
                status = ScanStatus.FAILED
            elif errors:
                status = ScanStatus.PARTIAL
            else:
                status = ScanStatus.COMPLETED
            
            # Create result
            result = ExecutionResult(
                scan_id=scan_id,
                status=status,
                findings=findings,
                errors=errors,
                duration_seconds=duration,
                llm_usage=llm_usage,
                metadata={
                    "target_url": target.url,
                    "modules_executed": len(modules),
                    "modules_failed": len(errors),
                },
            )
            
            # Store completed scan
            self.completed_scans[scan_id] = result
            
            logger.info(
                f"Scan {scan_id} completed with status {status}. "
                f"Findings: {len(findings)}, Errors: {len(errors)}, "
                f"Duration: {duration:.2f}s"
            )
            
            return result
            
        except Exception as e:
            logger.error(f"Scan {scan_id} failed with exception: {e}")
            
            # Create error result
            duration = (datetime.now() - context.start_time).total_seconds()
            
            result = ExecutionResult(
                scan_id=scan_id,
                status=ScanStatus.FAILED,
                findings=[],
                errors=[str(e)],
                duration_seconds=duration,
                llm_usage={},
            )
            
            self.completed_scans[scan_id] = result
            return result
            
        finally:
            # Remove from active scans
            if scan_id in self.active_scans:
                del self.active_scans[scan_id]
    
    async def execute_module_with_llm(
        self,
        module: BaseModule,
        target: Target,
        scan_id: str,
    ) -> List[Finding]:
        """Execute a module with LLM support.
        
        Args:
            module: Module to execute
            target: Target to scan
            scan_id: Scan identifier
        
        Returns:
            List of findings
        """
        if scan_id not in self.active_scans:
            raise ValueError(f"Scan {scan_id} not found")
        
        context = self.active_scans[scan_id]
        llm_orchestrator = context.llm_orchestrator
        
        if not llm_orchestrator:
            raise RuntimeError("LLM orchestrator not initialized")
        
        # Create wrapper for module to use orchestrator
        async def llm_complete(prompt: str, **kwargs) -> str:
            """LLM completion wrapper for module."""
            response = await llm_orchestrator.complete_for_module(
                module_name=module.name,
                prompt=prompt,
                scan_id=scan_id,
                **kwargs,
            )
            
            if response.choices:
                return response.choices[0].message.content
            return ""
        
        # Inject LLM completion function
        module.llm_complete = llm_complete
        
        # Execute module
        return await module.run(target)
    
    def get_scan_status(self, scan_id: str) -> Optional[ScanStatus]:
        """Get status of a scan.
        
        Args:
            scan_id: Scan identifier
        
        Returns:
            Scan status or None if not found
        """
        if scan_id in self.active_scans:
            return ScanStatus.RUNNING
        
        if scan_id in self.completed_scans:
            return self.completed_scans[scan_id].status
        
        return None
    
    def get_scan_result(self, scan_id: str) -> Optional[ExecutionResult]:
        """Get result of a completed scan.
        
        Args:
            scan_id: Scan identifier
        
        Returns:
            Execution result or None if not found
        """
        return self.completed_scans.get(scan_id)
    
    def list_active_scans(self) -> List[str]:
        """List active scan IDs.
        
        Returns:
            List of active scan IDs
        """
        return list(self.active_scans.keys())
    
    def list_completed_scans(self) -> List[str]:
        """List completed scan IDs.
        
        Returns:
            List of completed scan IDs
        """
        return list(self.completed_scans.keys())
    
    async def cancel_scan(self, scan_id: str) -> bool:
        """Cancel an active scan.
        
        Args:
            scan_id: Scan identifier
        
        Returns:
            True if cancelled, False if not found
        """
        if scan_id not in self.active_scans:
            return False
        
        context = self.active_scans[scan_id]
        
        # Complete scan in orchestrator
        if context.llm_orchestrator:
            await context.llm_orchestrator.complete_scan(scan_id)
        
        # Create cancelled result
        duration = (datetime.now() - context.start_time).total_seconds()
        
        result = ExecutionResult(
            scan_id=scan_id,
            status=ScanStatus.CANCELLED,
            findings=[],
            errors=["Scan cancelled by user"],
            duration_seconds=duration,
            llm_usage={},
        )
        
        self.completed_scans[scan_id] = result
        del self.active_scans[scan_id]
        
        logger.info(f"Scan {scan_id} cancelled")
        return True


# Global executor instance
_executor: Optional[ScanExecutor] = None


def get_scan_executor() -> ScanExecutor:
    """Get or create the global scan executor.
    
    Returns:
        Scan executor instance
    """
    global _executor
    
    if _executor is None:
        _executor = ScanExecutor()
    
    return _executor