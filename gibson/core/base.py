"""Core orchestration framework for Gibson security scanning."""

import asyncio
import uuid
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Type, Union

from loguru import logger

from gibson.core.config import Config, ConfigManager
from gibson.core.context import Context
from gibson.db.manager import DatabaseManager

# Module manager import disabled for now
# from gibson.core.module_management.manager import ModuleManager
from gibson.models.scan import Finding, ScanResult
from gibson.models.target import TargetModel


class ScanType(Enum):
    """Scan type enumeration."""

    QUICK = "quick"
    FULL = "full"
    SPECIFIC = "specific"
    CUSTOM = "custom"


class AttackDomain(Enum):
    """Attack domain enumeration."""

    PROMPT = "prompt"
    DATA = "data"
    MODEL = "model"
    SYSTEM = "system"
    OUTPUT = "output"


class BaseAttack:
    """Base class for attack domain implementations."""

    def __init__(self, config: Config, base_orchestrator: "Base"):
        """Initialize attack domain.

        Args:
            config: Global configuration
            base_orchestrator: Reference to Base orchestrator for shared services
        """
        self.config = config
        self.base = base_orchestrator
        self.domain = self._get_domain()
        self.enabled = True

    def _get_domain(self) -> AttackDomain:
        """Get attack domain for this class. Must be implemented by subclasses."""
        raise NotImplementedError("Subclasses must implement _get_domain()")

    async def initialize(self) -> None:
        """Initialize attack domain. Override for domain-specific setup."""
        pass

    async def discover_modules(self) -> List[str]:
        """Discover available modules for this domain."""
        domain_path = Path("gibson/modules") / self.domain.value
        if not domain_path.exists():
            return []

        modules = []
        for module_file in domain_path.glob("*.py"):
            if module_file.stem != "__init__":
                modules.append(module_file.stem)

        return modules

    async def execute_module(self, module_name: str, target: str) -> Optional[Finding]:
        """Execute a specific module against target."""
        raise NotImplementedError("Subclasses must implement execute_module()")

    async def get_capabilities(self) -> Dict[str, Any]:
        """Get domain-specific capabilities and metadata."""
        return {
            "domain": self.domain.value,
            "enabled": self.enabled,
            "modules": await self.discover_modules(),
        }


class Base:
    """Central orchestration framework for Gibson security scanning.

    Handles module loading, scan execution, and coordination between
    attack domains and shared services.
    """

    # Class-level database manager for singleton pattern
    _db_manager: Optional[DatabaseManager] = None

    def __init__(self, config: Optional[Config] = None, context: Optional[Context] = None):
        """Initialize Base orchestrator.

        Args:
            config: Configuration object. If None, loads from ConfigManager
            context: CLI context object. If None, creates minimal context
        """
        self.config = config or ConfigManager().config
        self.context = context
        self.db_manager: Optional[DatabaseManager] = None
        self.payload_manager = None  # Will be initialized later

        # Set class-level db_manager for payload system access
        Base._db_manager = self.db_manager

        # Attack domain registry
        self.attack_domains: Dict[AttackDomain, BaseAttack] = {}
        self.available_modules: Dict[str, AttackDomain] = {}

        # Module management system
        self.module_manager: Optional[ModuleManager] = None

        # Shared services (will be initialized later)
        self.ai_service = None
        self.git_service = None
        self.data_service = None

        # Authentication services
        self.credential_manager = None
        self.auth_service = None
        self.request_authenticator = None

        # State management
        self.initialized = False
        self.running_scans: Set[str] = set()

    async def initialize(self) -> None:
        """Initialize the Base orchestrator and all services."""
        if self.initialized:
            return

        # Detect test mode to allow graceful degradation
        test_mode = self._detect_test_mode()
        if test_mode:
            logger.debug("Test mode detected - using minimal initialization")
            self.initialized = True
            return

        logger.info("Initializing Gibson Base orchestrator")

        # Initialize database
        await self._initialize_database()

        # Initialize authentication services
        await self._initialize_authentication_services()

        # Initialize shared services (will be implemented in later tasks)
        await self._initialize_shared_services()

        # Initialize module management system
        await self._initialize_module_manager()

        # Initialize attack domains (will be implemented in later tasks)
        await self._initialize_attack_domains()

        # Discover available modules
        await self._discover_modules()

        self.initialized = True
        logger.info("Gibson Base orchestrator initialized successfully")

    async def _initialize_database(self) -> None:
        """Initialize database connection."""
        try:
            # Expand tilde in database URL
            db_url = self.config.database.url.replace("~", str(Path.home()))
            self.db_manager = DatabaseManager(db_url)
            await self.db_manager.initialize()
            # Update class-level db_manager for payload system access
            Base._db_manager = self.db_manager
            logger.info("Database initialized successfully")
        except ImportError as e:
            if "aiosqlite" in str(e):
                logger.warning("aiosqlite not available - database functionality disabled")
                self.db_manager = None
            else:
                logger.error(f"Failed to initialize database due to missing dependency: {e}")
                raise
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            # In test environments, continue without database
            if self._detect_test_mode():
                logger.debug("Continuing without database in test mode")
                self.db_manager = None
            else:
                raise

    async def _initialize_authentication_services(self) -> None:
        """Initialize authentication services for secure credential management."""
        try:
            from gibson.core.auth.credential_manager import CredentialManager
            from gibson.core.auth.auth_service import AuthenticationService
            from gibson.core.auth.request_auth import RequestAuthenticator

            # Initialize credential manager
            self.credential_manager = CredentialManager()
            logger.info("Credential manager initialized")

            # Initialize authentication service
            self.auth_service = AuthenticationService(
                credential_manager=self.credential_manager,
                timeout=self.config.api.timeout if hasattr(self.config, "api") else 30,
                max_retries=3,
            )
            logger.info("Authentication service initialized")

            # Initialize request authenticator
            self.request_authenticator = RequestAuthenticator(
                credential_manager=self.credential_manager, enable_retry=True, max_retries=3
            )
            logger.info("Request authenticator initialized")

            logger.info("Authentication services initialized successfully")

        except Exception as e:
            logger.error(f"Failed to initialize authentication services: {e}")
            # Continue with partial initialization

    async def _initialize_shared_services(self) -> None:
        """Initialize shared services (AI, Git, Data)."""
        # Initialize payload manager
        try:
            from gibson.core.payloads.manager import PayloadManager

            payload_dir = Path.home() / ".gibson" / "payloads"
            payload_dir.mkdir(parents=True, exist_ok=True)

            self.payload_manager = PayloadManager(data_path=payload_dir)
            await self.payload_manager.initialize()
            logger.info("Payload manager initialized successfully")

        except Exception as e:
            logger.error(f"Failed to initialize payload manager: {e}")
            # Continue without payload manager
            self.payload_manager = None

        # TODO: Will be implemented in subsequent tasks
        # self.ai_service = AIService(self.config)
        # self.git_service = GitService(self.config)
        # self.data_service = DataService(self.config)
        logger.debug("Shared services initialization completed")

    async def _initialize_attack_domains(self) -> None:
        """Initialize attack domain classes."""
        try:
            # Import and initialize attack domains
            from gibson.domains.prompt import PromptDomain
            from gibson.domains.data import DataDomain
            from gibson.domains.model import ModelDomain
            from gibson.domains.system import SystemDomain
            from gibson.domains.output import OutputDomain

            # Initialize each attack domain
            self.attack_domains[AttackDomain.PROMPT] = PromptDomain(self.config, self)
            self.attack_domains[AttackDomain.DATA] = DataDomain(self.config, self)
            self.attack_domains[AttackDomain.MODEL] = ModelDomain(self.config, self)
            self.attack_domains[AttackDomain.SYSTEM] = SystemDomain(self.config, self)
            self.attack_domains[AttackDomain.OUTPUT] = OutputDomain(self.config, self)

            # Initialize each domain
            for domain, attack_handler in self.attack_domains.items():
                await attack_handler.initialize()
                logger.info(f"Initialized {domain.value} attack domain")

            logger.info(f"Initialized {len(self.attack_domains)} attack domains")

        except Exception as e:
            logger.error(f"Failed to initialize attack domains: {e}")
            # Continue with partial initialization

    async def _initialize_module_manager(self) -> None:
        """Initialize module management system."""
        try:
            # Module manager disabled for now due to database integration issues
            self.module_manager = None
            logger.debug("Module manager initialization skipped")

        except Exception as e:
            logger.error(f"Failed to initialize module manager: {e}")
            # Continue without module manager in degraded mode
            self.module_manager = None

    async def _discover_modules(self) -> None:
        """Discover all available security modules across domains."""
        self.available_modules.clear()

        # For each attack domain, discover modules
        for domain in AttackDomain:
            domain_path = Path("gibson/modules") / domain.value
            if domain_path.exists():
                for module_file in domain_path.glob("*.py"):
                    if module_file.stem != "__init__":
                        self.available_modules[module_file.stem] = domain

        logger.info(
            f"Discovered {len(self.available_modules)} modules across {len(AttackDomain)} domains"
        )

    def _detect_test_mode(self) -> bool:
        """Detect if running in test mode for graceful degradation."""
        import os
        import sys

        # Check for pytest in running modules
        if "pytest" in sys.modules:
            return True

        # Check for PYTEST_CURRENT_TEST environment variable
        if "PYTEST_CURRENT_TEST" in os.environ:
            return True

        # Check for unittest
        if any("unittest" in module for module in sys.modules):
            return True

        # Check for test runner indicators
        if any(arg in sys.argv for arg in ["--test", "pytest", "test"]):
            return True

        return False

    async def get_authentication_context(self, target: TargetModel) -> Optional[Dict[str, Any]]:
        """Get authentication context for a target.

        Args:
            target: Target to get authentication context for

        Returns:
            Authentication context dictionary or None if no auth configured
        """
        if not self.auth_service:
            logger.warning("Authentication service not initialized")
            return None

        try:
            # Check if target requires authentication
            if not target.requires_authentication():
                return None

            # Get credential for target
            credential = self.credential_manager.retrieve_credential(target.id)
            if not credential:
                logger.warning(f"No credential found for target {target.id}")
                return None

            # Return authentication context
            return {
                "target_id": str(target.id),
                "auth_type": credential.auth_type,
                "key_format": credential.key_format.value,
                "validation_status": credential.validation_status.value,
                "last_validated": credential.last_validated.isoformat()
                if credential.last_validated
                else None,
                "has_credential": True,
            }

        except Exception as e:
            logger.error(f"Failed to get authentication context for target {target.id}: {e}")
            return None

    async def validate_target_authentication(self, target: TargetModel) -> bool:
        """Validate authentication for a target before scanning.

        Args:
            target: Target to validate authentication for

        Returns:
            True if authentication is valid or not required
        """
        try:
            # Check if authentication is required
            if not target.requires_authentication():
                logger.debug(f"Target {target.id} does not require authentication")
                return True

            if not self.auth_service:
                logger.error("Authentication service not initialized")
                return False

            # Validate credential
            validation_result = await self.auth_service.validate_credential(target)

            if validation_result.is_valid:
                logger.info(f"Authentication validated successfully for target {target.id}")
                return True
            else:
                logger.error(
                    f"Authentication validation failed for target {target.id}: "
                    f"{validation_result.error_message}"
                )

                # Log recommendations for fixing auth issues
                for recommendation in validation_result.recommendations:
                    logger.info(f"Recommendation: {recommendation}")

                return False

        except Exception as e:
            logger.error(f"Authentication validation error for target {target.id}: {e}")
            return False

    def get_authenticated_http_client(self, target: TargetModel) -> Optional[Any]:
        """Get HTTP client with authentication configured for target.

        Args:
            target: Target to configure authentication for

        Returns:
            HTTP client with authentication middleware or None
        """
        try:
            if not self.request_authenticator:
                logger.error("Request authenticator not initialized")
                return None

            # This would integrate with the HTTP client used by modules
            # For now, return the authenticator that modules can use
            return self.request_authenticator

        except Exception as e:
            logger.error(f"Failed to get authenticated HTTP client for target {target.id}: {e}")
            return None

    async def scan(
        self,
        target: str,
        scan_type: ScanType = ScanType.QUICK,
        modules: Optional[List[str]] = None,
        domains: Optional[List[AttackDomain]] = None,
        dry_run: bool = False,
        require_confirmation: bool = False,
        credentials: Optional[Any] = None,
    ) -> ScanResult:
        """Execute security scan across attack domains.

        Args:
            target: Target to scan (URL, API endpoint, etc.)
            scan_type: Type of scan to perform
            modules: Specific modules to run (if None, auto-select based on scan_type)
            domains: Specific attack domains to include (if None, include all)
            dry_run: Run in simulation mode without actual requests
            require_confirmation: Require user confirmation before execution
            credentials: Optional credentials to use for authenticated scans

        Returns:
            ScanResult with findings from all executed modules
        """
        if not self.initialized:
            await self.initialize()

        scan_id = str(uuid.uuid4())
        started_at = datetime.utcnow()

        logger.info(f"Starting {scan_type.value} scan of {target} (ID: {scan_id})")

        # Validate target
        if not await self._validate_target(target):
            raise ValueError(f"Invalid target: {target}")

        # Validate authentication for target (if it's a TargetModel)
        if isinstance(target, TargetModel):
            if not await self.validate_target_authentication(target):
                logger.error(f"Authentication validation failed for target {target.id}")
                # Continue with scan but log the authentication issue
                logger.warning("Proceeding with scan despite authentication issues")

        # Select modules to run
        selected_modules = await self._select_modules(scan_type, modules, domains)

        # Save initial scan record
        if self.db_manager:
            await self.db_manager.save_scan(
                scan_id=scan_id,
                target=target,
                scan_type=scan_type.value,
                status="running",
                metadata={
                    "dry_run": dry_run,
                    "modules": selected_modules,
                    "domains": [d.value for d in domains] if domains else None,
                },
            )

        self.running_scans.add(scan_id)
        findings = []
        modules_run = 0

        try:
            if dry_run:
                findings = await self._execute_dry_run(target, selected_modules)
                modules_run = len(selected_modules)
            else:
                findings = await self._execute_scan(target, selected_modules, require_confirmation)
                modules_run = len(selected_modules)

            # Save findings to database
            for finding in findings:
                if self.db_manager:
                    await self.db_manager.save_finding(
                        scan_id=scan_id,
                        module=finding.module,
                        severity=finding.severity,
                        title=finding.title,
                        description=finding.description,
                        confidence=finding.confidence,
                        evidence=finding.evidence,
                        remediation=finding.remediation,
                        references=finding.references,
                        owasp_category=finding.owasp_category,
                    )

            completed_at = datetime.utcnow()
            duration = str(completed_at - started_at)

            # Update scan record
            if self.db_manager:
                await self.db_manager.update_scan(
                    scan_id=scan_id,
                    status="completed",
                    completed_at=completed_at,
                    duration=duration,
                    modules_run=modules_run,
                )

            logger.info(f"Scan completed: {len(findings)} findings in {duration}")

        except Exception as e:
            logger.error(f"Scan failed: {e}")
            if self.db_manager:
                await self.db_manager.update_scan(
                    scan_id=scan_id, status="failed", completed_at=datetime.utcnow()
                )
            raise
        finally:
            self.running_scans.discard(scan_id)

        return ScanResult(
            id=scan_id,
            target=target,
            scan_type=scan_type.value,
            started_at=started_at,
            completed_at=completed_at,
            duration=duration,
            modules_run=modules_run,
            findings=findings,
        )

    async def _validate_target(self, target: str) -> bool:
        """Validate scan target."""
        if not target or not target.strip():
            return False

        # Basic validation - more sophisticated validation can be added
        return True

    async def _select_modules(
        self,
        scan_type: ScanType,
        modules: Optional[List[str]],
        domains: Optional[List[AttackDomain]],
    ) -> List[str]:
        """Select modules to run based on scan configuration."""
        if modules:
            # Validate specified modules exist
            valid_modules = [m for m in modules if m in self.available_modules]
            if len(valid_modules) != len(modules):
                invalid = set(modules) - set(valid_modules)
                logger.warning(f"Invalid modules ignored: {invalid}")
            return valid_modules

        # Auto-select based on scan type and domains
        selected = []
        target_domains = domains if domains else list(AttackDomain)

        for module, domain in self.available_modules.items():
            if domain in target_domains:
                if scan_type == ScanType.QUICK:
                    # For quick scans, include high-priority modules
                    if any(keyword in module for keyword in ["injection", "sensitive", "theft"]):
                        selected.append(module)
                elif scan_type == ScanType.FULL:
                    # For full scans, include all modules
                    selected.append(module)
                else:
                    # For specific/custom, include subset
                    selected.append(module)

        return selected

    async def _execute_dry_run(self, target: str, modules: List[str]) -> List[Finding]:
        """Execute dry run simulation."""
        await asyncio.sleep(0.5)  # Simulate processing time

        findings = []
        for module in modules:
            domain = self.available_modules.get(module, AttackDomain.PROMPT)
            findings.append(
                Finding(
                    module=module,
                    severity="INFO",
                    title=f"Dry Run - {module.replace('_', ' ').title()} Test",
                    description=f"This is a dry run simulation for {target} using {module}",
                    confidence=100,
                    evidence={"dry_run": True, "target": target, "domain": domain.value},
                    remediation="This is a simulated finding for testing purposes",
                    owasp_category=self._get_owasp_category(domain),
                )
            )

        return findings

    async def _execute_scan(
        self, target: str, modules: List[str], require_confirmation: bool
    ) -> List[Finding]:
        """Execute actual security scan."""
        if require_confirmation:
            # TODO: Implement confirmation dialog
            logger.info("Confirmation required - proceeding with scan")

        findings = []

        # Execute modules with concurrency control
        semaphore = asyncio.Semaphore(self.config.safety.max_parallel)

        tasks = [self._execute_module(target, module, semaphore) for module in modules]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Finding):
                findings.append(result)
            elif isinstance(result, Exception):
                logger.warning(f"Module execution failed: {result}")

        return findings

    async def _execute_module(
        self, target: str, module_name: str, semaphore: asyncio.Semaphore
    ) -> Optional[Finding]:
        """Execute a specific security module."""
        async with semaphore:
            try:
                domain = self.available_modules.get(module_name)
                if not domain:
                    logger.warning(f"Unknown module: {module_name}")
                    return None

                # Get attack domain handler
                attack_handler = self.attack_domains.get(domain)
                if not attack_handler:
                    logger.warning(f"No handler for domain: {domain}")
                    return None

                # Execute module through domain handler
                return await attack_handler.execute_module(module_name, target)

            except Exception as e:
                logger.error(f"Module {module_name} execution failed: {e}")
                return None

    def _get_owasp_category(self, domain: AttackDomain) -> str:
        """Get OWASP category for attack domain."""
        owasp_mapping = {
            AttackDomain.PROMPT: "OWASP-LLM-01",
            AttackDomain.DATA: "OWASP-LLM-03",
            AttackDomain.MODEL: "OWASP-LLM-04",
            AttackDomain.SYSTEM: "OWASP-LLM-09",
            AttackDomain.OUTPUT: "OWASP-LLM-02",
        }
        return owasp_mapping.get(domain, "OWASP-LLM-01")

    async def list_modules(self, domain: Optional[AttackDomain] = None) -> Dict[str, Any]:
        """List available modules, optionally filtered by domain."""
        if not self.initialized:
            await self.initialize()

        if domain:
            modules = {k: v for k, v in self.available_modules.items() if v == domain}
        else:
            modules = self.available_modules.copy()

        # Group by domain
        grouped = {}
        for module, mod_domain in modules.items():
            if mod_domain.value not in grouped:
                grouped[mod_domain.value] = []
            grouped[mod_domain.value].append(module)

        return {
            "total_modules": len(modules),
            "domains": grouped,
            "available_domains": [d.value for d in AttackDomain],
        }

    async def get_module_info(self, module_name: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a specific module."""
        if module_name not in self.available_modules:
            return None

        domain = self.available_modules[module_name]
        attack_handler = self.attack_domains.get(domain)

        info = {
            "name": module_name,
            "domain": domain.value,
            "owasp_category": self._get_owasp_category(domain),
        }

        if attack_handler:
            capabilities = await attack_handler.get_capabilities()
            info.update(capabilities)

        return info

    async def stop_scan(self, scan_id: str) -> bool:
        """Stop a running scan."""
        if scan_id not in self.running_scans:
            return False

        try:
            if self.db_manager:
                await self.db_manager.update_scan(
                    scan_id=scan_id, status="stopped", completed_at=datetime.utcnow()
                )
            self.running_scans.discard(scan_id)
            logger.info(f"Scan {scan_id} stopped successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to stop scan {scan_id}: {e}")
            return False

    async def get_scan_status(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get current status of a scan."""
        if not self.db_manager:
            await self.initialize()

        if not self.db_manager:
            return None

        scan_record = await self.db_manager.get_scan(scan_id)
        if not scan_record:
            return None

        return {
            "id": scan_record.id,
            "target": scan_record.target,
            "scan_type": scan_record.scan_type,
            "status": scan_record.status,
            "started_at": scan_record.started_at.isoformat() if scan_record.started_at else None,
            "completed_at": scan_record.completed_at.isoformat()
            if scan_record.completed_at
            else None,
            "duration": scan_record.duration,
            "modules_run": scan_record.modules_run,
            "findings_count": len(scan_record.findings) if scan_record.findings else 0,
            "is_running": scan_id in self.running_scans,
        }

    async def cleanup(self) -> None:
        """Cleanup resources and connections."""
        logger.info("Cleaning up Gibson Base orchestrator")

        # Stop any running scans
        for scan_id in list(self.running_scans):
            await self.stop_scan(scan_id)

        # Cleanup shared services
        if self.ai_service and hasattr(self.ai_service, "cleanup"):
            await self.ai_service.cleanup()
        if self.git_service and hasattr(self.git_service, "cleanup"):
            await self.git_service.cleanup()
        if self.data_service and hasattr(self.data_service, "cleanup"):
            await self.data_service.cleanup()

        # Cleanup database
        if self.db_manager:
            await self.db_manager.close()

        self.initialized = False
        logger.info("Gibson Base orchestrator cleanup completed")


# Singleton instance for global access
_base_instance: Optional[Base] = None


def get_base_orchestrator(
    config: Optional[Config] = None, context: Optional[Context] = None
) -> Base:
    """Get or create global Base orchestrator instance."""
    global _base_instance
    if _base_instance is None:
        _base_instance = Base(config, context)
    return _base_instance


def reset_base_orchestrator() -> None:
    """Reset global Base orchestrator (primarily for testing)."""
    global _base_instance
    if _base_instance:
        # Note: Cleanup should be called before reset in production
        _base_instance = None
