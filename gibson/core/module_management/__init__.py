"""Gibson Framework Module Management System.

Provides comprehensive module lifecycle management including discovery,
registration, installation, validation, and execution orchestration.
"""

from gibson.core.module_management.exceptions import (
    ModuleManagementError,
    ModuleNotFoundError,
    ModuleInstallationError,
    DependencyError,
    ModuleValidationError,
    ModuleExecutionError,
)
from gibson.core.module_management.manager import ModuleManager
from gibson.core.module_management.registry import ModuleRegistry
from gibson.core.module_management.cache import ModuleCache
from gibson.core.module_management.validator import ModuleValidator
from gibson.core.module_management.security_validator import SecurityValidator
from gibson.core.module_management.models import (
    ValidationResult,
    SecurityIssue,
    ModuleInstallOptions,
    ModuleFilter,
    DependencyGraph,
    CacheStats,
    ModuleUpdateInfo,
    ModuleExecutionContextModel,
    InstallationResult,
)

__all__ = [
    "ModuleManagementError",
    "ModuleNotFoundError",
    "ModuleInstallationError",
    "DependencyError",
    "ModuleValidationError",
    "ModuleExecutionError",
    "ModuleManager",
    "ModuleRegistry",
    "ModuleCache",
    "ModuleValidator",
    "SecurityValidator",
    "ValidationResult",
    "SecurityIssue",
    "ModuleInstallOptions",
    "ModuleFilter",
    "DependencyGraph",
    "CacheStats",
    "ModuleUpdateInfo",
    "ModuleExecutionContextModel",
    "InstallationResult",
]
