"""Custom exceptions for Module Management Layer.

Provides specialized exception hierarchy for module operations
with detailed error information and recovery guidance.
"""

from typing import Any, Dict, List, Optional


class ModuleManagementError(Exception):
    """Base exception for module management operations.
    
    All module management related exceptions inherit from this class
    to provide consistent error handling patterns.
    """
    
    def __init__(
        self,
        message: str,
        module_name: Optional[str] = None,
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        suggestions: Optional[List[str]] = None
    ):
        super().__init__(message, error_code, details)
        self.module_name = module_name
        self.suggestions = suggestions or []
    
    def __str__(self) -> str:
        """Enhanced string representation with suggestions."""
        msg = super().__str__()
        if self.module_name:
            msg = f"[{self.module_name}] {msg}"
        if self.suggestions:
            msg += f" Suggestions: {'; '.join(self.suggestions)}"
        return msg


class ModuleNotFoundError(ModuleManagementError):
    """Raised when a requested module cannot be found.
    
    Includes suggestions for similar module names and installation
    instructions for external modules.
    """
    
    def __init__(
        self,
        module_name: str,
        available_modules: Optional[List[str]] = None,
        search_locations: Optional[List[str]] = None
    ):
        # Generate helpful suggestions
        suggestions = []
        if available_modules:
            # Find similar module names using simple string matching
            similar = [
                name for name in available_modules 
                if module_name.lower() in name.lower() or name.lower() in module_name.lower()
            ]
            if similar:
                suggestions.append(f"Try: {', '.join(similar[:3])}")
            
        if search_locations:
            suggestions.append(f"Module searched in: {', '.join(search_locations)}")
            
        suggestions.extend([
            f"List available modules: gibson module list",
            f"Install from registry: gibson module install {module_name}",
            f"Search registry: gibson module search {module_name}"
        ])
        
        super().__init__(
            f"Module '{module_name}' not found",
            module_name=module_name,
            error_code="MODULE_NOT_FOUND",
            suggestions=suggestions
        )
        self.available_modules = available_modules or []
        self.search_locations = search_locations or []


class ModuleInstallationError(ModuleManagementError):
    """Raised when module installation fails.
    
    Provides detailed information about installation failure reasons
    and suggested recovery actions.
    """
    
    def __init__(
        self,
        message: str,
        module_name: Optional[str] = None,
        source: Optional[str] = None,
        stage: Optional[str] = None,
        original_error: Optional[Exception] = None,
        rollback_available: bool = False
    ):
        suggestions = []
        
        if stage == "validation":
            suggestions.extend([
                "Check module structure matches Gibson Framework requirements",
                "Ensure module inherits from BaseModule",
                "Verify required methods are implemented"
            ])
        elif stage == "dependencies":
            suggestions.extend([
                "Check network connectivity for dependency downloads",
                "Verify Python package versions are compatible",
                "Try installing with --no-deps to skip dependency resolution"
            ])
        elif stage == "fetch":
            suggestions.extend([
                "Verify source URL is accessible",
                "Check authentication credentials if required",
                "Try installing from a different source"
            ])
        
        if rollback_available:
            suggestions.append("Previous state has been preserved, no cleanup needed")
        
        if source:
            suggestions.append(f"Try installing from different source: {source}")
            
        super().__init__(
            message,
            module_name=module_name,
            error_code="INSTALLATION_FAILED",
            details={
                "source": source,
                "stage": stage,
                "original_error": str(original_error) if original_error else None,
                "rollback_available": rollback_available
            },
            suggestions=suggestions
        )
        self.source = source
        self.stage = stage
        self.original_error = original_error
        self.rollback_available = rollback_available


class DependencyError(ModuleManagementError):
    """Raised when dependency resolution fails.
    
    Handles circular dependencies, version conflicts, and missing
    dependencies with detailed conflict resolution guidance.
    """
    
    def __init__(
        self,
        message: str,
        module_name: Optional[str] = None,
        conflicts: Optional[List[Dict[str, Any]]] = None,
        circular_deps: Optional[List[str]] = None,
        missing_deps: Optional[List[str]] = None
    ):
        suggestions = []
        
        if circular_deps:
            suggestions.append(
                f"Circular dependency detected: {' -> '.join(circular_deps)}"
            )
            suggestions.append("Remove or restructure dependencies to break the cycle")
        
        if conflicts:
            suggestions.append("Version conflicts found:")
            for conflict in conflicts[:3]:  # Show first 3 conflicts
                dep_name = conflict.get("dependency", "unknown")
                required = conflict.get("required_version", "unknown")
                installed = conflict.get("installed_version", "unknown")
                suggestions.append(
                    f"  {dep_name}: required {required}, installed {installed}"
                )
        
        if missing_deps:
            suggestions.append(f"Missing dependencies: {', '.join(missing_deps[:5])}")
            suggestions.append("Install missing dependencies manually or use --force flag")
        
        suggestions.extend([
            "Try installing with different dependency resolution strategy",
            "Use --dependency-strategy best_effort for lenient resolution"
        ])
        
        super().__init__(
            message,
            module_name=module_name,
            error_code="DEPENDENCY_ERROR",
            details={
                "conflicts": conflicts,
                "circular_dependencies": circular_deps,
                "missing_dependencies": missing_deps
            },
            suggestions=suggestions
        )
        self.conflicts = conflicts or []
        self.circular_deps = circular_deps or []
        self.missing_deps = missing_deps or []


class CircularDependencyError(DependencyError):
    """Raised when circular dependencies are detected in module dependency graph."""
    
    def __init__(
        self,
        message: str,
        circular_path: List[str],
        module_name: Optional[str] = None
    ):
        super().__init__(
            message,
            module_name=module_name,
            circular_deps=circular_path
        )
        self.circular_path = circular_path


class DependencyConflictError(DependencyError):
    """Raised when dependency version conflicts cannot be resolved."""
    
    def __init__(
        self,
        message: str,
        conflicts: List[Dict[str, Any]],
        module_name: Optional[str] = None
    ):
        super().__init__(
            message,
            module_name=module_name,
            conflicts=conflicts
        )


class VersionConflictError(DependencyError):
    """Raised when specific version conflicts are detected."""
    
    def __init__(
        self,
        message: str,
        package_name: str,
        required_version: str,
        installed_version: str,
        module_name: Optional[str] = None
    ):
        conflicts = [{
            "dependency": package_name,
            "required_version": required_version,
            "installed_version": installed_version
        }]
        super().__init__(
            message,
            module_name=module_name,
            conflicts=conflicts
        )
        self.package_name = package_name
        self.required_version = required_version
        self.installed_version = installed_version


class ModuleValidationError(ModuleManagementError):
    """Raised when module validation fails.
    
    Covers structural validation, code analysis, and security
    validation failures with specific remediation guidance.
    """
    
    def __init__(
        self,
        message: str,
        module_name: Optional[str] = None,
        validation_type: Optional[str] = None,
        errors: Optional[List[str]] = None,
        warnings: Optional[List[str]] = None,
        security_issues: Optional[List[Dict[str, Any]]] = None
    ):
        suggestions = []
        
        if validation_type == "structure":
            suggestions.extend([
                "Ensure module inherits from BaseModule or domain-specific base class",
                "Implement required abstract methods: run(), get_config_schema()",
                "Check module file structure and naming conventions"
            ])
        elif validation_type == "code":
            suggestions.extend([
                "Review code for syntax errors and dangerous patterns",
                "Remove or secure potentially dangerous imports",
                "Follow Python best practices and Gibson coding standards"
            ])
        elif validation_type == "security":
            suggestions.extend([
                "Remove or justify security-sensitive operations",
                "Add proper permission declarations if elevated access needed",
                "Consider sandboxing or containerization for risky operations"
            ])
        
        if errors:
            suggestions.append(f"Address validation errors: {'; '.join(errors[:3])}")
        
        if security_issues:
            risk_levels = [issue.get("risk_level", "unknown") for issue in security_issues]
            if "critical" in risk_levels:
                suggestions.append("CRITICAL security issues found - module blocked")
            elif "high" in risk_levels:
                suggestions.append("High-risk security issues require manual review")
        
        super().__init__(
            message,
            module_name=module_name,
            error_code="VALIDATION_FAILED",
            details={
                "validation_type": validation_type,
                "errors": errors,
                "warnings": warnings,
                "security_issues": security_issues
            },
            suggestions=suggestions
        )
        self.validation_type = validation_type
        self.errors = errors or []
        self.warnings = warnings or []
        self.security_issues = security_issues or []


class ModuleExecutionError(ModuleManagementError):
    """Raised when module execution fails.
    
    Handles runtime errors, timeouts, resource limit violations,
    and execution environment issues.
    """
    
    def __init__(
        self,
        message: str,
        module_name: Optional[str] = None,
        execution_stage: Optional[str] = None,
        timeout: bool = False,
        resource_limit: Optional[str] = None,
        exit_code: Optional[int] = None,
        original_error: Optional[Exception] = None
    ):
        suggestions = []
        
        if timeout:
            suggestions.extend([
                "Module execution timed out",
                "Consider increasing timeout limit or optimizing module performance",
                "Check if module is waiting for user input or external resources"
            ])
        
        if resource_limit:
            suggestions.extend([
                f"Resource limit exceeded: {resource_limit}",
                "Optimize module to use fewer resources",
                "Consider increasing resource limits for this module"
            ])
        
        if execution_stage == "setup":
            suggestions.extend([
                "Module setup/initialization failed",
                "Check module dependencies and configuration",
                "Verify target compatibility with module requirements"
            ])
        elif execution_stage == "run":
            suggestions.extend([
                "Module execution failed during main run phase",
                "Review module logs for specific error details",
                "Verify target is accessible and properly configured"
            ])
        elif execution_stage == "teardown":
            suggestions.extend([
                "Module cleanup failed - resources may not be properly released",
                "Manual cleanup may be required"
            ])
        
        suggestions.extend([
            "Check module logs for detailed error information",
            "Try running with verbose logging enabled",
            "Verify module is compatible with current Gibson Framework version"
        ])
        
        super().__init__(
            message,
            module_name=module_name,
            error_code="EXECUTION_FAILED",
            details={
                "execution_stage": execution_stage,
                "timeout": timeout,
                "resource_limit": resource_limit,
                "exit_code": exit_code,
                "original_error": str(original_error) if original_error else None
            },
            suggestions=suggestions
        )
        self.execution_stage = execution_stage
        self.timeout = timeout
        self.resource_limit = resource_limit
        self.exit_code = exit_code
        self.original_error = original_error


class ModuleRegistryError(ModuleManagementError):
    """Raised when module registry operations fail.
    
    Handles registry corruption, network issues, and synchronization
    problems with recovery strategies.
    """
    
    def __init__(
        self,
        message: str,
        registry_url: Optional[str] = None,
        network_error: bool = False,
        corruption_detected: bool = False
    ):
        suggestions = []
        
        if network_error:
            suggestions.extend([
                "Check network connectivity",
                "Verify registry URL is accessible",
                "Try refreshing registry: gibson module registry --refresh"
            ])
        
        if corruption_detected:
            suggestions.extend([
                "Registry corruption detected",
                "Automatic rebuild will be attempted",
                "Clear registry cache if problems persist"
            ])
        
        if registry_url:
            suggestions.append(f"Registry URL: {registry_url}")
        
        super().__init__(
            message,
            error_code="REGISTRY_ERROR",
            details={
                "registry_url": registry_url,
                "network_error": network_error,
                "corruption_detected": corruption_detected
            },
            suggestions=suggestions
        )
        self.registry_url = registry_url
        self.network_error = network_error
        self.corruption_detected = corruption_detected
