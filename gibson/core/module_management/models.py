"""Pydantic models for Module Management Layer.

Provides type-safe data structures for module operations including
validation results, installation options, dependency management, and cache statistics.
"""

from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from uuid import UUID

from pydantic import BaseModel, Field, field_validator, model_validator

from gibson.models.base import GibsonBaseModel, TimestampedModel, ValidatedModel
from gibson.models.domain import AttackDomain, Severity
from gibson.models.module import ModuleStatus, ModuleDefinitionModel


class SecurityIssue(GibsonBaseModel):
    """Security issue found during module validation."""

    issue_type: str = Field(
        description="Type of security issue (e.g., 'dangerous_import', 'privilege_escalation')"
    )
    severity: str = Field(description="Severity level (low, medium, high, critical)")
    description: str = Field(description="Human-readable description of the issue")
    location: Optional[str] = Field(
        default=None, description="Location in code where issue was found (e.g., 'line 42')"
    )
    recommendation: Optional[str] = Field(
        default=None, description="Recommendation for fixing the issue"
    )
    code_snippet: Optional[str] = Field(
        default=None, description="Relevant code snippet showing the issue"
    )
    cwe_id: Optional[str] = Field(
        default=None, description="Common Weakness Enumeration ID if applicable"
    )

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        """Validate severity level."""
        allowed = ["low", "medium", "high", "critical"]
        if v.lower() not in allowed:
            raise ValueError(f"Severity must be one of: {allowed}")
        return v.lower()


class ValidationResult(GibsonBaseModel):
    """Result of module validation process."""

    valid: bool = Field(description="Whether the module passed validation")
    errors: List[str] = Field(
        default_factory=list, description="List of validation errors that prevent module use"
    )
    warnings: List[str] = Field(
        default_factory=list, description="List of validation warnings (non-blocking issues)"
    )
    security_issues: List[SecurityIssue] = Field(
        default_factory=list, description="List of security issues found in the module"
    )
    required_permissions: List[str] = Field(
        default_factory=list, description="List of permissions required by this module"
    )
    risk_level: str = Field(
        default="low", description="Overall risk level assessment (low, medium, high, critical)"
    )
    validation_time: float = Field(default=0.0, description="Time taken for validation in seconds")
    validated_at: datetime = Field(
        default_factory=datetime.utcnow, description="Timestamp when validation was performed"
    )
    validator_version: Optional[str] = Field(
        default=None, description="Version of the validation system used"
    )

    @field_validator("risk_level")
    @classmethod
    def validate_risk_level(cls, v: str) -> str:
        """Validate risk level."""
        allowed = ["low", "medium", "high", "critical"]
        if v.lower() not in allowed:
            raise ValueError(f"Risk level must be one of: {allowed}")
        return v.lower()

    @model_validator(mode="after")
    def validate_consistency(self) -> "ValidationResult":
        """Ensure validation result consistency."""
        # If there are errors, module should not be valid
        if self.errors and self.valid:
            raise ValueError("Module cannot be valid if there are validation errors")

        # Determine risk level from security issues if not explicitly set
        if self.security_issues and self.risk_level == "low":
            max_severity = "low"
            for issue in self.security_issues:
                if issue.severity == "critical":
                    max_severity = "critical"
                    break
                elif issue.severity == "high" and max_severity != "critical":
                    max_severity = "high"
                elif issue.severity == "medium" and max_severity in ["low"]:
                    max_severity = "medium"
            self.risk_level = max_severity

        return self

    def add_error(self, error: str) -> None:
        """Add validation error."""
        self.errors.append(error)
        self.valid = False

    def add_warning(self, warning: str) -> None:
        """Add validation warning."""
        self.warnings.append(warning)

    def add_security_issue(self, issue: SecurityIssue) -> None:
        """Add security issue."""
        self.security_issues.append(issue)
        # Re-evaluate risk level
        if issue.severity in ["critical", "high"]:
            if self.risk_level in ["low", "medium"]:
                self.risk_level = issue.severity

    def is_acceptable_risk(self, max_risk_level: str = "medium") -> bool:
        """Check if the risk level is acceptable."""
        risk_hierarchy = ["low", "medium", "high", "critical"]
        current_level = risk_hierarchy.index(self.risk_level)
        max_level = risk_hierarchy.index(max_risk_level)
        return current_level <= max_level


class DependencyResolutionStrategy(str, Enum):
    """Strategy for resolving module dependencies."""

    STRICT = "strict"  # Fail if any conflicts
    BEST_EFFORT = "best_effort"  # Try to resolve conflicts
    SKIP = "skip"  # Skip dependency resolution


class ModuleInstallOptions(GibsonBaseModel):
    """Options for module installation."""

    force: bool = Field(default=False, description="Force overwrite if module already exists")
    dev_mode: bool = Field(
        default=False, description="Install in development mode (editable install)"
    )
    skip_deps: bool = Field(default=False, description="Skip dependency installation")
    verify_signature: bool = Field(default=True, description="Verify module signature if available")
    target_directory: Optional[Path] = Field(
        default=None, description="Custom installation directory"
    )
    dependency_strategy: DependencyResolutionStrategy = Field(
        default=DependencyResolutionStrategy.STRICT,
        description="Strategy for dependency resolution",
    )
    max_install_time: int = Field(
        default=300, ge=30, description="Maximum installation time in seconds"
    )
    backup_existing: bool = Field(
        default=True, description="Create backup of existing module before overwrite"
    )
    install_docs: bool = Field(default=False, description="Install module documentation")
    enable_after_install: bool = Field(
        default=True, description="Enable module after successful installation"
    )


class DependencyNode(GibsonBaseModel):
    """Node in dependency graph."""

    name: str = Field(description="Package or module name")
    version_spec: str = Field(default="*", description="Version specification (e.g., '>=1.0.0')")
    resolved_version: Optional[str] = Field(
        default=None, description="Resolved version after conflict resolution"
    )
    is_dev: bool = Field(default=False, description="Whether this is a development dependency")
    dependencies: List[str] = Field(
        default_factory=list, description="List of this node's dependencies"
    )

    def is_version_compatible(self, available_version: str) -> bool:
        """Check if available version satisfies requirement."""
        if not self.version_spec or self.version_spec == "*":
            return True

        # Simple version comparison - in production would use packaging.specifiers
        try:
            from packaging import specifiers, version

            spec = specifiers.SpecifierSet(self.version_spec)
            return version.parse(available_version) in spec
        except ImportError:
            # Fallback to simple string comparison if packaging not available
            return available_version == self.version_spec.replace("==", "").strip()


class DependencyEdge(GibsonBaseModel):
    """Edge in dependency graph."""

    source: str = Field(description="Source node name")
    target: str = Field(description="Target node name")
    version_constraint: str = Field(
        default="*", description="Version constraint for this dependency"
    )
    is_dev: bool = Field(default=False, description="Whether this is a development dependency")


class DependencyConflict(GibsonBaseModel):
    """Dependency version conflict."""

    package: str = Field(description="Name of conflicting package")
    requirements: List[str] = Field(description="List of conflicting requirements")
    resolution: Optional[str] = Field(default=None, description="Suggested resolution")


class DependencyGraph(GibsonBaseModel):
    """Complete dependency graph for a module."""

    root_module: str = Field(description="Name of the root module")
    nodes: Dict[str, DependencyNode] = Field(
        default_factory=dict, description="Map of node names to dependency nodes"
    )
    edges: List[DependencyEdge] = Field(
        default_factory=list, description="List of dependency edges"
    )
    conflicts: List[DependencyConflict] = Field(
        default_factory=list, description="List of version conflicts"
    )

    def add_node(self, node: DependencyNode) -> None:
        """Add a dependency node."""
        self.nodes[node.name] = node

    def add_edge(self, edge: DependencyEdge) -> None:
        """Add a dependency edge."""
        self.edges.append(edge)

    def add_conflict(self, conflict: DependencyConflict) -> None:
        """Add a dependency conflict."""
        self.conflicts.append(conflict)

    def has_conflicts(self) -> bool:
        """Check if there are any unresolved conflicts."""
        return len(self.conflicts) > 0

    def get_node_dependencies(self, node_name: str) -> List[str]:
        """Get dependencies of a specific node."""
        deps = []
        for edge in self.edges:
            if edge.source == node_name:
                deps.append(edge.target)
        return deps


class DependencyResolutionResult(GibsonBaseModel):
    """Result of dependency resolution."""

    success: bool = Field(description="Whether resolution was successful")
    graph: DependencyGraph = Field(description="The dependency graph")
    resolution_order: List[str] = Field(
        default_factory=list, description="Order in which dependencies should be installed"
    )
    python_packages: List[str] = Field(
        default_factory=list, description="Python packages to install"
    )
    gibson_modules: List[str] = Field(default_factory=list, description="Gibson modules to install")
    conflicts: List[DependencyConflict] = Field(
        default_factory=list, description="Any conflicts found"
    )
    warnings: List[str] = Field(default_factory=list, description="Warning messages")
    error: Optional[str] = Field(default=None, description="Error message if resolution failed")


class CacheStats(GibsonBaseModel):
    """Cache statistics for monitoring performance."""

    hits: int = Field(default=0, ge=0, description="Number of cache hits")
    misses: int = Field(default=0, ge=0, description="Number of cache misses")
    size: int = Field(default=0, ge=0, description="Current cache size")
    max_size: int = Field(default=1000, gt=0, description="Maximum cache size")
    evictions: int = Field(default=0, ge=0, description="Number of cache evictions")

    @property
    def hit_rate(self) -> float:
        """Calculate cache hit rate as percentage."""
        total = self.hits + self.misses
        return (self.hits / total * 100) if total > 0 else 0.0

    @property
    def utilization(self) -> float:
        """Calculate cache utilization as percentage."""
        return (self.size / self.max_size * 100) if self.max_size > 0 else 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "hits": self.hits,
            "misses": self.misses,
            "size": self.size,
            "max_size": self.max_size,
            "evictions": self.evictions,
            "hit_rate": round(self.hit_rate, 2),
            "utilization": round(self.utilization, 2),
        }


class InstallationResult(GibsonBaseModel):
    """Result of module installation."""

    success: bool = Field(description="Whether installation was successful")
    module_name: str = Field(description="Name of the module")
    module_version: str = Field(description="Version of the module")
    install_path: Path = Field(description="Path where module was installed")
    source: str = Field(description="Source from which module was installed")
    validation_result: Optional[ValidationResult] = Field(
        default=None, description="Validation result if validation was performed"
    )
    dependency_result: Optional[DependencyResolutionResult] = Field(
        default=None, description="Dependency resolution result"
    )
    warnings: List[str] = Field(
        default_factory=list, description="Any warnings during installation"
    )
    error: Optional[str] = Field(default=None, description="Error message if installation failed")
    metadata: Optional[ModuleDefinitionModel] = Field(default=None, description="Module metadata")


class ModuleUpdateInfo(GibsonBaseModel):
    """Information about available module updates."""

    module_name: str = Field(description="Name of the module")
    current_version: str = Field(description="Currently installed version")
    latest_version: str = Field(description="Latest available version")
    changelog: Optional[str] = Field(default=None, description="Changelog or release notes")
    breaking_changes: bool = Field(
        default=False, description="Whether the update contains breaking changes"
    )
    update_size: int = Field(default=0, ge=0, description="Size of the update in bytes")
    dependencies_changed: bool = Field(
        default=False, description="Whether dependencies have changed"
    )
    security_fixes: List[str] = Field(
        default_factory=list, description="List of security issues fixed in this update"
    )
    release_date: Optional[datetime] = Field(
        default=None, description="Release date of the latest version"
    )
    update_priority: str = Field(
        default="normal", description="Priority level (low, normal, high, critical)"
    )

    @field_validator("update_priority")
    @classmethod
    def validate_priority(cls, v: str) -> str:
        """Validate update priority."""
        allowed = ["low", "normal", "high", "critical"]
        if v.lower() not in allowed:
            raise ValueError(f"Update priority must be one of: {allowed}")
        return v.lower()

    def is_major_update(self) -> bool:
        """Check if this is a major version update."""
        try:
            current_parts = self.current_version.split(".")
            latest_parts = self.latest_version.split(".")

            if len(current_parts) >= 1 and len(latest_parts) >= 1:
                current_major = int(current_parts[0])
                latest_major = int(latest_parts[0])
                return latest_major > current_major
        except (ValueError, IndexError):
            pass

        return False

    def requires_attention(self) -> bool:
        """Check if update requires user attention."""
        return (
            self.breaking_changes
            or self.dependencies_changed
            or self.update_priority in ["high", "critical"]
            or bool(self.security_fixes)
        )


class ModuleExecutionContextModel(GibsonBaseModel):
    """Execution context for module runs."""

    execution_id: UUID = Field(description="Unique execution identifier")
    module_name: str = Field(description="Name of module being executed")
    target_id: UUID = Field(description="Target identifier")
    scan_id: Optional[UUID] = Field(default=None, description="Associated scan identifier")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Execution parameters")
    environment: Dict[str, str] = Field(
        default_factory=dict, description="Environment variables for execution"
    )
    resource_limits: Dict[str, Any] = Field(
        default_factory=dict, description="Resource limits (memory, CPU, time, etc.)"
    )
    timeout: int = Field(default=300, gt=0, description="Execution timeout in seconds")
    max_memory_mb: int = Field(default=512, gt=0, description="Maximum memory usage in MB")
    started_at: Optional[datetime] = Field(default=None, description="Execution start time")
    user_context: Dict[str, Any] = Field(
        default_factory=dict, description="User context and permissions"
    )

    def set_resource_limit(self, resource: str, limit: Any) -> None:
        """Set a resource limit."""
        self.resource_limits[resource] = limit

    def get_resource_limit(self, resource: str, default: Any = None) -> Any:
        """Get a resource limit."""
        return self.resource_limits.get(resource, default)


class ModuleFilter(GibsonBaseModel):
    """Filter criteria for module searches and listings."""

    domains: Optional[List[AttackDomain]] = Field(
        default=None, description="Filter by attack domains"
    )
    status: Optional[List[ModuleStatus]] = Field(
        default=None, description="Filter by module status"
    )
    author: Optional[str] = Field(default=None, description="Filter by author name")
    tags: Optional[List[str]] = Field(default=None, description="Filter by tags (any match)")
    min_version: Optional[str] = Field(default=None, description="Minimum version constraint")
    severity: Optional[List[Severity]] = Field(
        default=None, description="Filter by risk severity levels"
    )
    search_term: Optional[str] = Field(default=None, description="Text search in name/description")
    enabled_only: bool = Field(default=False, description="Only return enabled modules")
    has_updates: bool = Field(
        default=False, description="Only return modules with available updates"
    )
    installed_after: Optional[datetime] = Field(
        default=None, description="Filter by installation date"
    )
    limit: Optional[int] = Field(default=None, gt=0, description="Maximum number of results")
    offset: int = Field(default=0, ge=0, description="Offset for pagination")
    sort_by: str = Field(
        default="name", description="Sort field (name, version, installed_date, etc.)"
    )
    sort_desc: bool = Field(default=False, description="Sort in descending order")

    @field_validator("sort_by")
    @classmethod
    def validate_sort_field(cls, v: str) -> str:
        """Validate sort field."""
        allowed = [
            "name",
            "version",
            "author",
            "installed_date",
            "last_updated",
            "usage_count",
            "domain",
        ]
        if v not in allowed:
            raise ValueError(f"Sort field must be one of: {allowed}")
        return v

    def applies_to(self, module: ModuleDefinitionModel) -> bool:
        """Check if filter applies to a given module."""
        # Domain filter
        if self.domains and module.domain not in self.domains:
            return False

        # Status filter
        if self.status and module.status not in self.status:
            return False

        # Author filter
        if self.author and self.author.lower() not in module.author.lower():
            return False

        # Tags filter
        if self.tags:
            module_tags_lower = [tag.lower() for tag in module.tags]
            if not any(tag.lower() in module_tags_lower for tag in self.tags):
                return False

        # Severity filter
        if self.severity and module.severity not in self.severity:
            return False

        # Search term filter
        if self.search_term:
            search_text = " ".join(
                [module.name.lower(), module.display_name.lower(), module.description.lower()]
            )
            if self.search_term.lower() not in search_text:
                return False

        # Enabled only filter
        if self.enabled_only and module.status != ModuleStatus.ENABLED:
            return False

        # Installation date filter
        if self.installed_after and module.installation_date < self.installed_after:
            return False

        return True


class InstallationResult(GibsonBaseModel):
    """Result of module installation operation."""

    success: bool = Field(description="Whether installation succeeded")
    module_name: str = Field(description="Name of installed module")
    version: Optional[str] = Field(default=None, description="Installed version")
    installed_modules: List[str] = Field(
        default_factory=list, description="List of modules successfully installed"
    )
    skipped_modules: List[str] = Field(
        default_factory=list, description="List of modules that were skipped"
    )
    failed_modules: List[str] = Field(
        default_factory=list, description="List of modules that failed to install"
    )
    dependency_failures: List[str] = Field(
        default_factory=list, description="List of dependencies that failed to install"
    )
    errors: List[str] = Field(default_factory=list, description="List of error messages")
    warnings: List[str] = Field(default_factory=list, description="List of warning messages")
    installation_time: float = Field(
        default=0.0, ge=0, description="Total installation time in seconds"
    )
    backup_path: Optional[Path] = Field(
        default=None, description="Path to backup of previous version"
    )
    rollback_available: bool = Field(default=False, description="Whether rollback is available")


# Type aliases for common model types
ModuleDict = Dict[str, ModuleDefinitionModel]
DependencyDict = Dict[str, DependencyNode]
ConflictList = List[DependencyConflict]
ValidationDict = Dict[str, ValidationResult]
