"""Parameter validation helpers for CLI commands."""

import typer
from typing import List, Optional, Set
from gibson.core.base import AttackDomain


def validate_domains(domains: Optional[str]) -> List[AttackDomain]:
    """Validate and parse domain parameter string.

    Args:
        domains: Comma-separated domain names (e.g., "prompt,data,model")

    Returns:
        List of valid AttackDomain enum values

    Raises:
        typer.BadParameter: If any domain is invalid
    """
    if not domains:
        return list(AttackDomain)

    domain_names = [d.strip().lower() for d in domains.split(",")]
    valid_domains = []
    invalid_domains = []

    valid_domain_names = {domain.value for domain in AttackDomain}

    for domain_name in domain_names:
        if domain_name in valid_domain_names:
            # Find the AttackDomain enum by value
            for domain in AttackDomain:
                if domain.value == domain_name:
                    valid_domains.append(domain)
                    break
        else:
            invalid_domains.append(domain_name)

    if invalid_domains:
        valid_options = ", ".join(sorted(valid_domain_names))
        raise typer.BadParameter(
            f"Invalid domain(s): {', '.join(invalid_domains)}. " f"Valid options: {valid_options}"
        )

    return valid_domains


def validate_output_format(output_format: str) -> str:
    """Validate output format parameter.

    Args:
        output_format: Output format string

    Returns:
        Validated output format string

    Raises:
        typer.BadParameter: If format is invalid
    """
    valid_formats = {"table", "json", "yaml", "csv"}

    if output_format.lower() not in valid_formats:
        raise typer.BadParameter(
            f"Invalid output format: {output_format}. "
            f"Valid options: {', '.join(sorted(valid_formats))}"
        )

    return output_format.lower()


def validate_severity_levels(severities: Optional[str]) -> Set[str]:
    """Validate and parse severity levels parameter.

    Args:
        severities: Comma-separated severity levels (e.g., "critical,high")

    Returns:
        Set of valid severity levels

    Raises:
        typer.BadParameter: If any severity is invalid
    """
    if not severities:
        return {"critical", "high", "medium", "low", "info"}

    severity_names = [s.strip().lower() for s in severities.split(",")]
    valid_severities = {"critical", "high", "medium", "low", "info"}
    invalid_severities = []

    for severity in severity_names:
        if severity not in valid_severities:
            invalid_severities.append(severity)

    if invalid_severities:
        valid_options = ", ".join(sorted(valid_severities))
        raise typer.BadParameter(
            f"Invalid severity level(s): {', '.join(invalid_severities)}. "
            f"Valid options: {valid_options}"
        )

    return set(severity_names)


def validate_module_names(modules: Optional[str]) -> List[str]:
    """Validate and parse module names parameter.

    Args:
        modules: Comma-separated module names

    Returns:
        List of module names

    Raises:
        typer.BadParameter: If modules parameter is malformed
    """
    if not modules:
        return []

    module_names = [m.strip() for m in modules.split(",") if m.strip()]

    if not module_names:
        raise typer.BadParameter("Module names cannot be empty")

    # Basic validation for module name format (alphanumeric, underscores, hyphens)
    invalid_modules = []
    for module in module_names:
        if not module.replace("_", "").replace("-", "").isalnum():
            invalid_modules.append(module)

    if invalid_modules:
        raise typer.BadParameter(
            f"Invalid module name format: {', '.join(invalid_modules)}. "
            "Module names should contain only alphanumeric characters, underscores, and hyphens."
        )

    return module_names


def validate_confidence_threshold(threshold: Optional[float]) -> float:
    """Validate confidence threshold parameter.

    Args:
        threshold: Confidence threshold value

    Returns:
        Validated threshold value

    Raises:
        typer.BadParameter: If threshold is out of valid range
    """
    if threshold is None:
        return 0.0

    if not (0.0 <= threshold <= 1.0):
        raise typer.BadParameter(
            f"Confidence threshold must be between 0.0 and 1.0, got: {threshold}"
        )

    return threshold


def validate_scan_type(scan_type: str) -> str:
    """Validate scan type parameter.

    Args:
        scan_type: Scan type string

    Returns:
        Validated scan type string

    Raises:
        typer.BadParameter: If scan type is invalid
    """
    valid_types = {"quick", "full", "specific", "custom"}

    if scan_type.lower() not in valid_types:
        raise typer.BadParameter(
            f"Invalid scan type: {scan_type}. " f"Valid options: {', '.join(sorted(valid_types))}"
        )

    return scan_type.lower()


def validate_positive_integer(value: Optional[int], param_name: str) -> int:
    """Validate that a parameter is a positive integer.

    Args:
        value: Integer value to validate
        param_name: Name of the parameter for error messages

    Returns:
        Validated integer value

    Raises:
        typer.BadParameter: If value is not a positive integer
    """
    if value is None:
        return 1

    if value <= 0:
        raise typer.BadParameter(f"{param_name} must be a positive integer, got: {value}")

    return value


def validate_timeout_seconds(timeout: Optional[int]) -> int:
    """Validate timeout parameter in seconds.

    Args:
        timeout: Timeout value in seconds

    Returns:
        Validated timeout value

    Raises:
        typer.BadParameter: If timeout is invalid
    """
    if timeout is None:
        return 30  # Default timeout

    if timeout <= 0:
        raise typer.BadParameter(f"Timeout must be a positive integer (seconds), got: {timeout}")

    if timeout > 3600:  # 1 hour max
        raise typer.BadParameter(f"Timeout cannot exceed 3600 seconds (1 hour), got: {timeout}")

    return timeout
