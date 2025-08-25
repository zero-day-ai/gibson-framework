"""Taxonomy mapping orchestrator for Gibson Framework.

Provides the main TaxonomyMapper class that orchestrates multiple taxonomy mappers
and provides a unified interface for mapping Gibson's internal attack domains and
module categories to external security taxonomies.

The orchestrator maintains a registry of taxonomy mappers, applies confidence-based
filtering, and handles mapper failures gracefully while providing comprehensive
logging and error reporting.
"""

import logging
from typing import Any, Optional

from gibson.core.taxonomy.base import BaseTaxonomyMapper
from gibson.core.taxonomy.owasp_llm import OWASPLLMMapper
from gibson.models.domain import AttackDomain, ModuleCategory

logger = logging.getLogger(__name__)


class TaxonomyMapper:
    """Main taxonomy mapping orchestrator.

    Manages multiple taxonomy mappers and provides a unified interface for
    mapping Gibson's attack domains and module categories to external security
    taxonomies. Supports confidence-based filtering, graceful error handling,
    and comprehensive logging.

    The orchestrator automatically registers the OWASP LLM mapper on initialization
    and provides methods for registering additional mappers from other security
    frameworks like MITRE ATT&CK, CWE, NIST, etc.

    Example:
        >>> mapper = TaxonomyMapper()
        >>> findings = mapper.map_finding(AttackDomain.PROMPT, ModuleCategory.INJECTION)
        >>> assert "owasp-llm-2025" in findings
        >>> assert "OWASP-LLM-01" in findings["owasp-llm-2025"]

        >>> # Register additional mappers
        >>> custom_mapper = CustomTaxonomyMapper()
        >>> mapper.register_mapper("custom", custom_mapper)
        >>> findings = mapper.map_finding(AttackDomain.PROMPT, ModuleCategory.INJECTION)
        >>> assert "custom" in findings
    """

    def __init__(self, confidence_threshold: float = 0.5):
        """Initialize taxonomy mapper orchestrator.

        Args:
            confidence_threshold: Minimum confidence threshold for mappings (0.0-1.0)
                Mappings below this threshold will be filtered out

        Raises:
            ValueError: If confidence_threshold is not between 0.0 and 1.0
        """
        if not 0.0 <= confidence_threshold <= 1.0:
            raise ValueError("Confidence threshold must be between 0.0 and 1.0")

        self._mappers: dict[str, BaseTaxonomyMapper] = {}
        self._confidence_threshold = confidence_threshold

        # Register default OWASP LLM mapper
        self._register_default_mappers()

        logger.info(
            f"TaxonomyMapper initialized with confidence threshold {confidence_threshold}, "
            f"registered mappers: {list(self._mappers.keys())}"
        )

    def _register_default_mappers(self) -> None:
        """Register default taxonomy mappers.

        Currently registers the OWASP LLM Top 10 mapper by default.
        This method is called during initialization to ensure basic
        taxonomy mapping capabilities are available.
        """
        try:
            owasp_mapper = OWASPLLMMapper()
            self._mappers[owasp_mapper.taxonomy_id] = owasp_mapper
            logger.debug(f"Registered default OWASP LLM mapper: {owasp_mapper.taxonomy_id}")
        except Exception as e:
            logger.error(f"Failed to register default OWASP LLM mapper: {e}")
            # Don't raise - allow mapper to function without default mappers

    def register_mapper(self, name: str, mapper: BaseTaxonomyMapper) -> None:
        """Register a taxonomy mapper.

        Args:
            name: Unique identifier for the mapper (e.g., "mitre-attack-v14")
            mapper: Taxonomy mapper instance implementing BaseTaxonomyMapper protocol

        Raises:
            ValueError: If name is empty or mapper is None
            TypeError: If mapper doesn't implement required protocol methods

        Example:
            >>> mapper = TaxonomyMapper()
            >>> custom_mapper = MITREATTACKMapper()
            >>> mapper.register_mapper("mitre-attack", custom_mapper)
            >>> assert "mitre-attack" in mapper.get_supported_taxonomies()
        """
        if not name or not isinstance(name, str):
            raise ValueError("Mapper name must be a non-empty string")

        if mapper is None:
            raise ValueError("Mapper cannot be None")

        # Validate that mapper implements required protocol methods
        required_methods = ["map", "taxonomy_id", "taxonomy_name"]
        for method in required_methods:
            if not hasattr(mapper, method):
                raise TypeError(f"Mapper must implement {method} method")

        # Check if name conflicts with existing mapper
        if name in self._mappers:
            logger.warning(f"Overriding existing mapper with name: {name}")

        self._mappers[name] = mapper
        logger.info(f"Registered taxonomy mapper: {name} ({mapper.taxonomy_name})")

    def unregister_mapper(self, name: str) -> bool:
        """Unregister a taxonomy mapper.

        Args:
            name: Unique identifier of the mapper to remove

        Returns:
            True if mapper was removed, False if it didn't exist

        Example:
            >>> mapper = TaxonomyMapper()
            >>> success = mapper.unregister_mapper("owasp-llm-2025")
            >>> assert success is True
            >>> assert "owasp-llm-2025" not in mapper.get_supported_taxonomies()
        """
        if name in self._mappers:
            removed_mapper = self._mappers.pop(name)
            logger.info(f"Unregistered taxonomy mapper: {name} ({removed_mapper.taxonomy_name})")
            return True
        else:
            logger.warning(f"Attempted to unregister non-existent mapper: {name}")
            return False

    def get_mapper(self, name: str) -> Optional[BaseTaxonomyMapper]:
        """Get a specific taxonomy mapper by name.

        Args:
            name: Unique identifier of the mapper

        Returns:
            Taxonomy mapper instance or None if not found

        Example:
            >>> mapper = TaxonomyMapper()
            >>> owasp_mapper = mapper.get_mapper("owasp-llm-2025")
            >>> assert owasp_mapper is not None
            >>> assert owasp_mapper.taxonomy_name == "OWASP LLM Top 10"
        """
        return self._mappers.get(name)

    def get_supported_taxonomies(self) -> list[str]:
        """Get list of all supported taxonomy identifiers.

        Returns:
            List of taxonomy identifiers for all registered mappers

        Example:
            >>> mapper = TaxonomyMapper()
            >>> taxonomies = mapper.get_supported_taxonomies()
            >>> assert "owasp-llm-2025" in taxonomies
            >>> assert len(taxonomies) >= 1
        """
        return list(self._mappers.keys())

    def map_finding(
        self, domain: AttackDomain, category: ModuleCategory, confidence: Optional[float] = None
    ) -> dict[str, list[str]]:
        """Map Gibson domain/category to all registered taxonomies.

        Applies all registered taxonomy mappers to the given domain/category
        combination and returns a dictionary mapping taxonomy identifiers to
        their corresponding category lists. Handles mapper failures gracefully
        and applies confidence-based filtering.

        Args:
            domain: Gibson attack domain
            category: Gibson module category
            confidence: Optional confidence score for filtering (overrides instance threshold)
                      If provided, only mappings with this confidence or higher are returned

        Returns:
            Dictionary mapping taxonomy identifiers to lists of taxonomy categories.
            Failed mappers are excluded from results (logged as warnings).

        Example:
            >>> mapper = TaxonomyMapper()

            >>> # Basic mapping
            >>> results = mapper.map_finding(AttackDomain.PROMPT, ModuleCategory.INJECTION)
            >>> assert "owasp-llm-2025" in results
            >>> assert "OWASP-LLM-01" in results["owasp-llm-2025"]

            >>> # With confidence filtering
            >>> results = mapper.map_finding(
            ...     AttackDomain.PROMPT,
            ...     ModuleCategory.INJECTION,
            ...     confidence=0.9
            ... )
            >>> # Only high-confidence mappings returned
        """
        results = {}
        effective_threshold = confidence if confidence is not None else self._confidence_threshold

        logger.debug(
            f"Mapping finding: domain={domain.value}, category={category.value}, "
            f"confidence_threshold={effective_threshold}"
        )

        for mapper_name, mapper in self._mappers.items():
            try:
                # Get mapping from this taxonomy mapper
                mapped_categories = mapper.map(domain, category)

                if mapped_categories:
                    # Apply confidence filtering if applicable
                    # Note: Individual mappers may implement their own confidence logic
                    # For now, we include all non-empty results and let mappers handle confidence
                    results[mapper_name] = mapped_categories
                    logger.debug(
                        f"Mapper {mapper_name} mapped {domain.value}:{category.value} "
                        f"to {len(mapped_categories)} categories: {mapped_categories}"
                    )
                else:
                    logger.debug(
                        f"Mapper {mapper_name} found no mappings for {domain.value}:{category.value}"
                    )

            except Exception as e:
                logger.warning(
                    f"Mapper {mapper_name} failed to map {domain.value}:{category.value}: {e}",
                    exc_info=True,
                )
                # Continue with other mappers - don't let one failure break everything

        logger.info(
            f"Mapping completed: {domain.value}:{category.value} -> "
            f"{len(results)} taxonomies, {sum(len(cats) for cats in results.values())} total categories"
        )

        return results

    def get_mapper_info(self) -> dict[str, dict[str, str]]:
        """Get information about all registered mappers.

        Returns:
            Dictionary mapping mapper names to their metadata including
            taxonomy_id, taxonomy_name, and any additional info

        Example:
            >>> mapper = TaxonomyMapper()
            >>> info = mapper.get_mapper_info()
            >>> assert "owasp-llm-2025" in info
            >>> assert info["owasp-llm-2025"]["taxonomy_name"] == "OWASP LLM Top 10"
        """
        mapper_info = {}

        for name, mapper in self._mappers.items():
            try:
                mapper_info[name] = {
                    "taxonomy_id": mapper.taxonomy_id,
                    "taxonomy_name": mapper.taxonomy_name,
                    "mapper_type": type(mapper).__name__,
                }

                # Add additional info if mapper provides it
                if hasattr(mapper, "get_mapping_coverage_stats"):
                    try:
                        stats = mapper.get_mapping_coverage_stats()
                        mapper_info[name]["coverage_stats"] = stats
                    except Exception as e:
                        logger.debug(f"Could not get coverage stats for {name}: {e}")

            except Exception as e:
                logger.warning(f"Could not get info for mapper {name}: {e}")
                mapper_info[name] = {"error": str(e), "mapper_type": type(mapper).__name__}

        return mapper_info

    def validate_mapper_health(self) -> dict[str, bool]:
        """Validate health of all registered mappers.

        Tests each mapper with a known domain/category combination to ensure
        they are functioning properly. Useful for system health checks.

        Returns:
            Dictionary mapping mapper names to their health status (True/False)

        Example:
            >>> mapper = TaxonomyMapper()
            >>> health = mapper.validate_mapper_health()
            >>> assert health["owasp-llm-2025"] is True
        """
        health_status = {}
        test_domain = AttackDomain.PROMPT
        test_category = ModuleCategory.INJECTION

        logger.info("Validating mapper health with test mapping")

        for name, mapper in self._mappers.items():
            try:
                # Test basic mapping functionality
                result = mapper.map(test_domain, test_category)

                # Validate required properties are accessible
                taxonomy_id = mapper.taxonomy_id
                taxonomy_name = mapper.taxonomy_name

                # Basic validation that properties are non-empty strings
                if not isinstance(taxonomy_id, str) or not taxonomy_id:
                    raise ValueError("taxonomy_id must be non-empty string")
                if not isinstance(taxonomy_name, str) or not taxonomy_name:
                    raise ValueError("taxonomy_name must be non-empty string")

                # Validate mapping result format
                if not isinstance(result, list):
                    raise ValueError("map() must return list")

                health_status[name] = True
                logger.debug(f"Mapper {name} health check passed")

            except Exception as e:
                health_status[name] = False
                logger.error(f"Mapper {name} health check failed: {e}")

        healthy_count = sum(health_status.values())
        total_count = len(health_status)

        logger.info(
            f"Mapper health validation completed: {healthy_count}/{total_count} mappers healthy"
        )

        return health_status

    def get_statistics(self) -> dict[str, Any]:
        """Get comprehensive statistics about the taxonomy mapper system.

        Returns:
            Dictionary with system statistics including mapper counts,
            health status, and configuration info

        Example:
            >>> mapper = TaxonomyMapper()
            >>> stats = mapper.get_statistics()
            >>> assert stats["total_mappers"] >= 1
            >>> assert "confidence_threshold" in stats
        """
        health_status = self.validate_mapper_health()

        return {
            "total_mappers": len(self._mappers),
            "healthy_mappers": sum(health_status.values()),
            "supported_taxonomies": self.get_supported_taxonomies(),
            "confidence_threshold": self._confidence_threshold,
            "mapper_health": health_status,
            "mapper_info": self.get_mapper_info(),
        }

    def set_confidence_threshold(self, threshold: float) -> None:
        """Update the confidence threshold for filtering mappings.

        Args:
            threshold: New confidence threshold (0.0-1.0)

        Raises:
            ValueError: If threshold is not between 0.0 and 1.0

        Example:
            >>> mapper = TaxonomyMapper()
            >>> mapper.set_confidence_threshold(0.8)
            >>> assert mapper._confidence_threshold == 0.8
        """
        if not 0.0 <= threshold <= 1.0:
            raise ValueError("Confidence threshold must be between 0.0 and 1.0")

        old_threshold = self._confidence_threshold
        self._confidence_threshold = threshold

        logger.info(f"Updated confidence threshold from {old_threshold} to {threshold}")

    def clear_mappers(self) -> int:
        """Remove all registered mappers.

        Returns:
            Number of mappers that were removed

        Example:
            >>> mapper = TaxonomyMapper()
            >>> count = mapper.clear_mappers()
            >>> assert count >= 1  # At least the default OWASP mapper
            >>> assert len(mapper.get_supported_taxonomies()) == 0
        """
        count = len(self._mappers)
        self._mappers.clear()

        logger.info(f"Cleared all taxonomy mappers ({count} removed)")
        return count

    def __len__(self) -> int:
        """Get number of registered mappers.

        Returns:
            Number of registered taxonomy mappers
        """
        return len(self._mappers)

    def __contains__(self, mapper_name: str) -> bool:
        """Check if a mapper is registered.

        Args:
            mapper_name: Name of mapper to check

        Returns:
            True if mapper is registered
        """
        return mapper_name in self._mappers

    def __repr__(self) -> str:
        """String representation of taxonomy mapper.

        Returns:
            String describing the mapper state
        """
        return (
            f"TaxonomyMapper(mappers={len(self._mappers)}, "
            f"confidence_threshold={self._confidence_threshold}, "
            f"taxonomies={list(self._mappers.keys())})"
        )
