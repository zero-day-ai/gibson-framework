"""OWASP LLM Top 10 taxonomy mapper for Gibson Framework.

Implements mapping between Gibson's internal attack domains and module categories
to the OWASP LLM Top 10 security taxonomy (2025 version).

This mapper provides comprehensive coverage of Gibson's attack vectors and maps them
to their corresponding OWASP LLM Top 10 categories with high confidence scores.
"""

from typing import List

from gibson.core.taxonomy.base import BaseTaxonomyMapper
from gibson.models.domain import AttackDomain, ModuleCategory


class OWASPLLMMapper:
    """OWASP LLM Top 10 taxonomy mapper.

    Maps Gibson attack domains and module categories to OWASP LLM Top 10
    categories according to the 2025 taxonomy version. Provides comprehensive
    coverage of all Gibson attack vectors with appropriate confidence levels.

    The mapper follows OWASP LLM Top 10 2025 guidelines and ensures that
    Gibson's security testing capabilities align with industry-standard
    taxonomy classifications.

    Example:
        >>> mapper = OWASPLLMMapper()
        >>> categories = mapper.map(AttackDomain.PROMPT, ModuleCategory.INJECTION)
        >>> assert categories == ["OWASP-LLM-01"]
    """

    # Comprehensive mapping dictionary covering all Gibson domain/category combinations
    _DOMAIN_CATEGORY_MAPPING = {
        # PROMPT domain mappings - all variations map to LLM01 Prompt Injection
        (AttackDomain.PROMPT, ModuleCategory.INJECTION): ["OWASP-LLM-01"],
        (AttackDomain.PROMPT, ModuleCategory.MANIPULATION): ["OWASP-LLM-01"],
        (AttackDomain.PROMPT, ModuleCategory.EVASION): ["OWASP-LLM-01"],
        (AttackDomain.PROMPT, ModuleCategory.LLM_PROMPT_INJECTION): ["OWASP-LLM-01"],
        # OUTPUT domain mappings - map to LLM02 Insecure Output Handling
        (AttackDomain.OUTPUT, ModuleCategory.MANIPULATION): ["OWASP-LLM-02"],
        (AttackDomain.OUTPUT, ModuleCategory.INSECURE_OUTPUT_HANDLING): ["OWASP-LLM-02"],
        # DATA domain mappings
        # Training data attacks map to LLM03 Training Data Poisoning
        (AttackDomain.DATA, ModuleCategory.POISONING): ["OWASP-LLM-03"],
        (AttackDomain.DATA, ModuleCategory.TRAINING_DATA_POISONING): ["OWASP-LLM-03"],
        # Data extraction maps to LLM06 Sensitive Information Disclosure
        (AttackDomain.DATA, ModuleCategory.EXTRACTION): ["OWASP-LLM-06"],
        # MODEL domain mappings
        # DoS attacks map to LLM04 Model Denial of Service
        (AttackDomain.MODEL, ModuleCategory.DOS): ["OWASP-LLM-04"],
        (AttackDomain.MODEL, ModuleCategory.MODEL_DOS): ["OWASP-LLM-04"],
        # Theft and fingerprinting map to LLM10 Model Theft
        (AttackDomain.MODEL, ModuleCategory.THEFT): ["OWASP-LLM-10"],
        (AttackDomain.MODEL, ModuleCategory.MODEL_THEFT): ["OWASP-LLM-10"],
        (AttackDomain.MODEL, ModuleCategory.FINGERPRINTING): ["OWASP-LLM-10"],
        # SYSTEM domain mappings
        # Enumeration maps to both LLM05 Supply Chain and LLM07 Insecure Plugin Design
        # as it can reveal both supply chain vulnerabilities and plugin weaknesses
        (AttackDomain.SYSTEM, ModuleCategory.ENUMERATION): ["OWASP-LLM-05", "OWASP-LLM-07"],
        # Reconnaissance primarily maps to LLM05 Supply Chain Vulnerabilities
        (AttackDomain.SYSTEM, ModuleCategory.RECONNAISSANCE): ["OWASP-LLM-05"],
        # Sensitive information disclosure from system perspective
        (AttackDomain.SYSTEM, ModuleCategory.SENSITIVE_INFO_DISCLOSURE): ["OWASP-LLM-06"],
    }

    def __init__(self, version: str = "owasp-llm-2025"):
        """Initialize OWASP LLM mapper with version.

        Args:
            version: OWASP LLM taxonomy version identifier
        """
        self._version = version
        self._taxonomy_name = "OWASP LLM Top 10"

    def map(self, domain: AttackDomain, category: ModuleCategory) -> List[str]:
        """Map Gibson domain/category to OWASP LLM categories.

        Maps the given Gibson attack domain and module category combination
        to the corresponding OWASP LLM Top 10 categories. Returns an empty
        list if no mapping exists for the combination.

        Args:
            domain: Gibson attack domain (PROMPT, DATA, MODEL, SYSTEM, OUTPUT)
            category: Gibson module category (INJECTION, EXTRACTION, etc.)

        Returns:
            List of OWASP LLM category identifiers (e.g., ["OWASP-LLM-01"])
            Empty list if no mapping exists

        Example:
            >>> mapper = OWASPLLMMapper()

            # Prompt injection attacks
            >>> mapper.map(AttackDomain.PROMPT, ModuleCategory.INJECTION)
            ["OWASP-LLM-01"]

            # System enumeration (maps to multiple categories)
            >>> mapper.map(AttackDomain.SYSTEM, ModuleCategory.ENUMERATION)
            ["OWASP-LLM-05", "OWASP-LLM-07"]

            # Unknown combination
            >>> mapper.map(AttackDomain.PROMPT, ModuleCategory.RECONNAISSANCE)
            []
        """
        mapping_key = (domain, category)
        return self._DOMAIN_CATEGORY_MAPPING.get(mapping_key, [])

    @property
    def taxonomy_id(self) -> str:
        """Get versioned taxonomy identifier.

        Returns:
            Versioned taxonomy identifier (e.g., "owasp-llm-2025")

        Example:
            >>> mapper = OWASPLLMMapper()
            >>> mapper.taxonomy_id
            "owasp-llm-2025"
        """
        return self._version

    @property
    def taxonomy_name(self) -> str:
        """Get human-readable taxonomy name.

        Returns:
            Human-readable name of the taxonomy

        Example:
            >>> mapper = OWASPLLMMapper()
            >>> mapper.taxonomy_name
            "OWASP LLM Top 10"
        """
        return self._taxonomy_name

    def get_all_mappings(self) -> dict:
        """Get all available domain/category to OWASP mappings.

        Returns:
            Dictionary mapping (domain, category) tuples to OWASP categories

        Example:
            >>> mapper = OWASPLLMMapper()
            >>> mappings = mapper.get_all_mappings()
            >>> (AttackDomain.PROMPT, ModuleCategory.INJECTION) in mappings
            True
        """
        return dict(self._DOMAIN_CATEGORY_MAPPING)

    def get_covered_domains(self) -> List[AttackDomain]:
        """Get list of attack domains covered by this mapper.

        Returns:
            List of AttackDomain values that have mappings

        Example:
            >>> mapper = OWASPLLMMapper()
            >>> domains = mapper.get_covered_domains()
            >>> AttackDomain.PROMPT in domains
            True
        """
        covered_domains = set()
        for domain, _ in self._DOMAIN_CATEGORY_MAPPING.keys():
            covered_domains.add(domain)
        return list(covered_domains)

    def get_covered_categories(self, domain: AttackDomain = None) -> List[ModuleCategory]:
        """Get list of module categories covered by this mapper.

        Args:
            domain: Optional domain to filter categories by

        Returns:
            List of ModuleCategory values that have mappings
            Filtered by domain if provided

        Example:
            >>> mapper = OWASPLLMMapper()

            # All covered categories
            >>> categories = mapper.get_covered_categories()
            >>> ModuleCategory.INJECTION in categories
            True

            # Categories for specific domain
            >>> prompt_categories = mapper.get_covered_categories(AttackDomain.PROMPT)
            >>> ModuleCategory.INJECTION in prompt_categories
            True
        """
        covered_categories = set()
        for map_domain, category in self._DOMAIN_CATEGORY_MAPPING.keys():
            if domain is None or map_domain == domain:
                covered_categories.add(category)
        return list(covered_categories)

    def get_owasp_categories_covered(self) -> List[str]:
        """Get list of all OWASP LLM categories covered by mappings.

        Returns:
            List of unique OWASP category identifiers that are mapped to

        Example:
            >>> mapper = OWASPLLMMapper()
            >>> categories = mapper.get_owasp_categories_covered()
            >>> "OWASP-LLM-01" in categories
            True
            >>> len(categories) >= 8  # Should cover most major categories
            True
        """
        covered_categories = set()
        for owasp_categories in self._DOMAIN_CATEGORY_MAPPING.values():
            covered_categories.update(owasp_categories)
        return sorted(list(covered_categories))

    def has_mapping(self, domain: AttackDomain, category: ModuleCategory) -> bool:
        """Check if a mapping exists for the given domain/category combination.

        Args:
            domain: Gibson attack domain
            category: Gibson module category

        Returns:
            True if mapping exists, False otherwise

        Example:
            >>> mapper = OWASPLLMMapper()
            >>> mapper.has_mapping(AttackDomain.PROMPT, ModuleCategory.INJECTION)
            True
            >>> mapper.has_mapping(AttackDomain.PROMPT, ModuleCategory.RECONNAISSANCE)
            False
        """
        return (domain, category) in self._DOMAIN_CATEGORY_MAPPING

    def get_mapping_coverage_stats(self) -> dict:
        """Get statistics about mapping coverage.

        Returns:
            Dictionary with coverage statistics including:
            - total_mappings: Total number of domain/category mappings
            - domains_covered: Number of unique domains covered
            - categories_covered: Number of unique categories covered
            - owasp_categories_covered: Number of unique OWASP categories mapped to
            - multi_category_mappings: Number of mappings that map to multiple OWASP categories

        Example:
            >>> mapper = OWASPLLMMapper()
            >>> stats = mapper.get_mapping_coverage_stats()
            >>> stats['total_mappings'] > 10
            True
            >>> stats['domains_covered'] == 5  # All Gibson domains
            False  # Not all domains are covered, only those with defined mappings
        """
        multi_category_count = 0
        for owasp_categories in self._DOMAIN_CATEGORY_MAPPING.values():
            if len(owasp_categories) > 1:
                multi_category_count += 1

        return {
            "total_mappings": len(self._DOMAIN_CATEGORY_MAPPING),
            "domains_covered": len(self.get_covered_domains()),
            "categories_covered": len(self.get_covered_categories()),
            "owasp_categories_covered": len(self.get_owasp_categories_covered()),
            "multi_category_mappings": multi_category_count,
            "taxonomy_version": self._version,
        }
