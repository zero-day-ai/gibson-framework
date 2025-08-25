"""MITRE ATLAS taxonomy mapper for Gibson Framework.

Implements mapping between Gibson's internal attack domains and module categories
to the MITRE ATLAS framework for adversarial AI/ML security taxonomy.

The MITRE ATLAS framework provides a comprehensive matrix of adversarial tactics
and techniques against machine learning systems. This mapper aligns Gibson's
attack vectors with ATLAS techniques to provide standardized threat intelligence
mapping for AI/ML security testing.

MITRE ATLAS focuses on adversarial ML attacks and provides detailed technique
descriptions, mitigations, and detection strategies for AI/ML systems.
"""

from typing import List

from gibson.core.taxonomy.base import BaseTaxonomyMapper
from gibson.models.domain import AttackDomain, ModuleCategory


class MITREATLASMapper:
    """MITRE ATLAS taxonomy mapper.

    Maps Gibson attack domains and module categories to MITRE ATLAS
    techniques according to the ATLAS framework. Provides comprehensive
    coverage of adversarial AI/ML attack vectors with appropriate mappings
    to ATLAS technique identifiers.

    The mapper follows MITRE ATLAS taxonomy structure and ensures that
    Gibson's AI/ML security testing capabilities align with the industry
    standard framework for adversarial machine learning threats.

    MITRE ATLAS organizes adversarial ML attacks into tactics and techniques,
    providing a structured approach to understanding and defending against
    AI/ML-specific threats.

    Example:
        >>> mapper = MITREATLASMapper()
        >>> techniques = mapper.map(AttackDomain.PROMPT, ModuleCategory.INJECTION)
        >>> assert techniques == ["AML.T0051"]
    """

    # Comprehensive mapping dictionary covering Gibson domain/category to ATLAS techniques
    _DOMAIN_CATEGORY_MAPPING = {
        # PROMPT domain mappings
        # Prompt injection attacks map to AML.T0051 (Prompt Injection)
        (AttackDomain.PROMPT, ModuleCategory.INJECTION): ["AML.T0051"],
        (AttackDomain.PROMPT, ModuleCategory.LLM_PROMPT_INJECTION): ["AML.T0051"],
        # Prompt manipulation also maps to prompt injection
        (AttackDomain.PROMPT, ModuleCategory.MANIPULATION): ["AML.T0051"],
        # Prompt evasion techniques map to ML model evasion
        (AttackDomain.PROMPT, ModuleCategory.EVASION): ["AML.T0043"],
        # DATA domain mappings
        # Data poisoning attacks map to AML.T0020 (Poison Training Data)
        (AttackDomain.DATA, ModuleCategory.POISONING): ["AML.T0020"],
        (AttackDomain.DATA, ModuleCategory.TRAINING_DATA_POISONING): ["AML.T0020"],
        # Data extraction maps to AML.T0037 (Data from ML Model)
        (AttackDomain.DATA, ModuleCategory.EXTRACTION): ["AML.T0037"],
        # MODEL domain mappings
        # Model theft and reverse engineering
        (AttackDomain.MODEL, ModuleCategory.THEFT): ["AML.T0035"],
        (AttackDomain.MODEL, ModuleCategory.MODEL_THEFT): ["AML.T0035"],
        # Model extraction techniques
        (AttackDomain.MODEL, ModuleCategory.EXTRACTION): ["AML.T0024"],
        # Model fingerprinting maps to ML inference API access
        (AttackDomain.MODEL, ModuleCategory.FINGERPRINTING): ["AML.T0018"],
        # Model evasion attacks
        (AttackDomain.MODEL, ModuleCategory.EVASION): ["AML.T0043"],
        # Model denial of service maps to resource hijacking
        (AttackDomain.MODEL, ModuleCategory.DOS): ["AML.T0034"],
        (AttackDomain.MODEL, ModuleCategory.MODEL_DOS): ["AML.T0034"],
        # SYSTEM domain mappings
        # System enumeration and reconnaissance map to discovering ML artifacts
        (AttackDomain.SYSTEM, ModuleCategory.ENUMERATION): ["AML.T0016"],
        (AttackDomain.SYSTEM, ModuleCategory.RECONNAISSANCE): ["AML.T0016"],
        # System fingerprinting for ML infrastructure discovery
        (AttackDomain.SYSTEM, ModuleCategory.FINGERPRINTING): ["AML.T0016"],
        # System-level sensitive information disclosure
        (AttackDomain.SYSTEM, ModuleCategory.SENSITIVE_INFO_DISCLOSURE): ["AML.T0037"],
        # OUTPUT domain mappings
        # Output manipulation can lead to data extraction
        (AttackDomain.OUTPUT, ModuleCategory.MANIPULATION): ["AML.T0037"],
        # Insecure output handling leading to information disclosure
        (AttackDomain.OUTPUT, ModuleCategory.INSECURE_OUTPUT_HANDLING): ["AML.T0037"],
        # Output extraction techniques
        (AttackDomain.OUTPUT, ModuleCategory.EXTRACTION): ["AML.T0037"],
    }

    def __init__(self, version: str = "mitre-atlas-2024"):
        """Initialize MITRE ATLAS mapper with version.

        Args:
            version: MITRE ATLAS taxonomy version identifier
        """
        self._version = version
        self._taxonomy_name = "MITRE ATLAS"

    def map(self, domain: AttackDomain, category: ModuleCategory) -> List[str]:
        """Map Gibson domain/category to MITRE ATLAS techniques.

        Maps the given Gibson attack domain and module category combination
        to the corresponding MITRE ATLAS technique identifiers. Returns an
        empty list if no mapping exists for the combination.

        Args:
            domain: Gibson attack domain (PROMPT, DATA, MODEL, SYSTEM, OUTPUT)
            category: Gibson module category (INJECTION, EXTRACTION, etc.)

        Returns:
            List of MITRE ATLAS technique identifiers (e.g., ["AML.T0051"])
            Empty list if no mapping exists

        Example:
            >>> mapper = MITREATLASMapper()

            # Prompt injection attacks
            >>> mapper.map(AttackDomain.PROMPT, ModuleCategory.INJECTION)
            ["AML.T0051"]

            # Data poisoning attacks
            >>> mapper.map(AttackDomain.DATA, ModuleCategory.POISONING)
            ["AML.T0020"]

            # Model theft attacks
            >>> mapper.map(AttackDomain.MODEL, ModuleCategory.THEFT)
            ["AML.T0035"]

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
            Versioned taxonomy identifier (e.g., "mitre-atlas-2024")

        Example:
            >>> mapper = MITREATLASMapper()
            >>> mapper.taxonomy_id
            "mitre-atlas-2024"
        """
        return self._version

    @property
    def taxonomy_name(self) -> str:
        """Get human-readable taxonomy name.

        Returns:
            Human-readable name of the taxonomy

        Example:
            >>> mapper = MITREATLASMapper()
            >>> mapper.taxonomy_name
            "MITRE ATLAS"
        """
        return self._taxonomy_name

    def get_all_mappings(self) -> dict:
        """Get all available domain/category to MITRE ATLAS mappings.

        Returns:
            Dictionary mapping (domain, category) tuples to ATLAS techniques

        Example:
            >>> mapper = MITREATLASMapper()
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
            >>> mapper = MITREATLASMapper()
            >>> domains = mapper.get_covered_domains()
            >>> AttackDomain.PROMPT in domains
            True
            >>> AttackDomain.MODEL in domains
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
            >>> mapper = MITREATLASMapper()

            # All covered categories
            >>> categories = mapper.get_covered_categories()
            >>> ModuleCategory.INJECTION in categories
            True
            >>> ModuleCategory.POISONING in categories
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

    def get_atlas_techniques_covered(self) -> List[str]:
        """Get list of all MITRE ATLAS techniques covered by mappings.

        Returns:
            List of unique ATLAS technique identifiers that are mapped to

        Example:
            >>> mapper = MITREATLASMapper()
            >>> techniques = mapper.get_atlas_techniques_covered()
            >>> "AML.T0051" in techniques  # Prompt Injection
            True
            >>> "AML.T0020" in techniques  # Poison Training Data
            True
            >>> "AML.T0035" in techniques  # ML Model Reverse Engineering
            True
            >>> len(techniques) >= 6  # Should cover multiple major techniques
            True
        """
        covered_techniques = set()
        for atlas_techniques in self._DOMAIN_CATEGORY_MAPPING.values():
            covered_techniques.update(atlas_techniques)
        return sorted(list(covered_techniques))

    def has_mapping(self, domain: AttackDomain, category: ModuleCategory) -> bool:
        """Check if a mapping exists for the given domain/category combination.

        Args:
            domain: Gibson attack domain
            category: Gibson module category

        Returns:
            True if mapping exists, False otherwise

        Example:
            >>> mapper = MITREATLASMapper()
            >>> mapper.has_mapping(AttackDomain.PROMPT, ModuleCategory.INJECTION)
            True
            >>> mapper.has_mapping(AttackDomain.DATA, ModuleCategory.POISONING)
            True
            >>> mapper.has_mapping(AttackDomain.PROMPT, ModuleCategory.RECONNAISSANCE)
            False
        """
        return (domain, category) in self._DOMAIN_CATEGORY_MAPPING

    def get_technique_description(self, technique_id: str) -> str:
        """Get description for a MITRE ATLAS technique.

        Args:
            technique_id: ATLAS technique identifier (e.g., "AML.T0051")

        Returns:
            Human-readable description of the technique

        Example:
            >>> mapper = MITREATLASMapper()
            >>> desc = mapper.get_technique_description("AML.T0051")
            >>> "prompt injection" in desc.lower()
            True
        """
        # Descriptions for mapped ATLAS techniques
        technique_descriptions = {
            "AML.T0051": "Prompt Injection - Adversaries may inject prompts into ML systems to manipulate model behavior and generate unintended outputs",
            "AML.T0020": "Poison Training Data - Adversaries may poison training datasets to cause ML models to make incorrect predictions during inference",
            "AML.T0035": "ML Model Reverse Engineering - Adversaries may reverse engineer ML models to understand their architecture, parameters, or training data",
            "AML.T0024": "Extract ML Model - Adversaries may extract ML models through various techniques including model stealing and parameter extraction",
            "AML.T0037": "Data from ML Model - Adversaries may extract sensitive data from ML models including training data, intermediate representations, or predictions",
            "AML.T0043": "Evade ML Model - Adversaries may craft adversarial inputs designed to evade detection or cause misclassification by ML models",
            "AML.T0016": "Discover ML Model Artifacts - Adversaries may discover and enumerate ML model artifacts, configurations, and infrastructure components",
            "AML.T0018": "ML Model Inference API Access - Adversaries may gain access to ML model inference APIs to probe model behavior and capabilities",
            "AML.T0034": "Resource Hijacking - Adversaries may hijack computational resources to perform unauthorized ML model training or inference operations",
        }
        return technique_descriptions.get(technique_id, f"MITRE ATLAS technique {technique_id}")

    def get_tactic_for_technique(self, technique_id: str) -> str:
        """Get the primary tactic for a MITRE ATLAS technique.

        Args:
            technique_id: ATLAS technique identifier

        Returns:
            Primary tactic name for the technique

        Example:
            >>> mapper = MITREATLASMapper()
            >>> tactic = mapper.get_tactic_for_technique("AML.T0051")
            >>> tactic in ["ML Attack Staging", "Initial Access"]
            True
        """
        # Primary tactic mappings for ATLAS techniques
        technique_tactics = {
            "AML.T0051": "Initial Access",
            "AML.T0020": "ML Attack Staging",
            "AML.T0035": "Collection",
            "AML.T0024": "Collection",
            "AML.T0037": "Collection",
            "AML.T0043": "Defense Evasion",
            "AML.T0016": "Discovery",
            "AML.T0018": "Discovery",
            "AML.T0034": "Impact",
        }
        return technique_tactics.get(technique_id, "Unknown")

    def get_mapping_coverage_stats(self) -> dict:
        """Get statistics about mapping coverage.

        Returns:
            Dictionary with coverage statistics including:
            - total_mappings: Total number of domain/category mappings
            - domains_covered: Number of unique domains covered
            - categories_covered: Number of unique categories covered
            - atlas_techniques_covered: Number of unique ATLAS techniques mapped to
            - tactics_covered: Number of unique ATLAS tactics represented
            - taxonomy_version: Version of ATLAS taxonomy used

        Example:
            >>> mapper = MITREATLASMapper()
            >>> stats = mapper.get_mapping_coverage_stats()
            >>> stats['total_mappings'] >= 15
            True
            >>> stats['domains_covered'] == 5  # All Gibson domains
            True
            >>> stats['atlas_techniques_covered'] >= 6
            True
        """
        atlas_techniques = self.get_atlas_techniques_covered()
        tactics_covered = set()
        for technique in atlas_techniques:
            tactic = self.get_tactic_for_technique(technique)
            if tactic != "Unknown":
                tactics_covered.add(tactic)

        return {
            "total_mappings": len(self._DOMAIN_CATEGORY_MAPPING),
            "domains_covered": len(self.get_covered_domains()),
            "categories_covered": len(self.get_covered_categories()),
            "atlas_techniques_covered": len(atlas_techniques),
            "tactics_covered": len(tactics_covered),
            "taxonomy_version": self._version,
        }

    def get_mappings_by_tactic(self) -> dict:
        """Get mappings organized by MITRE ATLAS tactic.

        Returns:
            Dictionary mapping tactic names to lists of (domain, category) tuples

        Example:
            >>> mapper = MITREATLASMapper()
            >>> by_tactic = mapper.get_mappings_by_tactic()
            >>> "Initial Access" in by_tactic
            True
            >>> "Collection" in by_tactic
            True
        """
        mappings_by_tactic = {}

        for (domain, category), techniques in self._DOMAIN_CATEGORY_MAPPING.items():
            for technique in techniques:
                tactic = self.get_tactic_for_technique(technique)
                if tactic not in mappings_by_tactic:
                    mappings_by_tactic[tactic] = []
                if (domain, category) not in mappings_by_tactic[tactic]:
                    mappings_by_tactic[tactic].append((domain, category))

        return mappings_by_tactic

    def search_techniques_by_keyword(self, keyword: str) -> List[str]:
        """Search ATLAS techniques by keyword in description.

        Args:
            keyword: Keyword to search for in technique descriptions

        Returns:
            List of technique IDs whose descriptions contain the keyword

        Example:
            >>> mapper = MITREATLASMapper()
            >>> techniques = mapper.search_techniques_by_keyword("injection")
            >>> "AML.T0051" in techniques
            True
            >>> techniques = mapper.search_techniques_by_keyword("data")
            >>> "AML.T0020" in techniques
            True
        """
        matching_techniques = []
        keyword_lower = keyword.lower()

        for technique in self.get_atlas_techniques_covered():
            description = self.get_technique_description(technique)
            if keyword_lower in description.lower():
                matching_techniques.append(technique)

        return matching_techniques
