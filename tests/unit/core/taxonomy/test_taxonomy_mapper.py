"""
Unit tests for taxonomy mapper components - TDD approach.

This test file follows TDD principles and tests:
1. BaseTaxonomyMapper protocol compliance
2. OWASP mapping for all domain/category combinations  
3. Edge cases (null values, unknown combinations)
4. TaxonomyMapper orchestrator functionality

The taxonomy system replaces hardcoded OWASP dependencies with flexible tag-based mapping.
"""

import pytest
from typing import Dict, List, Optional, Protocol
from unittest.mock import Mock, patch

from gibson.models.domain import AttackDomain, ModuleCategory


class BaseTaxonomyMapper(Protocol):
    """Protocol for taxonomy mappers that convert Gibson categories to external taxonomies."""

    def map_to_tags(
        self, domain: AttackDomain, category: ModuleCategory, confidence: Optional[float] = None
    ) -> Dict[str, List[str]]:
        """Map domain/category to taxonomy tags."""
        ...

    def get_supported_taxonomies(self) -> List[str]:
        """Return list of supported taxonomy names."""
        ...

    def get_version(self, taxonomy: str) -> Optional[str]:
        """Get version of specific taxonomy."""
        ...


class MockOWASPMapper:
    """Mock OWASP taxonomy mapper for testing."""

    def __init__(self, version: str = "owasp-llm-2025"):
        self.version = version
        self.confidence_threshold = 0.7

    def map_to_tags(
        self, domain: AttackDomain, category: ModuleCategory, confidence: Optional[float] = None
    ) -> Dict[str, List[str]]:
        """Map Gibson domain/category to OWASP tags."""
        mapping = {
            # Prompt domain mappings
            (AttackDomain.PROMPT, ModuleCategory.INJECTION): ["OWASP-LLM-01"],
            (AttackDomain.PROMPT, ModuleCategory.LLM_PROMPT_INJECTION): ["OWASP-LLM-01"],
            (AttackDomain.PROMPT, ModuleCategory.EVASION): ["OWASP-LLM-01"],
            # Data domain mappings
            (AttackDomain.DATA, ModuleCategory.POISONING): ["OWASP-LLM-03"],
            (AttackDomain.DATA, ModuleCategory.TRAINING_DATA_POISONING): ["OWASP-LLM-03"],
            (AttackDomain.DATA, ModuleCategory.EXTRACTION): ["OWASP-LLM-06"],
            (AttackDomain.DATA, ModuleCategory.SENSITIVE_INFO_DISCLOSURE): ["OWASP-LLM-06"],
            # Model domain mappings
            (AttackDomain.MODEL, ModuleCategory.THEFT): ["OWASP-LLM-10"],
            (AttackDomain.MODEL, ModuleCategory.MODEL_THEFT): ["OWASP-LLM-10"],
            (AttackDomain.MODEL, ModuleCategory.DOS): ["OWASP-LLM-04"],
            (AttackDomain.MODEL, ModuleCategory.MODEL_DOS): ["OWASP-LLM-04"],
            (AttackDomain.MODEL, ModuleCategory.FINGERPRINTING): ["OWASP-LLM-10"],
            # System domain mappings
            (AttackDomain.SYSTEM, ModuleCategory.ENUMERATION): ["OWASP-LLM-07", "OWASP-LLM-05"],
            (AttackDomain.SYSTEM, ModuleCategory.RECONNAISSANCE): ["OWASP-LLM-05"],
            # Output domain mappings
            (AttackDomain.OUTPUT, ModuleCategory.MANIPULATION): ["OWASP-LLM-02"],
            (AttackDomain.OUTPUT, ModuleCategory.INSECURE_OUTPUT_HANDLING): ["OWASP-LLM-02"],
        }

        key = (domain, category)
        tags = mapping.get(key, [])

        # Apply confidence threshold if provided
        if confidence is not None and confidence < self.confidence_threshold:
            return {"owasp": []}

        return {"owasp": tags}

    def get_supported_taxonomies(self) -> List[str]:
        return ["owasp"]

    def get_version(self, taxonomy: str) -> Optional[str]:
        if taxonomy == "owasp":
            return self.version
        return None


class MockTaxonomyMapper:
    """Main taxonomy mapper orchestrator for testing."""

    def __init__(self):
        self._mappers: Dict[str, BaseTaxonomyMapper] = {}
        self.default_confidence = 0.8

    def register_mapper(self, name: str, mapper: BaseTaxonomyMapper) -> None:
        """Register a taxonomy mapper."""
        self._mappers[name] = mapper

    def unregister_mapper(self, name: str) -> None:
        """Unregister a taxonomy mapper."""
        self._mappers.pop(name, None)

    def get_mapper(self, name: str) -> Optional[BaseTaxonomyMapper]:
        """Get specific mapper by name."""
        return self._mappers.get(name)

    def list_mappers(self) -> List[str]:
        """List all registered mappers."""
        return list(self._mappers.keys())

    def map_to_all_taxonomies(
        self, domain: AttackDomain, category: ModuleCategory, confidence: Optional[float] = None
    ) -> Dict[str, Dict[str, List[str]]]:
        """Map to all registered taxonomies."""
        result = {}

        for name, mapper in self._mappers.items():
            try:
                tags = mapper.map_to_tags(domain, category, confidence)
                result[name] = tags
            except Exception as e:
                result[name] = {"error": [str(e)]}

        return result


# Test fixtures
@pytest.fixture
def owasp_mapper():
    """OWASP mapper instance for testing."""
    return MockOWASPMapper()


@pytest.fixture
def taxonomy_mapper():
    """Main taxonomy mapper for testing."""
    return MockTaxonomyMapper()


@pytest.fixture
def populated_taxonomy_mapper(taxonomy_mapper, owasp_mapper):
    """Taxonomy mapper with OWASP mapper registered."""
    taxonomy_mapper.register_mapper("owasp", owasp_mapper)
    return taxonomy_mapper


# ========================================
# Protocol Compliance Tests
# ========================================


class TestBaseTaxonomyMapperProtocol:
    """Test that mappers comply with BaseTaxonomyMapper protocol."""

    @pytest.mark.unit
    def test_owasp_mapper_implements_protocol(self, owasp_mapper):
        """Test OWASP mapper implements BaseTaxonomyMapper protocol."""
        # Check required methods exist
        assert hasattr(owasp_mapper, "map_to_tags")
        assert hasattr(owasp_mapper, "get_supported_taxonomies")
        assert hasattr(owasp_mapper, "get_version")

        # Check method signatures work
        tags = owasp_mapper.map_to_tags(AttackDomain.PROMPT, ModuleCategory.INJECTION)
        assert isinstance(tags, dict)

        taxonomies = owasp_mapper.get_supported_taxonomies()
        assert isinstance(taxonomies, list)

        version = owasp_mapper.get_version("owasp")
        assert isinstance(version, (str, type(None)))

    @pytest.mark.unit
    def test_protocol_method_signatures(self, owasp_mapper):
        """Test protocol method signatures are correct."""
        # map_to_tags should accept domain, category, optional confidence
        result = owasp_mapper.map_to_tags(
            AttackDomain.PROMPT, ModuleCategory.INJECTION, confidence=0.9
        )
        assert isinstance(result, dict)

        # get_supported_taxonomies should return list of strings
        taxonomies = owasp_mapper.get_supported_taxonomies()
        assert all(isinstance(t, str) for t in taxonomies)

        # get_version should accept taxonomy name
        version = owasp_mapper.get_version("nonexistent")
        assert version is None


# ========================================
# OWASP Mapping Tests
# ========================================


class TestOWASPMapping:
    """Test OWASP LLM Top 10 mapping for all domain/category combinations."""

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "domain,category,expected_owasp",
        [
            # Prompt domain
            (AttackDomain.PROMPT, ModuleCategory.INJECTION, ["OWASP-LLM-01"]),
            (AttackDomain.PROMPT, ModuleCategory.LLM_PROMPT_INJECTION, ["OWASP-LLM-01"]),
            (AttackDomain.PROMPT, ModuleCategory.EVASION, ["OWASP-LLM-01"]),
            # Data domain
            (AttackDomain.DATA, ModuleCategory.POISONING, ["OWASP-LLM-03"]),
            (AttackDomain.DATA, ModuleCategory.TRAINING_DATA_POISONING, ["OWASP-LLM-03"]),
            (AttackDomain.DATA, ModuleCategory.EXTRACTION, ["OWASP-LLM-06"]),
            (AttackDomain.DATA, ModuleCategory.SENSITIVE_INFO_DISCLOSURE, ["OWASP-LLM-06"]),
            # Model domain
            (AttackDomain.MODEL, ModuleCategory.THEFT, ["OWASP-LLM-10"]),
            (AttackDomain.MODEL, ModuleCategory.MODEL_THEFT, ["OWASP-LLM-10"]),
            (AttackDomain.MODEL, ModuleCategory.DOS, ["OWASP-LLM-04"]),
            (AttackDomain.MODEL, ModuleCategory.MODEL_DOS, ["OWASP-LLM-04"]),
            (AttackDomain.MODEL, ModuleCategory.FINGERPRINTING, ["OWASP-LLM-10"]),
            # Output domain
            (AttackDomain.OUTPUT, ModuleCategory.MANIPULATION, ["OWASP-LLM-02"]),
            (AttackDomain.OUTPUT, ModuleCategory.INSECURE_OUTPUT_HANDLING, ["OWASP-LLM-02"]),
        ],
    )
    def test_domain_category_to_owasp_mapping(self, owasp_mapper, domain, category, expected_owasp):
        """Test mapping of domain/category pairs to OWASP categories."""
        result = owasp_mapper.map_to_tags(domain, category)

        assert "owasp" in result
        assert result["owasp"] == expected_owasp

    @pytest.mark.unit
    def test_multi_owasp_category_mapping(self, owasp_mapper):
        """Test mappings that result in multiple OWASP categories."""
        result = owasp_mapper.map_to_tags(AttackDomain.SYSTEM, ModuleCategory.ENUMERATION)

        assert "owasp" in result
        assert len(result["owasp"]) == 2
        assert "OWASP-LLM-07" in result["owasp"]
        assert "OWASP-LLM-05" in result["owasp"]

    @pytest.mark.unit
    def test_all_owasp_categories_covered(self, owasp_mapper):
        """Test that all OWASP LLM Top 10 categories are mappable."""
        # Get all mapped categories
        mapped_categories = set()

        test_combinations = [
            (AttackDomain.PROMPT, ModuleCategory.INJECTION),
            (AttackDomain.OUTPUT, ModuleCategory.MANIPULATION),
            (AttackDomain.DATA, ModuleCategory.POISONING),
            (AttackDomain.MODEL, ModuleCategory.DOS),
            (AttackDomain.SYSTEM, ModuleCategory.RECONNAISSANCE),
            (AttackDomain.DATA, ModuleCategory.EXTRACTION),
            (AttackDomain.SYSTEM, ModuleCategory.ENUMERATION),
            (AttackDomain.MODEL, ModuleCategory.THEFT),
        ]

        for domain, category in test_combinations:
            result = owasp_mapper.map_to_tags(domain, category)
            if "owasp" in result:
                mapped_categories.update(result["owasp"])

        # Should cover major OWASP categories
        expected_categories = {
            "OWASP-LLM-01",  # Prompt Injection
            "OWASP-LLM-02",  # Insecure Output Handling
            "OWASP-LLM-03",  # Training Data Poisoning
            "OWASP-LLM-04",  # Model DoS
            "OWASP-LLM-05",  # Supply Chain
            "OWASP-LLM-06",  # Sensitive Info Disclosure
            "OWASP-LLM-07",  # Insecure Plugin Design
            "OWASP-LLM-10",  # Model Theft
        }

        assert expected_categories.issubset(mapped_categories)

    @pytest.mark.unit
    def test_version_support(self, owasp_mapper):
        """Test OWASP version support."""
        assert owasp_mapper.get_version("owasp") == "owasp-llm-2025"
        assert "owasp" in owasp_mapper.get_supported_taxonomies()

    @pytest.mark.unit
    def test_confidence_threshold_filtering(self, owasp_mapper):
        """Test that low confidence results are filtered out."""
        # High confidence should return tags
        result_high = owasp_mapper.map_to_tags(
            AttackDomain.PROMPT, ModuleCategory.INJECTION, confidence=0.9
        )
        assert result_high["owasp"] == ["OWASP-LLM-01"]

        # Low confidence should return empty
        result_low = owasp_mapper.map_to_tags(
            AttackDomain.PROMPT, ModuleCategory.INJECTION, confidence=0.3
        )
        assert result_low["owasp"] == []


# ========================================
# Edge Cases Tests
# ========================================


class TestEdgeCases:
    """Test edge cases and error conditions."""

    @pytest.mark.unit
    def test_unknown_domain_category_combination(self, owasp_mapper):
        """Test handling of unknown domain/category combinations."""
        result = owasp_mapper.map_to_tags(AttackDomain.PROMPT, ModuleCategory.RECONNAISSANCE)

        # Should return empty list for unknown combinations
        assert "owasp" in result
        assert result["owasp"] == []

    @pytest.mark.unit
    def test_none_confidence_handling(self, owasp_mapper):
        """Test that None confidence doesn't break mapping."""
        result = owasp_mapper.map_to_tags(
            AttackDomain.PROMPT, ModuleCategory.INJECTION, confidence=None
        )

        assert "owasp" in result
        assert result["owasp"] == ["OWASP-LLM-01"]

    @pytest.mark.unit
    def test_boundary_confidence_values(self, owasp_mapper):
        """Test boundary confidence values."""
        # Test exactly at threshold
        result_at_threshold = owasp_mapper.map_to_tags(
            AttackDomain.PROMPT, ModuleCategory.INJECTION, confidence=0.7
        )
        assert result_at_threshold["owasp"] == ["OWASP-LLM-01"]

        # Test just below threshold
        result_below_threshold = owasp_mapper.map_to_tags(
            AttackDomain.PROMPT, ModuleCategory.INJECTION, confidence=0.69
        )
        assert result_below_threshold["owasp"] == []

    @pytest.mark.unit
    def test_invalid_taxonomy_version_request(self, owasp_mapper):
        """Test requesting version for unsupported taxonomy."""
        version = owasp_mapper.get_version("nonexistent_taxonomy")
        assert version is None

    @pytest.mark.unit
    def test_extreme_confidence_values(self, owasp_mapper):
        """Test extreme confidence values."""
        # Test negative confidence
        result_negative = owasp_mapper.map_to_tags(
            AttackDomain.PROMPT, ModuleCategory.INJECTION, confidence=-0.1
        )
        assert result_negative["owasp"] == []

        # Test confidence > 1.0
        result_over_one = owasp_mapper.map_to_tags(
            AttackDomain.PROMPT, ModuleCategory.INJECTION, confidence=1.5
        )
        assert result_over_one["owasp"] == ["OWASP-LLM-01"]


# ========================================
# TaxonomyMapper Orchestrator Tests
# ========================================


class TestTaxonomyMapperOrchestrator:
    """Test the main TaxonomyMapper orchestrator functionality."""

    @pytest.mark.unit
    def test_mapper_registration(self, taxonomy_mapper, owasp_mapper):
        """Test registering and listing mappers."""
        # Initially no mappers
        assert taxonomy_mapper.list_mappers() == []

        # Register OWASP mapper
        taxonomy_mapper.register_mapper("owasp", owasp_mapper)
        assert taxonomy_mapper.list_mappers() == ["owasp"]

        # Get registered mapper
        retrieved_mapper = taxonomy_mapper.get_mapper("owasp")
        assert retrieved_mapper == owasp_mapper

    @pytest.mark.unit
    def test_mapper_unregistration(self, populated_taxonomy_mapper):
        """Test unregistering mappers."""
        assert "owasp" in populated_taxonomy_mapper.list_mappers()

        populated_taxonomy_mapper.unregister_mapper("owasp")
        assert "owasp" not in populated_taxonomy_mapper.list_mappers()
        assert populated_taxonomy_mapper.get_mapper("owasp") is None

    @pytest.mark.unit
    def test_multiple_mapper_registration(self, taxonomy_mapper):
        """Test registering multiple mappers."""
        owasp_mapper = MockOWASPMapper()
        cwe_mapper = Mock()
        cwe_mapper.map_to_tags.return_value = {"cwe": ["CWE-79"]}
        cwe_mapper.get_supported_taxonomies.return_value = ["cwe"]
        cwe_mapper.get_version.return_value = "cwe-4.0"

        taxonomy_mapper.register_mapper("owasp", owasp_mapper)
        taxonomy_mapper.register_mapper("cwe", cwe_mapper)

        mappers = taxonomy_mapper.list_mappers()
        assert len(mappers) == 2
        assert "owasp" in mappers
        assert "cwe" in mappers

    @pytest.mark.unit
    def test_map_to_all_taxonomies(self, populated_taxonomy_mapper):
        """Test mapping to all registered taxonomies."""
        result = populated_taxonomy_mapper.map_to_all_taxonomies(
            AttackDomain.PROMPT, ModuleCategory.INJECTION
        )

        assert "owasp" in result
        assert result["owasp"]["owasp"] == ["OWASP-LLM-01"]

    @pytest.mark.unit
    def test_map_to_all_with_confidence(self, populated_taxonomy_mapper):
        """Test mapping with confidence parameter."""
        result = populated_taxonomy_mapper.map_to_all_taxonomies(
            AttackDomain.PROMPT, ModuleCategory.INJECTION, confidence=0.9
        )

        assert "owasp" in result
        assert result["owasp"]["owasp"] == ["OWASP-LLM-01"]

        # Low confidence result
        result_low = populated_taxonomy_mapper.map_to_all_taxonomies(
            AttackDomain.PROMPT, ModuleCategory.INJECTION, confidence=0.3
        )
        assert result_low["owasp"]["owasp"] == []

    @pytest.mark.unit
    def test_error_handling_in_mapping(self, taxonomy_mapper):
        """Test error handling when mapper raises exception."""
        # Create a mapper that raises an exception
        error_mapper = Mock()
        error_mapper.map_to_tags.side_effect = Exception("Test error")

        taxonomy_mapper.register_mapper("error_mapper", error_mapper)

        result = taxonomy_mapper.map_to_all_taxonomies(
            AttackDomain.PROMPT, ModuleCategory.INJECTION
        )

        assert "error_mapper" in result
        assert "error" in result["error_mapper"]
        assert "Test error" in result["error_mapper"]["error"][0]

    @pytest.mark.unit
    def test_get_nonexistent_mapper(self, taxonomy_mapper):
        """Test getting mapper that doesn't exist."""
        mapper = taxonomy_mapper.get_mapper("nonexistent")
        assert mapper is None

    @pytest.mark.unit
    def test_unregister_nonexistent_mapper(self, taxonomy_mapper):
        """Test unregistering mapper that doesn't exist."""
        # Should not raise exception
        taxonomy_mapper.unregister_mapper("nonexistent")
        assert taxonomy_mapper.list_mappers() == []


# ========================================
# Integration-style Tests
# ========================================


class TestTaxonomySystemIntegration:
    """Test taxonomy system integration scenarios."""

    @pytest.mark.unit
    def test_complete_workflow(self, taxonomy_mapper):
        """Test complete taxonomy mapping workflow."""
        # Setup
        owasp_mapper = MockOWASPMapper()
        taxonomy_mapper.register_mapper("owasp", owasp_mapper)

        # Test various domain/category combinations
        test_cases = [
            (AttackDomain.PROMPT, ModuleCategory.INJECTION, ["OWASP-LLM-01"]),
            (AttackDomain.DATA, ModuleCategory.POISONING, ["OWASP-LLM-03"]),
            (AttackDomain.MODEL, ModuleCategory.THEFT, ["OWASP-LLM-10"]),
            (AttackDomain.OUTPUT, ModuleCategory.MANIPULATION, ["OWASP-LLM-02"]),
        ]

        for domain, category, expected_owasp in test_cases:
            result = taxonomy_mapper.map_to_all_taxonomies(domain, category)

            assert "owasp" in result
            assert result["owasp"]["owasp"] == expected_owasp

    @pytest.mark.unit
    def test_confidence_scoring_workflow(self, populated_taxonomy_mapper):
        """Test confidence-based filtering workflow."""
        # High confidence scenario
        high_conf_result = populated_taxonomy_mapper.map_to_all_taxonomies(
            AttackDomain.PROMPT, ModuleCategory.INJECTION, confidence=0.95
        )

        # Medium confidence scenario
        med_conf_result = populated_taxonomy_mapper.map_to_all_taxonomies(
            AttackDomain.PROMPT, ModuleCategory.INJECTION, confidence=0.75
        )

        # Low confidence scenario
        low_conf_result = populated_taxonomy_mapper.map_to_all_taxonomies(
            AttackDomain.PROMPT, ModuleCategory.INJECTION, confidence=0.5
        )

        # High and medium should have tags
        assert high_conf_result["owasp"]["owasp"] == ["OWASP-LLM-01"]
        assert med_conf_result["owasp"]["owasp"] == ["OWASP-LLM-01"]

        # Low confidence should be filtered out
        assert low_conf_result["owasp"]["owasp"] == []

    @pytest.mark.unit
    def test_version_compatibility_check(self, populated_taxonomy_mapper):
        """Test version compatibility checking."""
        owasp_mapper = populated_taxonomy_mapper.get_mapper("owasp")

        # Check version
        version = owasp_mapper.get_version("owasp")
        assert version == "owasp-llm-2025"

        # Check supported taxonomies
        taxonomies = owasp_mapper.get_supported_taxonomies()
        assert "owasp" in taxonomies


# ========================================
# Performance and Robustness Tests
# ========================================


class TestRobustnessAndPerformance:
    """Test system robustness and edge performance scenarios."""

    @pytest.mark.unit
    def test_large_number_of_mappings(self, populated_taxonomy_mapper):
        """Test performance with large number of mapping requests."""
        # Test all possible domain/category combinations
        domains = list(AttackDomain)
        categories = list(ModuleCategory)

        results = []
        for domain in domains:
            for category in categories:
                result = populated_taxonomy_mapper.map_to_all_taxonomies(domain, category)
                results.append(result)

        # Should complete without errors
        assert len(results) == len(domains) * len(categories)

        # All results should have expected structure
        for result in results:
            assert isinstance(result, dict)
            assert "owasp" in result
            assert isinstance(result["owasp"], dict)

    @pytest.mark.unit
    def test_concurrent_mapping_safety(self, populated_taxonomy_mapper):
        """Test that mapper is safe for concurrent use."""
        # This is a basic thread safety test - real implementation might need more
        import threading
        import time

        results = []
        errors = []

        def mapping_worker():
            try:
                result = populated_taxonomy_mapper.map_to_all_taxonomies(
                    AttackDomain.PROMPT, ModuleCategory.INJECTION
                )
                results.append(result)
            except Exception as e:
                errors.append(e)

        # Start multiple threads
        threads = []
        for _ in range(10):
            thread = threading.Thread(target=mapping_worker)
            threads.append(thread)
            thread.start()

        # Wait for completion
        for thread in threads:
            thread.join()

        # Check results
        assert len(errors) == 0, f"Concurrent access caused errors: {errors}"
        assert len(results) == 10

        # All results should be identical
        expected_result = results[0]
        for result in results[1:]:
            assert result == expected_result
