"""
Integration tests for the complete schema workflow.
"""

import json
import pytest
from pathlib import Path
from typing import Dict, Any
import tempfile
import shutil

from gibson.models.payload import Payload
from gibson.utils.schema_generator import SchemaGenerator
from gibson.utils.payload_validator import PayloadValidator, SchemaVersionManager
from gibson.utils.schema_version import SchemaVersion, VersionManager
from gibson.utils.schema_diff import BreakingChangeDetector
from scripts.generate_schemas import SchemaOrchestrator


class TestSchemaWorkflowIntegration:
    """Test complete schema workflow integration."""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for test outputs."""
        temp_dir = tempfile.mkdtemp()
        yield Path(temp_dir)
        shutil.rmtree(temp_dir)

    @pytest.fixture
    def sample_payload(self) -> Dict[str, Any]:
        """Create a sample payload dictionary."""
        return {
            "hash": "abc123def456",
            "domain": "prompt",
            "attack_type": "prompt_injection",
            "attack_vector": "jailbreak",
            "name": "Test Payload",
            "description": "Test payload for integration testing",
            "content": "Ignore previous instructions and...",
            "metadata": {
                "author": "test",
                "version": "1.0.0",
                "tags": ["test", "injection"],
            },
        }

    def test_complete_schema_generation_workflow(self, temp_dir):
        """Test complete schema generation workflow."""
        # Create orchestrator
        orchestrator = SchemaOrchestrator(
            output_dir=temp_dir,
            version="1-0-0",
        )

        # Generate all schemas
        success = orchestrator.generate_all()
        assert success is True

        # Check generated files
        version_dir = temp_dir / "1-0-0"
        assert version_dir.exists()

        # Check JSON schema
        json_file = version_dir / "payload.json"
        assert json_file.exists()

        with open(json_file) as f:
            schema = json.load(f)

        assert schema["title"] == "Payload"
        assert "properties" in schema
        assert "required" in schema

        # Check TypeScript types
        ts_file = version_dir / "payload.d.ts"
        assert ts_file.exists()

        ts_content = ts_file.read_text()
        assert "export interface Payload" in ts_content
        assert "hash: string" in ts_content

        # Check Markdown documentation
        md_file = version_dir / "payload.md"
        assert md_file.exists()

        md_content = md_file.read_text()
        assert "# Payload Schema Documentation" in md_content
        assert "## Required Fields" in md_content

        # Check examples
        example_file = version_dir / "payload.example.json"
        assert example_file.exists()

        with open(example_file) as f:
            example = json.load(f)

        assert "hash" in example
        assert "domain" in example

    def test_validation_workflow(self, temp_dir, sample_payload):
        """Test validation workflow with generated schemas."""
        # Generate schemas first
        orchestrator = SchemaOrchestrator(
            output_dir=temp_dir,
            version="1-0-0",
        )
        orchestrator.generate_all()

        # Create validator
        validator = PayloadValidator(
            version="1-0-0",
            schemas_dir=temp_dir,
        )

        # Test valid payload
        is_valid, error = validator.validate(sample_payload)
        assert is_valid is True
        assert error is None

        # Test invalid payload (missing required field)
        invalid_payload = sample_payload.copy()
        del invalid_payload["hash"]

        is_valid, error = validator.validate(invalid_payload)
        assert is_valid is False
        assert "hash" in error

        # Test suggestions
        suggestions = validator.suggest_fixes(invalid_payload)
        assert len(suggestions) > 0
        assert any("hash" in s for s in suggestions)

    def test_version_management_workflow(self, temp_dir):
        """Test version management workflow."""
        version_manager = VersionManager(
            versions_dir=temp_dir,
            model_name="payload",
        )

        # Create initial version
        version = version_manager.create_version("1-0-0")
        assert version == SchemaVersion(1, 0, 0)

        # Get current version
        current = version_manager.get_current_version()
        assert current == SchemaVersion(1, 0, 0)

        # Bump version
        new_version = version_manager.bump_version("revision")
        assert new_version == SchemaVersion(1, 1, 0)

        # List versions
        versions = version_manager.list_versions()
        assert len(versions) == 2
        assert SchemaVersion(1, 0, 0) in versions
        assert SchemaVersion(1, 1, 0) in versions

    def test_breaking_change_detection_workflow(self, temp_dir):
        """Test breaking change detection workflow."""
        # Create two different schemas
        generator = SchemaGenerator()

        # Original schema
        from pydantic import BaseModel, Field

        class PayloadV1(BaseModel):
            hash: str
            domain: str
            name: str

        schema_v1 = generator.generate_json_schema(PayloadV1, version="1-0-0")

        # Modified schema (added required field)
        class PayloadV2(BaseModel):
            hash: str
            domain: str
            name: str
            attack_type: str  # New required field

        schema_v2 = generator.generate_json_schema(PayloadV2, version="2-0-0")

        # Detect changes
        detector = BreakingChangeDetector()
        changes = detector.analyze_changes(schema_v1, schema_v2)

        # Should detect the added required field
        assert len(changes) > 0

        breaking = [c for c in changes if c.category.value == "breaking"]
        potentially = [c for c in changes if c.category.value == "potentially_breaking"]

        # Adding a required field is potentially breaking
        assert len(potentially) > 0
        assert any("attack_type" in c.description for c in potentially)

        # Check if major bump is needed
        all_breaking = detector.detect_breaking_changes(schema_v1, schema_v2)
        should_bump = detector.should_bump_major(all_breaking)
        # In this case, no hard breaking changes (removed fields), so no major bump
        assert should_bump is False

    def test_multi_version_validation(self, temp_dir):
        """Test validation against multiple schema versions."""
        # Generate multiple versions
        for version in ["1-0-0", "1-1-0", "1-2-0"]:
            orchestrator = SchemaOrchestrator(
                output_dir=temp_dir,
                version=version,
            )
            orchestrator.generate_all()

        # Create version manager
        version_manager = SchemaVersionManager(schemas_dir=temp_dir)

        # List available versions
        versions = version_manager.list_versions()
        assert len(versions) >= 3

        # Validate against all versions
        sample_payload = {
            "hash": "test123",
            "domain": "prompt",
            "attack_type": "prompt_injection",
            "attack_vector": "jailbreak",
            "name": "Test",
            "description": "Test payload",
            "content": "Test content",
        }

        results = version_manager.validate_against_all(sample_payload)

        # All versions should validate successfully
        for version, (is_valid, error) in results.items():
            assert is_valid is True, f"Version {version} failed: {error}"

    def test_template_generation(self, temp_dir):
        """Test template generation from schemas."""
        # Generate schema
        orchestrator = SchemaOrchestrator(
            output_dir=temp_dir,
            version="1-0-0",
        )
        orchestrator.generate_all()

        # Create validator
        validator = PayloadValidator(
            version="1-0-0",
            schemas_dir=temp_dir,
        )

        # Get minimal template
        template = validator.get_template()
        assert "hash" in template
        assert "domain" in template
        assert "attack_type" in template
        assert "attack_vector" in template

        # Get full template
        full_template = validator.get_full_template()
        assert len(full_template) >= len(template)

        # Template should be valid
        # Replace template placeholders with actual values
        for key, value in template.items():
            if isinstance(value, str) and value.startswith("<"):
                if "domain" in key:
                    template[key] = "prompt"
                elif "attack_type" in key:
                    template[key] = "prompt_injection"
                elif "attack_vector" in key:
                    template[key] = "jailbreak"
                else:
                    template[key] = "test_value"

        is_valid, error = validator.validate(template)
        assert is_valid is True, f"Template validation failed: {error}"

    def test_schema_metadata(self, temp_dir):
        """Test schema metadata generation."""
        generator = SchemaGenerator(base_url="https://example.com/schemas")

        schema = generator.generate_json_schema(Payload, version="2-1-3", title="CustomPayload")

        # Check metadata
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert schema["$id"] == "https://example.com/schemas/2-1-3/payload.json"
        assert schema["version"] == "2-1-3"
        assert schema["title"] == "CustomPayload"
        assert "generated" in schema
        assert "modelHash" in schema
        assert "x-gibson" in schema
        assert schema["x-gibson"]["version"] == "2-1-3"
        assert schema["x-gibson"]["generator"] == "gibson-schema-workflow"

    @pytest.mark.asyncio
    async def test_concurrent_validation(self, temp_dir, sample_payload):
        """Test concurrent validation of multiple payloads."""
        import asyncio

        # Generate schema
        orchestrator = SchemaOrchestrator(
            output_dir=temp_dir,
            version="1-0-0",
        )
        orchestrator.generate_all()

        # Create validator
        validator = PayloadValidator(
            version="1-0-0",
            schemas_dir=temp_dir,
        )

        # Create multiple payloads
        payloads = [sample_payload.copy() for _ in range(10)]

        # Add some invalid payloads
        payloads[2]["domain"] = "invalid_domain"
        del payloads[5]["hash"]
        payloads[8]["attack_type"] = "invalid_type"

        # Validate concurrently
        async def validate_async(payload):
            return validator.validate(payload)

        tasks = [validate_async(p) for p in payloads]
        results = await asyncio.gather(*tasks)

        # Check results
        valid_count = sum(1 for is_valid, _ in results if is_valid)
        invalid_count = sum(1 for is_valid, _ in results if not is_valid)

        assert valid_count == 7  # 10 total - 3 invalid
        assert invalid_count == 3
