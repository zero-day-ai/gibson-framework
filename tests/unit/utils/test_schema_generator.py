"""
Unit tests for schema generation module.
"""

import json
import pytest
from datetime import datetime
from pathlib import Path
from typing import Optional, List
from pydantic import BaseModel, Field
from enum import Enum

from gibson.utils.schema_generator import SchemaGenerator


class TestEnum(str, Enum):
    """Test enum for schema generation."""

    OPTION_A = "option_a"
    OPTION_B = "option_b"
    OPTION_C = "option_c"


class SimpleModel(BaseModel):
    """Simple test model."""

    name: str
    age: int
    active: bool = True


class ComplexModel(BaseModel):
    """Complex model with various field types."""

    id: str = Field(..., description="Unique identifier")
    name: str = Field(..., min_length=1, max_length=100)
    age: Optional[int] = Field(None, ge=0, le=150)
    tags: List[str] = Field(default_factory=list)
    status: TestEnum = TestEnum.OPTION_A
    metadata: dict = Field(default_factory=dict)


class TestSchemaGenerator:
    """Test SchemaGenerator functionality."""

    @pytest.fixture
    def generator(self):
        """Create SchemaGenerator instance."""
        return SchemaGenerator(base_url="https://test.example.com/schemas")

    def test_generate_simple_schema(self, generator):
        """Test generating schema for simple model."""
        schema = generator.generate_json_schema(SimpleModel)

        assert schema["title"] == "SimpleModel"
        assert schema["type"] == "object"
        assert "properties" in schema
        assert "name" in schema["properties"]
        assert "age" in schema["properties"]
        assert "active" in schema["properties"]

        # Check required fields
        assert "required" in schema
        assert "name" in schema["required"]
        assert "age" in schema["required"]
        assert "active" not in schema["required"]  # Has default

    def test_generate_complex_schema(self, generator):
        """Test generating schema for complex model."""
        schema = generator.generate_json_schema(ComplexModel)

        assert schema["title"] == "ComplexModel"
        assert len(schema["properties"]) == 6

        # Check field descriptions
        assert schema["properties"]["id"]["description"] == "Unique identifier"

        # Check constraints
        name_prop = schema["properties"]["name"]
        assert name_prop["minLength"] == 1
        assert name_prop["maxLength"] == 100

        # Check optional field
        age_prop = schema["properties"]["age"]
        assert "anyOf" in age_prop or "type" in age_prop

        # Check enum
        status_prop = schema["properties"]["status"]
        assert "enum" in status_prop or "allOf" in status_prop

    def test_add_metadata(self, generator):
        """Test metadata addition to schema."""
        base_schema = {
            "title": "TestModel",
            "type": "object",
            "properties": {"field": {"type": "string"}},
        }

        schema = generator.add_metadata(base_schema, "1-0-0", "TestModel")

        assert schema["$id"] == "https://test.example.com/schemas/1-0-0/testmodel.json"
        assert schema["version"] == "1-0-0"
        assert "generated" in schema
        assert "modelHash" in schema
        assert "x-gibson" in schema
        assert schema["x-gibson"]["version"] == "1-0-0"
        assert schema["x-gibson"]["generator"] == "gibson-schema-workflow"

    def test_write_schema(self, generator, tmp_path):
        """Test writing schema to file."""
        schema = {"title": "Test", "type": "object"}
        output_path = tmp_path / "test_schema.json"

        generator.write_schema(schema, output_path)

        assert output_path.exists()
        with open(output_path) as f:
            loaded = json.load(f)
        assert loaded == schema

    def test_write_schema_minified(self, generator, tmp_path):
        """Test writing minified schema."""
        schema = {"title": "Test", "type": "object", "properties": {}}
        output_path = tmp_path / "test_schema_min.json"

        generator.write_schema(schema, output_path, minify=True)

        assert output_path.exists()
        content = output_path.read_text()
        assert "\n" not in content  # Minified should be single line
        assert " " not in content.replace('" "', '""')  # No extra spaces

    def test_extract_required_fields(self, generator):
        """Test extracting required fields from schema."""
        schema = {
            "required": ["field1", "field2"],
            "properties": {
                "field1": {"type": "string"},
                "field2": {"type": "number"},
                "field3": {"type": "boolean"},
            },
        }

        required = generator.extract_required_fields(schema)
        assert required == ["field1", "field2"]

    def test_extract_enum_values(self, generator):
        """Test extracting enum values from schema."""
        schema = {
            "properties": {
                "status": {"enum": ["active", "inactive"]},
                "type": {"enum": ["A", "B", "C"]},
                "optional": {
                    "anyOf": [
                        {"type": "null"},
                        {"enum": ["X", "Y", "Z"]},
                    ],
                },
            },
        }

        enums = generator.extract_enum_values(schema)
        assert enums["status"] == ["active", "inactive"]
        assert enums["type"] == ["A", "B", "C"]
        assert enums["optional"] == ["X", "Y", "Z"]

    def test_extract_field_types(self, generator):
        """Test extracting field types from schema."""
        schema = {
            "properties": {
                "name": {"type": "string"},
                "age": {"type": "integer"},
                "active": {"type": "boolean"},
                "optional": {
                    "anyOf": [
                        {"type": "null"},
                        {"type": "string"},
                    ],
                },
            },
        }

        types = generator.extract_field_types(schema)
        assert types["name"] == "string"
        assert types["age"] == "integer"
        assert types["active"] == "boolean"
        assert "null" in types["optional"] or "string" in types["optional"]

    def test_generate_schema_summary(self, generator):
        """Test generating schema summary."""
        schema = generator.generate_json_schema(ComplexModel)
        summary = generator.generate_schema_summary(schema)

        assert summary["title"] == "ComplexModel"
        assert summary["version"] == "1-0-0"
        assert "id" in summary["required_fields"]
        assert summary["total_fields"] == 6
        assert "status" in summary["enum_fields"]
        assert "id" in summary["field_types"]

    def test_validate_schema_structure(self, generator):
        """Test schema structure validation."""
        valid_schema = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "title": "Test",
            "type": "object",
            "properties": {"field": {"type": "string"}},
        }

        assert generator.validate_schema_structure(valid_schema) is True

        # Missing required field
        invalid_schema = {
            "title": "Test",
            "type": "object",
        }
        assert generator.validate_schema_structure(invalid_schema) is False

        # Wrong type
        invalid_type = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "title": "Test",
            "type": "array",
            "properties": {},
        }
        assert generator.validate_schema_structure(invalid_type) is False

    def test_schema_version_parameter(self, generator):
        """Test version parameter in schema generation."""
        schema = generator.generate_json_schema(SimpleModel, version="2-1-3")

        assert schema["version"] == "2-1-3"
        assert "2-1-3" in schema["$id"]

    def test_schema_title_override(self, generator):
        """Test title override in schema generation."""
        schema = generator.generate_json_schema(SimpleModel, title="CustomTitle")

        assert schema["title"] == "CustomTitle"

    def test_nested_model_schema(self, generator):
        """Test schema generation for nested models."""

        class NestedModel(BaseModel):
            simple: SimpleModel
            value: str

        schema = generator.generate_json_schema(NestedModel)

        assert "properties" in schema
        assert "simple" in schema["properties"]
        assert "value" in schema["properties"]

        # Check for definitions/defs section for nested model
        assert "$defs" in schema or "definitions" in schema
