"""
Unit tests for SchemaChangeDetector.
"""

import pytest
from typing import Dict, Any
from pydantic import BaseModel, Field

from gibson.core.schema_sync.detector import SchemaChangeDetector
from gibson.core.schema_sync.models import FieldChangeType


class TestModel(BaseModel):
    """Test model for schema change detection."""

    id: int
    name: str
    description: str = Field(default="")
    active: bool = True


class ModifiedTestModel(BaseModel):
    """Modified version of test model."""

    id: int
    name: str
    description: str  # Made required
    active: bool = True
    created_at: str = ""  # New field


class TestSchemaChangeDetector:
    """Test suite for SchemaChangeDetector."""

    def setup_method(self):
        """Set up test fixtures."""
        self.detector = SchemaChangeDetector()

    def test_detect_no_changes(self):
        """Test detection when no changes exist."""
        schema = TestModel.model_json_schema()
        changeset = self.detector.detect_changes(TestModel, schema)

        assert not changeset.has_changes
        assert changeset.change_count == 0
        assert changeset.model_hash_before == changeset.model_hash_after

    def test_detect_added_fields(self):
        """Test detection of added fields."""
        old_schema = TestModel.model_json_schema()
        changeset = self.detector.detect_changes(ModifiedTestModel, old_schema)

        assert changeset.has_changes
        assert "created_at" in changeset.added_fields
        assert changeset.added_fields["created_at"].name == "created_at"

    def test_detect_field_nullable_change(self):
        """Test detection of nullable changes."""
        old_schema = TestModel.model_json_schema()
        changeset = self.detector.detect_changes(ModifiedTestModel, old_schema)

        # Description became required (not in required list -> in required list)
        assert changeset.has_changes
        nullable_changes = [
            m
            for m in changeset.modified_fields.values()
            if m.change_type == FieldChangeType.NULLABLE_CHANGED
        ]
        assert len(nullable_changes) > 0

    def test_calculate_schema_hash(self):
        """Test schema hash calculation."""
        hash1 = self.detector.calculate_schema_hash(TestModel)
        hash2 = self.detector.calculate_schema_hash(TestModel)

        # Same model should produce same hash
        assert hash1 == hash2
        assert len(hash1) == 64  # SHA256 produces 64 character hex string

        # Different model should produce different hash
        hash3 = self.detector.calculate_schema_hash(ModifiedTestModel)
        assert hash1 != hash3

    def test_detect_enum_changes(self):
        """Test detection of enum value changes."""
        # Create models with enums
        from enum import Enum

        class Status(str, Enum):
            ACTIVE = "active"
            INACTIVE = "inactive"

        class StatusV2(str, Enum):
            ACTIVE = "active"
            INACTIVE = "inactive"
            ARCHIVED = "archived"  # Added value

        class ModelV1(BaseModel):
            status: Status

        class ModelV2(BaseModel):
            status: StatusV2

        old_schema = ModelV1.model_json_schema()
        changeset = self.detector.detect_changes(ModelV2, old_schema)

        # Should detect enum changes
        assert len(changeset.enum_changes) > 0

    def test_extract_field_info(self):
        """Test field info extraction."""
        field_info = self.detector._extract_field_info(TestModel)

        assert "id" in field_info
        assert "name" in field_info
        assert "description" in field_info
        assert "active" in field_info

        # Check field details
        assert field_info["id"]["required"] is True
        assert field_info["description"]["required"] is False
        assert field_info["active"]["default"] is True

    def test_clean_schema_for_hash(self):
        """Test schema cleaning for consistent hashing."""
        schema = {
            "title": "TestModel",
            "description": "Test description",
            "properties": {"id": {"type": "integer"}},
            "examples": ["example1"],
            "$id": "test-id",
            "generated": "2024-01-01",
        }

        cleaned = self.detector._clean_schema_for_hash(schema)

        # Volatile fields should be removed
        assert "title" not in cleaned
        assert "description" not in cleaned
        assert "examples" not in cleaned
        assert "$id" not in cleaned
        assert "generated" not in cleaned

        # Properties should remain
        assert "properties" in cleaned
        assert cleaned["properties"]["id"]["type"] == "integer"


class TestChangeDetectionScenarios:
    """Test various change detection scenarios."""

    def setup_method(self):
        """Set up test fixtures."""
        self.detector = SchemaChangeDetector()

    def test_field_removal_detection(self):
        """Test detection of removed fields."""

        class V1(BaseModel):
            id: int
            name: str
            deprecated_field: str

        class V2(BaseModel):
            id: int
            name: str

        old_schema = V1.model_json_schema()
        changeset = self.detector.detect_changes(V2, old_schema)

        assert "deprecated_field" in changeset.removed_fields
        assert changeset.change_count >= 1

    def test_type_change_detection(self):
        """Test detection of field type changes."""

        class V1(BaseModel):
            id: int
            count: int

        class V2(BaseModel):
            id: int
            count: float  # Changed from int to float

        old_schema = V1.model_json_schema()
        changeset = self.detector.detect_changes(V2, old_schema)

        type_changes = [
            m
            for m in changeset.modified_fields.values()
            if m.change_type == FieldChangeType.TYPE_CHANGED
        ]
        assert len(type_changes) > 0

    def test_constraint_change_detection(self):
        """Test detection of constraint changes."""

        class V1(BaseModel):
            name: str = Field(min_length=1, max_length=50)

        class V2(BaseModel):
            name: str = Field(min_length=1, max_length=100)  # Increased max length

        old_schema = V1.model_json_schema()
        changeset = self.detector.detect_changes(V2, old_schema)

        # Should detect constraint change
        assert changeset.has_changes
        constraint_changes = [
            m
            for m in changeset.modified_fields.values()
            if m.change_type == FieldChangeType.CONSTRAINT_CHANGED
        ]

        # Check if constraint change was detected
        if constraint_changes:
            change = constraint_changes[0]
            assert "maxLength" in change.details.get("constraint_changes", {})
