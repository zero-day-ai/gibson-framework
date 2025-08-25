"""
Unit tests for ChangeAnalyzer.
"""

import pytest
from gibson.core.schema_sync.analyzer import ChangeAnalyzer
from gibson.core.schema_sync.models import (
    ChangeSet,
    FieldInfo,
    FieldModification,
    FieldChangeType,
    EnumChange,
    CompatibilityLevel,
)


class TestChangeAnalyzer:
    """Test suite for ChangeAnalyzer."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.analyzer = ChangeAnalyzer()
    
    def test_analyze_compatible_changes(self):
        """Test analysis of compatible changes."""
        # Create changeset with only compatible changes
        changeset = ChangeSet(
            added_fields={
                "new_field": FieldInfo(
                    name="new_field",
                    type="string",
                    nullable=True,  # Nullable field is compatible
                    default="default_value"
                )
            },
            model_hash_before="hash1",
            model_hash_after="hash2"
        )
        
        analysis = self.analyzer.analyze_changeset(changeset)
        
        assert analysis.compatibility == CompatibilityLevel.COMPATIBLE
        assert len(analysis.breaking_changes) == 0
        assert analysis.is_safe
        assert analysis.risk_level == "low"
    
    def test_analyze_breaking_changes_field_removal(self):
        """Test analysis of breaking changes due to field removal."""
        changeset = ChangeSet(
            removed_fields=["important_field"],
            model_hash_before="hash1",
            model_hash_after="hash2"
        )
        
        analysis = self.analyzer.analyze_changeset(changeset)
        
        assert analysis.compatibility == CompatibilityLevel.DATA_LOSS
        assert len(analysis.breaking_changes) > 0
        assert not analysis.is_safe
        assert analysis.risk_level == "critical"
        
        # Check breaking change details
        breaking_change = analysis.breaking_changes[0]
        assert breaking_change.change_type == "field_removed"
        assert "important_field" in breaking_change.description
        assert breaking_change.impact == "Data loss - column will be dropped"
    
    def test_analyze_required_field_without_default(self):
        """Test analysis of required field added without default."""
        changeset = ChangeSet(
            added_fields={
                "required_field": FieldInfo(
                    name="required_field",
                    type="string",
                    nullable=False,  # Required
                    default=None     # No default
                )
            },
            model_hash_before="hash1",
            model_hash_after="hash2"
        )
        
        analysis = self.analyzer.analyze_changeset(changeset)
        
        assert analysis.compatibility == CompatibilityLevel.MAJOR_BREAKING
        assert len(analysis.breaking_changes) > 0
        assert not analysis.is_safe
        
        breaking_change = analysis.breaking_changes[0]
        assert breaking_change.change_type == "required_field_added"
        assert breaking_change.data_transformation_required
    
    def test_analyze_nullable_to_required_change(self):
        """Test analysis of nullable to required field change."""
        changeset = ChangeSet(
            modified_fields={
                "existing_field": FieldModification(
                    field_name="existing_field",
                    change_type=FieldChangeType.NULLABLE_CHANGED,
                    old_value=True,   # Was nullable
                    new_value=False   # Now required
                )
            },
            model_hash_before="hash1",
            model_hash_after="hash2"
        )
        
        analysis = self.analyzer.analyze_changeset(changeset)
        
        assert len(analysis.breaking_changes) > 0
        assert analysis.migration_required
        
        breaking_change = analysis.breaking_changes[0]
        assert breaking_change.change_type == "nullable_to_required"
        assert breaking_change.data_transformation_required
        assert "NULL values must be handled" in breaking_change.impact
    
    def test_analyze_type_changes(self):
        """Test analysis of type changes."""
        changeset = ChangeSet(
            modified_fields={
                "type_field": FieldModification(
                    field_name="type_field",
                    change_type=FieldChangeType.TYPE_CHANGED,
                    old_value="integer",
                    new_value="string"
                )
            },
            model_hash_before="hash1",
            model_hash_after="hash2"
        )
        
        analysis = self.analyzer.analyze_changeset(changeset)
        
        assert len(analysis.breaking_changes) > 0
        breaking_change = analysis.breaking_changes[0]
        assert breaking_change.change_type == "type_changed"
        assert breaking_change.data_transformation_required
    
    def test_analyze_enum_value_removal(self):
        """Test analysis of enum value removal."""
        changeset = ChangeSet(
            enum_changes={
                "status": EnumChange(
                    enum_name="status",
                    removed_values=["deprecated_status"]
                )
            },
            model_hash_before="hash1",
            model_hash_after="hash2"
        )
        
        analysis = self.analyzer.analyze_changeset(changeset)
        
        assert len(analysis.breaking_changes) > 0
        breaking_change = analysis.breaking_changes[0]
        assert breaking_change.change_type == "enum_values_removed"
        assert breaking_change.data_transformation_required
        assert "deprecated_status" in str(breaking_change.description)
    
    def test_identify_breaking_changes(self):
        """Test identification of breaking changes."""
        changeset = ChangeSet(
            removed_fields=["field1", "field2"],
            modified_fields={
                "field3": FieldModification(
                    field_name="field3",
                    change_type=FieldChangeType.NULLABLE_CHANGED,
                    old_value=True,
                    new_value=False
                )
            },
            model_hash_before="hash1",
            model_hash_after="hash2"
        )
        
        breaking_changes = self.analyzer.identify_breaking_changes(changeset)
        
        # Should identify 3 breaking changes (2 removals + 1 nullable change)
        assert len(breaking_changes) >= 3
        
        # Check types of breaking changes
        change_types = {change.change_type for change in breaking_changes}
        assert "field_removed" in change_types
        assert "nullable_changed" in change_types
    
    def test_risk_level_calculation(self):
        """Test risk level calculation."""
        # Low risk - compatible changes only
        changeset_low = ChangeSet(
            added_fields={
                "optional_field": FieldInfo(
                    name="optional_field",
                    type="string",
                    nullable=True
                )
            },
            model_hash_before="hash1",
            model_hash_after="hash2"
        )
        
        analysis_low = self.analyzer.analyze_changeset(changeset_low)
        assert analysis_low.risk_level == "low"
        
        # Critical risk - data loss
        changeset_critical = ChangeSet(
            removed_fields=["critical_field"],
            model_hash_before="hash1",
            model_hash_after="hash2"
        )
        
        analysis_critical = self.analyzer.analyze_changeset(changeset_critical)
        assert analysis_critical.risk_level == "critical"
    
    def test_suggested_actions(self):
        """Test generation of suggested actions."""
        # Data loss scenario
        changeset = ChangeSet(
            removed_fields=["important_data"],
            model_hash_before="hash1",
            model_hash_after="hash2"
        )
        
        analysis = self.analyzer.analyze_changeset(changeset)
        
        assert len(analysis.suggested_actions) > 0
        assert any("Back up" in action for action in analysis.suggested_actions)
        assert any("rollback" in action.lower() for action in analysis.suggested_actions)
    
    def test_type_compatibility_check(self):
        """Test type compatibility checking."""
        # Compatible type changes
        assert self.analyzer._check_type_compatibility("integer", "number")
        assert self.analyzer._check_type_compatibility("string", "text")
        assert self.analyzer._check_type_compatibility("boolean", "integer")
        
        # Incompatible type changes
        assert not self.analyzer._check_type_compatibility("string", "integer")
        assert not self.analyzer._check_type_compatibility("boolean", "string")
        
        # Same type is always compatible
        assert self.analyzer._check_type_compatibility("string", "string")