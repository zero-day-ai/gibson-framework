"""
Unit tests for DataMigrationPlanner.
"""

import pytest
from gibson.core.schema_sync.data_migration_planner import DataMigrationPlanner
from gibson.core.schema_sync.models import (
    ChangeSet,
    FieldInfo,
    FieldModification,
    FieldChangeType,
    DataTransformation,
    TransformationType,
    DataMigrationPlan,
)


class TestDataMigrationPlanner:
    """Test suite for DataMigrationPlanner."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.planner = DataMigrationPlanner()
    
    def test_plan_simple_type_conversion(self):
        """Test planning for simple type conversion."""
        changeset = ChangeSet(
            modified_fields={
                "count": FieldModification(
                    field_name="count",
                    change_type=FieldChangeType.TYPE_CHANGED,
                    old_value="string",
                    new_value="integer"
                )
            },
            model_hash_before="hash1",
            model_hash_after="hash2"
        )
        
        plan = self.planner.plan_migration(changeset)
        
        assert plan is not None
        assert len(plan.transformations) > 0
        
        # Check transformation details
        transformation = plan.transformations[0]
        assert transformation.field_name == "count"
        assert transformation.transformation_type == TransformationType.TYPE_CAST
        assert "CAST" in transformation.sql_template or "convert" in transformation.sql_template.lower()
    
    def test_plan_nullable_to_required(self):
        """Test planning for nullable to required field change."""
        changeset = ChangeSet(
            modified_fields={
                "email": FieldModification(
                    field_name="email",
                    change_type=FieldChangeType.NULLABLE_CHANGED,
                    old_value=True,  # Was nullable
                    new_value=False  # Now required
                )
            },
            model_hash_before="hash1",
            model_hash_after="hash2"
        )
        
        plan = self.planner.plan_migration(changeset)
        
        assert plan is not None
        assert len(plan.transformations) > 0
        
        transformation = plan.transformations[0]
        assert transformation.transformation_type == TransformationType.NULL_HANDLING
        assert transformation.requires_default
        assert plan.requires_data_transformation
    
    def test_plan_field_removal_with_backup(self):
        """Test planning for field removal with data backup."""
        changeset = ChangeSet(
            removed_fields=["legacy_data"],
            model_hash_before="hash1",
            model_hash_after="hash2"
        )
        
        plan = self.planner.plan_migration(changeset)
        
        assert plan is not None
        assert plan.backup_required
        assert any(
            t.transformation_type == TransformationType.BACKUP
            for t in plan.transformations
        )
    
    def test_plan_complex_migration(self):
        """Test planning for complex migration with multiple changes."""
        changeset = ChangeSet(
            added_fields={
                "status": FieldInfo(
                    name="status",
                    type="string",
                    nullable=False,
                    default="active"
                )
            },
            removed_fields=["old_status"],
            modified_fields={
                "timestamp": FieldModification(
                    field_name="timestamp",
                    change_type=FieldChangeType.TYPE_CHANGED,
                    old_value="string",
                    new_value="datetime"
                )
            },
            model_hash_before="hash1",
            model_hash_after="hash2"
        )
        
        plan = self.planner.plan_migration(changeset)
        
        assert plan is not None
        assert plan.requires_data_transformation
        assert len(plan.transformations) >= 2  # At least 2 transformations
        assert plan.estimated_risk in ["medium", "high"]
        
        # Check for different transformation types
        transformation_types = {t.transformation_type for t in plan.transformations}
        assert TransformationType.TYPE_CAST in transformation_types
    
    def test_plan_enum_value_migration(self):
        """Test planning for enum value changes."""
        changeset = ChangeSet(
            enum_changes={
                "status": {
                    "removed_values": ["deprecated"],
                    "added_values": ["archived"],
                    "field_name": "status"
                }
            },
            model_hash_before="hash1",
            model_hash_after="hash2"
        )
        
        plan = self.planner.plan_migration(changeset)
        
        assert plan is not None
        assert any(
            t.transformation_type == TransformationType.VALUE_MAPPING
            for t in plan.transformations
        )
        
        # Should have mapping for deprecated -> archived
        enum_transformation = next(
            t for t in plan.transformations
            if t.transformation_type == TransformationType.VALUE_MAPPING
        )
        assert "deprecated" in enum_transformation.sql_template
    
    def test_validation_rules_generation(self):
        """Test generation of validation rules."""
        changeset = ChangeSet(
            modified_fields={
                "age": FieldModification(
                    field_name="age",
                    change_type=FieldChangeType.TYPE_CHANGED,
                    old_value="string",
                    new_value="integer"
                )
            },
            model_hash_before="hash1",
            model_hash_after="hash2"
        )
        
        plan = self.planner.plan_migration(changeset)
        
        assert len(plan.validation_queries) > 0
        
        # Should have pre and post validation
        assert any("before" in q.lower() for q in plan.validation_queries)
        assert any("after" in q.lower() for q in plan.validation_queries)
    
    def test_rollback_plan_generation(self):
        """Test generation of rollback plan."""
        changeset = ChangeSet(
            added_fields={
                "new_field": FieldInfo(
                    name="new_field",
                    type="string",
                    nullable=True
                )
            },
            model_hash_before="hash1",
            model_hash_after="hash2"
        )
        
        plan = self.planner.plan_migration(changeset)
        
        assert plan.rollback_plan is not None
        assert len(plan.rollback_plan) > 0
        assert "DROP COLUMN" in plan.rollback_plan[0] or "drop" in plan.rollback_plan[0].lower()
    
    def test_estimate_risk_level(self):
        """Test risk level estimation."""
        # Low risk - adding nullable field
        changeset_low = ChangeSet(
            added_fields={
                "optional": FieldInfo(
                    name="optional",
                    type="string",
                    nullable=True
                )
            },
            model_hash_before="hash1",
            model_hash_after="hash2"
        )
        
        plan_low = self.planner.plan_migration(changeset_low)
        assert plan_low.estimated_risk == "low"
        
        # High risk - removing fields
        changeset_high = ChangeSet(
            removed_fields=["important_field"],
            model_hash_before="hash1",
            model_hash_after="hash2"
        )
        
        plan_high = self.planner.plan_migration(changeset_high)
        assert plan_high.estimated_risk == "high"
        
        # Medium risk - type changes
        changeset_medium = ChangeSet(
            modified_fields={
                "field": FieldModification(
                    field_name="field",
                    change_type=FieldChangeType.TYPE_CHANGED,
                    old_value="integer",
                    new_value="string"
                )
            },
            model_hash_before="hash1",
            model_hash_after="hash2"
        )
        
        plan_medium = self.planner.plan_migration(changeset_medium)
        assert plan_medium.estimated_risk in ["medium", "high"]
    
    def test_custom_transformation_function(self):
        """Test custom transformation function generation."""
        changeset = ChangeSet(
            modified_fields={
                "phone": FieldModification(
                    field_name="phone",
                    change_type=FieldChangeType.CONSTRAINT_CHANGED,
                    old_value={"pattern": None},
                    new_value={"pattern": r"^\+\d{1,3}-\d{3,14}$"}
                )
            },
            model_hash_before="hash1",
            model_hash_after="hash2"
        )
        
        plan = self.planner.plan_migration(changeset)
        
        # Should generate custom transformation
        assert any(
            t.transformation_type == TransformationType.CUSTOM_FUNCTION
            for t in plan.transformations
        )
        
        custom_transform = next(
            t for t in plan.transformations
            if t.transformation_type == TransformationType.CUSTOM_FUNCTION
        )
        assert custom_transform.python_function is not None
    
    def test_data_loss_detection(self):
        """Test detection of potential data loss."""
        # Scenario 1: Field removal
        changeset_removal = ChangeSet(
            removed_fields=["data_field"],
            model_hash_before="hash1",
            model_hash_after="hash2"
        )
        
        plan_removal = self.planner.plan_migration(changeset_removal)
        assert plan_removal.data_loss_possible
        assert plan_removal.backup_required
        
        # Scenario 2: Narrowing type conversion
        changeset_narrowing = ChangeSet(
            modified_fields={
                "value": FieldModification(
                    field_name="value",
                    change_type=FieldChangeType.TYPE_CHANGED,
                    old_value="string",
                    new_value="integer"
                )
            },
            model_hash_before="hash1",
            model_hash_after="hash2"
        )
        
        plan_narrowing = self.planner.plan_migration(changeset_narrowing)
        assert plan_narrowing.data_loss_possible
    
    def test_migration_phases(self):
        """Test migration phase generation."""
        changeset = ChangeSet(
            added_fields={
                "new_col": FieldInfo(
                    name="new_col",
                    type="string",
                    nullable=False,
                    default="default"
                )
            },
            removed_fields=["old_col"],
            model_hash_before="hash1",
            model_hash_after="hash2"
        )
        
        plan = self.planner.plan_migration(changeset)
        
        # Should have multiple phases
        assert len(plan.phases) > 1
        
        # Check phase ordering
        phase_names = [phase["name"] for phase in plan.phases]
        
        # Backup should come before removal
        if "backup" in phase_names and "remove_fields" in phase_names:
            assert phase_names.index("backup") < phase_names.index("remove_fields")
    
    def test_sql_template_generation(self):
        """Test SQL template generation for transformations."""
        changeset = ChangeSet(
            modified_fields={
                "amount": FieldModification(
                    field_name="amount",
                    change_type=FieldChangeType.TYPE_CHANGED,
                    old_value="string",
                    new_value="decimal"
                )
            },
            model_hash_before="hash1",
            model_hash_after="hash2"
        )
        
        plan = self.planner.plan_migration(changeset)
        
        transformation = plan.transformations[0]
        assert transformation.sql_template is not None
        assert "amount" in transformation.sql_template
        
        # Should include proper casting
        assert any(
            keyword in transformation.sql_template.upper()
            for keyword in ["CAST", "CONVERT", "::"]
        )
    
    def test_migration_with_dependencies(self):
        """Test handling of field dependencies in migration."""
        changeset = ChangeSet(
            modified_fields={
                "total": FieldModification(
                    field_name="total",
                    change_type=FieldChangeType.TYPE_CHANGED,
                    old_value="integer",
                    new_value="decimal",
                    details={"depends_on": ["quantity", "price"]}
                )
            },
            model_hash_before="hash1",
            model_hash_after="hash2"
        )
        
        plan = self.planner.plan_migration(changeset)
        
        # Should handle dependencies
        assert plan.metadata.get("has_dependencies") is True
        assert "depends_on" in str(plan.transformations[0].metadata)
    
    def test_dry_run_sql_generation(self):
        """Test generation of dry-run SQL."""
        changeset = ChangeSet(
            added_fields={
                "test_field": FieldInfo(
                    name="test_field",
                    type="boolean",
                    nullable=False,
                    default=False
                )
            },
            model_hash_before="hash1",
            model_hash_after="hash2"
        )
        
        plan = self.planner.plan_migration(changeset)
        
        # Should have dry-run queries
        assert plan.dry_run_queries is not None
        assert len(plan.dry_run_queries) > 0
        
        # Dry-run should use transactions
        dry_run_sql = "\n".join(plan.dry_run_queries)
        assert "BEGIN" in dry_run_sql or "START TRANSACTION" in dry_run_sql
        assert "ROLLBACK" in dry_run_sql