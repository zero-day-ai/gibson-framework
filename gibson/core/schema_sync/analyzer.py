"""
Change analysis for schema modifications.
"""

from typing import Any, Dict, List, Optional
from loguru import logger

from gibson.core.schema_sync.models import (
    ChangeSet,
    ChangeAnalysis,
    BreakingChange,
    CompatibilityLevel,
    FieldChangeType,
)


class ChangeAnalyzer:
    """Analyzes schema changes to determine compatibility and impact."""

    def __init__(self, database_session=None):
        """
        Initialize the change analyzer.

        Args:
            database_session: Optional database session for impact assessment
        """
        self.database_session = database_session

    def analyze_changeset(self, changes: ChangeSet) -> ChangeAnalysis:
        """
        Analyze a changeset to determine compatibility and required actions.

        Args:
            changes: ChangeSet containing detected changes

        Returns:
            ChangeAnalysis with compatibility assessment and recommendations
        """
        logger.debug(f"Analyzing changeset with {changes.change_count} changes")

        analysis = ChangeAnalysis(changeset=changes, compatibility=CompatibilityLevel.COMPATIBLE)

        # Analyze each type of change
        self._analyze_added_fields(changes, analysis)
        self._analyze_removed_fields(changes, analysis)
        self._analyze_modified_fields(changes, analysis)
        self._analyze_constraint_changes(changes, analysis)
        self._analyze_enum_changes(changes, analysis)

        # Determine overall risk level
        analysis.risk_level = self._calculate_risk_level(analysis)

        # Add suggested actions
        self._add_suggested_actions(analysis)

        # Estimate affected rows if database session available
        if self.database_session:
            analysis.estimated_affected_rows = self._estimate_affected_rows(analysis)

        logger.info(
            f"Analysis complete: compatibility={analysis.compatibility.value if hasattr(analysis.compatibility, 'value') else analysis.compatibility}, "
            f"risk={analysis.risk_level}, breaking_changes={len(analysis.breaking_changes)}"
        )

        return analysis

    def identify_breaking_changes(self, changes: ChangeSet) -> List[BreakingChange]:
        """
        Identify all breaking changes in a changeset.

        Args:
            changes: ChangeSet to analyze

        Returns:
            List of breaking changes
        """
        breaking_changes = []

        # Removed fields are always breaking
        for field_name in changes.removed_fields:
            breaking_changes.append(
                BreakingChange(
                    change_type="field_removed",
                    description=f"Field '{field_name}' was removed",
                    affected_table="payloads",  # Assuming PayloadModel maps to payloads table
                    affected_column=field_name,
                    impact="Data in this column will be lost",
                    remediation_required=True,
                    suggested_remediation="Archive data before removing field",
                    data_transformation_required=False,
                )
            )

        # Check modified fields for breaking changes
        for field_name, modification in changes.modified_fields.items():
            if modification.is_breaking:
                breaking_change = self._create_breaking_change_from_modification(
                    field_name, modification
                )
                if breaking_change:
                    breaking_changes.append(breaking_change)

        # Check enum changes for removed values
        for enum_name, enum_change in changes.enum_changes.items():
            if enum_change.has_breaking_changes:
                breaking_changes.append(
                    BreakingChange(
                        change_type="enum_values_removed",
                        description=f"Enum '{enum_name}' had values removed: {enum_change.removed_values}",
                        affected_table="payloads",
                        affected_column=enum_name,
                        impact="Existing data with removed enum values will be invalid",
                        remediation_required=True,
                        suggested_remediation="Migrate existing data to valid enum values",
                        data_transformation_required=True,
                    )
                )

        return breaking_changes

    def _analyze_added_fields(self, changes: ChangeSet, analysis: ChangeAnalysis) -> None:
        """Analyze impact of added fields."""
        for field_name, field_info in changes.added_fields.items():
            # Check if field is required without default
            if not field_info.nullable and field_info.default is None:
                # This is a breaking change - existing records won't have this field
                breaking_change = BreakingChange(
                    change_type="required_field_added",
                    description=f"Required field '{field_name}' added without default value",
                    affected_table="payloads",
                    affected_column=field_name,
                    impact="Existing records will violate NOT NULL constraint",
                    remediation_required=True,
                    suggested_remediation="Provide default value or make field nullable initially",
                    data_transformation_required=True,
                )
                analysis.add_breaking_change(breaking_change)
                analysis.compatibility = CompatibilityLevel.MAJOR_BREAKING
            else:
                # Non-breaking addition
                analysis.add_warning(f"New field '{field_name}' added (nullable or with default)")

    def _analyze_removed_fields(self, changes: ChangeSet, analysis: ChangeAnalysis) -> None:
        """Analyze impact of removed fields."""
        for field_name in changes.removed_fields:
            breaking_change = BreakingChange(
                change_type="field_removed",
                description=f"Field '{field_name}' removed",
                affected_table="payloads",
                affected_column=field_name,
                impact="Data loss - column will be dropped",
                remediation_required=True,
                suggested_remediation="Archive data before removal",
                data_transformation_required=False,
            )
            analysis.add_breaking_change(breaking_change)

            # Field removal always results in data loss
            if analysis.compatibility != CompatibilityLevel.MAJOR_BREAKING:
                analysis.compatibility = CompatibilityLevel.DATA_LOSS

    def _analyze_modified_fields(self, changes: ChangeSet, analysis: ChangeAnalysis) -> None:
        """Analyze impact of modified fields."""
        for field_name, modification in changes.modified_fields.items():
            if modification.change_type == FieldChangeType.TYPE_CHANGED:
                # Type changes are usually breaking
                compatible_changes = self._check_type_compatibility(
                    modification.old_value, modification.new_value
                )

                if not compatible_changes:
                    breaking_change = BreakingChange(
                        change_type="type_changed",
                        description=f"Field '{field_name}' type changed from {modification.old_value} to {modification.new_value}",
                        affected_table="payloads",
                        affected_column=field_name,
                        impact="Data type conversion required",
                        remediation_required=True,
                        suggested_remediation="Ensure data can be safely converted",
                        data_transformation_required=True,
                    )
                    analysis.add_breaking_change(breaking_change)
                else:
                    analysis.add_warning(f"Field '{field_name}' type changed (compatible)")

            elif modification.change_type == FieldChangeType.NULLABLE_CHANGED:
                if modification.new_value is False:  # Changing to NOT NULL
                    breaking_change = BreakingChange(
                        change_type="nullable_to_required",
                        description=f"Field '{field_name}' changed from nullable to required",
                        affected_table="payloads",
                        affected_column=field_name,
                        impact="NULL values must be handled",
                        remediation_required=True,
                        suggested_remediation="Update NULL values before applying constraint",
                        data_transformation_required=True,
                    )
                    analysis.add_breaking_change(breaking_change)
                else:
                    analysis.add_warning(f"Field '{field_name}' changed from required to nullable")

            elif modification.change_type == FieldChangeType.CONSTRAINT_CHANGED:
                # Constraint changes might be breaking depending on the constraint
                self._analyze_constraint_modification(modification, analysis)

    def _analyze_constraint_changes(self, changes: ChangeSet, analysis: ChangeAnalysis) -> None:
        """Analyze impact of constraint changes."""
        for constraint_change in changes.constraint_changes:
            if constraint_change.action == "add":
                if constraint_change.constraint_type == "unique":
                    # Adding unique constraint can fail if duplicates exist
                    analysis.add_warning(
                        f"Adding unique constraint on {constraint_change.column_name} - "
                        "ensure no duplicates exist"
                    )
                    analysis.migration_required = True
                elif constraint_change.constraint_type == "check":
                    # Check constraints can fail on existing data
                    analysis.add_warning(
                        f"Adding check constraint on {constraint_change.column_name} - "
                        "ensure existing data complies"
                    )
                    analysis.migration_required = True

            elif constraint_change.action == "drop":
                # Dropping constraints is usually safe
                analysis.add_warning(
                    f"Dropping {constraint_change.constraint_type} constraint on "
                    f"{constraint_change.column_name}"
                )

    def _analyze_enum_changes(self, changes: ChangeSet, analysis: ChangeAnalysis) -> None:
        """Analyze impact of enum changes."""
        for enum_name, enum_change in changes.enum_changes.items():
            if enum_change.removed_values:
                # Removing enum values is breaking
                breaking_change = BreakingChange(
                    change_type="enum_values_removed",
                    description=f"Enum '{enum_name}' values removed: {enum_change.removed_values}",
                    affected_table="payloads",
                    affected_column=enum_name,
                    impact="Existing data with removed values will be invalid",
                    remediation_required=True,
                    suggested_remediation="Migrate data to valid enum values",
                    data_transformation_required=True,
                )
                analysis.add_breaking_change(breaking_change)

            if enum_change.added_values:
                # Adding enum values is safe
                analysis.add_warning(f"Enum '{enum_name}' values added: {enum_change.added_values}")

            if enum_change.renamed_values:
                # Renaming requires data migration
                breaking_change = BreakingChange(
                    change_type="enum_values_renamed",
                    description=f"Enum '{enum_name}' values renamed",
                    affected_table="payloads",
                    affected_column=enum_name,
                    impact="Existing data needs to be updated",
                    remediation_required=True,
                    suggested_remediation="Update existing values to new names",
                    data_transformation_required=True,
                )
                analysis.add_breaking_change(breaking_change)

    def _analyze_constraint_modification(self, modification: Any, analysis: ChangeAnalysis) -> None:
        """Analyze a constraint modification."""
        details = modification.details.get("constraint_changes", {})

        for constraint_type, change in details.items():
            old_value = change.get("old")
            new_value = change.get("new")

            # Check if constraint is becoming more restrictive
            if constraint_type in ["minLength", "minimum"]:
                if new_value is not None and (old_value is None or new_value > old_value):
                    analysis.add_warning(
                        f"Constraint {constraint_type} on {modification.field_name} "
                        f"became more restrictive: {old_value} -> {new_value}"
                    )
                    analysis.migration_required = True

            elif constraint_type in ["maxLength", "maximum"]:
                if new_value is not None and (old_value is None or new_value < old_value):
                    # This could be breaking if existing data exceeds new limit
                    breaking_change = BreakingChange(
                        change_type="constraint_restrictive",
                        description=f"Constraint {constraint_type} on {modification.field_name} "
                        f"reduced from {old_value} to {new_value}",
                        affected_table="payloads",
                        affected_column=modification.field_name,
                        impact="Existing data may violate new constraint",
                        remediation_required=True,
                        suggested_remediation="Check and update violating data",
                        data_transformation_required=True,
                    )
                    analysis.add_breaking_change(breaking_change)

    def _check_type_compatibility(self, old_type: str, new_type: str) -> bool:
        """
        Check if type change is compatible.

        Args:
            old_type: Previous type
            new_type: New type

        Returns:
            True if types are compatible
        """
        # Define compatible type transitions
        compatible_transitions = {
            ("integer", "number"): True,  # int to float is safe
            ("string", "text"): True,  # string to text is safe
            ("boolean", "integer"): True,  # bool to int is safe (0/1)
        }

        # Check direct compatibility
        if (old_type, new_type) in compatible_transitions:
            return True

        # Same type is always compatible
        if old_type == new_type:
            return True

        # Everything else is potentially breaking
        return False

    def _calculate_risk_level(self, analysis: ChangeAnalysis) -> str:
        """
        Calculate overall risk level of changes.

        Args:
            analysis: ChangeAnalysis to evaluate

        Returns:
            Risk level: low, medium, high, or critical
        """
        if analysis.compatibility == CompatibilityLevel.DATA_LOSS:
            return "critical"
        elif analysis.compatibility == CompatibilityLevel.MAJOR_BREAKING:
            return "high"
        elif analysis.compatibility == CompatibilityLevel.MINOR_BREAKING:
            return "medium"
        elif len(analysis.warnings) > 5:
            return "medium"
        else:
            return "low"

    def _add_suggested_actions(self, analysis: ChangeAnalysis) -> None:
        """Add suggested actions based on analysis."""
        if analysis.compatibility == CompatibilityLevel.DATA_LOSS:
            analysis.suggested_actions.append("CRITICAL: Back up affected data before proceeding")
            analysis.suggested_actions.append("Review data loss impact and confirm acceptance")

        if analysis.breaking_changes:
            analysis.suggested_actions.append("Review breaking changes and plan remediation")
            analysis.suggested_actions.append("Test migrations in non-production environment first")

        if analysis.migration_required:
            analysis.suggested_actions.append("Generate and review migration scripts")
            analysis.suggested_actions.append("Plan maintenance window for migration")

        if analysis.risk_level in ["high", "critical"]:
            analysis.suggested_actions.append("Obtain approval from data owners")
            analysis.suggested_actions.append("Prepare rollback plan")

        if not analysis.suggested_actions:
            analysis.suggested_actions.append("Changes appear safe to apply automatically")

    def _estimate_affected_rows(self, analysis: ChangeAnalysis) -> Optional[int]:
        """
        Estimate number of rows affected by changes.

        Args:
            analysis: ChangeAnalysis to evaluate

        Returns:
            Estimated number of affected rows
        """
        if not self.database_session:
            return None

        # This would query the database to count affected rows
        # For now, return a placeholder
        # In real implementation, would execute COUNT queries

        if analysis.breaking_changes:
            # Would count rows with non-null values in removed fields
            # or rows with values that violate new constraints
            return 1000  # Placeholder

        return 0

    def _create_breaking_change_from_modification(
        self, field_name: str, modification: Any
    ) -> Optional[BreakingChange]:
        """Create a BreakingChange from a field modification."""
        if modification.change_type == FieldChangeType.TYPE_CHANGED:
            return BreakingChange(
                change_type="type_changed",
                description=f"Type of '{field_name}' changed",
                affected_table="payloads",
                affected_column=field_name,
                impact="Data type conversion may be required",
                remediation_required=True,
                suggested_remediation="Verify data can be converted safely",
                data_transformation_required=True,
            )

        elif modification.change_type == FieldChangeType.NULLABLE_CHANGED:
            if modification.new_value is False:  # Became required
                return BreakingChange(
                    change_type="nullable_changed",
                    description=f"Field '{field_name}' is now required",
                    affected_table="payloads",
                    affected_column=field_name,
                    impact="NULL values must be handled",
                    remediation_required=True,
                    suggested_remediation="Update NULL values before migration",
                    data_transformation_required=True,
                )

        return None
