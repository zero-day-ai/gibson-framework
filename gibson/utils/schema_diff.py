"""
Breaking change detection for JSON schemas.

This module analyzes schema changes to detect breaking modifications
that would invalidate existing data.
"""

from typing import Dict, Any, List, Set, Tuple, Optional
from enum import Enum


class ChangeCategory(Enum):
    """Categories of schema changes."""
    BREAKING = "breaking"  # Will break existing data
    POTENTIALLY_BREAKING = "potentially_breaking"  # May break some data
    COMPATIBLE = "compatible"  # Backward compatible
    

class SchemaChange:
    """Represents a single schema change."""
    
    def __init__(
        self,
        category: ChangeCategory,
        field: str,
        description: str,
        old_value: Any = None,
        new_value: Any = None,
    ):
        """Initialize a schema change.
        
        Args:
            category: Category of the change
            field: Field affected by the change
            description: Human-readable description
            old_value: Previous value (if applicable)
            new_value: New value (if applicable)
        """
        self.category = category
        self.field = field
        self.description = description
        self.old_value = old_value
        self.new_value = new_value
    
    def __str__(self) -> str:
        """String representation of the change."""
        return f"[{self.category.value}] {self.field}: {self.description}"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "category": self.category.value,
            "field": self.field,
            "description": self.description,
            "old_value": self.old_value,
            "new_value": self.new_value,
        }


class BreakingChangeDetector:
    """Analyzes schema changes to detect breaking modifications."""
    
    def detect_breaking_changes(
        self,
        old_schema: Dict[str, Any],
        new_schema: Dict[str, Any],
    ) -> List[str]:
        """Detect breaking changes between two schemas.
        
        Args:
            old_schema: Previous schema version
            new_schema: New schema version
        
        Returns:
            List of breaking change descriptions
        """
        all_changes = self.analyze_changes(old_schema, new_schema)
        breaking_changes = [
            change.description
            for change in all_changes
            if change.category == ChangeCategory.BREAKING
        ]
        return breaking_changes
    
    def analyze_changes(
        self,
        old_schema: Dict[str, Any],
        new_schema: Dict[str, Any],
    ) -> List[SchemaChange]:
        """Analyze all changes between two schemas.
        
        Args:
            old_schema: Previous schema version
            new_schema: New schema version
        
        Returns:
            List of SchemaChange objects
        """
        changes = []
        
        # Check required fields
        changes.extend(self._check_required_fields(old_schema, new_schema))
        
        # Check property changes
        changes.extend(self._check_property_changes(old_schema, new_schema))
        
        # Check enum changes
        changes.extend(self._check_enum_changes(old_schema, new_schema))
        
        # Check type changes
        changes.extend(self._check_type_changes(old_schema, new_schema))
        
        # Check constraint changes
        changes.extend(self._check_constraint_changes(old_schema, new_schema))
        
        return changes
    
    def classify_change(self, change: Dict[str, Any]) -> ChangeCategory:
        """Classify a single change.
        
        Args:
            change: Change description dictionary
        
        Returns:
            ChangeCategory for the change
        """
        change_type = change.get("type", "").lower()
        
        # Breaking changes
        if change_type in ["removed_required", "type_changed", "enum_removed"]:
            return ChangeCategory.BREAKING
        
        # Potentially breaking changes
        if change_type in ["added_required", "constraint_tightened"]:
            return ChangeCategory.POTENTIALLY_BREAKING
        
        # Compatible changes
        return ChangeCategory.COMPATIBLE
    
    def should_bump_major(self, changes: List[str]) -> bool:
        """Determine if changes require a major version bump.
        
        Args:
            changes: List of change descriptions
        
        Returns:
            True if major version bump is required
        """
        breaking_indicators = [
            "removed required field",
            "changed type",
            "removed enum value",
            "removed property",
        ]
        
        for change in changes:
            if any(indicator in change.lower() for indicator in breaking_indicators):
                return True
        
        return False
    
    def _check_required_fields(
        self,
        old_schema: Dict[str, Any],
        new_schema: Dict[str, Any],
    ) -> List[SchemaChange]:
        """Check for changes in required fields.
        
        Args:
            old_schema: Previous schema version
            new_schema: New schema version
        
        Returns:
            List of required field changes
        """
        changes = []
        
        old_required = set(old_schema.get("required", []))
        new_required = set(new_schema.get("required", []))
        
        # Removed required fields (BREAKING)
        removed = old_required - new_required
        for field in removed:
            changes.append(SchemaChange(
                ChangeCategory.BREAKING,
                field,
                f"Removed required field '{field}'",
                old_value=True,
                new_value=False,
            ))
        
        # Added required fields (POTENTIALLY BREAKING)
        added = new_required - old_required
        for field in added:
            changes.append(SchemaChange(
                ChangeCategory.POTENTIALLY_BREAKING,
                field,
                f"Added required field '{field}'",
                old_value=False,
                new_value=True,
            ))
        
        return changes
    
    def _check_property_changes(
        self,
        old_schema: Dict[str, Any],
        new_schema: Dict[str, Any],
    ) -> List[SchemaChange]:
        """Check for changes in properties.
        
        Args:
            old_schema: Previous schema version
            new_schema: New schema version
        
        Returns:
            List of property changes
        """
        changes = []
        
        old_props = set(old_schema.get("properties", {}).keys())
        new_props = set(new_schema.get("properties", {}).keys())
        
        # Removed properties (BREAKING if required)
        removed = old_props - new_props
        old_required = set(old_schema.get("required", []))
        
        for prop in removed:
            if prop in old_required:
                changes.append(SchemaChange(
                    ChangeCategory.BREAKING,
                    prop,
                    f"Removed required property '{prop}'",
                ))
            else:
                changes.append(SchemaChange(
                    ChangeCategory.POTENTIALLY_BREAKING,
                    prop,
                    f"Removed optional property '{prop}'",
                ))
        
        # Added properties (COMPATIBLE unless required)
        added = new_props - old_props
        new_required = set(new_schema.get("required", []))
        
        for prop in added:
            if prop in new_required:
                changes.append(SchemaChange(
                    ChangeCategory.POTENTIALLY_BREAKING,
                    prop,
                    f"Added required property '{prop}'",
                ))
            else:
                changes.append(SchemaChange(
                    ChangeCategory.COMPATIBLE,
                    prop,
                    f"Added optional property '{prop}'",
                ))
        
        return changes
    
    def _check_enum_changes(
        self,
        old_schema: Dict[str, Any],
        new_schema: Dict[str, Any],
    ) -> List[SchemaChange]:
        """Check for changes in enum values.
        
        Args:
            old_schema: Previous schema version
            new_schema: New schema version
        
        Returns:
            List of enum changes
        """
        changes = []
        
        old_props = old_schema.get("properties", {})
        new_props = new_schema.get("properties", {})
        
        # Check each property that exists in both
        common_props = set(old_props.keys()) & set(new_props.keys())
        
        for prop in common_props:
            old_enum = self._extract_enum(old_props[prop])
            new_enum = self._extract_enum(new_props[prop])
            
            if old_enum and new_enum:
                old_values = set(old_enum)
                new_values = set(new_enum)
                
                # Removed enum values (BREAKING)
                removed = old_values - new_values
                if removed:
                    changes.append(SchemaChange(
                        ChangeCategory.BREAKING,
                        prop,
                        f"Removed enum values from '{prop}': {removed}",
                        old_value=list(old_values),
                        new_value=list(new_values),
                    ))
                
                # Added enum values (COMPATIBLE)
                added = new_values - old_values
                if added:
                    changes.append(SchemaChange(
                        ChangeCategory.COMPATIBLE,
                        prop,
                        f"Added enum values to '{prop}': {added}",
                        old_value=list(old_values),
                        new_value=list(new_values),
                    ))
        
        return changes
    
    def _check_type_changes(
        self,
        old_schema: Dict[str, Any],
        new_schema: Dict[str, Any],
    ) -> List[SchemaChange]:
        """Check for type changes in properties.
        
        Args:
            old_schema: Previous schema version
            new_schema: New schema version
        
        Returns:
            List of type changes
        """
        changes = []
        
        old_props = old_schema.get("properties", {})
        new_props = new_schema.get("properties", {})
        
        # Check each property that exists in both
        common_props = set(old_props.keys()) & set(new_props.keys())
        
        for prop in common_props:
            old_type = self._extract_type(old_props[prop])
            new_type = self._extract_type(new_props[prop])
            
            if old_type != new_type and old_type and new_type:
                # Check if it's a compatible type change
                if self._is_compatible_type_change(old_type, new_type):
                    changes.append(SchemaChange(
                        ChangeCategory.COMPATIBLE,
                        prop,
                        f"Type of '{prop}' expanded from {old_type} to {new_type}",
                        old_value=old_type,
                        new_value=new_type,
                    ))
                else:
                    changes.append(SchemaChange(
                        ChangeCategory.BREAKING,
                        prop,
                        f"Type of '{prop}' changed from {old_type} to {new_type}",
                        old_value=old_type,
                        new_value=new_type,
                    ))
        
        return changes
    
    def _check_constraint_changes(
        self,
        old_schema: Dict[str, Any],
        new_schema: Dict[str, Any],
    ) -> List[SchemaChange]:
        """Check for changes in constraints (min/max values, patterns, etc.).
        
        Args:
            old_schema: Previous schema version
            new_schema: New schema version
        
        Returns:
            List of constraint changes
        """
        changes = []
        
        old_props = old_schema.get("properties", {})
        new_props = new_schema.get("properties", {})
        
        # Check each property that exists in both
        common_props = set(old_props.keys()) & set(new_props.keys())
        
        constraint_fields = [
            "minLength", "maxLength", "minimum", "maximum",
            "pattern", "minItems", "maxItems", "uniqueItems",
        ]
        
        for prop in common_props:
            old_prop = old_props[prop]
            new_prop = new_props[prop]
            
            for constraint in constraint_fields:
                old_val = old_prop.get(constraint)
                new_val = new_prop.get(constraint)
                
                if old_val != new_val and old_val is not None and new_val is not None:
                    # Determine if constraint was tightened or loosened
                    if self._is_constraint_tightened(constraint, old_val, new_val):
                        changes.append(SchemaChange(
                            ChangeCategory.POTENTIALLY_BREAKING,
                            prop,
                            f"Constraint '{constraint}' on '{prop}' tightened from {old_val} to {new_val}",
                            old_value=old_val,
                            new_value=new_val,
                        ))
                    else:
                        changes.append(SchemaChange(
                            ChangeCategory.COMPATIBLE,
                            prop,
                            f"Constraint '{constraint}' on '{prop}' loosened from {old_val} to {new_val}",
                            old_value=old_val,
                            new_value=new_val,
                        ))
        
        return changes
    
    def _extract_enum(self, prop_schema: Dict[str, Any]) -> Optional[List[Any]]:
        """Extract enum values from a property schema.
        
        Args:
            prop_schema: Property schema dictionary
        
        Returns:
            List of enum values or None
        """
        if "enum" in prop_schema:
            return prop_schema["enum"]
        
        # Check in anyOf/oneOf
        for key in ["anyOf", "oneOf"]:
            if key in prop_schema:
                for sub_schema in prop_schema[key]:
                    if "enum" in sub_schema:
                        return sub_schema["enum"]
        
        return None
    
    def _extract_type(self, prop_schema: Dict[str, Any]) -> Optional[str]:
        """Extract type from a property schema.
        
        Args:
            prop_schema: Property schema dictionary
        
        Returns:
            Type string or None
        """
        if "type" in prop_schema:
            return prop_schema["type"]
        
        # Check in anyOf/oneOf for union types
        types = []
        for key in ["anyOf", "oneOf"]:
            if key in prop_schema:
                for sub_schema in prop_schema[key]:
                    if "type" in sub_schema:
                        types.append(sub_schema["type"])
        
        if types:
            return " | ".join(sorted(set(types)))
        
        return None
    
    def _is_compatible_type_change(self, old_type: str, new_type: str) -> bool:
        """Check if a type change is backward compatible.
        
        Args:
            old_type: Old type
            new_type: New type
        
        Returns:
            True if the change is compatible
        """
        # Union type expansion is compatible
        if "|" in new_type and old_type in new_type:
            return True
        
        # Number to integer is not compatible, but integer to number is
        if old_type == "integer" and new_type == "number":
            return True
        
        return False
    
    def _is_constraint_tightened(
        self,
        constraint: str,
        old_val: Any,
        new_val: Any,
    ) -> bool:
        """Check if a constraint was tightened.
        
        Args:
            constraint: Constraint name
            old_val: Old constraint value
            new_val: New constraint value
        
        Returns:
            True if constraint was tightened
        """
        if constraint in ["minLength", "minimum", "minItems"]:
            return new_val > old_val
        elif constraint in ["maxLength", "maximum", "maxItems"]:
            return new_val < old_val
        elif constraint == "pattern":
            # Pattern changes are always potentially breaking
            return True
        
        return False