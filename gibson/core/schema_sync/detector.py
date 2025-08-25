"""
Schema change detection for PayloadModel and related models.
"""

import hashlib
import json
from typing import Any, Dict, List, Optional, Set, Type
from pydantic import BaseModel
from loguru import logger

from gibson.models.payload import PayloadModel, PayloadVariantModel, PayloadMetadataModel
from gibson.core.schema_sync.models import (
    ChangeSet,
    FieldInfo,
    FieldModification,
    FieldChangeType,
    ConstraintChange,
    EnumChange,
)


class SchemaChangeDetector:
    """Detects changes between Pydantic model schemas."""

    def __init__(self):
        """Initialize the schema change detector."""
        self.monitored_models = [
            PayloadModel,
            PayloadVariantModel,
            PayloadMetadataModel,
        ]

    def detect_changes(
        self, current_model: Type[BaseModel], previous_schema: Dict[str, Any]
    ) -> ChangeSet:
        """
        Detect changes between current model and previous schema.

        Args:
            current_model: Current Pydantic model class
            previous_schema: Previous schema as dictionary

        Returns:
            ChangeSet containing all detected changes
        """
        logger.debug(f"Detecting changes for model: {current_model.__name__}")

        # Generate current schema
        current_schema = self.get_model_schema(current_model)

        # Calculate hashes
        hash_before = self.calculate_schema_hash_from_dict(previous_schema)
        hash_after = self.calculate_schema_hash(current_model)

        # Quick check: if hashes match, no changes
        if hash_before == hash_after:
            logger.debug("No changes detected (hash match)")
            return ChangeSet(model_hash_before=hash_before, model_hash_after=hash_after)

        # Detect field-level changes
        added_fields = self._detect_added_fields(current_schema, previous_schema)
        removed_fields = self._detect_removed_fields(current_schema, previous_schema)
        modified_fields = self._detect_modified_fields(current_schema, previous_schema)

        # Detect constraint changes
        constraint_changes = self._detect_constraint_changes(current_schema, previous_schema)

        # Detect enum changes
        enum_changes = self._detect_enum_changes(current_schema, previous_schema)

        changeset = ChangeSet(
            added_fields=added_fields,
            removed_fields=removed_fields,
            modified_fields=modified_fields,
            constraint_changes=constraint_changes,
            enum_changes=enum_changes,
            model_hash_before=hash_before,
            model_hash_after=hash_after,
        )

        logger.info(f"Detected {changeset.change_count} changes in {current_model.__name__}")
        return changeset

    def calculate_schema_hash(self, model: Type[BaseModel]) -> str:
        """
        Calculate hash of model schema for versioning.

        Args:
            model: Pydantic model class

        Returns:
            SHA256 hash of schema
        """
        schema = self.get_model_schema(model)
        return self.calculate_schema_hash_from_dict(schema)

    def calculate_schema_hash_from_dict(self, schema: Dict[str, Any]) -> str:
        """
        Calculate hash from schema dictionary.

        Args:
            schema: Schema dictionary

        Returns:
            SHA256 hash of schema
        """
        # Remove volatile fields that shouldn't affect hash
        clean_schema = self._clean_schema_for_hash(schema)

        # Sort keys for consistent hashing
        # Use default=str to handle any non-serializable types
        schema_str = json.dumps(clean_schema, sort_keys=True, default=str)
        return hashlib.sha256(schema_str.encode()).hexdigest()

    def get_model_schema(self, model: Type[BaseModel]) -> Dict[str, Any]:
        """
        Get JSON schema from Pydantic model.

        Args:
            model: Pydantic model class

        Returns:
            JSON schema dictionary
        """
        schema = model.model_json_schema()

        # Add custom metadata for better change detection
        schema["_model_name"] = model.__name__
        schema["_field_info"] = self._extract_field_info(model)

        return schema

    def _detect_added_fields(
        self, current_schema: Dict[str, Any], previous_schema: Dict[str, Any]
    ) -> Dict[str, FieldInfo]:
        """Detect fields added in current schema."""
        added = {}

        current_props = current_schema.get("properties", {})
        previous_props = previous_schema.get("properties", {})

        for field_name, field_schema in current_props.items():
            if field_name not in previous_props:
                # Field was added
                field_info = self._schema_to_field_info(field_name, field_schema, current_schema)
                added[field_name] = field_info
                logger.debug(f"Detected added field: {field_name}")

        return added

    def _detect_removed_fields(
        self, current_schema: Dict[str, Any], previous_schema: Dict[str, Any]
    ) -> List[str]:
        """Detect fields removed from current schema."""
        removed = []

        current_props = current_schema.get("properties", {})
        previous_props = previous_schema.get("properties", {})

        for field_name in previous_props:
            if field_name not in current_props:
                # Field was removed
                removed.append(field_name)
                logger.debug(f"Detected removed field: {field_name}")

        return removed

    def _detect_modified_fields(
        self, current_schema: Dict[str, Any], previous_schema: Dict[str, Any]
    ) -> Dict[str, FieldModification]:
        """Detect fields that were modified."""
        modified = {}

        current_props = current_schema.get("properties", {})
        previous_props = previous_schema.get("properties", {})
        current_required = set(current_schema.get("required", []))
        previous_required = set(previous_schema.get("required", []))

        for field_name in current_props:
            if field_name in previous_props:
                current_field = current_props[field_name]
                previous_field = previous_props[field_name]

                # Check for type changes
                if current_field.get("type") != previous_field.get("type"):
                    modified[field_name] = FieldModification(
                        field_name=field_name,
                        change_type=FieldChangeType.TYPE_CHANGED,
                        old_value=previous_field.get("type"),
                        new_value=current_field.get("type"),
                        details={"current": current_field, "previous": previous_field},
                    )
                    logger.debug(f"Detected type change for field: {field_name}")

                # Check for nullable changes (required field changes)
                was_required = field_name in previous_required
                is_required = field_name in current_required

                if was_required != is_required:
                    modified[f"{field_name}_nullable"] = FieldModification(
                        field_name=field_name,
                        change_type=FieldChangeType.NULLABLE_CHANGED,
                        old_value=not was_required,  # nullable is opposite of required
                        new_value=not is_required,
                        details={"was_required": was_required, "is_required": is_required},
                    )
                    logger.debug(f"Detected nullable change for field: {field_name}")

                # Check for default value changes
                if current_field.get("default") != previous_field.get("default"):
                    modified[f"{field_name}_default"] = FieldModification(
                        field_name=field_name,
                        change_type=FieldChangeType.DEFAULT_CHANGED,
                        old_value=previous_field.get("default"),
                        new_value=current_field.get("default"),
                    )
                    logger.debug(f"Detected default change for field: {field_name}")

                # Check for constraint changes (min, max, pattern, etc.)
                constraints_changed = self._check_constraint_changes(
                    field_name, current_field, previous_field
                )
                if constraints_changed:
                    modified[f"{field_name}_constraints"] = constraints_changed

        return modified

    def _detect_constraint_changes(
        self, current_schema: Dict[str, Any], previous_schema: Dict[str, Any]
    ) -> List[ConstraintChange]:
        """Detect changes in constraints."""
        changes = []

        # Check unique constraints
        current_unique = self._extract_unique_fields(current_schema)
        previous_unique = self._extract_unique_fields(previous_schema)

        # Added unique constraints
        for field in current_unique - previous_unique:
            changes.append(
                ConstraintChange(
                    constraint_type="unique",
                    table_name=current_schema.get("_model_name", "unknown"),
                    column_name=field,
                    old_constraint=None,
                    new_constraint={"unique": True},
                    action="add",
                )
            )

        # Removed unique constraints
        for field in previous_unique - current_unique:
            changes.append(
                ConstraintChange(
                    constraint_type="unique",
                    table_name=current_schema.get("_model_name", "unknown"),
                    column_name=field,
                    old_constraint={"unique": True},
                    new_constraint=None,
                    action="drop",
                )
            )

        return changes

    def _detect_enum_changes(
        self, current_schema: Dict[str, Any], previous_schema: Dict[str, Any]
    ) -> Dict[str, EnumChange]:
        """Detect changes in enum values."""
        enum_changes = {}

        current_enums = self._extract_enums(current_schema)
        previous_enums = self._extract_enums(previous_schema)

        all_enum_names = set(current_enums.keys()) | set(previous_enums.keys())

        for enum_name in all_enum_names:
            current_values = set(current_enums.get(enum_name, []))
            previous_values = set(previous_enums.get(enum_name, []))

            if current_values != previous_values:
                change = EnumChange(
                    enum_name=enum_name,
                    added_values=list(current_values - previous_values),
                    removed_values=list(previous_values - current_values),
                )

                if change.added_values or change.removed_values:
                    enum_changes[enum_name] = change
                    logger.debug(f"Detected enum changes for: {enum_name}")

        return enum_changes

    def _schema_to_field_info(
        self, field_name: str, field_schema: Dict[str, Any], parent_schema: Dict[str, Any]
    ) -> FieldInfo:
        """Convert schema field to FieldInfo."""
        required_fields = parent_schema.get("required", [])

        return FieldInfo(
            name=field_name,
            type=field_schema.get("type", "unknown"),
            nullable=field_name not in required_fields,
            default=field_schema.get("default"),
            constraints=self._extract_constraints(field_schema),
            description=field_schema.get("description"),
            metadata=field_schema.get("metadata", {}),
        )

    def _extract_field_info(self, model: Type[BaseModel]) -> Dict[str, Any]:
        """Extract detailed field information from model."""
        field_info = {}

        for field_name, field in model.model_fields.items():
            info = {
                "type": str(field.annotation),
                "required": field.is_required(),
                "default": field.default if field.default is not None else None,
                "description": field.description,
            }

            # Extract validators if any
            if hasattr(field, "validators"):
                info["validators"] = [str(v) for v in field.validators]

            field_info[field_name] = info

        return field_info

    def _check_constraint_changes(
        self, field_name: str, current_field: Dict[str, Any], previous_field: Dict[str, Any]
    ) -> Optional[FieldModification]:
        """Check for constraint changes in a field."""
        constraint_keys = ["minLength", "maxLength", "minimum", "maximum", "pattern", "format"]

        changes = {}
        for key in constraint_keys:
            if current_field.get(key) != previous_field.get(key):
                changes[key] = {"old": previous_field.get(key), "new": current_field.get(key)}

        if changes:
            return FieldModification(
                field_name=field_name,
                change_type=FieldChangeType.CONSTRAINT_CHANGED,
                old_value=previous_field,
                new_value=current_field,
                details={"constraint_changes": changes},
            )

        return None

    def _extract_constraints(self, field_schema: Dict[str, Any]) -> Dict[str, Any]:
        """Extract constraints from field schema."""
        constraints = {}

        constraint_keys = [
            "minLength",
            "maxLength",
            "minimum",
            "maximum",
            "pattern",
            "format",
            "uniqueItems",
            "minItems",
            "maxItems",
        ]

        for key in constraint_keys:
            if key in field_schema:
                constraints[key] = field_schema[key]

        return constraints

    def _extract_unique_fields(self, schema: Dict[str, Any]) -> Set[str]:
        """Extract fields marked as unique."""
        unique_fields = set()

        # Check for unique markers in schema
        properties = schema.get("properties", {})
        for field_name, field_schema in properties.items():
            if field_schema.get("unique") or field_schema.get("x-unique"):
                unique_fields.add(field_name)

        return unique_fields

    def _extract_enums(self, schema: Dict[str, Any]) -> Dict[str, List[str]]:
        """Extract enum definitions from schema."""
        enums = {}

        # Check definitions/defs for enum types
        definitions = schema.get("definitions") or schema.get("$defs", {})
        for def_name, definition in definitions.items():
            if "enum" in definition:
                enums[def_name] = definition["enum"]

        # Check properties for inline enums
        properties = schema.get("properties", {})
        for field_name, field_schema in properties.items():
            if "enum" in field_schema:
                enums[field_name] = field_schema["enum"]

            # Check for anyOf/oneOf with enum
            for key in ["anyOf", "oneOf"]:
                if key in field_schema:
                    for sub_schema in field_schema[key]:
                        if "enum" in sub_schema:
                            enums[f"{field_name}_{key}"] = sub_schema["enum"]

        return enums

    def _clean_schema_for_hash(self, schema: Dict[str, Any]) -> Dict[str, Any]:
        """Clean schema for consistent hashing."""
        # Remove fields that shouldn't affect the hash
        exclude_keys = {"title", "description", "examples", "$id", "generated", "modelHash"}

        def clean_dict(d: Dict[str, Any]) -> Dict[str, Any]:
            cleaned = {}
            for key, value in d.items():
                if key not in exclude_keys:
                    if isinstance(value, dict):
                        cleaned[key] = clean_dict(value)
                    elif isinstance(value, list):
                        cleaned[key] = [clean_dict(v) if isinstance(v, dict) else v for v in value]
                    else:
                        cleaned[key] = value
            return cleaned

        return clean_dict(schema)
