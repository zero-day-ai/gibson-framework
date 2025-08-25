"""
Payload validation module using JSON schemas.

This module provides runtime validation of payloads against generated
JSON schemas with clear error messages and template generation.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from jsonschema import validate, ValidationError, Draft202012Validator
from jsonschema.exceptions import SchemaError


class PayloadValidator:
    """Validates payloads against JSON schemas."""
    
    def __init__(self, version: str = "latest", schemas_dir: Optional[Path] = None):
        """Initialize payload validator.
        
        Args:
            version: Schema version to use (default: "latest")
            schemas_dir: Directory containing schemas (default: project schemas/)
        
        Raises:
            FileNotFoundError: If schema file cannot be found
            json.JSONDecodeError: If schema file is invalid JSON
        """
        if schemas_dir is None:
            # Try to find schemas directory relative to this file
            module_path = Path(__file__).parent.parent.parent
            schemas_dir = module_path / "schemas"
        
        self.schemas_dir = schemas_dir
        self.version = version
        
        # Load schema
        schema_path = self._get_schema_path("payload")
        self.schema = self._load_schema(schema_path)
        
        # Create validator instance
        try:
            Draft202012Validator.check_schema(self.schema)
            self.validator = Draft202012Validator(self.schema)
        except SchemaError as e:
            raise ValueError(f"Invalid schema: {e}")
    
    def validate(self, payload_dict: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Validate a payload dictionary against the schema.
        
        Args:
            payload_dict: Payload dictionary to validate
        
        Returns:
            Tuple of (is_valid, error_message)
            - is_valid: True if payload is valid
            - error_message: Error message if invalid, None if valid
        """
        try:
            validate(payload_dict, self.schema)
            return True, None
        except ValidationError as e:
            error_msg = self._format_validation_error(e)
            return False, error_msg
    
    def validate_with_details(
        self,
        payload_dict: Dict[str, Any],
    ) -> Tuple[bool, List[Dict[str, Any]]]:
        """Validate with detailed error information.
        
        Args:
            payload_dict: Payload dictionary to validate
        
        Returns:
            Tuple of (is_valid, errors)
            - is_valid: True if payload is valid
            - errors: List of error dictionaries with details
        """
        errors = []
        
        for error in self.validator.iter_errors(payload_dict):
            errors.append({
                "field": ".".join(str(p) for p in error.absolute_path),
                "message": error.message,
                "validator": error.validator,
                "validator_value": error.validator_value,
                "instance": error.instance,
                "schema_path": ".".join(str(p) for p in error.absolute_schema_path),
            })
        
        return len(errors) == 0, errors
    
    def get_template(self) -> Dict[str, Any]:
        """Get a minimal valid payload template.
        
        Returns:
            Template dictionary with required fields
        """
        template = {}
        required = self.schema.get("required", [])
        properties = self.schema.get("properties", {})
        
        for field in required:
            if field in properties:
                template[field] = self._get_template_value(properties[field], field)
        
        return template
    
    def get_full_template(self) -> Dict[str, Any]:
        """Get a complete payload template with all fields.
        
        Returns:
            Template dictionary with all fields
        """
        template = {}
        properties = self.schema.get("properties", {})
        required = set(self.schema.get("required", []))
        
        for field, field_schema in properties.items():
            if field in required:
                template[field] = self._get_template_value(field_schema, field)
            else:
                template[field] = f"<optional: {self._get_template_value(field_schema, field)}>"
        
        return template
    
    def list_required_fields(self) -> List[str]:
        """List all required fields.
        
        Returns:
            List of required field names
        """
        return self.schema.get("required", [])
    
    def list_optional_fields(self) -> List[str]:
        """List all optional fields.
        
        Returns:
            List of optional field names
        """
        required = set(self.schema.get("required", []))
        all_fields = set(self.schema.get("properties", {}).keys())
        return list(all_fields - required)
    
    def get_field_info(self, field_name: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific field.
        
        Args:
            field_name: Name of the field
        
        Returns:
            Field information dictionary or None if field doesn't exist
        """
        properties = self.schema.get("properties", {})
        
        if field_name not in properties:
            return None
        
        field_schema = properties[field_name]
        required = field_name in self.schema.get("required", [])
        
        return {
            "name": field_name,
            "required": required,
            "type": self._extract_type(field_schema),
            "description": field_schema.get("description", ""),
            "enum": field_schema.get("enum"),
            "constraints": self._extract_constraints(field_schema),
            "schema": field_schema,
        }
    
    def get_enum_values(self, field_name: str) -> Optional[List[Any]]:
        """Get enum values for a field.
        
        Args:
            field_name: Name of the field
        
        Returns:
            List of enum values or None if not an enum field
        """
        field_info = self.get_field_info(field_name)
        if field_info:
            return field_info.get("enum")
        return None
    
    def suggest_fixes(self, payload_dict: Dict[str, Any]) -> List[str]:
        """Suggest fixes for an invalid payload.
        
        Args:
            payload_dict: Invalid payload dictionary
        
        Returns:
            List of suggested fixes
        """
        suggestions = []
        is_valid, errors = self.validate_with_details(payload_dict)
        
        if is_valid:
            return ["Payload is already valid"]
        
        for error in errors:
            if error["validator"] == "required":
                suggestions.append(
                    f"Add required field '{error['validator_value'][0]}'"
                )
            elif error["validator"] == "enum":
                suggestions.append(
                    f"Change '{error['field']}' to one of: {error['validator_value']}"
                )
            elif error["validator"] == "type":
                suggestions.append(
                    f"Change '{error['field']}' type to {error['validator_value']}"
                )
            elif error["validator"] == "minLength":
                suggestions.append(
                    f"Increase length of '{error['field']}' to at least {error['validator_value']}"
                )
            elif error["validator"] == "maxLength":
                suggestions.append(
                    f"Reduce length of '{error['field']}' to at most {error['validator_value']}"
                )
        
        return suggestions
    
    def _get_schema_path(self, model_name: str) -> Path:
        """Get path to schema file.
        
        Args:
            model_name: Name of the model
        
        Returns:
            Path to schema file
        
        Raises:
            FileNotFoundError: If schema file doesn't exist
        """
        schema_file = self.schemas_dir / self.version / f"{model_name.lower()}.json"
        
        if not schema_file.exists():
            raise FileNotFoundError(
                f"Schema file not found: {schema_file}\n"
                f"Run 'python scripts/generate_schemas.py' to generate schemas"
            )
        
        return schema_file
    
    def _load_schema(self, schema_path: Path) -> Dict[str, Any]:
        """Load schema from file.
        
        Args:
            schema_path: Path to schema file
        
        Returns:
            Schema dictionary
        
        Raises:
            json.JSONDecodeError: If schema file is invalid JSON
        """
        with open(schema_path) as f:
            return json.load(f)
    
    def _format_validation_error(self, error: ValidationError) -> str:
        """Format validation error for user display.
        
        Args:
            error: ValidationError from jsonschema
        
        Returns:
            Formatted error message
        """
        # Build field path
        if error.absolute_path:
            field_path = ".".join(str(p) for p in error.absolute_path)
            location = f"Field '{field_path}'"
        else:
            location = "Payload"
        
        # Format message based on validator type
        if error.validator == "required":
            missing_fields = error.validator_value
            return f"{location}: Missing required fields: {', '.join(missing_fields)}"
        elif error.validator == "enum":
            return f"{location}: Invalid value '{error.instance}'. Must be one of: {', '.join(error.validator_value)}"
        elif error.validator == "type":
            return f"{location}: Expected type '{error.validator_value}' but got '{type(error.instance).__name__}'"
        elif error.validator == "minLength":
            return f"{location}: String too short. Minimum length is {error.validator_value}"
        elif error.validator == "maxLength":
            return f"{location}: String too long. Maximum length is {error.validator_value}"
        else:
            return f"{location}: {error.message}"
    
    def _get_template_value(self, field_schema: Dict[str, Any], field_name: str) -> Any:
        """Get template value for a field.
        
        Args:
            field_schema: Field schema
            field_name: Field name
        
        Returns:
            Template value
        """
        if "enum" in field_schema:
            values = field_schema["enum"]
            return f"<one of: {', '.join(str(v) for v in values)}>"
        
        if "example" in field_schema:
            return field_schema["example"]
        
        field_type = field_schema.get("type", "any")
        
        if field_type == "string":
            if "minLength" in field_schema:
                return f"<string, min length: {field_schema['minLength']}>"
            return f"<string>"
        elif field_type == "integer":
            return "<integer>"
        elif field_type == "number":
            return "<number>"
        elif field_type == "boolean":
            return "<true or false>"
        elif field_type == "array":
            return []
        elif field_type == "object":
            return {}
        
        return f"<{field_type}>"
    
    def _extract_type(self, field_schema: Dict[str, Any]) -> str:
        """Extract type from field schema.
        
        Args:
            field_schema: Field schema
        
        Returns:
            Type string
        """
        if "type" in field_schema:
            return field_schema["type"]
        
        if "anyOf" in field_schema:
            types = []
            for sub_schema in field_schema["anyOf"]:
                if "type" in sub_schema:
                    types.append(sub_schema["type"])
            return " | ".join(types)
        
        if "enum" in field_schema:
            return "enum"
        
        return "any"
    
    def _extract_constraints(self, field_schema: Dict[str, Any]) -> Dict[str, Any]:
        """Extract constraints from field schema.
        
        Args:
            field_schema: Field schema
        
        Returns:
            Dictionary of constraints
        """
        constraints = {}
        
        constraint_keys = [
            "minLength", "maxLength", "minimum", "maximum",
            "pattern", "minItems", "maxItems", "uniqueItems",
            "minProperties", "maxProperties",
        ]
        
        for key in constraint_keys:
            if key in field_schema:
                constraints[key] = field_schema[key]
        
        return constraints


class SchemaVersionManager:
    """Manages multiple schema versions for validation."""
    
    def __init__(self, schemas_dir: Optional[Path] = None):
        """Initialize schema version manager.
        
        Args:
            schemas_dir: Directory containing schemas
        """
        if schemas_dir is None:
            module_path = Path(__file__).parent.parent.parent
            schemas_dir = module_path / "schemas"
        
        self.schemas_dir = schemas_dir
        self.validators: Dict[str, PayloadValidator] = {}
    
    def list_versions(self) -> List[str]:
        """List available schema versions.
        
        Returns:
            List of version strings
        """
        if not self.schemas_dir.exists():
            return []
        
        versions = []
        for path in self.schemas_dir.iterdir():
            if path.is_dir() and path.name.startswith("v"):
                versions.append(path.name)
        
        if (self.schemas_dir / "latest").exists():
            versions.append("latest")
        
        return sorted(versions)
    
    def get_validator(self, version: str = "latest") -> PayloadValidator:
        """Get validator for a specific version.
        
        Args:
            version: Schema version
        
        Returns:
            PayloadValidator for the version
        """
        if version not in self.validators:
            self.validators[version] = PayloadValidator(version, self.schemas_dir)
        
        return self.validators[version]
    
    def validate_against_all(
        self,
        payload_dict: Dict[str, Any],
    ) -> Dict[str, Tuple[bool, Optional[str]]]:
        """Validate payload against all available versions.
        
        Args:
            payload_dict: Payload to validate
        
        Returns:
            Dictionary mapping version to validation result
        """
        results = {}
        
        for version in self.list_versions():
            if version == "latest":
                continue  # Skip symlink
            
            try:
                validator = self.get_validator(version)
                results[version] = validator.validate(payload_dict)
            except Exception as e:
                results[version] = (False, str(e))
        
        return results