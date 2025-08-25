"""
Schema generation module for extracting JSON schemas from Pydantic models.

This module provides the core functionality for generating JSON schemas
from Pydantic models with metadata injection and versioning support.
"""

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Type, List
from pydantic import BaseModel


class SchemaGenerator:
    """Core component for extracting and generating schemas from Pydantic models."""
    
    def __init__(self, base_url: str = "https://gibson.ai/schemas"):
        """Initialize the schema generator.
        
        Args:
            base_url: Base URL for schema references
        """
        self.base_url = base_url
    
    def generate_json_schema(
        self,
        model: Type[BaseModel],
        version: Optional[str] = None,
        title: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Extract JSON schema from a Pydantic model.
        
        Args:
            model: Pydantic model class to generate schema from
            version: Optional version string for the schema
            title: Optional title override for the schema
        
        Returns:
            JSON schema dictionary with metadata
        """
        # Generate base schema using Pydantic's built-in method
        schema = model.model_json_schema()
        
        # Add metadata
        schema = self.add_metadata(schema, version or "1-0-0", model.__name__)
        
        # Override title if provided
        if title:
            schema["title"] = title
        
        # Add schema draft version
        schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
        
        return schema
    
    def add_metadata(
        self,
        schema: Dict[str, Any],
        version: str,
        model_name: str,
    ) -> Dict[str, Any]:
        """Add metadata to a JSON schema.
        
        Args:
            schema: Base JSON schema dictionary
            version: Schema version in SchemaVer format
            model_name: Name of the source model
        
        Returns:
            Schema with added metadata
        """
        # Add schema ID and version
        schema["$id"] = f"{self.base_url}/{version}/{model_name.lower()}.json"
        schema["version"] = version
        schema["generated"] = datetime.utcnow().isoformat() + "Z"
        
        # Add model hash for change detection
        schema_str = json.dumps(schema, sort_keys=True)
        schema["modelHash"] = hashlib.sha256(schema_str.encode()).hexdigest()[:16]
        
        # Add Gibson-specific metadata
        if "properties" in schema:
            schema["x-gibson"] = {
                "version": version,
                "generator": "gibson-schema-workflow",
                "model": model_name,
            }
        
        return schema
    
    def write_schema(
        self,
        schema: Dict[str, Any],
        output_path: Path,
        minify: bool = False,
    ) -> None:
        """Write a JSON schema to file.
        
        Args:
            schema: JSON schema dictionary
            output_path: Path to write the schema to
            minify: Whether to minify the JSON output
        """
        # Ensure parent directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Write schema to file
        with open(output_path, "w") as f:
            if minify:
                json.dump(schema, f, separators=(",", ":"))
            else:
                json.dump(schema, f, indent=2, sort_keys=True)
    
    def extract_required_fields(self, schema: Dict[str, Any]) -> List[str]:
        """Extract list of required fields from schema.
        
        Args:
            schema: JSON schema dictionary
        
        Returns:
            List of required field names
        """
        return schema.get("required", [])
    
    def extract_enum_values(self, schema: Dict[str, Any]) -> Dict[str, List[str]]:
        """Extract enum values from schema properties.
        
        Args:
            schema: JSON schema dictionary
        
        Returns:
            Dictionary mapping field names to their enum values
        """
        enums = {}
        properties = schema.get("properties", {})
        
        for field_name, field_schema in properties.items():
            if "enum" in field_schema:
                enums[field_name] = field_schema["enum"]
            elif "anyOf" in field_schema:
                # Handle union types that might contain enums
                for sub_schema in field_schema["anyOf"]:
                    if "enum" in sub_schema:
                        enums[field_name] = sub_schema["enum"]
                        break
        
        return enums
    
    def extract_field_types(self, schema: Dict[str, Any]) -> Dict[str, str]:
        """Extract field types from schema.
        
        Args:
            schema: JSON schema dictionary
        
        Returns:
            Dictionary mapping field names to their types
        """
        types = {}
        properties = schema.get("properties", {})
        
        for field_name, field_schema in properties.items():
            if "type" in field_schema:
                types[field_name] = field_schema["type"]
            elif "anyOf" in field_schema:
                # Handle union types
                type_list = []
                for sub_schema in field_schema["anyOf"]:
                    if "type" in sub_schema:
                        type_list.append(sub_schema["type"])
                if type_list:
                    types[field_name] = " | ".join(type_list)
        
        return types
    
    def generate_schema_summary(self, schema: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a summary of schema characteristics.
        
        Args:
            schema: JSON schema dictionary
        
        Returns:
            Summary dictionary with schema characteristics
        """
        return {
            "title": schema.get("title", "Unknown"),
            "version": schema.get("version", "Unknown"),
            "required_fields": self.extract_required_fields(schema),
            "total_fields": len(schema.get("properties", {})),
            "enum_fields": list(self.extract_enum_values(schema).keys()),
            "field_types": self.extract_field_types(schema),
            "has_additional_properties": schema.get("additionalProperties", True),
            "generated_at": schema.get("generated", "Unknown"),
        }
    
    def validate_schema_structure(self, schema: Dict[str, Any]) -> bool:
        """Validate that a schema has the expected structure.
        
        Args:
            schema: JSON schema dictionary
        
        Returns:
            True if schema structure is valid
        """
        # Check for required top-level fields
        required_fields = ["$schema", "title", "type", "properties"]
        
        for field in required_fields:
            if field not in schema:
                return False
        
        # Validate that properties is a dictionary
        if not isinstance(schema.get("properties"), dict):
            return False
        
        # Check that type is "object" for Pydantic models
        if schema.get("type") != "object":
            return False
        
        return True