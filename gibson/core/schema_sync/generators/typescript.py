"""
TypeScript interface generator for PayloadModel.
"""

import json
from typing import Dict, Any, List, Optional
from pathlib import Path

from gibson.models.base import GibsonBaseModel
from gibson.core.schema_sync.generators.base import SchemaGenerator, GenerationResult


class TypeScriptGenerator(SchemaGenerator):
    """Generate TypeScript interfaces from Pydantic models."""

    def __init__(self):
        """Initialize TypeScript generator."""
        super().__init__()
        self.type_mapping = {
            "string": "string",
            "integer": "number",
            "number": "number",
            "boolean": "boolean",
            "array": "Array",
            "object": "Record<string, any>",
            "null": "null",
        }

    def generate(
        self, model: type, output_path: Optional[Path] = None, **options
    ) -> GenerationResult:
        """
        Generate TypeScript interface from Pydantic model.

        Args:
            model: Pydantic model class
            output_path: Optional output file path
            **options: Additional generation options

        Returns:
            GenerationResult with generated content
        """
        try:
            # Get JSON schema from model
            json_schema = model.model_json_schema()

            # Generate TypeScript interface
            typescript_content = self._generate_typescript(
                json_schema,
                model.__name__,
                options.get("export", True),
                options.get("readonly", False),
                options.get("optional_fields", True),
            )

            # Generate type definitions for enums
            enum_content = self._generate_enums(json_schema)

            # Combine all content
            full_content = self._combine_content(
                typescript_content, enum_content, options.get("header_comment", True)
            )

            # Save if output path provided
            if output_path:
                output_path = Path(output_path)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_text(full_content)

            return GenerationResult(
                success=True,
                content=full_content,
                format="typescript",
                output_path=str(output_path) if output_path else None,
                metadata={
                    "model_name": model.__name__,
                    "interface_count": 1 + len(self._extract_nested_models(json_schema)),
                    "enum_count": len(self._extract_enums(json_schema)),
                    "field_count": len(json_schema.get("properties", {})),
                },
            )

        except Exception as e:
            return GenerationResult(success=False, content="", format="typescript", error=str(e))

    def _generate_typescript(
        self,
        schema: Dict[str, Any],
        interface_name: str,
        export: bool = True,
        readonly: bool = False,
        optional_fields: bool = True,
    ) -> str:
        """Generate TypeScript interface from JSON schema."""
        lines = []

        # Interface declaration
        export_keyword = "export " if export else ""
        lines.append(f"{export_keyword}interface {interface_name} {{")

        # Generate properties
        properties = schema.get("properties", {})
        required_fields = set(schema.get("required", []))

        for prop_name, prop_schema in properties.items():
            # Determine if field is optional
            is_optional = optional_fields and prop_name not in required_fields
            optional_marker = "?" if is_optional else ""

            # Add readonly modifier if requested
            readonly_modifier = "readonly " if readonly else ""

            # Get TypeScript type
            ts_type = self._get_typescript_type(prop_schema)

            # Add description as comment if available
            description = prop_schema.get("description", "")
            if description:
                lines.append(f"  /** {description} */")

            # Add property definition
            lines.append(f"  {readonly_modifier}{prop_name}{optional_marker}: {ts_type};")

        lines.append("}")

        return "\n".join(lines)

    def _get_typescript_type(self, schema: Dict[str, Any]) -> str:
        """Convert JSON schema type to TypeScript type."""
        # Handle references
        if "$ref" in schema:
            ref_name = schema["$ref"].split("/")[-1]
            return ref_name

        # Handle union types (anyOf, oneOf)
        if "anyOf" in schema:
            types = [self._get_typescript_type(s) for s in schema["anyOf"]]
            return " | ".join(types)

        if "oneOf" in schema:
            types = [self._get_typescript_type(s) for s in schema["oneOf"]]
            return " | ".join(types)

        # Handle arrays
        if schema.get("type") == "array":
            items_schema = schema.get("items", {})
            item_type = self._get_typescript_type(items_schema)
            return f"{item_type}[]"

        # Handle objects
        if schema.get("type") == "object":
            if "properties" in schema:
                # Inline object type
                props = []
                for prop_name, prop_schema in schema["properties"].items():
                    prop_type = self._get_typescript_type(prop_schema)
                    props.append(f"{prop_name}: {prop_type}")
                return f"{{ {'; '.join(props)} }}"
            else:
                return "Record<string, any>"

        # Handle enums
        if "enum" in schema:
            # Create union of literal types
            values = [f'"{v}"' if isinstance(v, str) else str(v) for v in schema["enum"]]
            return " | ".join(values)

        # Handle basic types
        json_type = schema.get("type", "any")
        if isinstance(json_type, list):
            # Multiple types allowed
            types = [self.type_mapping.get(t, t) for t in json_type]
            return " | ".join(types)

        return self.type_mapping.get(json_type, "any")

    def _generate_enums(self, schema: Dict[str, Any]) -> str:
        """Generate TypeScript enums from schema."""
        enums = self._extract_enums(schema)
        lines = []

        for enum_name, enum_values in enums.items():
            lines.append(f"export enum {enum_name} {{")
            for value in enum_values:
                if isinstance(value, str):
                    lines.append(f'  {value.upper()} = "{value}",')
                else:
                    lines.append(f"  {str(value).upper()} = {value},")
            lines.append("}")
            lines.append("")

        return "\n".join(lines)

    def _extract_enums(self, schema: Dict[str, Any]) -> Dict[str, List[Any]]:
        """Extract enum definitions from schema."""
        enums = {}

        # Check definitions/defs section
        definitions = schema.get("definitions", schema.get("$defs", {}))
        for def_name, def_schema in definitions.items():
            if "enum" in def_schema:
                enums[def_name] = def_schema["enum"]

        return enums

    def _extract_nested_models(self, schema: Dict[str, Any]) -> List[str]:
        """Extract nested model names from schema."""
        models = []

        # Check definitions/defs section
        definitions = schema.get("definitions", schema.get("$defs", {}))
        for def_name, def_schema in definitions.items():
            if def_schema.get("type") == "object":
                models.append(def_name)

        return models

    def _combine_content(
        self, typescript_content: str, enum_content: str, header_comment: bool = True
    ) -> str:
        """Combine all generated content."""
        parts = []

        if header_comment:
            parts.append("/**")
            parts.append(" * Auto-generated TypeScript definitions")
            parts.append(" * Generated from PayloadModel schema")
            parts.append(" * DO NOT EDIT MANUALLY")
            parts.append(" */")
            parts.append("")

        if enum_content:
            parts.append("// Enums")
            parts.append(enum_content)
            parts.append("")

        parts.append("// Interfaces")
        parts.append(typescript_content)

        return "\n".join(parts)

    def validate_output(self, content: str) -> bool:
        """
        Validate generated TypeScript code.

        Args:
            content: Generated TypeScript content

        Returns:
            True if valid TypeScript
        """
        # Basic syntax validation
        # Check for balanced braces
        open_braces = content.count("{")
        close_braces = content.count("}")
        if open_braces != close_braces:
            return False

        # Check for valid interface declarations
        if "interface" in content and not "interface " in content:
            return False

        # Check for semicolons after property declarations
        lines = content.split("\n")
        for line in lines:
            line = line.strip()
            if line and not line.startswith("//") and not line.startswith("/*"):
                if ":" in line and not line.endswith((";", "{", "}", ",")):
                    if not line.startswith("*"):  # Skip comment lines
                        return False

        return True
