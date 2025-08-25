"""
Schema generator hub for coordinating multi-format schema generation.
"""

from typing import Any, Dict, Optional, Type
from pydantic import BaseModel
from loguru import logger
import json
import hashlib

from gibson.core.schema_sync.models import SchemaBundle, ValidationStatus
from gibson.utils.schema_generator import SchemaGenerator


class SchemaGeneratorHub:
    """Coordinates generation of schemas in multiple formats."""

    def __init__(self, base_url: str = "https://gibson.ai/schemas"):
        """
        Initialize the schema generator hub.

        Args:
            base_url: Base URL for schema references
        """
        self.json_generator = SchemaGenerator(base_url)

    def generate_all_schemas(self, model: Type[BaseModel], version: str) -> SchemaBundle:
        """
        Generate schemas in all supported formats.

        Args:
            model: Pydantic model to generate schemas from
            version: Version string for the schemas

        Returns:
            SchemaBundle containing all generated schemas
        """
        logger.info(f"Generating schemas for {model.__name__} v{version}")

        # Generate JSON schema
        json_schema = self.json_generator.generate_json_schema(model, version)

        # Generate TypeScript types (placeholder)
        typescript_types = self._generate_typescript_types(model, json_schema)

        # Generate SQLAlchemy model (placeholder)
        sqlalchemy_model = self._generate_sqlalchemy_model(model, json_schema)

        # Generate Pydantic schema representation
        pydantic_schema = model.model_json_schema()

        # Calculate hash
        schema_hash = self._calculate_bundle_hash(json_schema)

        bundle = SchemaBundle(
            version=version,
            pydantic_schema=pydantic_schema,
            json_schema=json_schema,
            typescript_types=typescript_types,
            sqlalchemy_model=sqlalchemy_model,
            hash=schema_hash,
        )

        # Validate consistency
        validation_result = self.validate_schema_consistency(bundle)
        bundle.validation_status = validation_result["status"]
        bundle.validation_errors = validation_result.get("errors", [])

        logger.info(f"Generated schema bundle with hash: {schema_hash[:8]}")
        return bundle

    def _calculate_bundle_hash(self, schema: Dict[str, Any]) -> str:
        """Calculate hash of schema bundle."""
        import hashlib
        import json

        # Sort keys for consistent hashing
        schema_str = json.dumps(schema, sort_keys=True, default=str)
        return hashlib.sha256(schema_str.encode()).hexdigest()

    def validate_schema_consistency(self, bundle: SchemaBundle) -> Dict[str, Any]:
        """
        Validate consistency across schema formats.

        Args:
            bundle: SchemaBundle to validate

        Returns:
            Validation result dictionary
        """
        errors = []
        warnings = []

        # Check that all schemas are present
        if not bundle.json_schema:
            errors.append({"type": "missing", "format": "json", "message": "JSON schema missing"})

        if not bundle.typescript_types:
            warnings.append(
                {"type": "missing", "format": "typescript", "message": "TypeScript types missing"}
            )

        if not bundle.sqlalchemy_model:
            warnings.append(
                {"type": "missing", "format": "sqlalchemy", "message": "SQLAlchemy model missing"}
            )

        # Validate field consistency (placeholder for more complex validation)
        if bundle.json_schema and bundle.pydantic_schema:
            json_fields = set(bundle.json_schema.get("properties", {}).keys())
            pydantic_fields = set(bundle.pydantic_schema.get("properties", {}).keys())

            if json_fields != pydantic_fields:
                errors.append(
                    {
                        "type": "inconsistency",
                        "message": f"Field mismatch: JSON has {json_fields - pydantic_fields}, "
                        f"Pydantic has {pydantic_fields - json_fields}",
                    }
                )

        if errors:
            return {"status": ValidationStatus.INVALID, "errors": errors, "warnings": warnings}
        elif warnings:
            return {"status": ValidationStatus.WARNINGS, "warnings": warnings}
        else:
            return {"status": ValidationStatus.VALID}

    def _generate_typescript_types(
        self, model: Type[BaseModel], json_schema: Dict[str, Any]
    ) -> str:
        """
        Generate TypeScript type definitions from model.

        This is a placeholder implementation. Full implementation would
        generate complete TypeScript interfaces.
        """
        ts_lines = [
            f"// TypeScript types for {model.__name__}",
            f"export interface {model.__name__} {{",
        ]

        properties = json_schema.get("properties", {})
        required = set(json_schema.get("required", []))

        for prop_name, prop_schema in properties.items():
            prop_type = self._json_type_to_typescript(prop_schema.get("type", "any"))
            optional = "" if prop_name in required else "?"
            ts_lines.append(f"  {prop_name}{optional}: {prop_type};")

        ts_lines.append("}")

        return "\n".join(ts_lines)

    def _generate_sqlalchemy_model(
        self, model: Type[BaseModel], json_schema: Dict[str, Any]
    ) -> str:
        """
        Generate SQLAlchemy model code from Pydantic model.

        This is a placeholder implementation. Full implementation would
        generate complete SQLAlchemy model with proper column types.
        """
        sa_lines = [
            f"# SQLAlchemy model for {model.__name__}",
            "from sqlalchemy import Column, Integer, String, Float, Boolean, JSON, Text",
            "from sqlalchemy.ext.declarative import declarative_base",
            "",
            "Base = declarative_base()",
            "",
            f"class {model.__name__}Table(Base):",
            f"    __tablename__ = '{model.__name__.lower()}s'",
            "    ",
            "    id = Column(Integer, primary_key=True, autoincrement=True)",
        ]

        properties = json_schema.get("properties", {})
        required = set(json_schema.get("required", []))

        for prop_name, prop_schema in properties.items():
            if prop_name == "id":
                continue  # Already defined

            col_type = self._json_type_to_sqlalchemy(prop_schema.get("type", "string"))
            nullable = "False" if prop_name in required else "True"
            sa_lines.append(f"    {prop_name} = Column({col_type}, nullable={nullable})")

        return "\n".join(sa_lines)

    def _json_type_to_typescript(self, json_type: str) -> str:
        """Convert JSON schema type to TypeScript type."""
        mapping = {
            "string": "string",
            "integer": "number",
            "number": "number",
            "boolean": "boolean",
            "array": "any[]",
            "object": "Record<string, any>",
            "null": "null",
        }
        return mapping.get(json_type, "any")

    def _json_type_to_sqlalchemy(self, json_type: str) -> str:
        """Convert JSON schema type to SQLAlchemy column type."""
        mapping = {
            "string": "String(255)",
            "integer": "Integer",
            "number": "Float",
            "boolean": "Boolean",
            "array": "JSON",
            "object": "JSON",
        }
        return mapping.get(json_type, "Text")
