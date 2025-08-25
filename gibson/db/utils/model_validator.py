"""Model validation utilities for database integrity."""

from typing import Any, Dict, List, Optional, Type, TypeVar
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel as PydanticBaseModel, ValidationError, field_validator
from sqlalchemy import inspect
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from gibson.db.base import BaseDBModel

T = TypeVar("T", bound=BaseDBModel)


class ValidationResult:
    """Result of model validation."""
    
    def __init__(self):
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.is_valid: bool = True
    
    def add_error(self, message: str) -> None:
        """Add a validation error."""
        self.errors.append(message)
        self.is_valid = False
    
    def add_warning(self, message: str) -> None:
        """Add a validation warning."""
        self.warnings.append(message)
    
    def merge(self, other: "ValidationResult") -> None:
        """Merge another validation result into this one."""
        self.errors.extend(other.errors)
        self.warnings.extend(other.warnings)
        if other.errors:
            self.is_valid = False


class ModelValidator:
    """Validator for database models with comprehensive checks."""
    
    @staticmethod
    def validate_model(instance: BaseDBModel, session: Optional[Session] = None) -> ValidationResult:
        """Validate a model instance.
        
        Args:
            instance: Model instance to validate
            session: Optional database session for uniqueness checks
            
        Returns:
            ValidationResult with errors and warnings
        """
        result = ValidationResult()
        
        # Check basic field validation
        result.merge(ModelValidator._validate_required_fields(instance))
        result.merge(ModelValidator._validate_field_types(instance))
        result.merge(ModelValidator._validate_field_lengths(instance))
        
        # Check audit fields
        result.merge(ModelValidator._validate_audit_fields(instance))
        
        # Check versioning
        result.merge(ModelValidator._validate_version(instance))
        
        # Check uniqueness if session provided
        if session:
            result.merge(ModelValidator._validate_uniqueness(instance, session))
        
        return result
    
    @staticmethod
    def _validate_required_fields(instance: BaseDBModel) -> ValidationResult:
        """Validate required fields are present."""
        result = ValidationResult()
        mapper = inspect(instance.__class__)
        
        for column in mapper.columns:
            if not column.nullable and column.default is None:
                value = getattr(instance, column.name, None)
                if value is None:
                    result.add_error(f"Required field '{column.name}' is missing")
        
        return result
    
    @staticmethod
    def _validate_field_types(instance: BaseDBModel) -> ValidationResult:
        """Validate field types match column definitions."""
        result = ValidationResult()
        mapper = inspect(instance.__class__)
        
        for column in mapper.columns:
            value = getattr(instance, column.name, None)
            if value is not None:
                # Check common type mismatches
                column_type = str(column.type)
                
                if 'UUID' in column_type and not isinstance(value, (UUID, str)):
                    result.add_error(f"Field '{column.name}' should be UUID, got {type(value).__name__}")
                
                elif 'DateTime' in column_type and not isinstance(value, (datetime, str)):
                    result.add_error(f"Field '{column.name}' should be DateTime, got {type(value).__name__}")
                
                elif 'Integer' in column_type and not isinstance(value, (int, bool)):
                    result.add_error(f"Field '{column.name}' should be Integer, got {type(value).__name__}")
                
                elif 'Boolean' in column_type and not isinstance(value, bool):
                    result.add_error(f"Field '{column.name}' should be Boolean, got {type(value).__name__}")
        
        return result
    
    @staticmethod
    def _validate_field_lengths(instance: BaseDBModel) -> ValidationResult:
        """Validate string field lengths."""
        result = ValidationResult()
        mapper = inspect(instance.__class__)
        
        for column in mapper.columns:
            if hasattr(column.type, 'length'):
                value = getattr(instance, column.name, None)
                if value and isinstance(value, str):
                    max_length = column.type.length
                    if max_length and len(value) > max_length:
                        result.add_error(
                            f"Field '{column.name}' exceeds maximum length ({len(value)} > {max_length})"
                        )
        
        return result
    
    @staticmethod
    def _validate_audit_fields(instance: BaseDBModel) -> ValidationResult:
        """Validate audit field consistency."""
        result = ValidationResult()
        
        # Check created_by/updated_by consistency
        if hasattr(instance, 'created_by') and hasattr(instance, 'updated_by'):
            if instance.created_by and not instance.updated_by:
                result.add_warning("created_by is set but updated_by is not")
        
        # Check timestamp consistency
        if hasattr(instance, 'created_at') and hasattr(instance, 'updated_at'):
            if instance.created_at and instance.updated_at:
                if instance.updated_at < instance.created_at:
                    result.add_error("updated_at cannot be before created_at")
        
        return result
    
    @staticmethod
    def _validate_version(instance: BaseDBModel) -> ValidationResult:
        """Validate version field."""
        result = ValidationResult()
        
        if hasattr(instance, 'version'):
            if instance.version is not None:
                if instance.version < 1:
                    result.add_error("Version must be positive")
                elif instance.version > 1000000:
                    result.add_warning("Version number unusually high")
        
        return result
    
    @staticmethod
    def _validate_uniqueness(instance: BaseDBModel, session: Session) -> ValidationResult:
        """Validate uniqueness constraints."""
        result = ValidationResult()
        mapper = inspect(instance.__class__)
        
        # Check unique columns
        for column in mapper.columns:
            if column.unique and column.name != 'id':
                value = getattr(instance, column.name, None)
                if value is not None:
                    # Check if another record exists with this value
                    existing = session.query(instance.__class__).filter_by(
                        **{column.name: value}
                    ).first()
                    
                    if existing and existing.id != instance.id:
                        result.add_error(f"Duplicate value for unique field '{column.name}': {value}")
        
        return result


class PydanticIntegration:
    """Utilities for Pydantic model integration."""
    
    @staticmethod
    def create_pydantic_model(
        db_model: Type[T],
        exclude_fields: Optional[List[str]] = None,
        optional_fields: Optional[List[str]] = None
    ) -> Type[PydanticBaseModel]:
        """Create a Pydantic model from a SQLAlchemy model.
        
        Args:
            db_model: SQLAlchemy model class
            exclude_fields: Fields to exclude from Pydantic model
            optional_fields: Fields to make optional
            
        Returns:
            Generated Pydantic model class
        """
        exclude_fields = exclude_fields or []
        optional_fields = optional_fields or []
        
        # Build field definitions
        fields = {}
        mapper = inspect(db_model)
        
        for column in mapper.columns:
            if column.name not in exclude_fields:
                # Determine field type
                python_type = _get_python_type(column)
                
                # Make field optional if specified or nullable
                if column.name in optional_fields or column.nullable:
                    python_type = Optional[python_type]
                
                fields[column.name] = (python_type, ...)
        
        # Create dynamic Pydantic model
        return type(
            f"{db_model.__name__}Pydantic",
            (PydanticBaseModel,),
            {
                "__annotations__": {k: v[0] for k, v in fields.items()},
                **{k: v[1] for k, v in fields.items()},
                "model_config": {"from_attributes": True}
            }
        )
    
    @staticmethod
    def validate_with_pydantic(
        instance: BaseDBModel,
        pydantic_model: Type[PydanticBaseModel]
    ) -> ValidationResult:
        """Validate a database model instance using a Pydantic model.
        
        Args:
            instance: Database model instance
            pydantic_model: Pydantic model class for validation
            
        Returns:
            ValidationResult
        """
        result = ValidationResult()
        
        try:
            # Convert to dict and validate
            data = instance.to_dict(exclude_deleted=False)
            pydantic_model(**data)
        except ValidationError as e:
            for error in e.errors():
                field = ".".join(str(loc) for loc in error["loc"])
                message = f"{field}: {error['msg']}"
                result.add_error(message)
        except Exception as e:
            result.add_error(f"Validation error: {str(e)}")
        
        return result


def _get_python_type(column) -> Type:
    """Get Python type for a SQLAlchemy column."""
    type_str = str(column.type)
    
    if 'UUID' in type_str:
        return UUID
    elif 'DateTime' in type_str:
        return datetime
    elif 'Integer' in type_str:
        return int
    elif 'Float' in type_str or 'Numeric' in type_str:
        return float
    elif 'Boolean' in type_str:
        return bool
    elif 'JSON' in type_str:
        return Dict[str, Any]
    elif 'Text' in type_str or 'String' in type_str:
        return str
    else:
        return Any


class BulkValidator:
    """Validator for bulk operations."""
    
    @staticmethod
    def validate_bulk(
        instances: List[BaseDBModel],
        session: Optional[Session] = None,
        stop_on_error: bool = False
    ) -> Dict[int, ValidationResult]:
        """Validate multiple model instances.
        
        Args:
            instances: List of model instances
            session: Optional database session
            stop_on_error: Whether to stop on first error
            
        Returns:
            Dictionary mapping index to validation results
        """
        results = {}
        
        for i, instance in enumerate(instances):
            result = ModelValidator.validate_model(instance, session)
            results[i] = result
            
            if stop_on_error and not result.is_valid:
                break
        
        return results
    
    @staticmethod
    def get_summary(results: Dict[int, ValidationResult]) -> Dict[str, Any]:
        """Get summary of bulk validation results.
        
        Args:
            results: Validation results from validate_bulk
            
        Returns:
            Summary statistics
        """
        total = len(results)
        valid = sum(1 for r in results.values() if r.is_valid)
        invalid = total - valid
        
        all_errors = []
        all_warnings = []
        
        for result in results.values():
            all_errors.extend(result.errors)
            all_warnings.extend(result.warnings)
        
        return {
            "total": total,
            "valid": valid,
            "invalid": invalid,
            "total_errors": len(all_errors),
            "total_warnings": len(all_warnings),
            "unique_errors": len(set(all_errors)),
            "unique_warnings": len(set(all_warnings))
        }


# Export main components
__all__ = [
    "ValidationResult",
    "ModelValidator",
    "PydanticIntegration",
    "BulkValidator"
]