"""Base taxonomy mapping classes and protocols for Gibson Framework.

Defines the core interfaces and data structures for mapping Gibson's internal
attack domains and module categories to external security taxonomies.
"""

from abc import abstractmethod
from typing import Any, Dict, List, Optional, Protocol

from pydantic import Field, field_validator

from gibson.models.base import GibsonBaseModel
from gibson.models.domain import AttackDomain, ModuleCategory
from gibson.models.validators import NumericValidator


class BaseTaxonomyMapper(Protocol):
    """Protocol defining the interface for taxonomy mappers.

    All taxonomy mappers must implement this interface to provide consistent
    mapping functionality across different security frameworks.
    """

    @abstractmethod
    def map(self, domain: AttackDomain, category: ModuleCategory) -> List[str]:
        """Map Gibson domain/category to external taxonomy categories.

        Args:
            domain: Gibson attack domain
            category: Gibson module category

        Returns:
            List of external taxonomy category identifiers

        Example:
            >>> mapper.map(AttackDomain.PROMPT, ModuleCategory.INJECTION)
            ['OWASP-LLM-01']
        """
        ...

    @property
    @abstractmethod
    def taxonomy_id(self) -> str:
        """Get versioned taxonomy identifier.

        Returns:
            Versioned identifier like 'owasp-llm-2025' or 'mitre-attack-v14'
        """
        ...

    @property
    @abstractmethod
    def taxonomy_name(self) -> str:
        """Get human-readable taxonomy name.

        Returns:
            Human-readable name like 'OWASP LLM Top 10' or 'MITRE ATT&CK'
        """
        ...


class TaxonomyMapping(GibsonBaseModel):
    """Model representing a mapping between Gibson categories and external taxonomy.

    This model stores individual mappings and their metadata, including confidence
    scores and additional context information.
    """

    gibson_domain: AttackDomain = Field(description="Gibson attack domain being mapped")
    gibson_category: ModuleCategory = Field(description="Gibson module category being mapped")
    taxonomy: str = Field(
        min_length=1,
        max_length=100,
        description="External taxonomy identifier (e.g., 'owasp-llm-2025')",
        examples=["owasp-llm-2025", "mitre-attack-v14", "nist-csf-2.0"],
    )
    mapped_categories: List[str] = Field(
        description="List of external taxonomy category identifiers",
        examples=[["OWASP-LLM-01"], ["T1566.001", "T1566.002"]],
    )
    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Confidence score for this mapping (0.0-1.0)",
        examples=[0.95, 0.8, 0.6],
    )
    metadata: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Additional mapping metadata and context",
        examples=[
            {
                "mapping_rationale": "Direct correspondence between prompt injection concepts",
                "last_reviewed": "2024-01-15",
                "reviewer": "security-team",
                "taxonomy_version": "2025.1",
            }
        ],
    )

    @field_validator("taxonomy")
    @classmethod
    def validate_taxonomy(cls, v: str) -> str:
        """Validate taxonomy identifier format.

        Args:
            v: Taxonomy identifier to validate

        Returns:
            Validated taxonomy identifier

        Raises:
            ValueError: If taxonomy identifier is invalid
        """
        # Remove whitespace and convert to lowercase
        v = v.strip().lower()

        # Check for basic format requirements
        if not v:
            raise ValueError("Taxonomy identifier cannot be empty")

        # Must contain only alphanumeric, hyphens, periods, underscores
        if not all(c.isalnum() or c in "-._" for c in v):
            raise ValueError(
                "Taxonomy identifier can only contain alphanumeric characters, hyphens, periods, and underscores"
            )

        # Cannot start or end with special characters
        if v[0] in "-._" or v[-1] in "-._":
            raise ValueError("Taxonomy identifier cannot start or end with special characters")

        return v

    @field_validator("mapped_categories")
    @classmethod
    def validate_mapped_categories(cls, v: List[str]) -> List[str]:
        """Validate mapped category identifiers.

        Args:
            v: List of category identifiers to validate

        Returns:
            Validated list of category identifiers

        Raises:
            ValueError: If any category identifier is invalid
        """
        if not v:
            raise ValueError("At least one mapped category must be provided")

        validated_categories = []
        for category in v:
            # Remove whitespace
            category = category.strip()

            if not category:
                raise ValueError("Mapped category cannot be empty")

            # Basic format validation - allow more flexible formats for different taxonomies
            if len(category) > 200:
                raise ValueError("Mapped category identifier too long (max 200 characters)")

            validated_categories.append(category)

        # Remove duplicates while preserving order
        seen = set()
        unique_categories = []
        for category in validated_categories:
            if category not in seen:
                seen.add(category)
                unique_categories.append(category)

        return unique_categories

    @field_validator("confidence")
    @classmethod
    def validate_confidence(cls, v: float) -> float:
        """Validate confidence score.

        Args:
            v: Confidence score to validate

        Returns:
            Validated confidence score
        """
        return NumericValidator.validate_percentage(v, "confidence")

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, v: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Validate metadata dictionary.

        Args:
            v: Metadata dictionary to validate

        Returns:
            Validated metadata dictionary
        """
        if v is None:
            return None

        # Check for reasonable size limits
        if len(v) > 50:
            raise ValueError("Metadata cannot contain more than 50 keys")

        # Validate key formats
        for key in v.keys():
            if not isinstance(key, str):
                raise ValueError("All metadata keys must be strings")
            if len(key) > 100:
                raise ValueError("Metadata keys cannot exceed 100 characters")
            if not key.strip():
                raise ValueError("Metadata keys cannot be empty")

        return v

    def is_high_confidence(self, threshold: float = 0.8) -> bool:
        """Check if this mapping has high confidence.

        Args:
            threshold: Confidence threshold (default 0.8)

        Returns:
            True if confidence meets or exceeds threshold
        """
        return self.confidence >= threshold

    def get_primary_category(self) -> str:
        """Get the primary (first) mapped category.

        Returns:
            Primary category identifier
        """
        return self.mapped_categories[0] if self.mapped_categories else ""

    def has_category(self, category: str) -> bool:
        """Check if a specific category is mapped.

        Args:
            category: Category identifier to check

        Returns:
            True if category is in mapped_categories
        """
        return category in self.mapped_categories

    def add_metadata(self, key: str, value: Any) -> None:
        """Add or update metadata entry.

        Args:
            key: Metadata key
            value: Metadata value
        """
        if self.metadata is None:
            self.metadata = {}
        self.metadata[key] = value
        # Update timestamp - this would be handled by model update logic
        pass

    def get_mapping_key(self) -> str:
        """Get unique key for this mapping combination.

        Returns:
            Unique identifier string combining domain, category, and taxonomy
        """
        domain_value = (
            self.gibson_domain.value if hasattr(self.gibson_domain, "value") else self.gibson_domain
        )
        category_value = (
            self.gibson_category.value
            if hasattr(self.gibson_category, "value")
            else self.gibson_category
        )
        return f"{domain_value}:{category_value}:{self.taxonomy}"

    class Config:
        """Pydantic configuration."""

        json_schema_extra = {
            "example": {
                "gibson_domain": "prompt",
                "gibson_category": "injection",
                "taxonomy": "owasp-llm-2025",
                "mapped_categories": ["OWASP-LLM-01"],
                "confidence": 0.95,
                "metadata": {
                    "mapping_rationale": "Direct correspondence - both deal with prompt injection attacks",
                    "last_reviewed": "2024-01-15",
                    "reviewer": "security-team",
                    "taxonomy_version": "2025.1",
                    "automated_mapping": False,
                },
            }
        }
