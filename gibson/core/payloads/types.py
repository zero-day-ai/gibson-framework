"""Core data types and models for payload management."""
import hashlib
import json
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union
from pydantic import BaseModel, Field, HttpUrl, ConfigDict, field_validator, model_validator

# Import replacement models from gibson.models
from gibson.models.domain import AttackDomain, ModuleCategory, Severity
from gibson.models.payload import PayloadStatus


class PayloadQuery(BaseModel):
    """Query parameters for payload search and filtering."""

    search: Optional[str] = None
    domain: Optional[AttackDomain] = None
    attack_type: Optional[str] = None
    category: Optional[ModuleCategory] = None
    severity: Optional[Severity] = None
    status: Optional[PayloadStatus] = None
    tags: Optional[List[str]] = None
    owasp_categories: Optional[List[str]] = None
    author: Optional[str] = None
    min_success_rate: Optional[float] = Field(None, ge=0.0, le=1.0)
    max_response_time_ms: Optional[int] = Field(None, ge=0)
    created_after: Optional[datetime] = None
    created_before: Optional[datetime] = None
    updated_after: Optional[datetime] = None
    updated_before: Optional[datetime] = None
    source_repo: Optional[str] = None
    sort_by: str = "updated_at"
    sort_order: str = Field("desc", pattern="^(asc|desc)$")
    limit: Optional[int] = Field(None, ge=1, le=1000)
    offset: int = Field(0, ge=0)
    include_deprecated: bool = False
    include_experimental: bool = True

    @classmethod
    @field_validator("tags", mode="before")
    def normalize_query_tags(cls, v: Union[List[str], str, None]) -> Optional[List[str]]:
        """Normalize tags for query."""
        if not v:
            return None
        if isinstance(v, str):
            return [tag.strip().lower() for tag in v.split(",") if tag.strip()]
        return [tag.strip().lower() for tag in v if tag.strip()]


class ImportResult(BaseModel):
    """Result of payload import operation."""

    success: bool
    imported_count: int = 0
    updated_count: int = 0
    skipped_count: int = 0
    error_count: int = 0
    imported_payloads: List[str] = Field(default_factory=list)
    updated_payloads: List[str] = Field(default_factory=list)
    skipped_payloads: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
    processing_time_ms: int = 0
    source_info: Optional[Dict[str, Any]] = None

    @property
    def total_processed(self) -> int:
        """Total number of payloads processed."""
        return self.imported_count + self.updated_count + self.skipped_count + self.error_count

    @property
    def success_rate(self) -> float:
        """Success rate of import operation."""
        if self.total_processed == 0:
            return 0.0
        return (self.imported_count + self.updated_count) / self.total_processed


class SyncResult(BaseModel):
    """Result of payload synchronization operation."""

    success: bool
    repository: str
    branch: str = "main"
    fetched_count: int = 0
    processed_count: int = 0  # Alias for imported_count for backward compatibility
    imported_count: int = 0
    updated_count: int = 0
    deleted_count: int = 0
    error_count: int = 0
    error: Optional[str] = None  # Single error message for backward compatibility
    new_payloads: List[str] = Field(default_factory=list)
    updated_payloads: List[str] = Field(default_factory=list)
    deleted_payloads: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
    sync_duration_ms: int = 0
    download_size_bytes: int = 0
    last_commit: Optional[str] = None
    sync_timestamp: datetime = Field(default_factory=datetime.utcnow)
    total_processed: Optional[int] = None  # Total payloads processed
    auth_method: Optional[str] = None  # Authentication method used (public, ssh_key, token)
    clone_method: Optional[str] = None  # Clone method used (shallow, full)

    def add_error(self, error: str) -> None:
        """Add an error to the errors list and update error field."""
        self.errors.append(error)
        if not self.error:
            self.error = error  # Set first error as main error

    @model_validator(mode="after")
    def sync_processed_count(self) -> "SyncResult":
        """Keep processed_count in sync with imported_count."""
        self.processed_count = self.imported_count
        return self

    @property
    def total_changes(self) -> int:
        """Total number of changes made."""
        return self.imported_count + self.updated_count + self.deleted_count

    @property
    def change_rate(self) -> float:
        """Rate of successful changes."""
        if self.fetched_count == 0:
            return 0.0
        return self.total_changes / self.fetched_count


class PayloadMetrics(BaseModel):
    """Performance and usage metrics for payloads."""

    total_payloads: int = 0
    active_payloads: int = 0
    deprecated_payloads: int = 0
    experimental_payloads: int = 0
    domain_counts: Dict[AttackDomain, int] = Field(default_factory=dict)
    avg_success_rate: Optional[float] = None
    avg_response_time_ms: Optional[float] = None
    total_usage: int = 0
    most_used_payloads: List[str] = Field(default_factory=list)
    total_size_bytes: int = 0
    cache_hit_rate: Optional[float] = None
    payloads_with_documentation: int = 0
    payloads_with_references: int = 0
    avg_tags_per_payload: float = 0.0

    def calculate_coverage_by_domain(self) -> Dict[str, float]:
        """Calculate payload coverage percentage by domain."""
        if self.total_payloads == 0:
            return {domain.value: (0.0) for domain in AttackDomain}
        return {
            domain.value: (count / self.total_payloads * 100)
            for domain, count in self.domain_counts.items()
        }
