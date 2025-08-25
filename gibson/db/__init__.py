"""Gibson database models package - consolidated models location.

This package contains all database models for the Gibson framework,
organized by functional area for better maintainability.
"""

# Base classes and utilities
from gibson.db.base import Base, BaseDBModel, CRUDMixin, TimestampMixin

# Scan-related models
from gibson.db.models.scan import (
    ScanRecord,
    FindingRecord,
    ModuleRecord,
    ModuleResultRecord,
)

# Payload-related models
from gibson.db.models.payload import (
    PayloadRecord,
    PayloadCollectionRecord,
    PayloadSourceRecord,
    PayloadEffectivenessRecord,
    # Legacy models (temporary for backward compatibility)
    PromptSourceRecord,
    PromptCollectionRecord,
    PromptRecord,
)

# Authentication and credential models
from gibson.db.models.auth import (
    APIKeyRecord,
    EncryptedCredentialRecord,
    AuthenticationTokenRecord,
    OAuthProviderRecord,
    SessionRecord,
)

# Audit and statistics models
from gibson.db.models.audit import (
    MigrationAudit,
    AuditLogRecord,
    PromptAttackStats,
    DataAttackStats,
    ModelAttackStats,
    SystemAttackStats,
    OutputAttackStats,
    PerformanceMetrics,
    SecurityEventLog,
)

# Report and target models
from gibson.db.models.report import (
    TargetRecord,
    ReportRecord,
    ReportTemplateRecord,
    ReportDistributionRecord,
    ReportScheduleRecord,
)

# Utilities
from gibson.db.utils.converters import (
    ModelConverter,
    QueryHelper,
)

# Export all models and utilities
__all__ = [
    # Base classes
    'Base',
    'BaseDBModel',
    'CRUDMixin',
    'TimestampMixin',
    
    # Scan models
    'ScanRecord',
    'FindingRecord',
    'ModuleRecord',
    'ModuleResultRecord',
    
    # Payload models
    'PayloadRecord',
    'PayloadCollectionRecord',
    'PayloadSourceRecord',
    'PayloadEffectivenessRecord',
    'PromptSourceRecord',
    'PromptCollectionRecord',
    'PromptRecord',
    
    # Authentication models
    'APIKeyRecord',
    'EncryptedCredentialRecord',
    'AuthenticationTokenRecord',
    'OAuthProviderRecord',
    'SessionRecord',
    
    # Audit models
    'MigrationAudit',
    'AuditLogRecord',
    'PromptAttackStats',
    'DataAttackStats',
    'ModelAttackStats',
    'SystemAttackStats',
    'OutputAttackStats',
    'PerformanceMetrics',
    'SecurityEventLog',
    
    # Report models
    'TargetRecord',
    'ReportRecord',
    'ReportTemplateRecord',
    'ReportDistributionRecord',
    'ReportScheduleRecord',
    
    # Utilities
    'ModelConverter',
    'QueryHelper',
]