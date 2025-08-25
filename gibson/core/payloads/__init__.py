"""Payload management system for Gibson Framework.

This module provides comprehensive payload management capabilities including:
- Database storage for metadata and references
- File system organization by domain and attack type
- GitHub repository synchronization
- Memory caching for performance
- Import/export functionality
- Performance monitoring

The payload system follows a hybrid storage approach:
- Database stores metadata, references, and search indices
- File system stores actual payload content
- Memory cache provides fast access to frequently used payloads
"""

from .types import (
    PayloadQuery,
    ImportResult,
    SyncResult,
)

# Import replacement models from gibson.models
from gibson.models.payload import PayloadModel
from gibson.models.domain import AttackDomain, ModuleCategory, Severity
from .manager import PayloadManager
from .database import PayloadDatabase
from .fetcher import PayloadFetcher
from .cache import PayloadCache
from .organizer import PayloadOrganizer
from .git_sync import GitSync
from .git_models import GitURL, GitPlatform, GitCredentials
from .models.git_sync import AuthMethod, CloneResult, UpdateResult
from .validator import PayloadValidator
from .porter import PayloadPorter
from .monitor import PayloadMonitor

__all__ = [
    "PayloadModel",
    "PayloadQuery",
    "ImportResult",
    "SyncResult",
    "AttackDomain",
    "ModuleCategory",
    "Severity",
    "PayloadManager",
    "PayloadDatabase",
    "PayloadFetcher",
    "PayloadCache",
    "PayloadOrganizer",
    "GitSync",
    "GitURL",
    "GitPlatform",
    "GitCredentials",
    "AuthMethod",
    "CloneResult",
    "UpdateResult",
    "PayloadValidator",
    "PayloadPorter",
    "PayloadMonitor",
]
