"""Target management system for Gibson Framework.

Provides comprehensive target management including database operations,
credential integration, provider detection, and validation.
"""

from gibson.core.targets.manager import (
    TargetManager,
    TargetManagerError,
    TargetValidationError
)
from gibson.core.targets.repository import (
    TargetRepository,
    TargetRepositoryError,
    TargetNotFoundError,
    TargetAlreadyExistsError
)
from gibson.core.targets.litellm_adapter import LiteLLMAdapter

__all__ = [
    # Manager
    'TargetManager',
    'TargetManagerError',
    'TargetValidationError',
    
    # Repository
    'TargetRepository',
    'TargetRepositoryError',
    'TargetNotFoundError',
    'TargetAlreadyExistsError',
    
    # Adapter
    'LiteLLMAdapter'
]