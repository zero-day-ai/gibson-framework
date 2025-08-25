"""Authentication core module for Gibson Framework."""

from gibson.core.auth.crypto import CredentialEncryption
from gibson.core.auth.credential_manager import CredentialManager
from gibson.core.auth.auth_service import AuthenticationService
from gibson.core.auth.request_auth import RequestAuthenticator
from gibson.core.auth.env_injector import (
    EnvironmentCredentialInjector,
    detect_ci_environment,
    auto_inject_from_environment,
)
from gibson.core.auth.config import (
    resolve_credentials_path,
    resolve_config_directory,
    load_environment_credentials,
    validate_config_setup,
)

__all__ = [
    "CredentialEncryption",
    "CredentialManager",
    "AuthenticationService",
    "RequestAuthenticator",
    "EnvironmentCredentialInjector",
    "detect_ci_environment",
    "auto_inject_from_environment",
    "resolve_credentials_path",
    "resolve_config_directory",
    "load_environment_credentials",
    "validate_config_setup",
]
