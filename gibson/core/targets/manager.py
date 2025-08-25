"""Target management service layer.

Provides high-level target management operations including CRUD,
credential integration, validation, and provider detection.
"""

import asyncio
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from uuid import UUID, uuid4

from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession

from gibson.core.targets.repository import (
    TargetRepository,
    TargetRepositoryError,
    TargetNotFoundError,
    TargetAlreadyExistsError,
)
from gibson.core.targets.litellm_adapter import LiteLLMAdapter
from gibson.core.auth.credential_manager import CredentialManager
from gibson.models.target import (
    TargetModel,
    TargetType,
    TargetStatus,
    LLMProvider,
    TargetEndpointModel,
    AuthenticationType,
)
from gibson.models.auth import ApiKeyCredentialModel, ApiKeyFormat, ValidationStatus
from gibson.models.domain import AttackDomain


class TargetManagerError(Exception):
    """Base exception for target manager operations."""

    pass


class TargetValidationError(TargetManagerError):
    """Raised when target validation fails."""

    pass


class TargetManager:
    """High-level target management service.

    Orchestrates target operations including database persistence,
    credential management, provider detection, and validation.
    """

    def __init__(
        self,
        session: AsyncSession,
        credential_manager: Optional[CredentialManager] = None,
        litellm_adapter: Optional[LiteLLMAdapter] = None,
    ):
        """Initialize target manager.

        Args:
            session: Async database session
            credential_manager: Optional credential manager instance
            litellm_adapter: Optional LiteLLM adapter instance
        """
        self.repository = TargetRepository(session)
        self.credential_manager = credential_manager or CredentialManager()
        self.litellm_adapter = litellm_adapter or LiteLLMAdapter()
        self.session = session

    async def create_target(
        self,
        name: str,
        base_url: str,
        target_type: Union[str, TargetType] = TargetType.API,
        display_name: Optional[str] = None,
        description: Optional[str] = None,
        api_key: Optional[str] = None,
        key_format: Union[str, ApiKeyFormat] = ApiKeyFormat.BEARER_TOKEN,
        provider_hint: Optional[Union[str, LLMProvider]] = None,
        **kwargs,
    ) -> TargetModel:
        """Create a new target with automatic provider detection.

        Args:
            name: Unique target name
            base_url: Target base URL
            target_type: Type of target system
            display_name: Human-readable display name
            description: Target description
            api_key: Optional API key for authentication
            key_format: API key format
            provider_hint: Optional provider hint
            **kwargs: Additional target configuration

        Returns:
            Created target model

        Raises:
            TargetAlreadyExistsError: If target with same name exists
            TargetValidationError: If target configuration is invalid
            TargetManagerError: If creation fails
        """
        try:
            # Convert string enums to enum types
            if isinstance(target_type, str):
                target_type = TargetType(target_type)
            if isinstance(key_format, str):
                key_format = ApiKeyFormat(key_format)
            if isinstance(provider_hint, str):
                provider_hint = LLMProvider(provider_hint)

            # Auto-detect provider if not provided
            detected_provider = provider_hint or self.litellm_adapter.auto_detect_provider(base_url)

            # Create target model with auto-generated ID
            target = TargetModel(
                id=uuid4(),
                name=name,
                display_name=display_name or name,
                description=description,
                target_type=target_type,
                base_url=base_url,
                status=TargetStatus.PENDING_VERIFICATION,
                provider=detected_provider,
                requires_auth=api_key is not None,
                **kwargs,
            )

            # Validate target configuration
            await self._validate_target(target)

            # Create target in database
            created_target = await self.repository.create(target)

            # Store API key if provided
            if api_key:
                await self._store_credential(
                    target_id=created_target.id,
                    api_key=api_key,
                    key_format=key_format,
                    provider=detected_provider,
                )

            logger.info(
                f"Created target '{name}' with provider {detected_provider.value if detected_provider else 'auto-detect'}"
            )
            return created_target

        except (TargetAlreadyExistsError, TargetValidationError):
            raise
        except Exception as e:
            import traceback

            logger.error(f"Failed to create target '{name}': {e}\n{traceback.format_exc()}")
            raise TargetManagerError(f"Failed to create target: {e}") from e

    async def get_target(self, identifier: Union[str, UUID]) -> Optional[TargetModel]:
        """Get target by ID or name.

        Args:
            identifier: Target ID (UUID) or name (string)

        Returns:
            Target model if found, None otherwise
        """
        try:
            if isinstance(identifier, UUID):
                return await self.repository.get_by_id(identifier)
            elif isinstance(identifier, str):
                # Try to parse as UUID first
                try:
                    uuid_id = UUID(identifier)
                    return await self.repository.get_by_id(uuid_id)
                except ValueError:
                    # Not a UUID, search by name
                    return await self.repository.get_by_name(identifier)
            else:
                raise ValueError(f"Invalid identifier type: {type(identifier)}")

        except Exception as e:
            logger.error(f"Failed to get target '{identifier}': {e}")
            raise TargetManagerError(f"Failed to get target: {e}") from e

    async def update_target(self, target: TargetModel, **updates) -> TargetModel:
        """Update an existing target.

        Args:
            target: Target model to update
            **updates: Fields to update

        Returns:
            Updated target model

        Raises:
            TargetNotFoundError: If target doesn't exist
            TargetValidationError: If updated configuration is invalid
            TargetManagerError: If update fails
        """
        try:
            # Apply updates to target model
            for field, value in updates.items():
                if hasattr(target, field):
                    setattr(target, field, value)
                else:
                    logger.warning(f"Ignoring unknown field: {field}")

            # Re-detect provider if base_url changed
            if "base_url" in updates:
                target.provider = self.litellm_adapter.auto_detect_provider(target.base_url)

            # Validate updated configuration
            await self._validate_target(target)

            # Update in database
            updated_target = await self.repository.update(target)

            logger.info(f"Updated target '{target.name}' (ID: {target.id})")
            return updated_target

        except (TargetNotFoundError, TargetValidationError):
            raise
        except Exception as e:
            logger.error(f"Failed to update target {target.id}: {e}")
            raise TargetManagerError(f"Failed to update target: {e}") from e

    async def delete_target(self, identifier: Union[str, UUID]) -> bool:
        """Delete a target and its associated credentials.

        Args:
            identifier: Target ID or name

        Returns:
            True if deleted, False if not found

        Raises:
            TargetManagerError: If deletion fails
        """
        try:
            # Get target to ensure it exists and get ID
            target = await self.get_target(identifier)
            if not target:
                return False

            # Delete associated credentials first
            try:
                self.credential_manager.delete_credential(target.id)
            except Exception as e:
                logger.warning(f"Failed to delete credentials for target {target.id}: {e}")

            # Delete target from database
            success = await self.repository.delete(target.id)

            if success:
                logger.info(f"Deleted target '{target.name}' (ID: {target.id})")

            return success

        except Exception as e:
            logger.error(f"Failed to delete target '{identifier}': {e}")
            raise TargetManagerError(f"Failed to delete target: {e}") from e

    async def list_targets(
        self,
        status: Optional[TargetStatus] = None,
        target_type: Optional[TargetType] = None,
        environment: Optional[str] = None,
        enabled_only: bool = False,
        with_credentials: bool = False,
        limit: Optional[int] = None,
        offset: int = 0,
    ) -> List[TargetModel]:
        """List targets with optional filtering.

        Args:
            status: Filter by status
            target_type: Filter by target type
            environment: Filter by environment
            enabled_only: Only return enabled targets
            with_credentials: Include credential status information
            limit: Maximum number of results
            offset: Number of results to skip

        Returns:
            List of target models
        """
        try:
            targets = await self.repository.list_all(
                status=status,
                provider=None,  # Could add provider filter if needed
                environment=environment,
                enabled_only=enabled_only,
                limit=limit,
                offset=offset,
            )

            # Add credential information if requested
            if with_credentials:
                for target in targets:
                    auth_status = target.get_authentication_status(self.credential_manager)
                    # Add credential info to metadata for display
                    target.metadata["has_credential"] = auth_status.get("has_credential", False)
                    target.metadata["credential_status"] = auth_status.get(
                        "validation_status", "unknown"
                    )

            return targets

        except Exception as e:
            logger.error(f"Failed to list targets: {e}")
            raise TargetManagerError(f"Failed to list targets: {e}") from e

    async def search_targets(self, query: str, limit: Optional[int] = None) -> List[TargetModel]:
        """Search targets by name, description, or URL.

        Args:
            query: Search query
            limit: Maximum number of results

        Returns:
            List of matching target models
        """
        try:
            return await self.repository.search(query, limit)

        except Exception as e:
            logger.error(f"Failed to search targets with query '{query}': {e}")
            raise TargetManagerError(f"Failed to search targets: {e}") from e

    async def validate_target(
        self,
        identifier: Union[str, UUID],
        test_connection: bool = True,
        validate_credentials: bool = True,
    ) -> Dict[str, Any]:
        """Validate target configuration and connectivity.

        Args:
            identifier: Target ID or name
            test_connection: Whether to test network connectivity
            validate_credentials: Whether to validate authentication

        Returns:
            Validation results dictionary

        Raises:
            TargetNotFoundError: If target doesn't exist
            TargetManagerError: If validation fails
        """
        try:
            target = await self.get_target(identifier)
            if not target:
                raise TargetNotFoundError(f"Target not found: {identifier}")

            results = {
                "target_id": str(target.id),
                "target_name": target.name,
                "validation_timestamp": datetime.utcnow().isoformat(),
                "config_valid": True,
                "config_errors": [],
                "connectivity_valid": None,
                "connectivity_errors": [],
                "credentials_valid": None,
                "credentials_errors": [],
                "overall_valid": False,
            }

            # Validate configuration
            try:
                await self._validate_target(target)
            except TargetValidationError as e:
                results["config_valid"] = False
                results["config_errors"] = [str(e)]

            # Test connectivity if requested
            if test_connection:
                try:
                    connectivity_result = await self._test_connectivity(target)
                    results["connectivity_valid"] = connectivity_result["success"]
                    if not connectivity_result["success"]:
                        results["connectivity_errors"] = [
                            connectivity_result.get("error", "Connection failed")
                        ]
                except Exception as e:
                    results["connectivity_valid"] = False
                    results["connectivity_errors"] = [str(e)]

            # Validate credentials if requested
            if validate_credentials and target.requires_auth:
                try:
                    cred_result = await target.validate_authentication()
                    results["credentials_valid"] = cred_result.get("is_valid", False)
                    if not cred_result.get("is_valid"):
                        results["credentials_errors"] = [
                            cred_result.get("error_message", "Credential validation failed")
                        ]
                except Exception as e:
                    results["credentials_valid"] = False
                    results["credentials_errors"] = [str(e)]

            # Determine overall validity
            results["overall_valid"] = (
                results["config_valid"]
                and (results["connectivity_valid"] is None or results["connectivity_valid"])
                and (results["credentials_valid"] is None or results["credentials_valid"])
            )

            # Update target status based on validation
            if results["overall_valid"]:
                target.status = TargetStatus.ACTIVE
                target.mark_verified(success=True)
            else:
                target.status = TargetStatus.VERIFICATION_FAILED
                target.mark_verified(success=False)

            await self.repository.update(target)

            return results

        except TargetNotFoundError:
            raise
        except Exception as e:
            logger.error(f"Failed to validate target '{identifier}': {e}")
            raise TargetManagerError(f"Failed to validate target: {e}") from e

    async def set_target_credential(
        self,
        identifier: Union[str, UUID],
        api_key: str,
        key_format: Union[str, ApiKeyFormat] = ApiKeyFormat.BEARER_TOKEN,
        validate: bool = True,
    ) -> bool:
        """Set or update API key for target.

        Args:
            identifier: Target ID or name
            api_key: API key value
            key_format: Key format
            validate: Whether to validate the credential

        Returns:
            True if successful

        Raises:
            TargetNotFoundError: If target doesn't exist
            TargetManagerError: If credential storage fails
        """
        try:
            target = await self.get_target(identifier)
            if not target:
                raise TargetNotFoundError(f"Target not found: {identifier}")

            if isinstance(key_format, str):
                key_format = ApiKeyFormat(key_format)

            success = await self._store_credential(
                target_id=target.id,
                api_key=api_key,
                key_format=key_format,
                provider=target.provider or LLMProvider.LITELLM,
            )

            if success:
                # Update target to indicate it requires auth
                target.requires_auth = True
                await self.repository.update(target)

                # Validate credential if requested
                if validate:
                    try:
                        validation_result = await target.validate_authentication()
                        if validation_result.get("is_valid"):
                            logger.info(f"Credential validated for target '{target.name}'")
                        else:
                            logger.warning(
                                f"Credential validation failed for target '{target.name}': {validation_result.get('error_message')}"
                            )
                    except Exception as e:
                        logger.warning(
                            f"Failed to validate credential for target '{target.name}': {e}"
                        )

                logger.info(f"Set credential for target '{target.name}' (ID: {target.id})")

            return success

        except TargetNotFoundError:
            raise
        except Exception as e:
            logger.error(f"Failed to set credential for target '{identifier}': {e}")
            raise TargetManagerError(f"Failed to set credential: {e}") from e

    async def remove_target_credential(self, identifier: Union[str, UUID]) -> bool:
        """Remove API key for target.

        Args:
            identifier: Target ID or name

        Returns:
            True if successful

        Raises:
            TargetNotFoundError: If target doesn't exist
            TargetManagerError: If credential removal fails
        """
        try:
            target = await self.get_target(identifier)
            if not target:
                raise TargetNotFoundError(f"Target not found: {identifier}")

            success = self.credential_manager.delete_credential(target.id)

            if success:
                # Update target to indicate it no longer requires auth
                target.requires_auth = False
                await self.repository.update(target)

                logger.info(f"Removed credential for target '{target.name}' (ID: {target.id})")

            return success

        except TargetNotFoundError:
            raise
        except Exception as e:
            logger.error(f"Failed to remove credential for target '{identifier}': {e}")
            raise TargetManagerError(f"Failed to remove credential: {e}") from e

    async def export_targets(
        self,
        file_path: Union[str, Path],
        include_credentials: bool = False,
        filter_kwargs: Optional[Dict] = None,
    ) -> int:
        """Export targets to JSON file.

        Args:
            file_path: Output file path
            include_credentials: Whether to include credential information
            filter_kwargs: Optional filters for target selection

        Returns:
            Number of targets exported

        Raises:
            TargetManagerError: If export fails
        """
        try:
            # Get targets to export
            filter_kwargs = filter_kwargs or {}
            targets = await self.list_targets(**filter_kwargs)

            # Convert to export format
            export_data = {
                "export_timestamp": datetime.utcnow().isoformat(),
                "gibson_version": "1.0.0",  # Would get from package metadata
                "targets": [],
            }

            for target in targets:
                target_data = target.model_dump()

                # Add credential information if requested
                if include_credentials:
                    auth_status = target.get_authentication_status(self.credential_manager)
                    target_data["credential_info"] = {
                        "has_credential": auth_status.get("has_credential", False),
                        "validation_status": auth_status.get("validation_status", "unknown"),
                        "key_format": auth_status.get("key_format"),
                        "last_validated": auth_status.get("last_validated"),
                    }

                    # Note: We don't export actual API keys for security

                export_data["targets"].append(target_data)

            # Write to file
            output_path = Path(file_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            with open(output_path, "w") as f:
                json.dump(export_data, f, indent=2, default=str)

            logger.info(f"Exported {len(targets)} targets to {output_path}")
            return len(targets)

        except Exception as e:
            logger.error(f"Failed to export targets: {e}")
            raise TargetManagerError(f"Failed to export targets: {e}") from e

    async def import_targets(
        self,
        file_path: Union[str, Path],
        update_existing: bool = False,
        skip_credentials: bool = True,
    ) -> Dict[str, int]:
        """Import targets from JSON file.

        Args:
            file_path: Input file path
            update_existing: Whether to update existing targets
            skip_credentials: Whether to skip credential information

        Returns:
            Dictionary with import statistics

        Raises:
            TargetManagerError: If import fails
        """
        try:
            input_path = Path(file_path)
            if not input_path.exists():
                raise FileNotFoundError(f"Import file not found: {input_path}")

            with open(input_path, "r") as f:
                import_data = json.load(f)

            if "targets" not in import_data:
                raise ValueError("Invalid import file format: missing 'targets' field")

            stats = {
                "total": len(import_data["targets"]),
                "created": 0,
                "updated": 0,
                "skipped": 0,
                "errors": 0,
            }

            for target_data in import_data["targets"]:
                try:
                    # Remove non-model fields
                    target_data.pop("credential_info", None)

                    # Create target model
                    target = TargetModel(**target_data)

                    # Check if target exists
                    existing = await self.get_target(target.name)

                    if existing:
                        if update_existing:
                            # Update existing target
                            await self.update_target(existing, **target_data)
                            stats["updated"] += 1
                            logger.info(f"Updated target: {target.name}")
                        else:
                            stats["skipped"] += 1
                            logger.info(f"Skipped existing target: {target.name}")
                    else:
                        # Create new target
                        await self.repository.create(target)
                        stats["created"] += 1
                        logger.info(f"Created target: {target.name}")

                except Exception as e:
                    stats["errors"] += 1
                    logger.error(f"Failed to import target: {e}")

            logger.info(f"Import completed: {stats}")
            return stats

        except Exception as e:
            logger.error(f"Failed to import targets: {e}")
            raise TargetManagerError(f"Failed to import targets: {e}") from e

    async def get_statistics(self) -> Dict[str, Any]:
        """Get target management statistics.

        Returns:
            Dictionary with statistics
        """
        try:
            return await self.repository.get_statistics()

        except Exception as e:
            logger.error(f"Failed to get statistics: {e}")
            raise TargetManagerError(f"Failed to get statistics: {e}") from e

    async def _validate_target(self, target: TargetModel) -> None:
        """Validate target configuration.

        Args:
            target: Target model to validate

        Raises:
            TargetValidationError: If validation fails
        """
        errors = []

        # Basic validation
        if not target.name or not target.name.strip():
            errors.append("Target name is required")

        if not target.base_url or not target.base_url.strip():
            errors.append("Base URL is required")

        # URL format validation
        if target.base_url:
            try:
                from urllib.parse import urlparse

                parsed = urlparse(target.base_url)
                if not parsed.scheme or not parsed.netloc:
                    errors.append("Invalid URL format")
            except Exception:
                errors.append("Invalid URL format")

        # Provider-specific validation
        if target.provider:
            provider_config = self.litellm_adapter.get_provider_config(
                provider=target.provider, base_url=target.base_url, model_hint=None
            )

            is_valid, config_errors = self.litellm_adapter.validate_provider_config(
                provider=target.provider, config=provider_config
            )

            if not is_valid:
                errors.extend(config_errors)

        if errors:
            raise TargetValidationError("; ".join(errors))

    async def _test_connectivity(self, target: TargetModel) -> Dict[str, Any]:
        """Test network connectivity to target.

        Args:
            target: Target model to test

        Returns:
            Connectivity test results
        """
        import aiohttp
        import asyncio

        try:
            timeout = aiohttp.ClientTimeout(total=10)

            async with aiohttp.ClientSession(timeout=timeout) as session:
                start_time = datetime.utcnow()

                # Test basic connectivity with HEAD request
                async with session.head(
                    target.base_url, ssl=target.verify_ssl, allow_redirects=target.follow_redirects
                ) as response:
                    end_time = datetime.utcnow()
                    response_time = (end_time - start_time).total_seconds() * 1000

                    return {
                        "success": True,
                        "status_code": response.status,
                        "response_time_ms": response_time,
                        "headers": dict(response.headers),
                    }

        except asyncio.TimeoutError:
            return {"success": False, "error": "Connection timeout", "error_type": "timeout"}
        except Exception as e:
            return {"success": False, "error": str(e), "error_type": type(e).__name__}

    async def _store_credential(
        self, target_id: UUID, api_key: str, key_format: ApiKeyFormat, provider: LLMProvider
    ) -> bool:
        """Store credential for target.

        Args:
            target_id: Target ID
            api_key: API key value
            key_format: Key format
            provider: LLM provider

        Returns:
            True if successful
        """
        try:
            credential = ApiKeyCredentialModel(
                target_id=target_id,
                auth_type=AuthenticationType.API_KEY,
                token=api_key,
                key_format=key_format,
                validation_status=ValidationStatus.UNTESTED,
                description=f"API key for target {target_id}",
            )

            return self.credential_manager.store_credential(
                target_id=target_id, credential=credential, target_name=str(target_id)
            )

        except Exception as e:
            logger.error(f"Failed to store credential for target {target_id}: {e}")
            return False


# Export manager class
__all__ = ["TargetManager", "TargetManagerError", "TargetValidationError"]
