"""
Target repository for data access operations.

Handles all database operations for targets.
"""

import json
from datetime import datetime
from typing import List, Optional, Dict, Any
from uuid import UUID

from sqlalchemy import select, update, delete, and_, or_, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError
from loguru import logger

from gibson.db.models.target import Target as TargetRecord
from gibson.models.target import (
    TargetModel,
    TargetType,
    TargetStatus,
    LLMProvider,
    TargetEndpointModel,
)


class TargetRepositoryError(Exception):
    """Base exception for target repository errors."""

    pass


class TargetNotFoundError(TargetRepositoryError):
    """Raised when target is not found."""

    pass


class TargetAlreadyExistsError(TargetRepositoryError):
    """Raised when target already exists."""

    pass


class TargetRepository:
    """Repository for target data access."""

    def __init__(self, session: AsyncSession):
        """Initialize repository.

        Args:
            session: Async database session
        """
        self.session = session

    async def create(self, target: TargetModel) -> TargetModel:
        """Create a new target.

        Args:
            target: Target model to create

        Returns:
            Created target model

        Raises:
            TargetAlreadyExistsError: If target with same name exists
        """
        try:
            # Convert endpoints and metadata to JSON
            config_json = {
                "endpoints": [ep.model_dump() for ep in target.endpoints],
                "tags": target.tags,
                "environment": target.environment,
                "priority": target.priority,
                "compliance_requirements": target.compliance_requirements,
                "requires_approval": target.requires_approval,
                "metadata": target.metadata,
            }

            # Create database record
            record = TargetRecord(
                id=str(target.id),
                name=target.name,
                display_name=target.display_name,
                description=target.description,
                target_type=target.target_type,
                base_url=target.base_url,
                provider=target.provider,
                status=target.status,
                enabled=target.enabled,
                requires_auth=target.requires_auth,
                scan_count=target.scan_count,
                finding_count=target.finding_count,
                config_json=config_json,
            )

            self.session.add(record)
            await self.session.commit()
            await self.session.refresh(record)

            # Convert back to model
            return self._record_to_model(record)

        except IntegrityError as e:
            await self.session.rollback()
            if "unique" in str(e).lower():
                raise TargetAlreadyExistsError(f"Target with name '{target.name}' already exists")
            raise TargetRepositoryError(f"Database error: {e}")
        except Exception as e:
            await self.session.rollback()
            logger.error(f"Failed to create target: {e}")
            raise TargetRepositoryError(f"Failed to create target: {e}")

    async def get_by_id(self, target_id: UUID) -> Optional[TargetModel]:
        """Get target by ID.

        Args:
            target_id: Target UUID

        Returns:
            Target model or None if not found
        """
        try:
            stmt = select(TargetRecord).where(TargetRecord.id == str(target_id))
            result = await self.session.execute(stmt)
            record = result.scalar_one_or_none()

            if record:
                return self._record_to_model(record)
            return None

        except Exception as e:
            logger.error(f"Failed to get target by ID: {e}")
            return None

    async def get_by_name(self, name: str) -> Optional[TargetModel]:
        """Get target by name.

        Args:
            name: Target name

        Returns:
            Target model or None if not found
        """
        try:
            stmt = select(TargetRecord).where(TargetRecord.name == name)
            result = await self.session.execute(stmt)
            record = result.scalar_one_or_none()

            if record:
                return self._record_to_model(record)
            return None

        except Exception as e:
            logger.error(f"Failed to get target by name: {e}")
            return None

    async def update(self, target: TargetModel) -> TargetModel:
        """Update existing target.

        Args:
            target: Target model with updates

        Returns:
            Updated target model

        Raises:
            TargetNotFoundError: If target doesn't exist
        """
        try:
            # Check if target exists
            stmt = select(TargetRecord).where(TargetRecord.id == str(target.id))
            result = await self.session.execute(stmt)
            record = result.scalar_one_or_none()

            if not record:
                raise TargetNotFoundError(f"Target with ID {target.id} not found")

            # Update fields
            record.name = target.name
            record.display_name = target.display_name
            record.description = target.description
            record.target_type = target.target_type
            record.base_url = target.base_url
            record.provider = target.provider
            record.status = target.status
            record.enabled = target.enabled
            record.requires_auth = target.requires_auth
            record.scan_count = target.scan_count
            record.finding_count = target.finding_count
            record.last_scanned = target.last_scanned
            record.last_validated = target.last_verified
            record.updated_at = datetime.utcnow()

            # Update config JSON
            config_json = {
                "endpoints": [ep.model_dump() for ep in target.endpoints],
                "tags": target.tags,
                "environment": target.environment,
                "priority": target.priority,
                "compliance_requirements": target.compliance_requirements,
                "requires_approval": target.requires_approval,
                "metadata": target.metadata,
            }
            record.config_json = config_json

            await self.session.commit()
            await self.session.refresh(record)

            return self._record_to_model(record)

        except TargetNotFoundError:
            raise
        except Exception as e:
            await self.session.rollback()
            logger.error(f"Failed to update target: {e}")
            raise TargetRepositoryError(f"Failed to update target: {e}")

    async def delete(self, target_id: UUID) -> bool:
        """Delete target.

        Args:
            target_id: Target UUID

        Returns:
            True if deleted, False if not found
        """
        try:
            stmt = delete(TargetRecord).where(TargetRecord.id == str(target_id))
            result = await self.session.execute(stmt)
            await self.session.commit()

            return result.rowcount > 0

        except Exception as e:
            await self.session.rollback()
            logger.error(f"Failed to delete target: {e}")
            return False

    async def list_all(
        self,
        status: Optional[TargetStatus] = None,
        provider: Optional[LLMProvider] = None,
        environment: Optional[str] = None,
        enabled_only: bool = False,
        limit: Optional[int] = None,
        offset: int = 0,
    ) -> List[TargetModel]:
        """List all targets with optional filters.

        Args:
            status: Filter by status
            provider: Filter by provider
            environment: Filter by environment
            enabled_only: Only return enabled targets
            limit: Maximum number of results
            offset: Number of results to skip

        Returns:
            List of target models
        """
        try:
            stmt = select(TargetRecord)

            # Apply filters
            conditions = []
            if status:
                conditions.append(TargetRecord.status == status)
            if provider:
                conditions.append(TargetRecord.provider == provider)
            if enabled_only:
                conditions.append(TargetRecord.enabled == True)

            if conditions:
                stmt = stmt.where(and_(*conditions))

            # Apply environment filter through JSON
            if environment:
                stmt = stmt.where(TargetRecord.config_json["environment"].astext == environment)

            # Apply pagination
            stmt = stmt.offset(offset)
            if limit:
                stmt = stmt.limit(limit)

            # Order by name
            stmt = stmt.order_by(TargetRecord.name)

            result = await self.session.execute(stmt)
            records = result.scalars().all()

            return [self._record_to_model(record) for record in records]

        except Exception as e:
            logger.error(f"Failed to list targets: {e}")
            return []

    async def search(self, query: str, limit: Optional[int] = None) -> List[TargetModel]:
        """Search targets by name, description, or URL.

        Args:
            query: Search query
            limit: Maximum number of results

        Returns:
            List of matching target models
        """
        try:
            # Case-insensitive search
            search_pattern = f"%{query}%"

            stmt = select(TargetRecord).where(
                or_(
                    TargetRecord.name.ilike(search_pattern),
                    TargetRecord.display_name.ilike(search_pattern),
                    TargetRecord.description.ilike(search_pattern),
                    TargetRecord.base_url.ilike(search_pattern),
                )
            )

            if limit:
                stmt = stmt.limit(limit)

            stmt = stmt.order_by(TargetRecord.name)

            result = await self.session.execute(stmt)
            records = result.scalars().all()

            return [self._record_to_model(record) for record in records]

        except Exception as e:
            logger.error(f"Failed to search targets: {e}")
            return []

    async def get_by_tags(self, tags: List[str]) -> List[TargetModel]:
        """Get targets by tags.

        Args:
            tags: List of tags to match

        Returns:
            List of target models with matching tags
        """
        try:
            # Search for targets where config_json['tags'] contains any of the provided tags
            conditions = []
            for tag in tags:
                conditions.append(
                    func.json_contains(TargetRecord.config_json["tags"], json.dumps(tag))
                )

            stmt = select(TargetRecord)
            if conditions:
                stmt = stmt.where(or_(*conditions))

            result = await self.session.execute(stmt)
            records = result.scalars().all()

            return [self._record_to_model(record) for record in records]

        except Exception as e:
            logger.error(f"Failed to get targets by tags: {e}")
            return []

    async def update_statistics(
        self, target_id: UUID, scan_count_increment: int = 0, finding_count_increment: int = 0
    ) -> bool:
        """Update target statistics.

        Args:
            target_id: Target UUID
            scan_count_increment: Amount to increment scan count
            finding_count_increment: Amount to increment finding count

        Returns:
            True if updated successfully
        """
        try:
            stmt = (
                update(TargetRecord)
                .where(TargetRecord.id == str(target_id))
                .values(
                    scan_count=TargetRecord.scan_count + scan_count_increment,
                    finding_count=TargetRecord.finding_count + finding_count_increment,
                    last_scanned=datetime.utcnow()
                    if scan_count_increment > 0
                    else TargetRecord.last_scanned,
                    updated_at=datetime.utcnow(),
                )
            )

            result = await self.session.execute(stmt)
            await self.session.commit()

            return result.rowcount > 0

        except Exception as e:
            await self.session.rollback()
            logger.error(f"Failed to update statistics: {e}")
            return False

    async def get_statistics(self) -> Dict[str, Any]:
        """Get repository statistics.

        Returns:
            Dictionary with statistics
        """
        try:
            # Total targets
            total_stmt = select(func.count(TargetRecord.id))
            total_result = await self.session.execute(total_stmt)
            total_targets = total_result.scalar() or 0

            # Active targets
            active_stmt = select(func.count(TargetRecord.id)).where(
                TargetRecord.status == TargetStatus.ACTIVE
            )
            active_result = await self.session.execute(active_stmt)
            active_targets = active_result.scalar() or 0

            # Inactive targets
            inactive_stmt = select(func.count(TargetRecord.id)).where(
                TargetRecord.status == TargetStatus.INACTIVE
            )
            inactive_result = await self.session.execute(inactive_stmt)
            inactive_targets = inactive_result.scalar() or 0

            # Targets by type
            type_stmt = select(TargetRecord.target_type, func.count(TargetRecord.id)).group_by(
                TargetRecord.target_type
            )
            type_result = await self.session.execute(type_stmt)
            targets_by_type = {
                str(row[0].value if hasattr(row[0], "value") else row[0] or "unknown"): row[1]
                for row in type_result
            }

            # Targets by provider
            provider_stmt = select(TargetRecord.provider, func.count(TargetRecord.id)).group_by(
                TargetRecord.provider
            )
            provider_result = await self.session.execute(provider_stmt)
            targets_by_provider = {
                str(row[0].value if hasattr(row[0], "value") else row[0] or "unknown"): row[1]
                for row in provider_result
            }

            # Get targets by environment (from JSON)
            all_targets = await self.list_all()
            targets_by_environment = {}
            for target in all_targets:
                env = target.environment
                targets_by_environment[env] = targets_by_environment.get(env, 0) + 1

            return {
                "total_targets": total_targets,
                "active_targets": active_targets,
                "inactive_targets": inactive_targets,
                "targets_by_type": targets_by_type,
                "targets_by_provider": targets_by_provider,
                "targets_by_environment": targets_by_environment,
                "timestamp": datetime.utcnow().isoformat(),
            }

        except Exception as e:
            logger.error(f"Failed to get statistics: {e}")
            return {"total_targets": 0, "error": str(e)}

    def _record_to_model(self, record: TargetRecord) -> TargetModel:
        """Convert database record to model.

        Args:
            record: Database record

        Returns:
            Target model
        """
        # Extract config from JSON
        config = record.config_json or {}

        # Convert endpoints
        endpoints = []
        for ep_data in config.get("endpoints", []):
            endpoints.append(TargetEndpointModel(**ep_data))

        # Create model
        return TargetModel(
            id=UUID(record.id),
            name=record.name,
            display_name=record.display_name,
            description=record.description,
            target_type=record.target_type,
            base_url=record.base_url,
            provider=record.provider,
            status=record.status,
            enabled=record.enabled,
            requires_auth=record.requires_auth,
            endpoints=endpoints,
            tags=config.get("tags", []),
            environment=config.get("environment", "production"),
            priority=config.get("priority", 3),
            compliance_requirements=config.get("compliance_requirements", []),
            requires_approval=config.get("requires_approval", False),
            metadata=config.get("metadata", {}),
            scan_count=record.scan_count,
            finding_count=record.finding_count,
            last_scanned=record.last_scanned,
            last_verified=record.last_validated,
        )
