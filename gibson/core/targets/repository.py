"""Target repository for database operations.

Provides data access layer for target management with async SQLAlchemy operations.
"""

import uuid
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from uuid import UUID

from loguru import logger
from sqlalchemy import and_, desc, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from gibson.db import TargetRecord
from gibson.models.target import TargetModel, TargetStatus, TargetType
from gibson.models.domain import AttackDomain


class TargetRepositoryError(Exception):
    """Base exception for target repository operations."""
    pass


class TargetNotFoundError(TargetRepositoryError):
    """Raised when a target is not found."""
    pass


class TargetAlreadyExistsError(TargetRepositoryError):
    """Raised when attempting to create a target that already exists."""
    pass


class TargetRepository:
    """Data access layer for target management.
    
    Provides CRUD operations and queries for targets using async SQLAlchemy.
    Handles conversion between TargetModel (Pydantic) and TargetRecord (SQLAlchemy).
    """
    
    def __init__(self, session: AsyncSession):
        """Initialize repository with database session.
        
        Args:
            session: Async database session
        """
        self.session = session
    
    async def create(self, target: TargetModel) -> TargetModel:
        """Create a new target.
        
        Args:
            target: Target model to create
            
        Returns:
            Created target model with database ID
            
        Raises:
            TargetAlreadyExistsError: If target with same name already exists
            TargetRepositoryError: If database operation fails
        """
        try:
            # Check if target with same name already exists
            existing = await self._get_by_name(target.name)
            if existing:
                raise TargetAlreadyExistsError(f"Target with name '{target.name}' already exists")
            
            # Convert Pydantic model to database record
            record = self._model_to_record(target)
            
            self.session.add(record)
            await self.session.commit()
            await self.session.refresh(record)
            
            # Convert back to Pydantic model
            created_target = self._record_to_model(record)
            
            logger.info(f"Created target: {created_target.name} (ID: {created_target.id})")
            return created_target
            
        except TargetAlreadyExistsError:
            await self.session.rollback()
            raise
        except Exception as e:
            await self.session.rollback()
            logger.error(f"Failed to create target {target.name}: {e}")
            raise TargetRepositoryError(f"Failed to create target: {e}") from e
    
    async def get_by_id(self, target_id: UUID) -> Optional[TargetModel]:
        """Get target by ID.
        
        Args:
            target_id: Target UUID
            
        Returns:
            Target model if found, None otherwise
        """
        try:
            stmt = (
                select(TargetRecord)
                .options(selectinload(TargetRecord.credentials))
                .where(TargetRecord.id == target_id)
            )
            result = await self.session.execute(stmt)
            record = result.scalar_one_or_none()
            
            return self._record_to_model(record) if record else None
            
        except Exception as e:
            logger.error(f"Failed to get target by ID {target_id}: {e}")
            raise TargetRepositoryError(f"Failed to get target: {e}") from e
    
    async def get_by_name(self, name: str) -> Optional[TargetModel]:
        """Get target by name.
        
        Args:
            name: Target name
            
        Returns:
            Target model if found, None otherwise
        """
        return await self._get_by_name(name)
    
    async def _get_by_name(self, name: str) -> Optional[TargetModel]:
        """Internal method to get target by name."""
        try:
            stmt = (
                select(TargetRecord)
                .options(selectinload(TargetRecord.credentials))
                .where(TargetRecord.name == name)
            )
            result = await self.session.execute(stmt)
            record = result.scalar_one_or_none()
            
            return self._record_to_model(record) if record else None
            
        except Exception as e:
            logger.error(f"Failed to get target by name {name}: {e}")
            raise TargetRepositoryError(f"Failed to get target: {e}") from e
    
    async def update(self, target: TargetModel) -> TargetModel:
        """Update an existing target.
        
        Args:
            target: Target model with updates
            
        Returns:
            Updated target model
            
        Raises:
            TargetNotFoundError: If target doesn't exist
            TargetRepositoryError: If database operation fails
        """
        try:
            # Get existing record
            existing_record = await self.session.get(TargetRecord, target.id)
            if not existing_record:
                raise TargetNotFoundError(f"Target with ID {target.id} not found")
            
            # Update fields from model
            self._update_record_from_model(existing_record, target)
            existing_record.updated_at = datetime.utcnow()
            
            await self.session.commit()
            await self.session.refresh(existing_record)
            
            updated_target = self._record_to_model(existing_record)
            
            logger.info(f"Updated target: {updated_target.name} (ID: {updated_target.id})")
            return updated_target
            
        except TargetNotFoundError:
            await self.session.rollback()
            raise
        except Exception as e:
            await self.session.rollback()
            logger.error(f"Failed to update target {target.id}: {e}")
            raise TargetRepositoryError(f"Failed to update target: {e}") from e
    
    async def delete(self, target_id: UUID) -> bool:
        """Delete a target.
        
        Args:
            target_id: Target UUID
            
        Returns:
            True if deleted, False if not found
            
        Raises:
            TargetRepositoryError: If database operation fails
        """
        try:
            record = await self.session.get(TargetRecord, target_id)
            if not record:
                return False
            
            target_name = record.name
            await self.session.delete(record)
            await self.session.commit()
            
            logger.info(f"Deleted target: {target_name} (ID: {target_id})")
            return True
            
        except Exception as e:
            await self.session.rollback()
            logger.error(f"Failed to delete target {target_id}: {e}")
            raise TargetRepositoryError(f"Failed to delete target: {e}") from e
    
    async def list_all(self, 
                      status: Optional[TargetStatus] = None,
                      target_type: Optional[TargetType] = None,
                      environment: Optional[str] = None,
                      enabled_only: bool = False,
                      limit: Optional[int] = None,
                      offset: int = 0) -> List[TargetModel]:
        """List targets with optional filtering.
        
        Args:
            status: Filter by status
            target_type: Filter by target type
            environment: Filter by environment
            enabled_only: Only return enabled targets
            limit: Maximum number of results
            offset: Number of results to skip
            
        Returns:
            List of target models
        """
        try:
            stmt = (
                select(TargetRecord)
                .options(selectinload(TargetRecord.credentials))
                .order_by(desc(TargetRecord.created_at))
            )
            
            # Apply filters
            if status:
                stmt = stmt.where(TargetRecord.status == status.value)
            if target_type:
                stmt = stmt.where(TargetRecord.target_type == target_type.value)
            if environment:
                stmt = stmt.where(TargetRecord.environment == environment)
            if enabled_only:
                stmt = stmt.where(TargetRecord.enabled == True)
            
            # Apply pagination
            if limit:
                stmt = stmt.limit(limit)
            if offset:
                stmt = stmt.offset(offset)
            
            result = await self.session.execute(stmt)
            records = result.scalars().all()
            
            return [self._record_to_model(record) for record in records]
            
        except Exception as e:
            logger.error(f"Failed to list targets: {e}")
            raise TargetRepositoryError(f"Failed to list targets: {e}") from e
    
    async def search(self, 
                    query: str,
                    limit: Optional[int] = None) -> List[TargetModel]:
        """Search targets by name, description, or URL.
        
        Args:
            query: Search query string
            limit: Maximum number of results
            
        Returns:
            List of matching target models
        """
        try:
            search_pattern = f"%{query}%"
            
            stmt = (
                select(TargetRecord)
                .options(selectinload(TargetRecord.credentials))
                .where(
                    or_(
                        TargetRecord.name.ilike(search_pattern),
                        TargetRecord.display_name.ilike(search_pattern),
                        TargetRecord.description.ilike(search_pattern),
                        TargetRecord.base_url.ilike(search_pattern)
                    )
                )
                .order_by(desc(TargetRecord.created_at))
            )
            
            if limit:
                stmt = stmt.limit(limit)
            
            result = await self.session.execute(stmt)
            records = result.scalars().all()
            
            return [self._record_to_model(record) for record in records]
            
        except Exception as e:
            logger.error(f"Failed to search targets with query '{query}': {e}")
            raise TargetRepositoryError(f"Failed to search targets: {e}") from e
    
    async def get_by_tags(self, tags: List[str]) -> List[TargetModel]:
        """Get targets that have any of the specified tags.
        
        Args:
            tags: List of tags to search for
            
        Returns:
            List of matching target models
        """
        try:
            # This is a simplified implementation - for production use,
            # consider using PostgreSQL array operations or a proper tag system
            stmt = (
                select(TargetRecord)
                .options(selectinload(TargetRecord.credentials))
                .order_by(desc(TargetRecord.created_at))
            )
            
            result = await self.session.execute(stmt)
            records = result.scalars().all()
            
            # Filter records that have matching tags
            matching_records = []
            for record in records:
                record_tags = record.tags or []
                if any(tag in record_tags for tag in tags):
                    matching_records.append(record)
            
            return [self._record_to_model(record) for record in matching_records]
            
        except Exception as e:
            logger.error(f"Failed to get targets by tags {tags}: {e}")
            raise TargetRepositoryError(f"Failed to get targets by tags: {e}") from e
    
    async def update_statistics(self, 
                               target_id: UUID,
                               scan_count_increment: int = 0,
                               finding_count_increment: int = 0) -> None:
        """Update target statistics.
        
        Args:
            target_id: Target UUID
            scan_count_increment: Number to add to scan count
            finding_count_increment: Number to add to finding count
        """
        try:
            stmt = (
                update(TargetRecord)
                .where(TargetRecord.id == target_id)
                .values(
                    scan_count=TargetRecord.scan_count + scan_count_increment,
                    finding_count=TargetRecord.finding_count + finding_count_increment,
                    last_scanned=datetime.utcnow() if scan_count_increment > 0 else TargetRecord.last_scanned,
                    updated_at=datetime.utcnow()
                )
            )
            
            await self.session.execute(stmt)
            await self.session.commit()
            
            logger.debug(f"Updated statistics for target {target_id}")
            
        except Exception as e:
            await self.session.rollback()
            logger.error(f"Failed to update statistics for target {target_id}: {e}")
            raise TargetRepositoryError(f"Failed to update statistics: {e}") from e
    
    async def get_statistics(self) -> Dict[str, Any]:
        """Get target statistics summary.
        
        Returns:
            Dictionary with target statistics
        """
        try:
            # Total targets
            total_stmt = select(func.count(TargetRecord.id))
            total_result = await self.session.execute(total_stmt)
            total_targets = total_result.scalar()
            
            # Active targets
            active_stmt = select(func.count(TargetRecord.id)).where(
                TargetRecord.enabled == True,
                TargetRecord.status == TargetStatus.ACTIVE.value
            )
            active_result = await self.session.execute(active_stmt)
            active_targets = active_result.scalar()
            
            # Targets by type
            type_stmt = select(
                TargetRecord.target_type,
                func.count(TargetRecord.id)
            ).group_by(TargetRecord.target_type)
            type_result = await self.session.execute(type_stmt)
            targets_by_type = dict(type_result.all())
            
            # Targets by environment
            env_stmt = select(
                TargetRecord.environment,
                func.count(TargetRecord.id)
            ).group_by(TargetRecord.environment)
            env_result = await self.session.execute(env_stmt)
            targets_by_environment = dict(env_result.all())
            
            return {
                "total_targets": total_targets,
                "active_targets": active_targets,
                "inactive_targets": total_targets - active_targets,
                "targets_by_type": targets_by_type,
                "targets_by_environment": targets_by_environment
            }
            
        except Exception as e:
            logger.error(f"Failed to get target statistics: {e}")
            raise TargetRepositoryError(f"Failed to get statistics: {e}") from e
    
    def _model_to_record(self, target: TargetModel) -> TargetRecord:
        """Convert TargetModel to TargetRecord."""
        return TargetRecord(
            id=target.id,
            name=target.name,
            display_name=target.display_name,
            description=target.description,
            target_type=target.target_type.value,
            base_url=target.base_url,
            status=target.status.value,
            enabled=target.enabled,
            
            # Convert endpoints to JSON
            endpoints=[endpoint.model_dump() for endpoint in target.endpoints],
            
            # Configuration as JSON
            configuration={
                "provider": target.provider.value if target.provider else None,
                "requires_auth": target.requires_auth,
                "proxy_url": target.proxy_url,
                "verify_ssl": target.verify_ssl,
                "follow_redirects": target.follow_redirects,
                "max_redirects": target.max_redirects,
                "global_rate_limit": target.global_rate_limit,
                "concurrent_limit": target.concurrent_limit,
                "request_delay": target.request_delay,
                "scan_timeout": target.scan_timeout,
                "allowed_domains": [domain.value for domain in target.allowed_domains],
                "blocked_modules": target.blocked_modules,
                "default_endpoint": target.default_endpoint,
                "verification_interval": target.verification_interval,
                "metadata": target.metadata
            },
            
            # Organization and metadata
            tags=target.tags,
            environment=target.environment,
            priority=target.priority,
            owner=target.owner,
            contact_email=target.contact_email,
            
            # Compliance and governance
            compliance_requirements=target.compliance_requirements,
            data_classification=target.data_classification,
            requires_approval=target.requires_approval,
            
            # Statistics
            scan_count=target.scan_count,
            finding_count=target.finding_count,
            last_scanned=target.last_scanned,
            last_verified=target.last_verified,
            verification_interval=target.verification_interval,
            
            # Additional metadata
            meta_data=target.metadata
        )
    
    def _record_to_model(self, record: TargetRecord) -> TargetModel:
        """Convert TargetRecord to TargetModel."""
        from gibson.models.target import TargetEndpointModel, LLMProvider
        
        # Parse configuration
        config = record.configuration or {}
        
        # Parse endpoints
        endpoints = []
        if record.endpoints:
            for endpoint_data in record.endpoints:
                endpoints.append(TargetEndpointModel(**endpoint_data))
        
        # Parse allowed domains
        allowed_domains = []
        if config.get("allowed_domains"):
            for domain_str in config["allowed_domains"]:
                try:
                    allowed_domains.append(AttackDomain(domain_str))
                except ValueError:
                    pass  # Skip invalid domains
        
        # Parse provider
        provider = None
        if config.get("provider"):
            try:
                provider = LLMProvider(config["provider"])
            except ValueError:
                pass  # Skip invalid provider
        
        return TargetModel(
            id=record.id,
            name=record.name,
            display_name=record.display_name,
            description=record.description,
            target_type=TargetType(record.target_type),
            base_url=record.base_url,
            status=TargetStatus(record.status),
            enabled=record.enabled,
            
            # Provider configuration
            provider=provider,
            requires_auth=config.get("requires_auth", False),
            
            # Endpoints
            endpoints=endpoints,
            default_endpoint=config.get("default_endpoint"),
            
            # Network configuration
            proxy_url=config.get("proxy_url"),
            verify_ssl=config.get("verify_ssl", True),
            follow_redirects=config.get("follow_redirects", True),
            max_redirects=config.get("max_redirects", 5),
            
            # Rate limiting and throttling
            global_rate_limit=config.get("global_rate_limit"),
            concurrent_limit=config.get("concurrent_limit", 10),
            request_delay=config.get("request_delay", 0.0),
            
            # Scanning configuration
            scan_timeout=config.get("scan_timeout", 3600),
            allowed_domains=allowed_domains,
            blocked_modules=config.get("blocked_modules", []),
            
            # Organization and categorization
            tags=record.tags or [],
            environment=record.environment,
            priority=record.priority,
            owner=record.owner,
            contact_email=record.contact_email,
            
            # Compliance and governance
            compliance_requirements=record.compliance_requirements or [],
            data_classification=record.data_classification,
            requires_approval=record.requires_approval,
            
            # Monitoring and maintenance
            last_scanned=record.last_scanned,
            last_verified=record.last_verified,
            verification_interval=record.verification_interval,
            
            # Statistics
            scan_count=record.scan_count,
            finding_count=record.finding_count,
            last_finding_date=None,  # Would need additional query for this
            
            # Additional metadata
            metadata=config.get("metadata", {}),
            
            # Timestamps
            created_at=record.created_at,
            updated_at=record.updated_at
        )
    
    def _update_record_from_model(self, record: TargetRecord, target: TargetModel) -> None:
        """Update database record fields from model."""
        record.name = target.name
        record.display_name = target.display_name
        record.description = target.description
        record.target_type = target.target_type.value
        record.base_url = target.base_url
        record.status = target.status.value
        record.enabled = target.enabled
        
        # Convert endpoints to JSON
        record.endpoints = [endpoint.model_dump() for endpoint in target.endpoints]
        
        # Update configuration
        record.configuration = {
            "provider": target.provider.value if target.provider else None,
            "requires_auth": target.requires_auth,
            "proxy_url": target.proxy_url,
            "verify_ssl": target.verify_ssl,
            "follow_redirects": target.follow_redirects,
            "max_redirects": target.max_redirects,
            "global_rate_limit": target.global_rate_limit,
            "concurrent_limit": target.concurrent_limit,
            "request_delay": target.request_delay,
            "scan_timeout": target.scan_timeout,
            "allowed_domains": [domain.value for domain in target.allowed_domains],
            "blocked_modules": target.blocked_modules,
            "default_endpoint": target.default_endpoint,
            "verification_interval": target.verification_interval,
            "metadata": target.metadata
        }
        
        # Organization and metadata
        record.tags = target.tags
        record.environment = target.environment
        record.priority = target.priority
        record.owner = target.owner
        record.contact_email = target.contact_email
        
        # Compliance and governance
        record.compliance_requirements = target.compliance_requirements
        record.data_classification = target.data_classification
        record.requires_approval = target.requires_approval
        
        # Statistics (don't overwrite scan counts from model)
        record.last_verified = target.last_verified
        record.verification_interval = target.verification_interval
        
        # Additional metadata
        record.meta_data = target.metadata


# Export repository class
__all__ = [
    'TargetRepository',
    'TargetRepositoryError',
    'TargetNotFoundError', 
    'TargetAlreadyExistsError'
]