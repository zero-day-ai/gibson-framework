"""Repository for Target model with specialized operations."""

from typing import List, Optional, Dict, Any
from datetime import datetime
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import and_, or_, func

from gibson.db.base import BaseDBModel
from gibson.db.models.target import Target
from gibson.db.repositories.base import BaseRepository
from gibson.models.target import TargetType, TargetStatus, LLMProvider


class TargetRepository(BaseRepository[Target]):
    """Repository for Target model with enhanced features."""
    
    def __init__(self, session: AsyncSession):
        """Initialize target repository.
        
        Args:
            session: Async database session
        """
        super().__init__(Target, session)
    
    async def get_by_name(self, name: str) -> Optional[Target]:
        """Get target by name.
        
        Args:
            name: Target name
            
        Returns:
            Target or None
        """
        return await self.find_one({'name': name})
    
    async def get_active_targets(
        self,
        target_type: Optional[TargetType] = None,
        provider: Optional[LLMProvider] = None
    ) -> List[Target]:
        """Get all active targets with optional filtering.
        
        Args:
            target_type: Optional target type filter
            provider: Optional provider filter
            
        Returns:
            List of active targets
        """
        query = select(Target).where(
            and_(
                Target.enabled == True,
                Target.status == TargetStatus.ACTIVE,
                Target.is_deleted == False
            )
        )
        
        if target_type:
            query = query.where(Target.target_type == target_type)
        
        if provider:
            query = query.where(Target.provider == provider)
        
        result = await self.session.execute(query)
        return list(result.scalars().all())
    
    async def get_targets_for_scanning(
        self,
        limit: int = 10,
        min_interval_hours: int = 24
    ) -> List[Target]:
        """Get targets that are due for scanning.
        
        Args:
            limit: Maximum number of targets to return
            min_interval_hours: Minimum hours since last scan
            
        Returns:
            List of targets ready for scanning
        """
        cutoff_time = datetime.utcnow()
        cutoff_time = cutoff_time.replace(
            hour=cutoff_time.hour - min_interval_hours
        )
        
        query = select(Target).where(
            and_(
                Target.enabled == True,
                Target.status == TargetStatus.ACTIVE,
                Target.is_deleted == False,
                or_(
                    Target.last_scanned == None,
                    Target.last_scanned < cutoff_time
                )
            )
        ).order_by(
            Target.last_scanned.asc().nullsfirst()
        ).limit(limit)
        
        result = await self.session.execute(query)
        return list(result.scalars().all())
    
    async def get_pending_verification(self) -> List[Target]:
        """Get targets pending verification.
        
        Returns:
            List of targets pending verification
        """
        return await self.list(
            filters={'status': TargetStatus.PENDING_VERIFICATION}
        )
    
    async def mark_validated(
        self,
        target_id: UUID,
        validated_by: Optional[str] = None
    ) -> Optional[Target]:
        """Mark target as validated.
        
        Args:
            target_id: Target ID
            validated_by: User who validated
            
        Returns:
            Updated target or None
        """
        target = await self.get(target_id)
        if not target:
            return None
        
        target.validate_target()
        
        return await self.update(
            target_id,
            {
                'last_validated': target.last_validated,
                'status': target.status
            },
            updated_by=validated_by
        )
    
    async def increment_scan_stats(
        self,
        target_id: UUID,
        finding_count: int = 0,
        scanned_by: Optional[str] = None
    ) -> Optional[Target]:
        """Increment scan statistics for target.
        
        Args:
            target_id: Target ID
            finding_count: Number of findings to add
            scanned_by: User who performed scan
            
        Returns:
            Updated target or None
        """
        target = await self.get(target_id)
        if not target:
            return None
        
        target.increment_scan_count()
        if finding_count > 0:
            target.increment_finding_count(finding_count)
        
        return await self.update(
            target_id,
            {
                'scan_count': target.scan_count,
                'finding_count': target.finding_count,
                'last_scanned': target.last_scanned
            },
            updated_by=scanned_by
        )
    
    async def bulk_enable(
        self,
        target_ids: List[UUID],
        enabled_by: Optional[str] = None
    ) -> int:
        """Enable multiple targets.
        
        Args:
            target_ids: List of target IDs
            enabled_by: User enabling targets
            
        Returns:
            Number of targets enabled
        """
        return await self.bulk_update(
            {'id': target_ids},
            {
                'enabled': True,
                'status': TargetStatus.ACTIVE
            },
            updated_by=enabled_by
        )
    
    async def bulk_disable(
        self,
        target_ids: List[UUID],
        reason: Optional[str] = None,
        disabled_by: Optional[str] = None
    ) -> int:
        """Disable multiple targets.
        
        Args:
            target_ids: List of target IDs
            reason: Reason for disabling
            disabled_by: User disabling targets
            
        Returns:
            Number of targets disabled
        """
        updates = {
            'enabled': False,
            'status': TargetStatus.INACTIVE
        }
        
        # Note: For config_json updates, we'd need to handle this differently
        # as bulk_update doesn't support complex JSON operations
        
        return await self.bulk_update(
            {'id': target_ids},
            updates,
            updated_by=disabled_by
        )
    
    async def search_targets(
        self,
        search_term: str,
        include_disabled: bool = False
    ) -> List[Target]:
        """Search targets by name or description.
        
        Args:
            search_term: Search term
            include_disabled: Whether to include disabled targets
            
        Returns:
            List of matching targets
        """
        query = select(Target).where(
            and_(
                Target.is_deleted == False,
                or_(
                    Target.name.ilike(f"%{search_term}%"),
                    Target.display_name.ilike(f"%{search_term}%"),
                    Target.description.ilike(f"%{search_term}%")
                )
            )
        )
        
        if not include_disabled:
            query = query.where(Target.enabled == True)
        
        result = await self.session.execute(query)
        return list(result.scalars().all())
    
    async def get_statistics(self) -> Dict[str, Any]:
        """Get target statistics.
        
        Returns:
            Dictionary of statistics
        """
        # Total counts
        total_query = select(func.count(Target.id)).where(
            Target.is_deleted == False
        )
        total_result = await self.session.execute(total_query)
        total_count = total_result.scalar()
        
        # Active counts
        active_query = select(func.count(Target.id)).where(
            and_(
                Target.is_deleted == False,
                Target.enabled == True,
                Target.status == TargetStatus.ACTIVE
            )
        )
        active_result = await self.session.execute(active_query)
        active_count = active_result.scalar()
        
        # Pending verification
        pending_query = select(func.count(Target.id)).where(
            and_(
                Target.is_deleted == False,
                Target.status == TargetStatus.PENDING_VERIFICATION
            )
        )
        pending_result = await self.session.execute(pending_query)
        pending_count = pending_result.scalar()
        
        # Type distribution
        type_query = select(
            Target.target_type,
            func.count(Target.id)
        ).where(
            Target.is_deleted == False
        ).group_by(Target.target_type)
        
        type_result = await self.session.execute(type_query)
        type_distribution = {
            str(row[0].value): row[1] 
            for row in type_result if row[0]
        }
        
        # Provider distribution
        provider_query = select(
            Target.provider,
            func.count(Target.id)
        ).where(
            and_(
                Target.is_deleted == False,
                Target.provider != None
            )
        ).group_by(Target.provider)
        
        provider_result = await self.session.execute(provider_query)
        provider_distribution = {
            str(row[0].value): row[1] 
            for row in provider_result if row[0]
        }
        
        return {
            'total_targets': total_count,
            'active_targets': active_count,
            'pending_verification': pending_count,
            'disabled_targets': total_count - active_count,
            'type_distribution': type_distribution,
            'provider_distribution': provider_distribution
        }


# Export repository
__all__ = ['TargetRepository']