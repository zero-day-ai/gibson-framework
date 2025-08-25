"""Repository for Module-related models with specialized operations."""

from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import and_, or_, func, desc

from gibson.db.models.scan import ModuleRecord, ModuleResultRecord
from gibson.db.repositories.base import BaseRepository


class ModuleRepository(BaseRepository[ModuleRecord]):
    """Repository for ModuleRecord with enhanced features."""
    
    def __init__(self, session: AsyncSession):
        """Initialize module repository.
        
        Args:
            session: Async database session
        """
        super().__init__(ModuleRecord, session)
    
    async def get_by_name(self, name: str) -> Optional[ModuleRecord]:
        """Get module by name.
        
        Args:
            name: Module name
            
        Returns:
            Module or None
        """
        return await self.find_one({'name': name})
    
    async def get_by_domain(self, domain: str) -> List[ModuleRecord]:
        """Get all modules for a specific domain.
        
        Args:
            domain: Attack domain
            
        Returns:
            List of modules
        """
        return await self.list(
            filters={'domain': domain, 'status': 'installed'},
            order_by='-usage_count'
        )
    
    async def get_by_category(self, category: str) -> List[ModuleRecord]:
        """Get all modules for a specific category.
        
        Args:
            category: Module category
            
        Returns:
            List of modules
        """
        return await self.list(
            filters={'category': category, 'status': 'installed'},
            order_by='-usage_count'
        )
    
    async def get_reliable_modules(
        self,
        min_success_rate: float = 80.0,
        min_usage_count: int = 5
    ) -> List[ModuleRecord]:
        """Get reliable modules based on success rate.
        
        Args:
            min_success_rate: Minimum success rate percentage
            min_usage_count: Minimum number of executions
            
        Returns:
            List of reliable modules
        """
        query = select(ModuleRecord).where(
            and_(
                ModuleRecord.is_deleted == False,
                ModuleRecord.status == 'installed',
                ModuleRecord.usage_count >= min_usage_count,
                # Calculate success rate in query
                (ModuleRecord.success_count * 100.0 / ModuleRecord.usage_count) >= min_success_rate
            )
        ).order_by(desc(ModuleRecord.success_count))
        
        result = await self.session.execute(query)
        return list(result.scalars().all())
    
    async def get_problematic_modules(
        self,
        max_success_rate: float = 50.0,
        min_usage_count: int = 3
    ) -> List[ModuleRecord]:
        """Get problematic modules with low success rates.
        
        Args:
            max_success_rate: Maximum success rate percentage
            min_usage_count: Minimum number of executions
            
        Returns:
            List of problematic modules
        """
        query = select(ModuleRecord).where(
            and_(
                ModuleRecord.is_deleted == False,
                ModuleRecord.status == 'installed',
                ModuleRecord.usage_count >= min_usage_count,
                (ModuleRecord.success_count * 100.0 / ModuleRecord.usage_count) <= max_success_rate
            )
        ).order_by(desc(ModuleRecord.failure_count))
        
        result = await self.session.execute(query)
        return list(result.scalars().all())
    
    async def update_statistics(
        self,
        module_id: UUID,
        success: bool,
        execution_time: float,
        findings_count: int = 0
    ) -> Optional[ModuleRecord]:
        """Update module statistics after execution.
        
        Args:
            module_id: Module ID
            success: Whether execution was successful
            execution_time: Execution time in seconds
            findings_count: Number of findings generated
            
        Returns:
            Updated module or None
        """
        module = await self.get(module_id)
        if not module:
            return None
        
        module.increment_usage(success, execution_time)
        
        updates = {
            'usage_count': module.usage_count,
            'success_count': module.success_count,
            'failure_count': module.failure_count,
            'avg_execution_time': module.avg_execution_time,
            'last_updated': datetime.utcnow()
        }
        
        return await self.update(module_id, updates)
    
    async def search_modules(
        self,
        search_term: str,
        domain: Optional[str] = None,
        category: Optional[str] = None
    ) -> List[ModuleRecord]:
        """Search modules by name or description.
        
        Args:
            search_term: Search term
            domain: Optional domain filter
            category: Optional category filter
            
        Returns:
            List of matching modules
        """
        query = select(ModuleRecord).where(
            and_(
                ModuleRecord.is_deleted == False,
                ModuleRecord.status == 'installed',
                or_(
                    ModuleRecord.name.ilike(f"%{search_term}%"),
                    ModuleRecord.display_name.ilike(f"%{search_term}%"),
                    ModuleRecord.description.ilike(f"%{search_term}%")
                )
            )
        )
        
        if domain:
            query = query.where(ModuleRecord.domain == domain)
        
        if category:
            query = query.where(ModuleRecord.category == category)
        
        result = await self.session.execute(query)
        return list(result.scalars().all())
    
    async def get_popular_modules(self, limit: int = 10) -> List[ModuleRecord]:
        """Get most frequently used modules.
        
        Args:
            limit: Maximum number of modules to return
            
        Returns:
            List of popular modules
        """
        return await self.list(
            filters={'status': 'installed'},
            order_by='-usage_count',
            limit=limit
        )
    
    async def get_statistics(self) -> Dict[str, Any]:
        """Get module statistics.
        
        Returns:
            Dictionary of statistics
        """
        # Total modules
        total_query = select(func.count(ModuleRecord.id)).where(
            and_(
                ModuleRecord.is_deleted == False,
                ModuleRecord.status == 'installed'
            )
        )
        total_result = await self.session.execute(total_query)
        total_count = total_result.scalar()
        
        # Domain distribution
        domain_query = select(
            ModuleRecord.domain,
            func.count(ModuleRecord.id)
        ).where(
            and_(
                ModuleRecord.is_deleted == False,
                ModuleRecord.status == 'installed'
            )
        ).group_by(ModuleRecord.domain)
        
        domain_result = await self.session.execute(domain_query)
        domain_distribution = {row[0]: row[1] for row in domain_result}
        
        # Category distribution
        category_query = select(
            ModuleRecord.category,
            func.count(ModuleRecord.id)
        ).where(
            and_(
                ModuleRecord.is_deleted == False,
                ModuleRecord.status == 'installed'
            )
        ).group_by(ModuleRecord.category)
        
        category_result = await self.session.execute(category_query)
        category_distribution = {row[0]: row[1] for row in category_result}
        
        # Usage statistics
        usage_query = select(
            func.sum(ModuleRecord.usage_count),
            func.sum(ModuleRecord.success_count),
            func.sum(ModuleRecord.failure_count),
            func.avg(ModuleRecord.avg_execution_time)
        ).where(
            and_(
                ModuleRecord.is_deleted == False,
                ModuleRecord.status == 'installed'
            )
        )
        
        usage_result = await self.session.execute(usage_query)
        usage_stats = usage_result.one()
        
        total_usage = usage_stats[0] or 0
        total_success = usage_stats[1] or 0
        total_failure = usage_stats[2] or 0
        avg_execution = usage_stats[3] or 0.0
        
        return {
            'total_modules': total_count,
            'domain_distribution': domain_distribution,
            'category_distribution': category_distribution,
            'total_executions': total_usage,
            'total_successes': total_success,
            'total_failures': total_failure,
            'overall_success_rate': (total_success / total_usage * 100) if total_usage > 0 else 0,
            'avg_execution_time': round(avg_execution, 2)
        }


class ModuleResultRepository(BaseRepository[ModuleResultRecord]):
    """Repository for ModuleResultRecord with enhanced features."""
    
    def __init__(self, session: AsyncSession):
        """Initialize module result repository.
        
        Args:
            session: Async database session
        """
        super().__init__(ModuleResultRecord, session)
    
    async def get_by_execution_id(self, execution_id: UUID) -> Optional[ModuleResultRecord]:
        """Get module result by execution ID.
        
        Args:
            execution_id: Execution ID
            
        Returns:
            Module result or None
        """
        return await self.find_one({'execution_id': execution_id})
    
    async def get_scan_results(
        self,
        scan_id: UUID,
        status: Optional[str] = None
    ) -> List[ModuleResultRecord]:
        """Get all module results for a scan.
        
        Args:
            scan_id: Scan ID
            status: Optional status filter
            
        Returns:
            List of module results
        """
        filters = {'scan_id': scan_id}
        if status:
            filters['status'] = status
        
        return await self.list(
            filters=filters,
            order_by='started_at'
        )
    
    async def get_module_history(
        self,
        module_id: UUID,
        limit: int = 100,
        days_back: int = 30
    ) -> List[ModuleResultRecord]:
        """Get execution history for a module.
        
        Args:
            module_id: Module ID
            limit: Maximum number of results
            days_back: Number of days to look back
            
        Returns:
            List of module results
        """
        cutoff_date = datetime.utcnow() - timedelta(days=days_back)
        
        query = select(ModuleResultRecord).where(
            and_(
                ModuleResultRecord.module_id == module_id,
                ModuleResultRecord.is_deleted == False,
                ModuleResultRecord.started_at >= cutoff_date
            )
        ).order_by(desc(ModuleResultRecord.started_at)).limit(limit)
        
        result = await self.session.execute(query)
        return list(result.scalars().all())
    
    async def get_failed_executions(
        self,
        limit: int = 50,
        hours_back: int = 24
    ) -> List[ModuleResultRecord]:
        """Get recent failed module executions.
        
        Args:
            limit: Maximum number of results
            hours_back: Number of hours to look back
            
        Returns:
            List of failed executions
        """
        cutoff_time = datetime.utcnow() - timedelta(hours=hours_back)
        
        query = select(ModuleResultRecord).where(
            and_(
                ModuleResultRecord.status == 'failed',
                ModuleResultRecord.is_deleted == False,
                ModuleResultRecord.started_at >= cutoff_time
            )
        ).order_by(desc(ModuleResultRecord.started_at)).limit(limit)
        
        result = await self.session.execute(query)
        return list(result.scalars().all())
    
    async def mark_execution_started(
        self,
        execution_id: UUID,
        started_by: Optional[str] = None
    ) -> Optional[ModuleResultRecord]:
        """Mark module execution as started.
        
        Args:
            execution_id: Execution ID
            started_by: User who started execution
            
        Returns:
            Updated result or None
        """
        result = await self.get_by_execution_id(execution_id)
        if not result:
            return None
        
        result.mark_started()
        
        return await self.update(
            result.id,
            {
                'status': result.status,
                'started_at': result.started_at
            },
            updated_by=started_by
        )
    
    async def mark_execution_completed(
        self,
        execution_id: UUID,
        success: bool,
        findings_count: int = 0,
        error_message: Optional[str] = None,
        completed_by: Optional[str] = None
    ) -> Optional[ModuleResultRecord]:
        """Mark module execution as completed.
        
        Args:
            execution_id: Execution ID
            success: Whether execution was successful
            findings_count: Number of findings generated
            error_message: Error message if failed
            completed_by: User who completed execution
            
        Returns:
            Updated result or None
        """
        result = await self.get_by_execution_id(execution_id)
        if not result:
            return None
        
        result.mark_completed(success, error_message)
        result.findings_count = findings_count
        
        return await self.update(
            result.id,
            {
                'status': result.status,
                'completed_at': result.completed_at,
                'duration': result.duration,
                'findings_count': result.findings_count,
                'error_message': result.error_message
            },
            updated_by=completed_by
        )
    
    async def get_execution_statistics(
        self,
        module_id: Optional[UUID] = None,
        scan_id: Optional[UUID] = None
    ) -> Dict[str, Any]:
        """Get execution statistics.
        
        Args:
            module_id: Optional module ID filter
            scan_id: Optional scan ID filter
            
        Returns:
            Dictionary of statistics
        """
        base_query = select(
            func.count(ModuleResultRecord.id),
            func.sum(func.cast(ModuleResultRecord.status == 'completed', Integer)),
            func.sum(func.cast(ModuleResultRecord.status == 'failed', Integer)),
            func.avg(ModuleResultRecord.duration),
            func.sum(ModuleResultRecord.findings_count)
        ).where(ModuleResultRecord.is_deleted == False)
        
        if module_id:
            base_query = base_query.where(ModuleResultRecord.module_id == module_id)
        
        if scan_id:
            base_query = base_query.where(ModuleResultRecord.scan_id == scan_id)
        
        result = await self.session.execute(base_query)
        stats = result.one()
        
        total_executions = stats[0] or 0
        completed_count = stats[1] or 0
        failed_count = stats[2] or 0
        avg_duration = stats[3] or 0.0
        total_findings = stats[4] or 0
        
        return {
            'total_executions': total_executions,
            'completed_executions': completed_count,
            'failed_executions': failed_count,
            'success_rate': (completed_count / total_executions * 100) if total_executions > 0 else 0,
            'avg_duration_seconds': round(avg_duration, 2),
            'total_findings': total_findings,
            'avg_findings_per_execution': round(total_findings / total_executions, 2) if total_executions > 0 else 0
        }


# Export repositories
__all__ = [
    'ModuleRepository',
    'ModuleResultRepository'
]