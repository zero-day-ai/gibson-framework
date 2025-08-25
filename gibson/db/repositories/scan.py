"""Repository for Scan and Finding models with specialized operations."""

from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import and_, or_, func, desc

from gibson.db.models.scan import ScanRecord, FindingRecord
from gibson.db.repositories.base import BaseRepository


class ScanRepository(BaseRepository[ScanRecord]):
    """Repository for ScanRecord with enhanced features."""
    
    def __init__(self, session: AsyncSession):
        """Initialize scan repository.
        
        Args:
            session: Async database session
        """
        super().__init__(ScanRecord, session)
    
    async def get_by_target(
        self,
        target_id: UUID,
        status: Optional[str] = None,
        limit: int = 100
    ) -> List[ScanRecord]:
        """Get scans for a specific target.
        
        Args:
            target_id: Target ID
            status: Optional status filter
            limit: Maximum number of results
            
        Returns:
            List of scans
        """
        filters = {'target_id': target_id}
        if status:
            filters['status'] = status
        
        return await self.list(
            filters=filters,
            order_by='-created_at',
            limit=limit
        )
    
    async def get_active_scans(self) -> List[ScanRecord]:
        """Get currently running scans.
        
        Returns:
            List of active scans
        """
        return await self.list(
            filters={'status': 'running'},
            order_by='started_at'
        )
    
    async def get_recent_scans(
        self,
        hours_back: int = 24,
        limit: int = 50
    ) -> List[ScanRecord]:
        """Get recent scans.
        
        Args:
            hours_back: Number of hours to look back
            limit: Maximum number of results
            
        Returns:
            List of recent scans
        """
        cutoff_time = datetime.utcnow() - timedelta(hours=hours_back)
        
        query = select(ScanRecord).where(
            and_(
                ScanRecord.is_deleted == False,
                ScanRecord.created_at >= cutoff_time
            )
        ).order_by(desc(ScanRecord.created_at)).limit(limit)
        
        result = await self.session.execute(query)
        return list(result.scalars().all())
    
    async def mark_scan_started(
        self,
        scan_id: UUID,
        started_by: Optional[str] = None
    ) -> Optional[ScanRecord]:
        """Mark scan as started.
        
        Args:
            scan_id: Scan ID
            started_by: User who started scan
            
        Returns:
            Updated scan or None
        """
        return await self.update(
            scan_id,
            {
                'status': 'running',
                'started_at': datetime.utcnow()
            },
            updated_by=started_by
        )
    
    async def mark_scan_completed(
        self,
        scan_id: UUID,
        modules_run: int,
        modules_failed: int,
        total_findings: int,
        error_message: Optional[str] = None,
        completed_by: Optional[str] = None
    ) -> Optional[ScanRecord]:
        """Mark scan as completed.
        
        Args:
            scan_id: Scan ID
            modules_run: Number of modules executed
            modules_failed: Number of modules that failed
            total_findings: Total findings generated
            error_message: Error message if scan failed
            completed_by: User who completed scan
            
        Returns:
            Updated scan or None
        """
        scan = await self.get(scan_id)
        if not scan:
            return None
        
        completed_at = datetime.utcnow()
        duration = None
        
        if scan.started_at:
            duration = (completed_at - scan.started_at).total_seconds()
        
        status = 'failed' if error_message else 'completed'
        
        return await self.update(
            scan_id,
            {
                'status': status,
                'completed_at': completed_at,
                'duration': duration,
                'modules_run': modules_run,
                'modules_failed': modules_failed,
                'total_findings': total_findings,
                'error_message': error_message
            },
            updated_by=completed_by
        )
    
    async def get_scan_statistics(
        self,
        target_id: Optional[UUID] = None,
        days_back: int = 30
    ) -> Dict[str, Any]:
        """Get scan statistics.
        
        Args:
            target_id: Optional target ID filter
            days_back: Number of days to include
            
        Returns:
            Dictionary of statistics
        """
        cutoff_date = datetime.utcnow() - timedelta(days=days_back)
        
        base_query = select(
            func.count(ScanRecord.id),
            func.sum(func.cast(ScanRecord.status == 'completed', Integer)),
            func.sum(func.cast(ScanRecord.status == 'failed', Integer)),
            func.sum(func.cast(ScanRecord.status == 'running', Integer)),
            func.avg(ScanRecord.duration),
            func.sum(ScanRecord.total_findings),
            func.sum(ScanRecord.modules_run),
            func.sum(ScanRecord.modules_failed)
        ).where(
            and_(
                ScanRecord.is_deleted == False,
                ScanRecord.created_at >= cutoff_date
            )
        )
        
        if target_id:
            base_query = base_query.where(ScanRecord.target_id == target_id)
        
        result = await self.session.execute(base_query)
        stats = result.one()
        
        total_scans = stats[0] or 0
        completed_scans = stats[1] or 0
        failed_scans = stats[2] or 0
        running_scans = stats[3] or 0
        avg_duration = stats[4] or 0.0
        total_findings = stats[5] or 0
        total_modules_run = stats[6] or 0
        total_modules_failed = stats[7] or 0
        
        return {
            'total_scans': total_scans,
            'completed_scans': completed_scans,
            'failed_scans': failed_scans,
            'running_scans': running_scans,
            'success_rate': (completed_scans / total_scans * 100) if total_scans > 0 else 0,
            'avg_duration_seconds': round(avg_duration, 2),
            'total_findings': total_findings,
            'avg_findings_per_scan': round(total_findings / total_scans, 2) if total_scans > 0 else 0,
            'module_success_rate': ((total_modules_run - total_modules_failed) / total_modules_run * 100) if total_modules_run > 0 else 0
        }


class FindingRepository(BaseRepository[FindingRecord]):
    """Repository for FindingRecord with enhanced features."""
    
    def __init__(self, session: AsyncSession):
        """Initialize finding repository.
        
        Args:
            session: Async database session
        """
        super().__init__(FindingRecord, session)
    
    async def get_by_scan(
        self,
        scan_id: UUID,
        severity: Optional[str] = None
    ) -> List[FindingRecord]:
        """Get findings for a specific scan.
        
        Args:
            scan_id: Scan ID
            severity: Optional severity filter
            
        Returns:
            List of findings
        """
        filters = {'scan_id': scan_id}
        if severity:
            filters['severity'] = severity
        
        return await self.list(
            filters=filters,
            order_by='-confidence'
        )
    
    async def get_by_target(
        self,
        target_id: UUID,
        status: str = 'open',
        limit: int = 100
    ) -> List[FindingRecord]:
        """Get findings for a specific target.
        
        Args:
            target_id: Target ID
            status: Finding status filter
            limit: Maximum number of results
            
        Returns:
            List of findings
        """
        return await self.list(
            filters={'target_id': target_id, 'status': status},
            order_by='-created_at',
            limit=limit
        )
    
    async def get_critical_findings(
        self,
        min_confidence: int = 70
    ) -> List[FindingRecord]:
        """Get critical severity findings with high confidence.
        
        Args:
            min_confidence: Minimum confidence score
            
        Returns:
            List of critical findings
        """
        query = select(FindingRecord).where(
            and_(
                FindingRecord.is_deleted == False,
                FindingRecord.severity == 'critical',
                FindingRecord.confidence >= min_confidence,
                FindingRecord.status == 'open'
            )
        ).order_by(desc(FindingRecord.confidence))
        
        result = await self.session.execute(query)
        return list(result.scalars().all())
    
    async def get_by_module(
        self,
        module_name: str,
        days_back: int = 30
    ) -> List[FindingRecord]:
        """Get findings generated by a specific module.
        
        Args:
            module_name: Module name
            days_back: Number of days to look back
            
        Returns:
            List of findings
        """
        cutoff_date = datetime.utcnow() - timedelta(days=days_back)
        
        query = select(FindingRecord).where(
            and_(
                FindingRecord.is_deleted == False,
                FindingRecord.module == module_name,
                FindingRecord.created_at >= cutoff_date
            )
        ).order_by(desc(FindingRecord.created_at))
        
        result = await self.session.execute(query)
        return list(result.scalars().all())
    
    async def mark_as_false_positive(
        self,
        finding_id: UUID,
        reason: str,
        marked_by: Optional[str] = None
    ) -> Optional[FindingRecord]:
        """Mark finding as false positive.
        
        Args:
            finding_id: Finding ID
            reason: Reason for marking as false positive
            marked_by: User who marked it
            
        Returns:
            Updated finding or None
        """
        return await self.update(
            finding_id,
            {
                'status': 'false_positive',
                'false_positive_reason': reason
            },
            updated_by=marked_by
        )
    
    async def mark_as_resolved(
        self,
        finding_id: UUID,
        resolved_by: Optional[str] = None
    ) -> Optional[FindingRecord]:
        """Mark finding as resolved.
        
        Args:
            finding_id: Finding ID
            resolved_by: User who resolved it
            
        Returns:
            Updated finding or None
        """
        return await self.update(
            finding_id,
            {'status': 'resolved'},
            updated_by=resolved_by
        )
    
    async def search_findings(
        self,
        search_term: str,
        severity: Optional[str] = None,
        domain: Optional[str] = None
    ) -> List[FindingRecord]:
        """Search findings by title or description.
        
        Args:
            search_term: Search term
            severity: Optional severity filter
            domain: Optional attack domain filter
            
        Returns:
            List of matching findings
        """
        query = select(FindingRecord).where(
            and_(
                FindingRecord.is_deleted == False,
                or_(
                    FindingRecord.title.ilike(f"%{search_term}%"),
                    FindingRecord.description.ilike(f"%{search_term}%")
                )
            )
        )
        
        if severity:
            query = query.where(FindingRecord.severity == severity)
        
        if domain:
            query = query.where(FindingRecord.attack_domain == domain)
        
        result = await self.session.execute(query)
        return list(result.scalars().all())
    
    async def get_finding_statistics(
        self,
        target_id: Optional[UUID] = None,
        days_back: int = 30
    ) -> Dict[str, Any]:
        """Get finding statistics.
        
        Args:
            target_id: Optional target ID filter
            days_back: Number of days to include
            
        Returns:
            Dictionary of statistics
        """
        cutoff_date = datetime.utcnow() - timedelta(days=days_back)
        
        base_query = select(
            func.count(FindingRecord.id),
            func.sum(func.cast(FindingRecord.severity == 'critical', Integer)),
            func.sum(func.cast(FindingRecord.severity == 'high', Integer)),
            func.sum(func.cast(FindingRecord.severity == 'medium', Integer)),
            func.sum(func.cast(FindingRecord.severity == 'low', Integer)),
            func.sum(func.cast(FindingRecord.status == 'open', Integer)),
            func.sum(func.cast(FindingRecord.status == 'resolved', Integer)),
            func.sum(func.cast(FindingRecord.status == 'false_positive', Integer)),
            func.avg(FindingRecord.confidence)
        ).where(
            and_(
                FindingRecord.is_deleted == False,
                FindingRecord.created_at >= cutoff_date
            )
        )
        
        if target_id:
            base_query = base_query.where(FindingRecord.target_id == target_id)
        
        result = await self.session.execute(base_query)
        stats = result.one()
        
        total_findings = stats[0] or 0
        critical_count = stats[1] or 0
        high_count = stats[2] or 0
        medium_count = stats[3] or 0
        low_count = stats[4] or 0
        open_count = stats[5] or 0
        resolved_count = stats[6] or 0
        false_positive_count = stats[7] or 0
        avg_confidence = stats[8] or 0.0
        
        # Domain distribution
        domain_query = select(
            FindingRecord.attack_domain,
            func.count(FindingRecord.id)
        ).where(
            and_(
                FindingRecord.is_deleted == False,
                FindingRecord.created_at >= cutoff_date
            )
        )
        
        if target_id:
            domain_query = domain_query.where(FindingRecord.target_id == target_id)
        
        domain_query = domain_query.group_by(FindingRecord.attack_domain)
        domain_result = await self.session.execute(domain_query)
        domain_distribution = {row[0]: row[1] for row in domain_result}
        
        return {
            'total_findings': total_findings,
            'severity_distribution': {
                'critical': critical_count,
                'high': high_count,
                'medium': medium_count,
                'low': low_count
            },
            'status_distribution': {
                'open': open_count,
                'resolved': resolved_count,
                'false_positive': false_positive_count
            },
            'domain_distribution': domain_distribution,
            'avg_confidence': round(avg_confidence, 1),
            'false_positive_rate': (false_positive_count / total_findings * 100) if total_findings > 0 else 0,
            'resolution_rate': (resolved_count / total_findings * 100) if total_findings > 0 else 0
        }


# Export repositories
__all__ = [
    'ScanRepository',
    'FindingRepository'
]