"""Utility functions for converting between Pydantic and SQLAlchemy models."""

from typing import Any, Dict, Optional, Type, TypeVar
from uuid import UUID

from gibson.db.models.report import TargetRecord
from gibson.db.models.scan import FindingRecord, ScanRecord

# Import Pydantic models (these imports will be updated when models are moved)
try:
    from gibson.models.target import TargetModel as PydanticTargetModel
    from gibson.models.scan import ScanModel as PydanticScanModel
    from gibson.models.finding import FindingModel as PydanticFindingModel
except ImportError:
    # Temporary fallback for compatibility during migration
    PydanticTargetModel = None
    PydanticScanModel = None
    PydanticFindingModel = None

T = TypeVar('T')


class ModelConverter:
    """Utility class for converting between Pydantic and SQLAlchemy models."""
    
    @staticmethod
    def target_to_pydantic(db_target: TargetRecord) -> Optional[PydanticTargetModel]:
        """Convert SQLAlchemy TargetRecord to Pydantic TargetModel.
        
        Args:
            db_target: Database target record
            
        Returns:
            Pydantic target model or None if models not available
        """
        if not PydanticTargetModel:
            return None
            
        return PydanticTargetModel(
            id=db_target.id,
            created_at=db_target.created_at,
            updated_at=db_target.updated_at,
            name=db_target.name,
            display_name=db_target.display_name,
            description=db_target.description,
            target_type=db_target.target_type,
            base_url=db_target.base_url,
            status=db_target.status,
            enabled=db_target.enabled,
            authentication=db_target.authentication,
            endpoints=db_target.endpoints or [],
            tags=db_target.tags or [],
            environment=db_target.environment,
            priority=db_target.priority,
            owner=db_target.owner,
            contact_email=db_target.contact_email,
            scan_count=db_target.scan_count,
            finding_count=db_target.finding_count,
            last_scanned=db_target.last_scanned,
            last_verified=db_target.last_verified,
            verification_interval=db_target.verification_interval,
            compliance_requirements=db_target.compliance_requirements or [],
            data_classification=db_target.data_classification,
            requires_approval=db_target.requires_approval,
            metadata=db_target.meta_data or {}
        )
    
    @staticmethod
    def pydantic_to_target(pydantic_target: PydanticTargetModel) -> Optional[TargetRecord]:
        """Convert Pydantic TargetModel to SQLAlchemy TargetRecord.
        
        Args:
            pydantic_target: Pydantic target model
            
        Returns:
            Database target record or None if models not available
        """
        if not pydantic_target:
            return None
            
        return TargetRecord(
            id=pydantic_target.id,
            created_at=pydantic_target.created_at,
            updated_at=pydantic_target.updated_at,
            name=pydantic_target.name,
            display_name=pydantic_target.display_name,
            description=pydantic_target.description,
            target_type=pydantic_target.target_type.value if hasattr(pydantic_target.target_type, 'value') else pydantic_target.target_type,
            base_url=pydantic_target.base_url,
            status=pydantic_target.status.value if hasattr(pydantic_target.status, 'value') else pydantic_target.status,
            enabled=pydantic_target.enabled,
            authentication=pydantic_target.authentication.model_dump() if hasattr(pydantic_target.authentication, 'model_dump') else pydantic_target.authentication,
            endpoints=[e.model_dump() if hasattr(e, 'model_dump') else e for e in pydantic_target.endpoints],
            tags=pydantic_target.tags,
            environment=pydantic_target.environment,
            priority=pydantic_target.priority,
            owner=pydantic_target.owner,
            contact_email=pydantic_target.contact_email,
            scan_count=pydantic_target.scan_count,
            finding_count=pydantic_target.finding_count,
            last_scanned=pydantic_target.last_scanned,
            last_verified=pydantic_target.last_verified,
            verification_interval=pydantic_target.verification_interval,
            compliance_requirements=pydantic_target.compliance_requirements,
            data_classification=pydantic_target.data_classification,
            requires_approval=pydantic_target.requires_approval,
            meta_data=pydantic_target.metadata
        )
    
    @staticmethod
    def scan_to_dict(db_scan: ScanRecord) -> Dict[str, Any]:
        """Convert SQLAlchemy ScanRecord to dictionary.
        
        Args:
            db_scan: Database scan record
            
        Returns:
            Dictionary representation of scan
        """
        return {
            'id': str(db_scan.id) if isinstance(db_scan.id, UUID) else db_scan.id,
            'created_at': db_scan.created_at.isoformat() if db_scan.created_at else None,
            'updated_at': db_scan.updated_at.isoformat() if db_scan.updated_at else None,
            'target_id': str(db_scan.target_id) if isinstance(db_scan.target_id, UUID) else db_scan.target_id,
            'target_url': db_scan.target_url,
            'status': db_scan.status,
            'scan_type': db_scan.scan_type,
            'config': db_scan.config,
            'started_at': db_scan.started_at.isoformat() if db_scan.started_at else None,
            'completed_at': db_scan.completed_at.isoformat() if db_scan.completed_at else None,
            'duration': db_scan.duration,
            'modules_run': db_scan.modules_run,
            'modules_failed': db_scan.modules_failed,
            'total_findings': db_scan.total_findings,
            'error_message': db_scan.error_message,
            'meta_data': db_scan.meta_data
        }
    
    @staticmethod
    def finding_to_dict(db_finding: FindingRecord) -> Dict[str, Any]:
        """Convert SQLAlchemy FindingRecord to dictionary.
        
        Args:
            db_finding: Database finding record
            
        Returns:
            Dictionary representation of finding
        """
        return {
            'id': str(db_finding.id) if isinstance(db_finding.id, UUID) else db_finding.id,
            'created_at': db_finding.created_at.isoformat() if db_finding.created_at else None,
            'updated_at': db_finding.updated_at.isoformat() if db_finding.updated_at else None,
            'scan_id': str(db_finding.scan_id) if isinstance(db_finding.scan_id, UUID) else db_finding.scan_id,
            'target_id': str(db_finding.target_id) if isinstance(db_finding.target_id, UUID) else db_finding.target_id,
            'module': db_finding.module,
            'severity': db_finding.severity,
            'title': db_finding.title,
            'description': db_finding.description,
            'confidence': db_finding.confidence,
            'evidence': db_finding.evidence,
            'remediation': db_finding.remediation,
            'references': db_finding.references,
            'owasp_category': db_finding.owasp_category,
            'attack_domain': db_finding.attack_domain,
            'status': db_finding.status,
            'false_positive_reason': db_finding.false_positive_reason,
            'cvss_score': db_finding.cvss_score,
            'cwe_id': db_finding.cwe_id
        }
    
    @staticmethod
    def bulk_convert(records: list, converter_method: str) -> list:
        """Bulk convert multiple records using specified converter method.
        
        Args:
            records: List of database records
            converter_method: Name of converter method to use
            
        Returns:
            List of converted records
        """
        converter = getattr(ModelConverter, converter_method, None)
        if not converter:
            raise ValueError(f"Unknown converter method: {converter_method}")
        
        return [converter(record) for record in records if record is not None]


class QueryHelper:
    """Helper functions for common database queries."""
    
    @staticmethod
    def apply_pagination(query, page: int = 1, per_page: int = 50):
        """Apply pagination to a SQLAlchemy query.
        
        Args:
            query: SQLAlchemy query object
            page: Page number (1-indexed)
            per_page: Items per page
            
        Returns:
            Paginated query
        """
        if page < 1:
            page = 1
        if per_page < 1:
            per_page = 50
        if per_page > 1000:
            per_page = 1000
            
        offset = (page - 1) * per_page
        return query.limit(per_page).offset(offset)
    
    @staticmethod
    def apply_filters(query, model_class: Type[T], filters: Dict[str, Any]):
        """Apply filters to a SQLAlchemy query.
        
        Args:
            query: SQLAlchemy query object
            model_class: Model class to filter
            filters: Dictionary of field: value filters
            
        Returns:
            Filtered query
        """
        for field, value in filters.items():
            if hasattr(model_class, field):
                column = getattr(model_class, field)
                if value is None:
                    query = query.filter(column.is_(None))
                elif isinstance(value, list):
                    query = query.filter(column.in_(value))
                elif isinstance(value, dict):
                    # Handle complex filters like {">=": 5, "<=": 10}
                    for op, val in value.items():
                        if op == ">=":
                            query = query.filter(column >= val)
                        elif op == "<=":
                            query = query.filter(column <= val)
                        elif op == ">":
                            query = query.filter(column > val)
                        elif op == "<":
                            query = query.filter(column < val)
                        elif op == "!=":
                            query = query.filter(column != val)
                        elif op == "like":
                            query = query.filter(column.like(f"%{val}%"))
                        elif op == "ilike":
                            query = query.filter(column.ilike(f"%{val}%"))
                else:
                    query = query.filter(column == value)
        
        return query
    
    @staticmethod
    def apply_ordering(query, model_class: Type[T], order_by: str):
        """Apply ordering to a SQLAlchemy query.
        
        Args:
            query: SQLAlchemy query object
            model_class: Model class to order
            order_by: Field to order by (prefix with - for descending)
            
        Returns:
            Ordered query
        """
        if not order_by:
            return query
            
        descending = order_by.startswith('-')
        field_name = order_by[1:] if descending else order_by
        
        if hasattr(model_class, field_name):
            column = getattr(model_class, field_name)
            if descending:
                query = query.order_by(column.desc())
            else:
                query = query.order_by(column.asc())
        
        return query


# Export utilities
__all__ = [
    'ModelConverter',
    'QueryHelper',
]