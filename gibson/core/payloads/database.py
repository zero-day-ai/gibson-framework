"""Database operations for payload management."""

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from loguru import logger
from sqlalchemy import and_, desc, func, or_, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

from gibson.db import PromptRecord, PromptCollectionRecord, PromptSourceRecord
from gibson.models.payload import PayloadModel
from gibson.models.domain import AttackDomain, ModuleCategory, Severity
from .types import PayloadQuery, PayloadMetrics


class PayloadDatabase:
    """Database operations for payload management.
    
    Leverages existing PromptRecord models for payload storage while extending
    functionality for the broader payload management system.
    """
    
    def __init__(self, session: AsyncSession):
        """Initialize database operations.
        
        Args:
            session: Async database session
        """
        self.session = session
    
    async def store_payload(self, payload: PayloadModel) -> int:
        """Store payload in database.
        
        Args:
            payload: PayloadModel to store
            
        Returns:
            Database ID of stored payload
            
        Raises:
            Exception: If storage fails
        """
        try:
            # Check if payload already exists by hash
            existing = await self._get_payload_by_hash(payload.hash)
            if existing:
                logger.debug(f"Payload with hash {payload.hash} already exists")
                return existing.id
            
            # Get or create collection for the payload
            collection = await self._get_or_create_collection(payload)
            
            # Create PromptRecord from PayloadModel
            # Convert category from ModuleCategory to string format for database
            # Handle both string and enum types
            domain_str = payload.domain.value if hasattr(payload.domain, 'value') else str(payload.domain)
            category_str = payload.category.value if hasattr(payload.category, 'value') else str(payload.category)
            db_category = f"{domain_str}_{category_str}"
            
            # Handle severity - it might be a string or enum
            if hasattr(payload.severity, 'value'):
                severity_str = payload.severity.value
            else:
                severity_str = str(payload.severity)
            
            record = PromptRecord(
                collection_id=collection.id,
                name=payload.name,
                content=payload.content,
                description=payload.description,
                category=db_category,
                severity=severity_str,
                tags=payload.tags,
                hash=payload.hash
            )
            
            self.session.add(record)
            await self.session.commit()
            await self.session.refresh(record)
            
            # Database ID is stored internally, PayloadModel keeps its UUID
            
            logger.debug(f"Stored payload {payload.name} with ID {record.id}")
            return record.id
            
        except Exception as e:
            await self.session.rollback()
            logger.error(f"Failed to store payload {payload.name}: {e}")
            raise
    
    async def get_payload_by_id(self, payload_id: int) -> Optional[PayloadModel]:
        """Retrieve payload by database ID.
        
        Args:
            payload_id: Database ID
            
        Returns:
            Payload if found, None otherwise
        """
        try:
            query = (
                select(PromptRecord)
                .options(selectinload(PromptRecord.collection))
                .where(PromptRecord.id == payload_id)
            )
            result = await self.session.execute(query)
            record = result.scalar_one_or_none()
            
            if not record:
                return None
            
            return await self._record_to_payload(record)
            
        except Exception as e:
            logger.error(f"Failed to get payload by ID {payload_id}: {e}")
            return None
    
    async def get_payload_by_hash(self, hash_value: str) -> Optional[PayloadModel]:
        """Retrieve payload by content hash.
        
        Args:
            hash_value: Content hash
            
        Returns:
            Payload if found, None otherwise
        """
        try:
            record = await self._get_payload_by_hash(hash_value)
            if not record:
                return None
            
            return await self._record_to_payload(record)
            
        except Exception as e:
            logger.error(f"Failed to get payload by hash {hash_value}: {e}")
            return None
    
    async def query_payloads(
        self, 
        query: PayloadQuery
    ) -> Tuple[List[PayloadModel], int]:
        """Query payloads with filtering and pagination.
        
        Args:
            query: Query parameters
            
        Returns:
            Tuple of (payloads, total_count)
        """
        try:
            # Build base query
            base_query = select(PromptRecord).options(
                selectinload(PromptRecord.collection)
            )
            
            # Apply filters
            conditions = []
            
            # Text search
            if query.search:
                search_term = f"%{query.search}%"
                conditions.append(
                    or_(
                        PromptRecord.name.ilike(search_term),
                        PromptRecord.description.ilike(search_term),
                        PromptRecord.payload.ilike(search_term)
                    )
                )
            
            # Domain and attack type filtering via category
            if query.domain or query.attack_type:
                if query.domain and query.attack_type:
                    category_pattern = f"{query.domain.value}_{query.attack_type}"
                    conditions.append(PromptRecord.category == category_pattern)
                elif query.domain:
                    category_pattern = f"{query.domain.value}_%"
                    conditions.append(PromptRecord.category.like(category_pattern))
            
            # Severity filter
            if query.severity:
                conditions.append(PromptRecord.severity == query.severity.value)
            
            # Tag filters
            if query.tags:
                for tag in query.tags:
                    conditions.append(PromptRecord.tags.contains([tag]))
            
            # Performance filters
            if query.min_success_rate is not None:
                conditions.append(PromptRecord.success_rate >= query.min_success_rate)
            
            # Temporal filters (using collection fetched_at as proxy)
            if query.created_after:
                conditions.append(PromptRecord.collection.has(
                    PromptCollectionRecord.fetched_at >= query.created_after
                ))
            
            if query.created_before:
                conditions.append(PromptRecord.collection.has(
                    PromptCollectionRecord.fetched_at <= query.created_before
                ))
            
            # Apply all conditions
            if conditions:
                base_query = base_query.where(and_(*conditions))
            
            # Get total count
            count_query = select(func.count(PromptRecord.id))
            if conditions:
                count_query = count_query.where(and_(*conditions))
            
            count_result = await self.session.execute(count_query)
            total_count = count_result.scalar()
            
            # Apply sorting
            sort_field = getattr(PromptRecord, query.sort_by, PromptRecord.id)
            if query.sort_order == "desc":
                base_query = base_query.order_by(desc(sort_field))
            else:
                base_query = base_query.order_by(sort_field)
            
            # Apply pagination
            if query.limit:
                base_query = base_query.limit(query.limit)
            if query.offset:
                base_query = base_query.offset(query.offset)
            
            # Execute query
            result = await self.session.execute(base_query)
            records = result.scalars().all()
            
            # Convert records to payloads
            payloads = []
            for record in records:
                payload = await self._record_to_payload(record)
                if payload:
                    payloads.append(payload)
            
            logger.debug(f"Query returned {len(payloads)} payloads (total: {total_count})")
            return payloads, total_count
            
        except Exception as e:
            logger.error(f"Failed to query payloads: {e}")
            return [], 0
    
    async def update_payload(self, payload: PayloadModel) -> bool:
        """Update existing payload in database.
        
        Args:
            payload: Updated payload
            
        Returns:
            True if update successful
        """
        try:
            if not payload.id:
                logger.error("Cannot update payload without ID")
                return False
            
            query = select(PromptRecord).where(PromptRecord.id == payload.id)
            result = await self.session.execute(query)
            record = result.scalar_one_or_none()
            
            if not record:
                logger.error(f"Payload with ID {payload.id} not found")
                return False
            
            # Update record fields
            record.name = payload.name
            record.payload = payload.content
            record.description = payload.description
            # Handle both string and enum types for category
            domain_str = payload.domain.value if hasattr(payload.domain, 'value') else str(payload.domain)
            category_str = payload.category.value if hasattr(payload.category, 'value') else str(payload.category)
            record.category = f"{domain_str}_{category_str}"
            # Handle severity - it might be a string or enum
            if hasattr(payload.severity, 'value'):
                record.severity = payload.severity.value
            else:
                record.severity = str(payload.severity)
            record.tags = payload.tags
            record.expected_indicators = payload.expected_indicators
            record.success_rate = payload.success_rate
            record.references = [str(ref) for ref in payload.references]
            record.hash = payload.hash
            
            await self.session.commit()
            
            logger.debug(f"Updated payload {payload.name}")
            return True
            
        except Exception as e:
            await self.session.rollback()
            logger.error(f"Failed to update payload {payload.name}: {e}")
            return False
    
    async def delete_payload(self, payload_id: int) -> bool:
        """Delete payload from database.
        
        Args:
            payload_id: Database ID of payload to delete
            
        Returns:
            True if deletion successful
        """
        try:
            query = select(PromptRecord).where(PromptRecord.id == payload_id)
            result = await self.session.execute(query)
            record = result.scalar_one_or_none()
            
            if not record:
                logger.warning(f"Payload with ID {payload_id} not found for deletion")
                return False
            
            await self.session.delete(record)
            await self.session.commit()
            
            logger.debug(f"Deleted payload with ID {payload_id}")
            return True
            
        except Exception as e:
            await self.session.rollback()
            logger.error(f"Failed to delete payload {payload_id}: {e}")
            return False
    
    async def get_payload_metrics(self) -> PayloadMetrics:
        """Get comprehensive payload metrics.
        
        Returns:
            PayloadMetrics object with statistics
        """
        try:
            metrics = PayloadMetrics()
            
            # Total payload count
            total_query = select(func.count(PromptRecord.id))
            result = await self.session.execute(total_query)
            metrics.total_payloads = result.scalar() or 0
            
            # Status distribution (using severity as proxy)
            status_query = select(
                PromptRecord.severity,
                func.count(PromptRecord.id)
            ).group_by(PromptRecord.severity)
            
            result = await self.session.execute(status_query)
            for severity, count in result.all():
                if severity == "critical":
                    metrics.active_payloads += count
                elif severity == "high":
                    metrics.active_payloads += count
                elif severity == "medium":
                    metrics.active_payloads += count
                elif severity == "low":
                    metrics.experimental_payloads += count
                else:
                    metrics.deprecated_payloads += count
            
            # Domain distribution
            domain_query = select(
                PromptRecord.category,
                func.count(PromptRecord.id)
            ).group_by(PromptRecord.category)
            
            result = await self.session.execute(domain_query)
            domain_counts = {}
            
            for category, count in result.all():
                # Extract domain from category (format: domain_attacktype)
                if "_" in category:
                    domain_name = category.split("_")[0]
                    if domain_name in [d.value for d in PayloadDomain]:
                        domain = PayloadDomain(domain_name)
                        domain_counts[domain] = domain_counts.get(domain, 0) + count
            
            metrics.domain_counts = domain_counts
            
            # Performance metrics
            perf_query = select(
                func.avg(PromptRecord.success_rate),
                func.count(PromptRecord.id).filter(PromptRecord.success_rate.isnot(None))
            )
            
            result = await self.session.execute(perf_query)
            avg_success, success_count = result.one()
            
            if avg_success:
                metrics.avg_success_rate = float(avg_success)
            
            # Quality metrics
            quality_query = select(
                func.count(PromptRecord.id).filter(PromptRecord.description.isnot(None)),
                func.count(PromptRecord.id).filter(PromptRecord.references != '[]'),
                func.avg(func.json_array_length(PromptRecord.tags))
            )
            
            result = await self.session.execute(quality_query)
            docs_count, refs_count, avg_tags = result.one()
            
            metrics.payloads_with_documentation = docs_count or 0
            metrics.payloads_with_references = refs_count or 0
            metrics.avg_tags_per_payload = float(avg_tags) if avg_tags else 0.0
            
            return metrics
            
        except Exception as e:
            logger.error(f"Failed to get payload metrics: {e}")
            return PayloadMetrics()
    
    async def cleanup_orphaned_records(self) -> int:
        """Clean up orphaned payload records.
        
        Returns:
            Number of records cleaned up
        """
        try:
            # Find records with missing collections
            orphan_query = select(PromptRecord).where(
                ~PromptRecord.collection_id.in_(
                    select(PromptCollectionRecord.id)
                )
            )
            
            result = await self.session.execute(orphan_query)
            orphaned_records = result.scalars().all()
            
            cleanup_count = 0
            for record in orphaned_records:
                await self.session.delete(record)
                cleanup_count += 1
            
            if cleanup_count > 0:
                await self.session.commit()
                logger.info(f"Cleaned up {cleanup_count} orphaned payload records")
            
            return cleanup_count
            
        except Exception as e:
            await self.session.rollback()
            logger.error(f"Failed to cleanup orphaned records: {e}")
            return 0
    
    async def _get_payload_by_hash(self, hash_value: str) -> Optional[PromptRecord]:
        """Get payload record by hash."""
        query = (
            select(PromptRecord)
            .options(selectinload(PromptRecord.collection))
            .where(PromptRecord.hash == hash_value)
        )
        result = await self.session.execute(query)
        return result.scalar_one_or_none()
    
    async def _get_or_create_collection(self, payload: PayloadModel) -> PromptCollectionRecord:
        """Get or create collection for payload."""
        # Use domain and category to determine collection
        # Handle both string and enum types
        domain_str = payload.domain.value if hasattr(payload.domain, 'value') else str(payload.domain)
        category_str = payload.category.value if hasattr(payload.category, 'value') else str(payload.category)
        collection_name = f"{domain_str}_{category_str}"
        
        # Try to get existing collection
        query = (
            select(PromptCollectionRecord)
            .where(PromptCollectionRecord.name == collection_name)
        )
        result = await self.session.execute(query)
        collection = result.scalar_one_or_none()
        
        if collection:
            return collection
        
        # Get or create source
        source = await self._get_or_create_source("local")
        
        # Create new collection
        collection = PromptCollectionRecord(
            source_id=source.id,
            name=collection_name,
            version="1.0.0",
            author=payload.author or "unknown",
            description=f"Collection for {domain_str} {category_str} payloads",
            category=domain_str,
            tags=payload.tags,
            verified=True,
            fetched_at=datetime.utcnow()
        )
        
        self.session.add(collection)
        await self.session.commit()
        await self.session.refresh(collection)
        
        return collection
    
    async def _get_or_create_source(self, source_name: str) -> PromptSourceRecord:
        """Get or create source record."""
        query = select(PromptSourceRecord).where(PromptSourceRecord.name == source_name)
        result = await self.session.execute(query)
        source = result.scalar_one_or_none()
        
        if source:
            return source
        
        # Create new source
        source = PromptSourceRecord(
            name=source_name,
            url="local://payloads",
            priority=100,
            branch="main",
            enabled=True,
            has_token=False,
            added_date=datetime.utcnow()
        )
        
        self.session.add(source)
        await self.session.commit()
        await self.session.refresh(source)
        
        return source
    
    async def _record_to_payload(self, record: PromptRecord) -> Optional[PayloadModel]:
        """Convert database record to PayloadModel object."""
        try:
            # Parse category to extract domain and attack type
            category_parts = record.category.split("_", 1)
            if len(category_parts) != 2:
                logger.warning(f"Invalid category format: {record.category}")
                # Try to use defaults for malformed categories
                domain = AttackDomain.PROMPT
                category = ModuleCategory.UNSPECIFIED
            else:
                domain_str, attack_type = category_parts
                
                # Map old domain values to new AttackDomain enum
                domain_mapping = {
                    "PROMPTS": AttackDomain.PROMPT,
                    "prompt": AttackDomain.PROMPT,
                    "DATA": AttackDomain.DATA,
                    "data": AttackDomain.DATA,
                    "MODEL": AttackDomain.MODEL,
                    "model": AttackDomain.MODEL,
                    "SYSTEM": AttackDomain.SYSTEM,
                    "system": AttackDomain.SYSTEM,
                    "OUTPUT": AttackDomain.OUTPUT,
                    "output": AttackDomain.OUTPUT
                }
                domain = domain_mapping.get(domain_str, AttackDomain.PROMPT)
                
                # Map attack type to category
                category_mapping = {
                    "injection": ModuleCategory.INJECTION,
                    "extraction": ModuleCategory.EXTRACTION,
                    "enumeration": ModuleCategory.ENUMERATION,
                    "poisoning": ModuleCategory.POISONING,
                    "dos": ModuleCategory.DOS,
                    "jailbreak": ModuleCategory.EVASION,
                    "theft": ModuleCategory.THEFT
                }
                category = category_mapping.get(attack_type, ModuleCategory.UNSPECIFIED)
            
            # Map severity
            severity_mapping = {
                "CRITICAL": Severity.CRITICAL,
                "HIGH": Severity.HIGH,
                "MEDIUM": Severity.MEDIUM,
                "LOW": Severity.LOW,
                "INFO": Severity.INFO
            }
            severity = severity_mapping.get(record.severity, Severity.MEDIUM)
            
            # Create PayloadModel using from_minimal and then populate additional fields
            payload = PayloadModel.from_minimal(
                name=record.name,
                content=record.payload,
                domain=domain,
                category=category,
                author=record.collection.author if record.collection else "unknown"
            )
            
            # Set additional fields
            payload.id = record.id
            payload.hash = record.hash
            payload.description = record.description
            payload.severity = severity
            payload.tags = record.tags or []
            payload.expected_indicators = record.expected_indicators or []
            payload.success_rate = record.success_rate
            payload.references = record.references or []
            payload.created_at = record.collection.fetched_at if record.collection else datetime.utcnow()
            payload.updated_at = record.collection.fetched_at if record.collection else datetime.utcnow()
            
            return payload
            
        except Exception as e:
            logger.error(f"Failed to convert record to payload: {e}")
            return None
    
    def _infer_attack_vector(self, attack_type: str) -> str:
        """Infer attack vector from attack type."""
        vector_mapping = {
            "injection": "injection",
            "jailbreak": "evasion", 
            "poisoning": "poisoning",
            "theft": "extraction",
            "enumeration": "enumeration",
            "bypass": "bypass",
            "evasion": "evasion",
            "extraction": "extraction",
            "manipulation": "manipulation",
            "inference": "inference"
        }
        
        return vector_mapping.get(attack_type, "injection")