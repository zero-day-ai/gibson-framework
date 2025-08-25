"""
Integration tests for taxonomy system.

These tests verify the complete end-to-end flow of Gibson's taxonomy system:
1. Full flow from finding creation to tag storage
2. Database migration with sample data  
3. Tag-based querying and filtering
4. All domain modules work with new system
5. Taxonomy mapper integration with findings

Note: These tests are designed to work with both pre-migration (owasp_category) 
and post-migration (tags) database schemas.

IMPORTANT: Database-related tests will pass once the taxonomy migration 
(57b51fa6e084_migrate_owasp_category_to_tags.py) has been applied to the database.
Until then, the core taxonomy functionality (mapping, finding integration, etc.) 
works correctly as verified by the standalone tests.
"""

import asyncio
import json
import pytest
from pathlib import Path
from typing import Dict, List
from uuid import uuid4, UUID

from gibson.db.manager import DatabaseManager
from gibson.core.taxonomy import TaxonomyMapper
from gibson.core.taxonomy.owasp_llm import OWASPLLMMapper
from gibson.models.domain import (
    AttackDomain,
    ModuleCategory,
    Severity,
    FindingStatus,
    FindingModel as ScanFinding,
    ScanResultModel as ScanResult,
    TargetModel,
)
from gibson.db.models.scan import FindingRecord as DBFinding, ScanRecord as DBScanResult


class TestTaxonomyIntegration:
    """Integration tests for complete taxonomy workflow."""

    @pytest.fixture
    async def db_manager(self, tmp_path):
        """Create test database manager."""
        db_path = tmp_path / "test_taxonomy.db"
        db_manager = DatabaseManager(f"sqlite+aiosqlite:///{db_path}")
        await db_manager.initialize()
        yield db_manager
        await db_manager.close()

    @pytest.fixture
    def taxonomy_mapper(self):
        """Create taxonomy mapper instance."""
        return TaxonomyMapper()

    @pytest.fixture
    def sample_scan_id(self):
        """Generate sample scan ID."""
        return uuid4()

    @pytest.fixture
    def sample_target_id(self):
        """Generate sample target ID."""
        return uuid4()

    async def _has_tags_column(self, db_manager) -> bool:
        """Check if the database has been migrated to include tags column."""
        try:
            async with db_manager.get_session() as session:
                # Try to query tags column
                from sqlalchemy import text

                await session.execute(text("SELECT tags FROM findings LIMIT 1"))
                return True
        except Exception:
            return False

    @pytest.mark.asyncio
    async def test_taxonomy_mapper_basic_functionality(self, taxonomy_mapper):
        """Test basic taxonomy mapper functionality."""
        # Test different domain/category combinations
        test_cases = [
            (AttackDomain.PROMPT, ModuleCategory.INJECTION, "OWASP-LLM-01"),
            (AttackDomain.DATA, ModuleCategory.POISONING, "OWASP-LLM-03"),
            (AttackDomain.MODEL, ModuleCategory.THEFT, "OWASP-LLM-10"),
            # Note: SYSTEM domain not currently mapped in OWASP LLM taxonomy
            (AttackDomain.OUTPUT, ModuleCategory.MANIPULATION, "OWASP-LLM-02"),
        ]

        for domain, category, expected_owasp in test_cases:
            # Get taxonomy mappings
            taxonomy_tags = taxonomy_mapper.map_finding(domain, category)

            # Verify mapping worked
            assert isinstance(taxonomy_tags, dict)
            assert len(taxonomy_tags) > 0
            assert "owasp-llm-2025" in taxonomy_tags

            owasp_tags = taxonomy_tags["owasp-llm-2025"]
            assert isinstance(owasp_tags, list)
            assert expected_owasp in owasp_tags

    @pytest.mark.asyncio
    async def test_finding_taxonomy_integration(self, taxonomy_mapper, sample_scan_id):
        """Test taxonomy integration directly with findings."""
        # Create finding
        finding = ScanFinding(
            scan_id=sample_scan_id,
            module="test_module",
            severity=Severity.MEDIUM,
            title="Test Finding",
            description="Test finding for taxonomy integration",
            confidence=80,
            attack_domain=AttackDomain.PROMPT,
            evidence=[],
            remediation="Test remediation",
        )

        # Apply taxonomy mapping
        taxonomy_tags = taxonomy_mapper.map_finding(AttackDomain.PROMPT, ModuleCategory.INJECTION)

        # Add tags to finding
        for taxonomy, tags in taxonomy_tags.items():
            finding.add_taxonomy_tags(taxonomy, tags)

        # Test tag manipulation methods
        assert "owasp-llm-2025" in finding.tags
        owasp_tags = finding.get_taxonomy_tags("owasp-llm-2025")
        assert "OWASP-LLM-01" in owasp_tags

        # Test adding custom taxonomy
        finding.add_taxonomy_tags("custom-taxonomy", ["CUSTOM-001", "CUSTOM-002"])
        custom_tags = finding.get_taxonomy_tags("custom-taxonomy")
        assert len(custom_tags) == 2
        assert "CUSTOM-001" in custom_tags
        assert "CUSTOM-002" in custom_tags

        # Test adding duplicate tags (should be prevented)
        finding.add_taxonomy_tags("custom-taxonomy", ["CUSTOM-001"])  # Duplicate
        custom_tags_after = finding.get_taxonomy_tags("custom-taxonomy")
        assert len(custom_tags_after) == 2  # Should still be 2, no duplicates

    @pytest.mark.asyncio
    async def test_finding_creation_to_storage_flow(
        self, db_manager, taxonomy_mapper, sample_scan_id, sample_target_id
    ):
        """Test complete flow from finding creation to database storage with taxonomy mapping."""
        has_tags = await self._has_tags_column(db_manager)

        async with db_manager.get_session() as session:
            # Create finding using domain models with taxonomy mapping
            finding = ScanFinding(
                scan_id=sample_scan_id,
                module="prompt_injection_basic",
                severity=Severity.HIGH,
                title="Prompt Injection Detected",
                description="Successfully executed prompt injection attack",
                confidence=85,
                attack_domain=AttackDomain.PROMPT,
                evidence=[],
                remediation="Implement input validation and output filtering",
            )

            # Map finding to taxonomies
            taxonomy_tags = taxonomy_mapper.map_finding(
                AttackDomain.PROMPT, ModuleCategory.INJECTION
            )

            # Add taxonomy tags to finding
            for taxonomy, tags in taxonomy_tags.items():
                finding.add_taxonomy_tags(taxonomy, tags)

            # Verify tags were added correctly
            assert "owasp-llm-2025" in finding.tags
            owasp_tags = finding.get_taxonomy_tags("owasp-llm-2025")
            assert "OWASP-LLM-01" in owasp_tags

            # Convert to database model based on schema version
            if has_tags:
                # Post-migration: use tags column
                db_finding = DBFinding(
                    id=uuid4(),
                    scan_id=finding.scan_id,
                    target_id=sample_target_id,
                    module=finding.module,
                    severity=finding.severity.value,
                    title=finding.title,
                    description=finding.description,
                    confidence=finding.confidence,
                    attack_domain=finding.attack_domain.value,
                    status=finding.status.value,
                    evidence=[],
                    remediation=finding.remediation,
                    tags=finding.tags,
                )
            else:
                # Pre-migration: use owasp_category column
                owasp_category = owasp_tags[0] if owasp_tags else None
                db_finding = DBFinding(
                    id=uuid4(),
                    scan_id=finding.scan_id,
                    target_id=sample_target_id,
                    module=finding.module,
                    severity=finding.severity.value,
                    title=finding.title,
                    description=finding.description,
                    confidence=finding.confidence,
                    attack_domain=finding.attack_domain.value,
                    status=finding.status.value,
                    evidence=[],
                    remediation=finding.remediation,
                    owasp_category=owasp_category,
                )

            session.add(db_finding)
            await session.commit()

            # Verify finding was stored correctly
            stored_finding = await session.get(DBFinding, db_finding.id)
            assert stored_finding is not None

            if has_tags:
                assert stored_finding.tags is not None
                assert "owasp-llm-2025" in stored_finding.tags
                assert "OWASP-LLM-01" in stored_finding.tags["owasp-llm-2025"]
            else:
                assert stored_finding.owasp_category == "OWASP-LLM-01"

    @pytest.mark.asyncio
    async def test_database_finding_storage_and_queries(
        self, db_manager, taxonomy_mapper, sample_target_id
    ):
        """Test storing findings in database and querying them."""
        has_tags = await self._has_tags_column(db_manager)

        async with db_manager.get_session() as session:
            # Create diverse test findings
            test_findings_data = [
                {
                    "module": "prompt_injection_basic",
                    "domain": AttackDomain.PROMPT,
                    "category": ModuleCategory.INJECTION,
                    "severity": Severity.HIGH,
                    "title": "Prompt Injection Attack",
                    "confidence": 85,
                },
                {
                    "module": "data_poisoning_basic",
                    "domain": AttackDomain.DATA,
                    "category": ModuleCategory.POISONING,
                    "severity": Severity.MEDIUM,
                    "title": "Data Poisoning Detected",
                    "confidence": 70,
                },
                {
                    "module": "model_theft_basic",
                    "domain": AttackDomain.MODEL,
                    "category": ModuleCategory.THEFT,
                    "severity": Severity.HIGH,
                    "title": "Model Theft Attempt",
                    "confidence": 88,
                },
            ]

            created_findings = []
            for finding_data in test_findings_data:
                # Create finding model
                finding = ScanFinding(
                    scan_id=uuid4(),
                    module=finding_data["module"],
                    severity=finding_data["severity"],
                    title=finding_data["title"],
                    description=f"Test finding for {finding_data['domain'].value}",
                    confidence=finding_data["confidence"],
                    attack_domain=finding_data["domain"],
                    evidence=[],
                    remediation="Test remediation",
                )

                # Apply taxonomy mapping
                taxonomy_tags = taxonomy_mapper.map_finding(
                    finding_data["domain"], finding_data["category"]
                )

                for taxonomy, tags in taxonomy_tags.items():
                    finding.add_taxonomy_tags(taxonomy, tags)

                # Convert to database model
                if has_tags:
                    db_finding = DBFinding(
                        id=uuid4(),
                        scan_id=finding.scan_id,
                        target_id=sample_target_id,
                        module=finding.module,
                        severity=finding.severity.value,
                        title=finding.title,
                        description=finding.description,
                        confidence=finding.confidence,
                        attack_domain=finding.attack_domain.value,
                        status=finding.status.value,
                        evidence=[],
                        remediation=finding.remediation,
                        tags=finding.tags,
                    )
                else:
                    owasp_tags = finding.get_taxonomy_tags("owasp-llm-2025")
                    owasp_category = owasp_tags[0] if owasp_tags else None
                    db_finding = DBFinding(
                        id=uuid4(),
                        scan_id=finding.scan_id,
                        target_id=sample_target_id,
                        module=finding.module,
                        severity=finding.severity.value,
                        title=finding.title,
                        description=finding.description,
                        confidence=finding.confidence,
                        attack_domain=finding.attack_domain.value,
                        status=finding.status.value,
                        evidence=[],
                        remediation=finding.remediation,
                        owasp_category=owasp_category,
                    )

                session.add(db_finding)
                created_findings.append((db_finding, finding))

            await session.commit()

            # Test queries
            from sqlalchemy import select

            # Test 1: Query by attack domain
            stmt = select(DBFinding).where(DBFinding.attack_domain == "prompt")
            result = await session.execute(stmt)
            prompt_findings = result.scalars().all()

            assert len(prompt_findings) >= 1
            for finding in prompt_findings:
                assert finding.attack_domain == "prompt"

            # Test 2: Query by severity
            stmt = select(DBFinding).where(DBFinding.severity == "HIGH")
            result = await session.execute(stmt)
            high_findings = result.scalars().all()

            assert len(high_findings) >= 2  # prompt and model findings are HIGH

            # Test 3: Query by OWASP category (method depends on schema)
            if has_tags:
                # Post-migration: query tags JSON
                from sqlalchemy import text

                stmt = select(DBFinding).where(
                    text("json_extract(tags, '$[\"owasp-llm-2025\"]') LIKE '%OWASP-LLM-01%'")
                )
                result = await session.execute(stmt)
                llm01_findings = result.scalars().all()
            else:
                # Pre-migration: query owasp_category column
                stmt = select(DBFinding).where(DBFinding.owasp_category == "OWASP-LLM-01")
                result = await session.execute(stmt)
                llm01_findings = result.scalars().all()

            assert len(llm01_findings) >= 1  # At least the prompt injection finding

    @pytest.mark.asyncio
    async def test_taxonomy_mapper_error_handling(self, taxonomy_mapper):
        """Test taxonomy mapper error handling and edge cases."""
        # Test with edge case category
        results = taxonomy_mapper.map_finding(AttackDomain.PROMPT, ModuleCategory.UNSPECIFIED)

        # Should still return results or empty dict, but not crash
        assert isinstance(results, dict)

        # Test mapper health validation
        health = taxonomy_mapper.validate_mapper_health()
        assert isinstance(health, dict)
        assert "owasp-llm-2025" in health
        assert health["owasp-llm-2025"] is True

        # Test mapper statistics
        stats = taxonomy_mapper.get_statistics()
        assert "total_mappers" in stats
        assert "supported_taxonomies" in stats
        assert stats["total_mappers"] >= 1  # At least OWASP mapper

        # Test confidence threshold adjustment
        original_threshold = taxonomy_mapper._confidence_threshold
        taxonomy_mapper.set_confidence_threshold(0.8)
        assert taxonomy_mapper._confidence_threshold == 0.8

        # Reset threshold
        taxonomy_mapper.set_confidence_threshold(original_threshold)

        # Test with invalid confidence threshold
        with pytest.raises(ValueError):
            taxonomy_mapper.set_confidence_threshold(1.5)  # > 1.0

        with pytest.raises(ValueError):
            taxonomy_mapper.set_confidence_threshold(-0.1)  # < 0.0

    @pytest.mark.asyncio
    async def test_owasp_llm_mapper_coverage(self):
        """Test OWASP LLM mapper coverage of different attack types."""
        mapper = OWASPLLMMapper()

        # Test specific mappings we know should exist
        test_mappings = [
            (AttackDomain.PROMPT, ModuleCategory.INJECTION, "OWASP-LLM-01"),
            (AttackDomain.DATA, ModuleCategory.POISONING, "OWASP-LLM-03"),
            (AttackDomain.MODEL, ModuleCategory.THEFT, "OWASP-LLM-10"),
        ]

        for domain, category, expected in test_mappings:
            result = mapper.map(domain, category)
            assert isinstance(result, list)
            assert expected in result

        # Test mapper metadata
        assert mapper.taxonomy_id == "owasp-llm-2025"
        assert mapper.taxonomy_name == "OWASP LLM Top 10"

    @pytest.mark.asyncio
    async def test_multiple_taxonomy_mappers(self):
        """Test system with multiple taxonomy mappers registered."""
        # Create mapper with default OWASP mapper
        mapper = TaxonomyMapper()

        # Verify default mapper is registered
        assert len(mapper) >= 1
        assert "owasp-llm-2025" in mapper.get_supported_taxonomies()

        # Test mapping with single mapper
        results = mapper.map_finding(AttackDomain.PROMPT, ModuleCategory.INJECTION)
        assert "owasp-llm-2025" in results

        # Test mapper info
        info = mapper.get_mapper_info()
        assert "owasp-llm-2025" in info
        assert info["owasp-llm-2025"]["taxonomy_name"] == "OWASP LLM Top 10"

        # Test clearing mappers
        original_count = len(mapper)
        cleared_count = mapper.clear_mappers()
        assert cleared_count == original_count
        assert len(mapper) == 0

        # Test re-registering default mappers
        mapper._register_default_mappers()
        assert len(mapper) >= 1

    @pytest.mark.asyncio
    async def test_end_to_end_workflow_simulation(
        self, db_manager, taxonomy_mapper, sample_target_id
    ):
        """Test complete end-to-end workflow simulation."""
        has_tags = await self._has_tags_column(db_manager)

        async with db_manager.get_session() as session:
            # Simulate a scan with multiple findings
            scan_id = uuid4()

            # Create findings with taxonomy mapping
            findings_data = [
                (AttackDomain.PROMPT, ModuleCategory.INJECTION, Severity.CRITICAL, 95),
                (AttackDomain.DATA, ModuleCategory.POISONING, Severity.HIGH, 85),
                (AttackDomain.MODEL, ModuleCategory.THEFT, Severity.MEDIUM, 75),
                (AttackDomain.PROMPT, ModuleCategory.EXTRACTION, Severity.HIGH, 80),
                (AttackDomain.OUTPUT, ModuleCategory.MANIPULATION, Severity.MEDIUM, 70),
            ]

            created_findings = []
            for i, (domain, category, severity, confidence) in enumerate(findings_data):
                # Create finding
                finding = ScanFinding(
                    scan_id=scan_id,
                    module=f"test_module_{i}",
                    severity=severity,
                    title=f"Test Finding {i+1}",
                    description=f"Test finding for {domain.value} domain",
                    confidence=confidence,
                    attack_domain=domain,
                    evidence=[],
                    remediation="Test remediation",
                )

                # Apply taxonomy mapping
                taxonomy_tags = taxonomy_mapper.map_finding(domain, category)
                for taxonomy, tags in taxonomy_tags.items():
                    finding.add_taxonomy_tags(taxonomy, tags)

                # Convert to database model
                if has_tags:
                    db_finding = DBFinding(
                        id=uuid4(),
                        scan_id=scan_id,
                        target_id=sample_target_id,
                        module=finding.module,
                        severity=finding.severity.value,
                        title=finding.title,
                        description=finding.description,
                        confidence=finding.confidence,
                        attack_domain=finding.attack_domain.value,
                        status=finding.status.value,
                        evidence=[],
                        remediation=finding.remediation,
                        tags=finding.tags,
                    )
                else:
                    owasp_tags = finding.get_taxonomy_tags("owasp-llm-2025")
                    owasp_category = owasp_tags[0] if owasp_tags else None
                    db_finding = DBFinding(
                        id=uuid4(),
                        scan_id=scan_id,
                        target_id=sample_target_id,
                        module=finding.module,
                        severity=finding.severity.value,
                        title=finding.title,
                        description=finding.description,
                        confidence=finding.confidence,
                        attack_domain=finding.attack_domain.value,
                        status=finding.status.value,
                        evidence=[],
                        remediation=finding.remediation,
                        owasp_category=owasp_category,
                    )

                session.add(db_finding)
                created_findings.append(db_finding)

            await session.commit()

            # Verify all findings were created
            from sqlalchemy import select

            stmt = select(DBFinding).where(DBFinding.scan_id == scan_id)
            result = await session.execute(stmt)
            all_findings = result.scalars().all()

            assert len(all_findings) == 5

            # Test aggregated reporting by taxonomy
            taxonomy_report = {}
            for finding in all_findings:
                if has_tags and hasattr(finding, "tags") and finding.tags:
                    # Post-migration: use tags
                    for taxonomy, tags in finding.tags.items():
                        if taxonomy not in taxonomy_report:
                            taxonomy_report[taxonomy] = {}
                        for tag in tags:
                            if tag not in taxonomy_report[taxonomy]:
                                taxonomy_report[taxonomy][tag] = []
                            taxonomy_report[taxonomy][tag].append(
                                {
                                    "severity": finding.severity,
                                    "confidence": finding.confidence,
                                    "title": finding.title,
                                }
                            )
                elif finding.owasp_category:
                    # Pre-migration: use owasp_category
                    if "owasp-llm-2025" not in taxonomy_report:
                        taxonomy_report["owasp-llm-2025"] = {}
                    if finding.owasp_category not in taxonomy_report["owasp-llm-2025"]:
                        taxonomy_report["owasp-llm-2025"][finding.owasp_category] = []
                    taxonomy_report["owasp-llm-2025"][finding.owasp_category].append(
                        {
                            "severity": finding.severity,
                            "confidence": finding.confidence,
                            "title": finding.title,
                        }
                    )

            # Verify report contains expected data
            assert "owasp-llm-2025" in taxonomy_report
            owasp_report = taxonomy_report["owasp-llm-2025"]

            # Should have findings across multiple OWASP categories
            assert len(owasp_report) >= 3  # At least 3 different OWASP categories

    @pytest.mark.asyncio
    async def test_performance_with_many_findings(self, db_manager, taxonomy_mapper):
        """Test system performance with moderate numbers of findings."""
        has_tags = await self._has_tags_column(db_manager)

        async with db_manager.get_session() as session:
            # Create a moderate number of findings for performance testing
            findings_count = 20  # Reduced for test stability
            scan_id = uuid4()
            target_id = uuid4()

            domains = list(AttackDomain)
            categories = [ModuleCategory.INJECTION, ModuleCategory.EXTRACTION, ModuleCategory.THEFT]
            severities = list(Severity)

            import time

            start_time = time.time()

            findings = []
            for i in range(findings_count):
                domain = domains[i % len(domains)]
                category = categories[i % len(categories)]
                severity = severities[i % len(severities)]

                # Create finding
                finding = ScanFinding(
                    scan_id=scan_id,
                    module=f"perf_test_module_{i}",
                    severity=severity,
                    title=f"Performance Test Finding {i}",
                    description=f"Performance test finding for {domain.value}",
                    confidence=50 + (i % 50),
                    attack_domain=domain,
                    evidence=[],
                    remediation="Performance test remediation",
                )

                # Apply taxonomy mapping
                taxonomy_tags = taxonomy_mapper.map_finding(domain, category)
                for taxonomy, tags in taxonomy_tags.items():
                    finding.add_taxonomy_tags(taxonomy, tags)

                # Convert to database model
                if has_tags:
                    db_finding = DBFinding(
                        id=uuid4(),
                        scan_id=scan_id,
                        target_id=target_id,
                        module=finding.module,
                        severity=finding.severity.value,
                        title=finding.title,
                        description=finding.description,
                        confidence=finding.confidence,
                        attack_domain=finding.attack_domain.value,
                        status=finding.status.value,
                        evidence=[],
                        remediation=finding.remediation,
                        tags=finding.tags,
                    )
                else:
                    owasp_tags = finding.get_taxonomy_tags("owasp-llm-2025")
                    owasp_category = owasp_tags[0] if owasp_tags else None
                    db_finding = DBFinding(
                        id=uuid4(),
                        scan_id=scan_id,
                        target_id=target_id,
                        module=finding.module,
                        severity=finding.severity.value,
                        title=finding.title,
                        description=finding.description,
                        confidence=finding.confidence,
                        attack_domain=finding.attack_domain.value,
                        status=finding.status.value,
                        evidence=[],
                        remediation=finding.remediation,
                        owasp_category=owasp_category,
                    )

                findings.append(db_finding)

            # Bulk insert
            session.add_all(findings)
            await session.commit()

            creation_time = time.time() - start_time
            assert creation_time < 30.0  # Should complete within 30 seconds

            # Test query performance
            start_time = time.time()

            from sqlalchemy import select

            if has_tags:
                from sqlalchemy import text

                stmt = select(DBFinding).where(
                    text("json_extract(tags, '$[\"owasp-llm-2025\"]') LIKE '%OWASP-LLM-01%'")
                )
            else:
                stmt = select(DBFinding).where(DBFinding.owasp_category == "OWASP-LLM-01")

            result = await session.execute(stmt)
            filtered_findings = result.scalars().all()

            query_time = time.time() - start_time
            assert query_time < 5.0  # Query should complete within 5 seconds

            # Verify results
            assert len(filtered_findings) > 0

            print(
                f"Performance test: Created {findings_count} findings in {creation_time:.2f}s, "
                f"queried {len(filtered_findings)} results in {query_time:.2f}s"
            )

    @pytest.mark.asyncio
    async def test_migration_workflow_simulation(self, db_manager, taxonomy_mapper):
        """Test workflow simulating pre and post migration scenarios."""
        has_tags = await self._has_tags_column(db_manager)

        async with db_manager.get_session() as session:
            # Create findings that simulate the migration scenario
            pre_migration_findings = []

            # Sample OWASP categories that would exist pre-migration
            legacy_owasp_categories = [
                "OWASP-LLM-01",  # Prompt Injection
                "OWASP-LLM-03",  # Training Data Poisoning
                "OWASP-LLM-10",  # Model Theft
                "OWASP-LLM-02",  # Insecure Output Handling
            ]

            scan_id = uuid4()
            target_id = uuid4()

            for i, owasp_cat in enumerate(legacy_owasp_categories):
                # Create finding as it would exist pre-migration
                db_finding = DBFinding(
                    id=uuid4(),
                    scan_id=scan_id,
                    target_id=target_id,
                    module=f"legacy_module_{i}",
                    severity="HIGH",
                    title=f"Legacy Finding {i+1}",
                    description=f"Finding that existed before migration to tags system",
                    confidence=80 + i * 5,
                    attack_domain="prompt"
                    if "01" in owasp_cat
                    else "data"
                    if "03" in owasp_cat
                    else "model",
                    status="open",
                    evidence=[],
                    remediation="Legacy remediation advice",
                    owasp_category=owasp_cat,
                )

                session.add(db_finding)
                pre_migration_findings.append(db_finding)

            await session.commit()

            # Verify pre-migration data
            from sqlalchemy import select

            stmt = select(DBFinding).where(DBFinding.scan_id == scan_id)
            result = await session.execute(stmt)
            stored_findings = result.scalars().all()

            assert len(stored_findings) == 4

            # Test querying by legacy owasp_category
            stmt = select(DBFinding).where(DBFinding.owasp_category == "OWASP-LLM-01")
            result = await session.execute(stmt)
            llm01_findings = result.scalars().all()

            assert len(llm01_findings) >= 1

            # Test migration mapping validation
            for finding in stored_findings:
                if finding.owasp_category:
                    # Verify that we can map legacy categories back to domain/category
                    category_to_domain = {
                        "OWASP-LLM-01": AttackDomain.PROMPT,
                        "OWASP-LLM-02": AttackDomain.OUTPUT,
                        "OWASP-LLM-03": AttackDomain.DATA,
                        "OWASP-LLM-10": AttackDomain.MODEL,
                    }

                    expected_domain = category_to_domain.get(finding.owasp_category)
                    if expected_domain:
                        # Test that taxonomy mapping would produce the same result
                        if finding.owasp_category == "OWASP-LLM-01":
                            mapping = taxonomy_mapper.map_finding(
                                AttackDomain.PROMPT, ModuleCategory.INJECTION
                            )
                        elif finding.owasp_category == "OWASP-LLM-03":
                            mapping = taxonomy_mapper.map_finding(
                                AttackDomain.DATA, ModuleCategory.POISONING
                            )
                        elif finding.owasp_category == "OWASP-LLM-10":
                            mapping = taxonomy_mapper.map_finding(
                                AttackDomain.MODEL, ModuleCategory.THEFT
                            )
                        else:
                            continue

                        assert "owasp-llm-2025" in mapping
                        assert finding.owasp_category in mapping["owasp-llm-2025"]

            print(
                f"Migration workflow test: Verified {len(stored_findings)} legacy findings "
                f"with OWASP categories can be properly mapped to new taxonomy system"
            )
