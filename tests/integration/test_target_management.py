"""Integration tests for target management system."""

import asyncio
import pytest
from pathlib import Path
from uuid import uuid4

from gibson.db.manager import DatabaseManager
from gibson.core.targets import TargetManager
from gibson.models.target import TargetType, TargetStatus, LLMProvider
from gibson.models.auth import ApiKeyFormat


class TestTargetManagementIntegration:
    """Integration tests for complete target management workflow."""
    
    @pytest.fixture
    async def db_manager(self, tmp_path):
        """Create test database manager."""
        db_path = tmp_path / "test.db"
        db_manager = DatabaseManager(f"sqlite+aiosqlite:///{db_path}")
        await db_manager.initialize()
        return db_manager
    
    @pytest.mark.asyncio
    async def test_complete_target_workflow(self, db_manager):
        """Test complete target management workflow."""
        async with db_manager.get_session() as session:
            target_manager = TargetManager(session)
            
            # 1. Create target
            target = await target_manager.create_target(
                name="integration-test-api",
                base_url="https://api.openai.com/v1",
                target_type=TargetType.API,
                description="Integration test target",
                environment="test",
                tags=["integration", "test"]
            )
            
            assert target.name == "integration-test-api"
            assert target.provider == LLMProvider.OPENAI  # Auto-detected
            assert target.status == TargetStatus.PENDING_VERIFICATION
            
            # 2. Set credential
            success = await target_manager.set_target_credential(
                target.id,
                api_key="sk-test123456789",
                key_format=ApiKeyFormat.BEARER_TOKEN,
                validate=False  # Skip validation in test
            )
            assert success is True
            
            # 3. Update target
            updated = await target_manager.update_target(
                target,
                description="Updated integration test target",
                status=TargetStatus.ACTIVE
            )
            assert updated.description == "Updated integration test target"
            assert updated.status == TargetStatus.ACTIVE
            
            # 4. List targets
            targets = await target_manager.list_targets()
            assert len(targets) >= 1
            assert any(t.name == "integration-test-api" for t in targets)
            
            # 5. Search targets
            results = await target_manager.search_targets("integration")
            assert len(results) >= 1
            assert results[0].name == "integration-test-api"
            
            # 6. Get statistics
            stats = await target_manager.get_statistics()
            assert stats["total_targets"] >= 1
            assert stats["active_targets"] >= 1
            
            # 7. Remove credential
            success = await target_manager.remove_target_credential(target.id)
            assert success is True
            
            # 8. Delete target
            success = await target_manager.delete_target(target.id)
            assert success is True
            
            # Verify deletion
            deleted = await target_manager.get_target(target.id)
            assert deleted is None
    
    @pytest.mark.asyncio
    async def test_export_import_workflow(self, db_manager, tmp_path):
        """Test export/import workflow."""
        async with db_manager.get_session() as session:
            target_manager = TargetManager(session)
            
            # Create test targets
            targets = []
            for i in range(3):
                target = await target_manager.create_target(
                    name=f"export-test-{i}",
                    base_url=f"https://api{i}.test.com",
                    target_type=TargetType.API,
                    environment="test",
                    tags=["export", f"test-{i}"]
                )
                targets.append(target)
            
            # Export targets
            export_file = tmp_path / "targets_export.json"
            export_count = await target_manager.export_targets(
                export_file,
                include_credentials=False,
                filter_kwargs={"environment": "test"}
            )
            
            assert export_count == 3
            assert export_file.exists()
            
            # Delete targets
            for target in targets:
                await target_manager.delete_target(target.id)
            
            # Verify deletion
            remaining = await target_manager.list_targets(environment="test")
            test_targets = [t for t in remaining if t.name.startswith("export-test-")]
            assert len(test_targets) == 0
            
            # Import targets back
            import_stats = await target_manager.import_targets(
                export_file,
                update_existing=False
            )
            
            assert import_stats["total"] == 3
            assert import_stats["created"] == 3
            assert import_stats["errors"] == 0
            
            # Verify import
            imported = await target_manager.list_targets(environment="test")
            imported_test_targets = [t for t in imported if t.name.startswith("export-test-")]
            assert len(imported_test_targets) == 3
    
    @pytest.mark.asyncio
    async def test_provider_detection(self, db_manager):
        """Test automatic provider detection."""
        async with db_manager.get_session() as session:
            target_manager = TargetManager(session)
            
            test_cases = [
                ("https://api.openai.com/v1", LLMProvider.OPENAI),
                ("https://api.anthropic.com/v1", LLMProvider.ANTHROPIC),
                ("https://custom-api.example.com", LLMProvider.LITELLM),  # Default
            ]
            
            for base_url, expected_provider in test_cases:
                target = await target_manager.create_target(
                    name=f"provider-test-{expected_provider.value}",
                    base_url=base_url,
                    target_type=TargetType.API
                )
                
                assert target.provider == expected_provider
                
                # Clean up
                await target_manager.delete_target(target.id)
    
    @pytest.mark.asyncio
    async def test_validation_workflow(self, db_manager):
        """Test target validation workflow."""
        async with db_manager.get_session() as session:
            target_manager = TargetManager(session)
            
            # Create target
            target = await target_manager.create_target(
                name="validation-test",
                base_url="https://httpbin.org/status/200",  # Reliable test endpoint
                target_type=TargetType.API
            )
            
            # Test validation (connectivity only)
            result = await target_manager.validate_target(
                target.id,
                test_connection=True,
                validate_credentials=False
            )
            
            # Check validation result
            assert "overall_valid" in result
            assert "config_valid" in result
            assert "connectivity_valid" in result
            assert result["config_valid"] is True  # Config should be valid
            
            # Clean up
            await target_manager.delete_target(target.id)
    
    @pytest.mark.asyncio
    async def test_concurrent_operations(self, db_manager):
        """Test concurrent target operations."""
        async with db_manager.get_session() as session:
            target_manager = TargetManager(session)
            
            # Create targets concurrently
            async def create_target(i):
                return await target_manager.create_target(
                    name=f"concurrent-test-{i}",
                    base_url=f"https://api{i}.test.com",
                    target_type=TargetType.API
                )
            
            # Create 5 targets concurrently
            tasks = [create_target(i) for i in range(5)]
            targets = await asyncio.gather(*tasks)
            
            assert len(targets) == 5
            for i, target in enumerate(targets):
                assert target.name == f"concurrent-test-{i}"
            
            # List all targets
            all_targets = await target_manager.list_targets()
            concurrent_targets = [t for t in all_targets if t.name.startswith("concurrent-test-")]
            assert len(concurrent_targets) == 5
            
            # Clean up concurrently
            async def delete_target(target):
                return await target_manager.delete_target(target.id)
            
            delete_tasks = [delete_target(target) for target in targets]
            delete_results = await asyncio.gather(*delete_tasks)
            
            assert all(delete_results)  # All deletions should succeed