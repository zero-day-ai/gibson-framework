"""
Integration tests for LiteLLM module adapter.

Tests the adapter in realistic scenarios with actual module instances.
"""

import asyncio
import pytest
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

from gibson.core.modules.base import BaseModule
from gibson.core.llm.module_adapter import ModuleAuthHelper, check_migration_status
from gibson.models.scan import Finding
from gibson.models.target import TargetModel as Target
from gibson.models.domain import ModuleCategory, Severity


class MockLegacyModule(BaseModule):
    """Mock legacy module for integration testing."""

    name = "mock_legacy_module"
    version = "1.0.0"
    description = "Mock legacy module for testing"
    category = ModuleCategory.INJECTION

    def __init__(self, config=None, base_orchestrator=None, llm_client_factory=None):
        super().__init__(config, base_orchestrator, llm_client_factory)

        # Simulate legacy credential manager
        self.credential_manager = (
            Mock()
            if base_orchestrator is None
            else getattr(base_orchestrator, "credential_manager", None)
        )

        # Create auth helper for backward compatibility
        self.auth_helper = ModuleAuthHelper(
            module_instance=self,
            credential_manager=self.credential_manager,
            llm_client_factory=llm_client_factory,
        )

    async def run(self, target: Target, config: Optional[Dict[str, Any]] = None) -> List[Finding]:
        """Simulate legacy module execution using auth helper."""
        findings = []

        try:
            # Use auth helper for backward compatibility
            client = await self.auth_helper.get_authenticated_client("openai")

            if client:
                findings.append(
                    Finding(
                        id=uuid4(),
                        title="Legacy Module Success",
                        description="Successfully used auth helper to get client",
                        severity=Severity.INFO,
                        category=self.category,
                        module_name=self.name,
                    )
                )
            else:
                findings.append(
                    Finding(
                        id=uuid4(),
                        title="Legacy Module Auth Failed",
                        description="Could not authenticate via auth helper",
                        severity=Severity.HIGH,
                        category=self.category,
                        module_name=self.name,
                    )
                )

        except Exception as e:
            findings.append(
                Finding(
                    id=uuid4(),
                    title="Legacy Module Error",
                    description=f"Error in legacy module: {str(e)}",
                    severity=Severity.MEDIUM,
                    category=self.category,
                    module_name=self.name,
                )
            )

        return findings

    def get_config_schema(self) -> Dict[str, Any]:
        return {"type": "object", "properties": {}}


class MockModernModule(BaseModule):
    """Mock modern module for integration testing."""

    name = "mock_modern_module"
    version = "2.0.0"
    description = "Mock modern module for testing"
    category = ModuleCategory.LLM_PROMPT_INJECTION

    async def run(self, target: Target, config: Optional[Dict[str, Any]] = None) -> List[Finding]:
        """Simulate modern module execution using built-in LLM client."""
        findings = []

        try:
            # Use built-in LLM client method (modern pattern)
            if self.llm_available:
                client = await self.get_llm_client("openai")
                findings.append(
                    Finding(
                        id=uuid4(),
                        title="Modern Module Success",
                        description="Successfully used built-in LLM client",
                        severity=Severity.INFO,
                        category=self.category,
                        module_name=self.name,
                    )
                )
            else:
                findings.append(
                    Finding(
                        id=uuid4(),
                        title="Modern Module LLM Unavailable",
                        description="LLM functionality not available",
                        severity=Severity.MEDIUM,
                        category=self.category,
                        module_name=self.name,
                    )
                )

        except Exception as e:
            findings.append(
                Finding(
                    id=uuid4(),
                    title="Modern Module Error",
                    description=f"Error in modern module: {str(e)}",
                    severity=Severity.MEDIUM,
                    category=self.category,
                    module_name=self.name,
                )
            )

        return findings

    def get_config_schema(self) -> Dict[str, Any]:
        return {"type": "object", "properties": {}}


@pytest.fixture
def mock_target():
    """Create mock target for testing."""
    target = Mock(spec=Target)
    target.id = uuid4()
    target.url = "https://example.com/api"
    return target


@pytest.fixture
def mock_credential_manager():
    """Create mock credential manager."""
    manager = Mock()
    manager.retrieve_credential = AsyncMock()
    return manager


@pytest.fixture
def mock_llm_client_factory():
    """Create mock LLM client factory."""
    factory = Mock()
    factory.get_client = AsyncMock()
    return factory


class TestLegacyModuleIntegration:
    """Test legacy module with auth adapter integration."""

    @pytest.mark.asyncio
    async def test_legacy_module_without_llm_factory(self, mock_target):
        """Test legacy module behavior without LLM client factory."""
        module = MockLegacyModule()

        findings = await module.run(mock_target)

        # Should have findings indicating auth failure
        assert len(findings) == 1
        assert findings[0].title == "Legacy Module Auth Failed"
        assert findings[0].severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_legacy_module_with_mock_factory(self, mock_target, mock_llm_client_factory):
        """Test legacy module with mocked LLM client factory."""
        # Setup mock client
        mock_client = Mock()
        mock_llm_client_factory.get_client.return_value = mock_client

        module = MockLegacyModule(llm_client_factory=mock_llm_client_factory)

        findings = await module.run(mock_target)

        # Should succeed with mock factory
        assert len(findings) == 1
        assert findings[0].title == "Legacy Module Success"
        assert findings[0].severity == Severity.INFO

    def test_legacy_module_migration_status(self):
        """Test migration status of legacy module."""
        module = MockLegacyModule()

        status = check_migration_status(module)

        # Legacy module should not be fully migrated
        assert status["migration_complete"] is False
        assert status["has_llm_client_factory"] is False
        assert status["has_get_llm_client"] is False
        assert len(status["recommendations"]) > 0

    @pytest.mark.asyncio
    async def test_legacy_module_auth_validation(self, mock_llm_client_factory):
        """Test authentication validation for legacy module."""
        # Setup mock for health check
        mock_client = Mock()
        mock_client.health_check = AsyncMock(return_value=True)
        mock_llm_client_factory.get_client.return_value = mock_client

        module = MockLegacyModule(llm_client_factory=mock_llm_client_factory)

        is_valid = await module.auth_helper.validate_authentication("openai")

        assert is_valid is True


class TestModernModuleIntegration:
    """Test modern module integration."""

    @pytest.mark.asyncio
    async def test_modern_module_without_llm_factory(self, mock_target):
        """Test modern module behavior without LLM client factory."""
        module = MockModernModule()

        findings = await module.run(mock_target)

        # Should indicate LLM unavailable
        assert len(findings) == 1
        assert findings[0].title == "Modern Module LLM Unavailable"
        assert findings[0].severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_modern_module_with_factory(self, mock_target, mock_llm_client_factory):
        """Test modern module with LLM client factory."""
        mock_client = Mock()
        mock_llm_client_factory.get_client.return_value = mock_client

        module = MockModernModule(llm_client_factory=mock_llm_client_factory)

        findings = await module.run(mock_target)

        # Should succeed with mock factory
        assert len(findings) == 1
        assert findings[0].title == "Modern Module Success"
        assert findings[0].severity == Severity.INFO

    def test_modern_module_migration_status(self, mock_llm_client_factory):
        """Test migration status of modern module."""
        module = MockModernModule(llm_client_factory=mock_llm_client_factory)

        status = check_migration_status(module)

        # Modern module should be fully migrated
        assert status["migration_complete"] is True
        assert status["has_llm_client_factory"] is True
        assert status["has_get_llm_client"] is True


class TestMigrationComparison:
    """Test comparison between legacy and modern modules."""

    @pytest.mark.asyncio
    async def test_side_by_side_execution(self, mock_target, mock_llm_client_factory):
        """Test both legacy and modern modules side by side."""
        mock_client = Mock()
        mock_llm_client_factory.get_client.return_value = mock_client

        # Create both types of modules
        legacy_module = MockLegacyModule(llm_client_factory=mock_llm_client_factory)
        modern_module = MockModernModule(llm_client_factory=mock_llm_client_factory)

        # Execute both
        legacy_findings = await legacy_module.run(mock_target)
        modern_findings = await modern_module.run(mock_target)

        # Both should succeed
        assert len(legacy_findings) == 1
        assert len(modern_findings) == 1
        assert legacy_findings[0].severity == Severity.INFO
        assert modern_findings[0].severity == Severity.INFO

    def test_migration_guidance_comparison(self, mock_llm_client_factory):
        """Test migration guidance for both module types."""
        legacy_module = MockLegacyModule()
        modern_module = MockModernModule(llm_client_factory=mock_llm_client_factory)

        legacy_status = check_migration_status(legacy_module)
        modern_status = check_migration_status(modern_module)

        # Legacy should need migration
        assert not legacy_status["migration_complete"]
        assert len(legacy_status["recommendations"]) >= 2

        # Modern should be complete
        assert modern_status["migration_complete"]
        assert "✅" in modern_status["recommendations"][0]


class TestAuthHelperIntegration:
    """Test ModuleAuthHelper integration scenarios."""

    @pytest.mark.asyncio
    async def test_auth_helper_fallback_chain(
        self, mock_credential_manager, mock_llm_client_factory
    ):
        """Test authentication fallback chain."""
        # Setup credential manager fallback
        mock_credential = Mock()
        mock_credential.token = "fallback-key"
        mock_credential_manager.retrieve_credential.return_value = mock_credential

        # Setup LLM factory to fail initially
        mock_llm_client_factory.get_client.side_effect = Exception("LLM factory failed")

        module = MockLegacyModule(llm_client_factory=mock_llm_client_factory)
        module.credential_manager = mock_credential_manager

        # Should fall back gracefully
        helper = ModuleAuthHelper(
            module_instance=module,
            credential_manager=mock_credential_manager,
            llm_client_factory=mock_llm_client_factory,
        )

        # This should not raise an exception
        client = await helper.get_authenticated_client("openai")
        # Without working LLM factory, should return None
        assert client is None

    def test_auth_helper_migration_guidance(self):
        """Test migration guidance from auth helper."""
        module = MockLegacyModule()
        helper = ModuleAuthHelper(module_instance=module)

        guidance = helper.get_migration_guidance()

        assert guidance["module_name"] == "mock_legacy_module"
        assert guidance["current_pattern"] == "legacy_credential_manager"
        assert guidance["recommended_pattern"] == "llm_client_factory"
        assert len(guidance["migration_steps"]) >= 5
        assert len(guidance["benefits"]) >= 4


# Test runner for pytest
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
