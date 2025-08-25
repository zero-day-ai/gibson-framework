"""Module validation system for Gibson Framework.

Provides comprehensive validation of module structure, code quality,
security compliance, and dependency requirements.
"""

import ast
import importlib.util
import inspect
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Type
import time

from loguru import logger

from gibson.core.module_management.models import ValidationResult, SecurityIssue
from gibson.core.module_management.security_validator import SecurityValidator
from gibson.core.module_management.exceptions import ModuleValidationError
from gibson.core.modules.base import BaseModule
from gibson.models.module import ModuleDefinitionModel


class ModuleValidator:
    """Comprehensive module validator.

    Validates modules for:
    - Structural requirements (inheritance, methods)
    - Code quality and safety
    - Security compliance
    - Dependency compatibility
    """

    def __init__(self, security_validator: Optional[SecurityValidator] = None):
        """Initialize validator with security validator."""
        self.security_validator = security_validator or SecurityValidator()
        self.required_methods = ["run", "get_config_schema"]
        self.dangerous_imports = {
            "os.system",
            "subprocess.call",
            "eval",
            "exec",
            "compile",
            "__import__",
            "open",
            "file",
            "input",
            "raw_input",
        }

    async def validate_structure(
        self, module_path: Path, expected_base: Type = BaseModule
    ) -> ValidationResult:
        """Validate module structural requirements.

        Args:
            module_path: Path to module file
            expected_base: Expected base class

        Returns:
            ValidationResult with structure validation details
        """
        start_time = time.time()
        result = ValidationResult(valid=True)

        try:
            if not module_path.exists():
                result.add_error(f"Module file not found: {module_path}")
                return result

            if not module_path.is_file() or module_path.suffix != ".py":
                result.add_error(f"Invalid module file: {module_path}")
                return result

            # Load and inspect module
            spec = importlib.util.spec_from_file_location(module_path.stem, module_path)
            if not spec or not spec.loader:
                result.add_error("Could not load module specification")
                return result

            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            # Find module classes
            module_classes = self._find_module_classes(module, expected_base)

            if not module_classes:
                result.add_error(
                    f"No valid module classes found inheriting from {expected_base.__name__}"
                )
                return result

            if len(module_classes) > 1:
                result.add_warning(
                    f"Multiple module classes found: {[cls.__name__ for cls in module_classes]}"
                )

            # Validate primary module class
            primary_class = module_classes[0]
            self._validate_class_structure(primary_class, result)
            self._validate_class_metadata(primary_class, result)

        except Exception as e:
            result.add_error(f"Module loading failed: {str(e)}")

        result.validation_time = time.time() - start_time
        return result

    async def validate_code(self, module_path: Path) -> ValidationResult:
        """Validate module code quality and safety.

        Args:
            module_path: Path to module file

        Returns:
            ValidationResult with code validation details
        """
        start_time = time.time()
        result = ValidationResult(valid=True)

        try:
            if not module_path.exists():
                result.add_error(f"Module file not found: {module_path}")
                return result

            # Parse AST for static analysis
            with open(module_path, "r", encoding="utf-8") as f:
                source_code = f.read()

            try:
                tree = ast.parse(source_code)
            except SyntaxError as e:
                result.add_error(f"Syntax error: {e}")
                return result

            # Analyze AST for potential issues
            self._analyze_imports(tree, result)
            self._analyze_function_calls(tree, result)
            self._analyze_code_complexity(tree, result)
            self._check_code_patterns(tree, result)

        except Exception as e:
            result.add_error(f"Code analysis failed: {str(e)}")

        result.validation_time = time.time() - start_time
        return result

    async def validate_security(self, module_path: Path) -> ValidationResult:
        """Validate module security compliance.

        Args:
            module_path: Path to module file

        Returns:
            ValidationResult with security validation details
        """
        return await self.security_validator.validate_security(module_path)

    async def validate_dependencies(self, deps: List[str]) -> ValidationResult:
        """Validate module dependencies.

        Args:
            deps: List of dependency specifications

        Returns:
            ValidationResult with dependency validation
        """
        start_time = time.time()
        result = ValidationResult(valid=True)

        try:
            for dep in deps:
                if not self._is_valid_dependency_spec(dep):
                    result.add_error(f"Invalid dependency specification: {dep}")
                    continue

                # Check if dependency is potentially dangerous
                if self._is_dangerous_dependency(dep):
                    result.add_security_issue(
                        SecurityIssue(
                            issue_type="dangerous_dependency",
                            severity="medium",
                            description=f"Potentially dangerous dependency: {dep}",
                            recommendation="Review dependency for security implications",
                        )
                    )

                # Check for known vulnerable versions
                vuln_check = self._check_vulnerability_database(dep)
                if vuln_check:
                    result.add_security_issue(vuln_check)

        except Exception as e:
            result.add_error(f"Dependency validation failed: {str(e)}")

        result.validation_time = time.time() - start_time
        return result

    async def validate_signature(self, module_path: Path) -> bool:
        """Validate module digital signature.

        Args:
            module_path: Path to module file

        Returns:
            True if signature is valid or no signature required
        """
        # Placeholder for signature validation
        # In production, would integrate with GPG or similar
        signature_file = module_path.with_suffix(module_path.suffix + ".sig")
        return not signature_file.exists()  # Pass if no signature file

    def get_required_permissions(self, module_path: Path) -> List[str]:
        """Extract required permissions from module.

        Args:
            module_path: Path to module file

        Returns:
            List of required permission strings
        """
        permissions = []

        try:
            with open(module_path, "r", encoding="utf-8") as f:
                source_code = f.read()

            tree = ast.parse(source_code)

            # Look for permission declarations in docstrings or comments
            for node in ast.walk(tree):
                if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
                    if isinstance(node.value.value, str):
                        content = node.value.value
                        if "REQUIRES_PERMISSION:" in content:
                            perms = content.split("REQUIRES_PERMISSION:")[1].strip()
                            permissions.extend(p.strip() for p in perms.split(","))

                # Check for dangerous operations that might require permissions
                elif isinstance(node, (ast.Import, ast.ImportFrom)):
                    module_name = getattr(node, "module", None)
                    if module_name in ["os", "subprocess", "socket", "urllib"]:
                        permissions.append(f"system_access:{module_name}")

        except Exception as e:
            logger.warning(f"Could not extract permissions from {module_path}: {e}")

        return list(set(permissions))  # Remove duplicates

    # Private helper methods

    def _find_module_classes(self, module: Any, expected_base: Type) -> List[Type]:
        """Find all classes inheriting from expected base."""
        classes = []

        for name, obj in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(obj, expected_base)
                and obj is not expected_base
                and obj.__module__ == module.__name__
            ):
                classes.append(obj)

        return classes

    def _validate_class_structure(self, cls: Type, result: ValidationResult) -> None:
        """Validate class has required methods and structure."""
        # Check required methods
        for method_name in self.required_methods:
            if not hasattr(cls, method_name):
                result.add_error(f"Missing required method: {method_name}")
                continue

            method = getattr(cls, method_name)
            if not callable(method):
                result.add_error(f"Required attribute {method_name} is not callable")
                continue

            # Check method signature
            try:
                sig = inspect.signature(method)
                if method_name == "run":
                    params = list(sig.parameters.keys())
                    if len(params) < 2:  # self + target at minimum
                        result.add_error(
                            "run() method must accept at least (self, target) parameters"
                        )
            except Exception as e:
                result.add_warning(f"Could not inspect {method_name} signature: {e}")

        # Check for async run method
        if hasattr(cls, "run"):
            if not inspect.iscoroutinefunction(cls.run):
                result.add_error("run() method must be async")

    def _validate_class_metadata(self, cls: Type, result: ValidationResult) -> None:
        """Validate class metadata attributes."""
        required_attrs = ["name", "version", "description"]
        recommended_attrs = ["author", "license", "category"]

        for attr in required_attrs:
            if not hasattr(cls, attr):
                result.add_error(f"Missing required class attribute: {attr}")
            elif not getattr(cls, attr):
                result.add_error(f"Empty required class attribute: {attr}")

        for attr in recommended_attrs:
            if not hasattr(cls, attr) or not getattr(cls, attr):
                result.add_warning(f"Missing recommended class attribute: {attr}")

    def _analyze_imports(self, tree: ast.AST, result: ValidationResult) -> None:
        """Analyze module imports for dangerous patterns."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self._check_import_safety(alias.name, result)

            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    import_name = f"{module}.{alias.name}" if module else alias.name
                    self._check_import_safety(import_name, result)

    def _check_import_safety(self, import_name: str, result: ValidationResult) -> None:
        """Check if import is potentially dangerous."""
        if import_name in self.dangerous_imports:
            result.add_security_issue(
                SecurityIssue(
                    issue_type="dangerous_import",
                    severity="high",
                    description=f"Potentially dangerous import: {import_name}",
                    recommendation="Use safer alternatives or justify usage",
                )
            )

        # Check for imports that might indicate malicious behavior
        suspicious_patterns = [
            "ctypes",
            "ctypes.util",
            "win32api",
            "win32con",
            "multiprocessing",
            "threading",
            "asyncio.subprocess",
        ]

        for pattern in suspicious_patterns:
            if pattern in import_name:
                result.add_warning(f"Import requires review for security: {import_name}")

    def _analyze_function_calls(self, tree: ast.AST, result: ValidationResult) -> None:
        """Analyze function calls for dangerous patterns."""
        dangerous_calls = {
            "eval",
            "exec",
            "compile",
            "__import__",
            "open",
            "file",
            "input",
            "raw_input",
        }

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                    if func_name in dangerous_calls:
                        result.add_security_issue(
                            SecurityIssue(
                                issue_type="dangerous_function_call",
                                severity="critical",
                                description=f"Dangerous function call: {func_name}()",
                                location=f"line {node.lineno}",
                                recommendation="Remove or replace with safer alternative",
                            )
                        )

                elif isinstance(node.func, ast.Attribute):
                    if isinstance(node.func.value, ast.Name):
                        obj_name = node.func.value.id
                        attr_name = node.func.attr
                        call_name = f"{obj_name}.{attr_name}"

                        if call_name in self.dangerous_imports:
                            result.add_security_issue(
                                SecurityIssue(
                                    issue_type="dangerous_method_call",
                                    severity="high",
                                    description=f"Dangerous method call: {call_name}()",
                                    location=f"line {node.lineno}",
                                    recommendation="Use safer alternatives",
                                )
                            )

    def _analyze_code_complexity(self, tree: ast.AST, result: ValidationResult) -> None:
        """Analyze code complexity metrics."""
        complexity_visitor = ComplexityVisitor()
        complexity_visitor.visit(tree)

        if complexity_visitor.max_complexity > 20:
            result.add_warning(
                f"High cyclomatic complexity detected: {complexity_visitor.max_complexity}"
            )

        if complexity_visitor.nesting_depth > 6:
            result.add_warning(f"Deep nesting detected: {complexity_visitor.nesting_depth} levels")

    def _check_code_patterns(self, tree: ast.AST, result: ValidationResult) -> None:
        """Check for problematic code patterns."""
        for node in ast.walk(tree):
            # Check for bare except clauses
            if isinstance(node, ast.ExceptHandler):
                if node.type is None:
                    result.add_warning(
                        f"Bare except clause at line {node.lineno} - specify exception types"
                    )

            # Check for print statements (should use logging)
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id == "print":
                    result.add_warning(
                        f"Print statement at line {node.lineno} - use logging instead"
                    )

    def _is_valid_dependency_spec(self, dep: str) -> bool:
        """Check if dependency specification is valid."""
        if not dep or not isinstance(dep, str):
            return False

        # Basic validation - more sophisticated validation would use packaging
        invalid_chars = ["<script>", "${", "`", ";", "&&", "||"]
        return not any(char in dep for char in invalid_chars)

    def _is_dangerous_dependency(self, dep: str) -> bool:
        """Check if dependency is potentially dangerous."""
        dangerous_keywords = [
            "backdoor",
            "malware",
            "virus",
            "trojan",
            "keylogger",
            "rootkit",
            "exploit",
        ]
        dep_lower = dep.lower()
        return any(keyword in dep_lower for keyword in dangerous_keywords)

    def _check_vulnerability_database(self, dep: str) -> Optional[SecurityIssue]:
        """Check dependency against vulnerability databases."""
        # Placeholder for vulnerability checking
        # In production, would integrate with OSV, Safety DB, etc.

        # Mock vulnerable packages for demonstration
        known_vulnerable = {"requests<2.20.0": "CVE-2018-18074", "urllib3<1.24.2": "CVE-2019-11324"}

        for vuln_spec, cve in known_vulnerable.items():
            if dep.startswith(vuln_spec.split("<")[0]):
                return SecurityIssue(
                    issue_type="vulnerable_dependency",
                    severity="high",
                    description=f"Vulnerable dependency: {dep}",
                    recommendation=f"Update to fix {cve}",
                    cwe_id=cve,
                )

        return None


class ComplexityVisitor(ast.NodeVisitor):
    """AST visitor for calculating code complexity metrics."""

    def __init__(self):
        self.complexity = 1  # Base complexity
        self.max_complexity = 1
        self.nesting_depth = 0
        self.max_nesting_depth = 0

    def visit_FunctionDef(self, node):
        # Reset complexity for each function
        old_complexity = self.complexity
        self.complexity = 1

        self.generic_visit(node)

        # Update max complexity
        if self.complexity > self.max_complexity:
            self.max_complexity = self.complexity

        # Restore complexity
        self.complexity = old_complexity

    def visit_If(self, node):
        self.complexity += 1
        self._visit_nested(node)

    def visit_For(self, node):
        self.complexity += 1
        self._visit_nested(node)

    def visit_While(self, node):
        self.complexity += 1
        self._visit_nested(node)

    def visit_Try(self, node):
        self.complexity += 1
        self._visit_nested(node)

    def _visit_nested(self, node):
        """Visit nested node with depth tracking."""
        self.nesting_depth += 1
        if self.nesting_depth > self.max_nesting_depth:
            self.max_nesting_depth = self.nesting_depth

        self.generic_visit(node)
        self.nesting_depth -= 1
