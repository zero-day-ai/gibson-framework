"""Security validation for Gibson Framework modules.

Provides specialized security analysis including malicious pattern detection,
signature verification, and permission requirement extraction.
"""

import ast
import hashlib
import re
from pathlib import Path
from typing import List, Optional, Set
import time

from loguru import logger

from gibson.core.module_management.models import ValidationResult, SecurityIssue


class SecurityValidator:
    """Specialized security validator for modules.

    Performs deep security analysis including:
    - Malicious pattern detection
    - Code obfuscation detection
    - Network activity analysis
    - File system access patterns
    - Privilege escalation attempts
    """

    def __init__(self):
        """Initialize security validator with threat patterns."""
        self.malicious_patterns = self._load_malicious_patterns()
        self.suspicious_functions = self._load_suspicious_functions()
        self.network_patterns = self._load_network_patterns()
        self.file_patterns = self._load_file_patterns()
        self.obfuscation_indicators = self._load_obfuscation_indicators()

    async def validate_security(self, module_path: Path) -> ValidationResult:
        """Perform comprehensive security validation.

        Args:
            module_path: Path to module file

        Returns:
            ValidationResult with security analysis
        """
        start_time = time.time()
        result = ValidationResult(valid=True)

        try:
            if not module_path.exists():
                result.add_error(f"Module file not found: {module_path}")
                return result

            # Read source code
            with open(module_path, "r", encoding="utf-8") as f:
                source_code = f.read()

            # Parse AST for analysis
            try:
                tree = ast.parse(source_code)
            except SyntaxError as e:
                result.add_error(f"Syntax error prevents security analysis: {e}")
                return result

            # Perform security checks
            await self._check_malicious_patterns(source_code, result)
            await self._check_obfuscation(source_code, tree, result)
            await self._analyze_imports(tree, result)
            await self._analyze_network_activity(tree, result)
            await self._analyze_file_operations(tree, result)
            await self._check_privilege_escalation(tree, result)
            await self._analyze_code_injection(tree, result)
            await self._check_data_exfiltration(tree, result)

            # Calculate overall risk level
            self._calculate_risk_level(result)

        except Exception as e:
            result.add_error(f"Security validation failed: {str(e)}")
            logger.error(f"Security validation error for {module_path}: {e}")

        result.validation_time = time.time() - start_time
        return result

    async def verify_signature(self, module_path: Path) -> bool:
        """Verify module digital signature.

        Args:
            module_path: Path to module file

        Returns:
            True if signature is valid
        """
        # Placeholder for GPG signature verification
        # In production, would integrate with GPG/cryptography
        signature_file = module_path.with_suffix(".sig")

        if not signature_file.exists():
            logger.debug(f"No signature file found for {module_path}")
            return True  # No signature required

        # Mock signature verification
        try:
            with open(signature_file, "r") as f:
                signature_content = f.read().strip()

            # Basic validation - signature should not be empty
            return len(signature_content) > 0

        except Exception as e:
            logger.warning(f"Signature verification failed for {module_path}: {e}")
            return False

    def extract_permissions(self, module_path: Path) -> List[str]:
        """Extract required permissions from module.

        Args:
            module_path: Path to module file

        Returns:
            List of required permission strings
        """
        permissions = set()

        try:
            with open(module_path, "r", encoding="utf-8") as f:
                source_code = f.read()

            tree = ast.parse(source_code)

            # Check imports for permission requirements
            for node in ast.walk(tree):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    module_name = getattr(node, "module", None)

                    # System access permissions
                    if module_name == "os":
                        permissions.add("system_access")
                    elif module_name == "subprocess":
                        permissions.add("process_execution")
                    elif module_name in ["socket", "urllib", "requests", "httpx"]:
                        permissions.add("network_access")
                    elif module_name in ["sqlite3", "psycopg2", "pymongo"]:
                        permissions.add("database_access")
                    elif module_name == "threading":
                        permissions.add("thread_creation")
                    elif module_name == "multiprocessing":
                        permissions.add("process_creation")

                # Check for file operations
                elif isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        if node.func.id in ["open", "file"]:
                            permissions.add("file_access")

            # Check docstrings for explicit permission declarations
            permission_pattern = r"REQUIRES_PERMISSION:\s*([\w,\s_-]+)"
            matches = re.findall(permission_pattern, source_code, re.IGNORECASE)
            for match in matches:
                perms = [p.strip() for p in match.split(",")]
                permissions.update(perms)

        except Exception as e:
            logger.warning(f"Could not extract permissions from {module_path}: {e}")

        return list(permissions)

    def generate_security_report(self, result: ValidationResult) -> dict:
        """Generate detailed security report.

        Args:
            result: Validation result with security issues

        Returns:
            Detailed security report dictionary
        """
        report = {
            "overall_risk": result.risk_level,
            "issues_found": len(result.security_issues),
            "critical_issues": len([i for i in result.security_issues if i.severity == "critical"]),
            "high_issues": len([i for i in result.security_issues if i.severity == "high"]),
            "medium_issues": len([i for i in result.security_issues if i.severity == "medium"]),
            "low_issues": len([i for i in result.security_issues if i.severity == "low"]),
            "recommendations": [],
            "required_permissions": result.required_permissions,
            "validation_time": result.validation_time,
        }

        # Collect recommendations
        for issue in result.security_issues:
            if issue.recommendation and issue.recommendation not in report["recommendations"]:
                report["recommendations"].append(issue.recommendation)

        return report

    # Private security check methods

    async def _check_malicious_patterns(self, source_code: str, result: ValidationResult) -> None:
        """Check for known malicious patterns in source code."""
        for pattern_name, pattern in self.malicious_patterns.items():
            if re.search(pattern, source_code, re.IGNORECASE | re.MULTILINE):
                result.add_security_issue(
                    SecurityIssue(
                        issue_type="malicious_pattern",
                        severity="critical",
                        description=f"Malicious pattern detected: {pattern_name}",
                        recommendation="Remove malicious code or provide justification",
                    )
                )

    async def _check_obfuscation(
        self, source_code: str, tree: ast.AST, result: ValidationResult
    ) -> None:
        """Check for code obfuscation indicators."""
        obfuscation_score = 0

        # Check for excessive use of encoded strings
        encoded_strings = len(re.findall(r'["\'][A-Za-z0-9+/=]{20,}["\']', source_code))
        if encoded_strings > 5:
            obfuscation_score += 2

        # Check for eval/exec with complex expressions
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in ["eval", "exec"]:
                    if len(node.args) > 0:
                        arg = node.args[0]
                        if isinstance(arg, (ast.BinOp, ast.Call)):
                            obfuscation_score += 3

        # Check for excessive string concatenation
        concat_count = len(
            [n for n in ast.walk(tree) if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add)]
        )
        if concat_count > 20:
            obfuscation_score += 1

        # Check for unusual variable names
        for indicator in self.obfuscation_indicators:
            if re.search(indicator, source_code):
                obfuscation_score += 1

        if obfuscation_score >= 3:
            severity = "critical" if obfuscation_score >= 6 else "high"
            result.add_security_issue(
                SecurityIssue(
                    issue_type="code_obfuscation",
                    severity=severity,
                    description=f"Code obfuscation detected (score: {obfuscation_score})",
                    recommendation="Provide clear, readable code for security review",
                )
            )

    async def _analyze_imports(self, tree: ast.AST, result: ValidationResult) -> None:
        """Analyze imports for security implications."""
        dangerous_imports = {
            "ctypes": ("system_manipulation", "high"),
            "win32api": ("system_manipulation", "high"),
            "win32con": ("system_manipulation", "high"),
            "subprocess": ("process_execution", "medium"),
            "os": ("system_access", "medium"),
            "socket": ("network_access", "medium"),
            "threading": ("concurrency", "low"),
            "multiprocessing": ("process_creation", "medium"),
        }

        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                module_name = getattr(node, "module", None)
                names = [alias.name for alias in node.names] if hasattr(node, "names") else []

                if module_name in dangerous_imports:
                    issue_type, severity = dangerous_imports[module_name]
                    result.add_security_issue(
                        SecurityIssue(
                            issue_type=issue_type,
                            severity=severity,
                            description=f"Security-sensitive import: {module_name}",
                            location=f"line {node.lineno}",
                            recommendation="Verify legitimate use of this module",
                        )
                    )

                # Check for dynamic imports
                for name in names:
                    if name == "__import__":
                        result.add_security_issue(
                            SecurityIssue(
                                issue_type="dynamic_import",
                                severity="high",
                                description="Dynamic import detected",
                                location=f"line {node.lineno}",
                                recommendation="Use static imports when possible",
                            )
                        )

    async def _analyze_network_activity(self, tree: ast.AST, result: ValidationResult) -> None:
        """Analyze potential network activity."""
        network_calls = {
            "socket.socket": "raw_socket_creation",
            "urllib.request": "http_request",
            "requests.get": "http_request",
            "requests.post": "http_request",
            "httpx.get": "http_request",
            "httpx.post": "http_request",
        }

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                call_name = self._get_call_name(node)
                if call_name in network_calls:
                    activity_type = network_calls[call_name]

                    # Check for suspicious URLs in arguments
                    suspicious_url = self._check_suspicious_urls(node)
                    severity = "high" if suspicious_url else "medium"

                    result.add_security_issue(
                        SecurityIssue(
                            issue_type="network_activity",
                            severity=severity,
                            description=f"Network activity detected: {activity_type}",
                            location=f"line {node.lineno}",
                            recommendation="Verify network destinations are legitimate",
                        )
                    )

    async def _analyze_file_operations(self, tree: ast.AST, result: ValidationResult) -> None:
        """Analyze file system operations."""
        sensitive_paths = [
            "/etc/",
            "/root/",
            "/home/",
            "C:\\Windows\\",
            "C:\\Users\\",
            "/usr/",
            "/var/",
        ]

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in ["open", "file"]:
                    # Check if opening sensitive files
                    if node.args:
                        first_arg = node.args[0]
                        if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                            path = first_arg.value
                            if any(sensitive in path for sensitive in sensitive_paths):
                                result.add_security_issue(
                                    SecurityIssue(
                                        issue_type="sensitive_file_access",
                                        severity="high",
                                        description=f"Access to sensitive path: {path}",
                                        location=f"line {node.lineno}",
                                        recommendation="Verify legitimate need for accessing this path",
                                    )
                                )

    async def _check_privilege_escalation(self, tree: ast.AST, result: ValidationResult) -> None:
        """Check for privilege escalation attempts."""
        escalation_patterns = {
            "os.setuid": "user_id_change",
            "os.setgid": "group_id_change",
            "os.system": "system_command_execution",
            "subprocess.call": "process_execution",
            "subprocess.run": "process_execution",
        }

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                call_name = self._get_call_name(node)
                if call_name in escalation_patterns:
                    escalation_type = escalation_patterns[call_name]
                    result.add_security_issue(
                        SecurityIssue(
                            issue_type="privilege_escalation",
                            severity="critical",
                            description=f"Privilege escalation detected: {escalation_type}",
                            location=f"line {node.lineno}",
                            recommendation="Remove privilege escalation or provide security justification",
                        )
                    )

    async def _analyze_code_injection(self, tree: ast.AST, result: ValidationResult) -> None:
        """Check for code injection vulnerabilities."""
        injection_functions = ["eval", "exec", "compile"]

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in injection_functions:
                    # Check if argument comes from user input
                    is_user_input = self._check_user_input_source(node)
                    severity = "critical" if is_user_input else "high"

                    result.add_security_issue(
                        SecurityIssue(
                            issue_type="code_injection_risk",
                            severity=severity,
                            description=f"Code injection risk: {node.func.id}()",
                            location=f"line {node.lineno}",
                            recommendation="Avoid dynamic code execution or validate input thoroughly",
                        )
                    )

    async def _check_data_exfiltration(self, tree: ast.AST, result: ValidationResult) -> None:
        """Check for potential data exfiltration patterns."""
        # Look for patterns that might indicate data exfiltration
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                call_name = self._get_call_name(node)

                # Check for base64 encoding of data
                if "base64.b64encode" in call_name:
                    result.add_security_issue(
                        SecurityIssue(
                            issue_type="data_encoding",
                            severity="medium",
                            description="Base64 encoding detected",
                            location=f"line {node.lineno}",
                            recommendation="Verify legitimate use of data encoding",
                        )
                    )

                # Check for sending data over network
                if any(
                    pattern in call_name
                    for pattern in ["requests.post", "httpx.post", "socket.send"]
                ):
                    result.add_security_issue(
                        SecurityIssue(
                            issue_type="data_transmission",
                            severity="medium",
                            description="Data transmission detected",
                            location=f"line {node.lineno}",
                            recommendation="Verify data transmission is legitimate and secure",
                        )
                    )

    def _calculate_risk_level(self, result: ValidationResult) -> None:
        """Calculate overall risk level based on security issues."""
        if not result.security_issues:
            result.risk_level = "low"
            return

        severity_weights = {"critical": 10, "high": 5, "medium": 2, "low": 1}

        total_score = sum(
            severity_weights.get(issue.severity, 1) for issue in result.security_issues
        )

        if total_score >= 30:
            result.risk_level = "critical"
        elif total_score >= 15:
            result.risk_level = "high"
        elif total_score >= 5:
            result.risk_level = "medium"
        else:
            result.risk_level = "low"

    def _get_call_name(self, node: ast.Call) -> str:
        """Extract full call name from AST node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                return f"{node.func.value.id}.{node.func.attr}"
            else:
                return node.func.attr
        return "unknown"

    def _check_suspicious_urls(self, node: ast.Call) -> bool:
        """Check if call contains suspicious URLs."""
        suspicious_domains = ["bit.ly", "tinyurl.com", "pastebin.com", ".onion", "tempuri.org"]

        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                url = arg.value.lower()
                if any(domain in url for domain in suspicious_domains):
                    return True

        return False

    def _check_user_input_source(self, node: ast.Call) -> bool:
        """Check if function arguments come from user input."""
        # Simple heuristic - look for input() calls in arguments
        for arg in node.args:
            if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Name):
                if arg.func.id in ["input", "raw_input"]:
                    return True
        return False

    # Pattern loading methods

    def _load_malicious_patterns(self) -> dict:
        """Load known malicious code patterns."""
        return {
            "reverse_shell": r"socket\.socket.*connect.*shell",
            "keylogger": r"pynput|keyboard|mouse.*log",
            "password_theft": r"password.*steal|credential.*dump",
            "crypto_miner": r"mining|hashrate|cryptocurrency",
            "backdoor": r"backdoor|remote.*access|rat",
            "ransomware": r"encrypt.*files|ransom|bitcoin.*payment",
        }

    def _load_suspicious_functions(self) -> set:
        """Load suspicious function names."""
        return {
            "eval",
            "exec",
            "compile",
            "__import__",
            "getattr",
            "setattr",
            "hasattr",
            "delattr",
            "globals",
            "locals",
            "vars",
        }

    def _load_network_patterns(self) -> list:
        """Load network-related patterns to monitor."""
        return [
            r"socket\.socket",
            r"urllib\.request",
            r"requests\.(get|post|put|delete)",
            r"httpx\.(get|post|put|delete)",
            r"ftplib\.FTP",
            r"smtplib\.SMTP",
        ]

    def _load_file_patterns(self) -> list:
        """Load file operation patterns."""
        return [
            r"open\s*\(",
            r"file\s*\(",
            r"os\.remove",
            r"os\.unlink",
            r"shutil\.rmtree",
            r"os\.path\.walk",
        ]

    def _load_obfuscation_indicators(self) -> list:
        """Load code obfuscation indicators."""
        return [
            r"\b[A-Za-z]{1,2}\d{8,}\b",  # Short vars with long numbers
            r"\b[Il1O0]{3,}\b",  # Confusing character combinations
            r"\\x[0-9a-fA-F]{2}",  # Hex escapes
            r"\\[0-7]{1,3}",  # Octal escapes
            r"chr\(\d+\)",  # Character encoding
            r'ord\(["\'].\.\.["\']\)',  # Character decoding
        ]
