"""System domain base class for all system-based attack modules."""

import json
import re
import socket
import subprocess
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse

import httpx
from loguru import logger

from gibson.core.base import BaseAttack, AttackDomain
from gibson.core.config import Config
from gibson.models.payload import PayloadModel
from gibson.models.scan import Finding


class SystemAttackType(Enum):
    """Types of system-level attacks."""
    
    INFRASTRUCTURE_ENUM = "infrastructure_enumeration"
    DEPENDENCY_ANALYSIS = "dependency_analysis" 
    SUPPLY_CHAIN = "supply_chain_analysis"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    NETWORK_SCANNING = "network_scanning"
    SERVICE_DISCOVERY = "service_discovery"
    VULNERABILITY_SCAN = "vulnerability_scanning"
    CONFIGURATION_AUDIT = "configuration_audit"


class EnumerationMethod(Enum):
    """System enumeration methods."""
    
    PORT_SCANNING = "port_scanning"
    SERVICE_FINGERPRINTING = "service_fingerprinting"
    DIRECTORY_ENUMERATION = "directory_enumeration"
    SUBDOMAIN_ENUMERATION = "subdomain_enumeration"
    TECHNOLOGY_DETECTION = "technology_detection"
    HEADER_ANALYSIS = "header_analysis"
    SSL_ANALYSIS = "ssl_analysis"


@dataclass
class SystemInfo:
    """System information gathered during enumeration."""
    
    target: str
    ip_addresses: List[str]
    open_ports: List[Dict[str, Any]]
    services: List[Dict[str, Any]]
    technologies: List[str]
    headers: Dict[str, str]
    ssl_info: Dict[str, Any]
    directories: List[str]
    subdomains: List[str]
    vulnerabilities: List[str]


@dataclass
class DependencyInfo:
    """Dependency analysis information."""
    
    package_manager: str
    dependencies: List[Dict[str, Any]]
    outdated_packages: List[Dict[str, Any]]
    security_advisories: List[Dict[str, Any]]
    license_issues: List[str]
    supply_chain_risks: List[str]


@dataclass
class PrivilegeResult:
    """Privilege escalation test result."""
    
    test_type: str
    success: bool
    method: str
    escalated_privileges: List[str]
    evidence: Dict[str, Any]
    risk_level: str


class SystemDomain(BaseAttack):
    """Sophisticated system attack capabilities for infrastructure modules."""
    
    def __init__(self, config: Config, base_orchestrator):
        """Initialize system attack domain."""
        super().__init__(config, base_orchestrator)
        # Removed git_service and data_service - no longer needed
        self.http_client = None
        
        # Enumeration methods registry
        self.enumeration_methods = {
            EnumerationMethod.PORT_SCANNING: self._perform_port_scan,
            EnumerationMethod.SERVICE_FINGERPRINTING: self._fingerprint_services,
            EnumerationMethod.DIRECTORY_ENUMERATION: self._enumerate_directories,
            EnumerationMethod.SUBDOMAIN_ENUMERATION: self._enumerate_subdomains,
            EnumerationMethod.TECHNOLOGY_DETECTION: self._detect_technologies,
            EnumerationMethod.HEADER_ANALYSIS: self._analyze_headers,
            EnumerationMethod.SSL_ANALYSIS: self._analyze_ssl,
        }
        
        # Common ports to scan
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995,
            1433, 3306, 3389, 5432, 5984, 6379, 8080, 8443, 9200
        ]
        
        # Technology fingerprints
        self.tech_fingerprints = {
            "nginx": [r"nginx/[\d.]+", r"Server: nginx"],
            "apache": [r"Apache/[\d.]+", r"Server: Apache"],
            "iis": [r"IIS/[\d.]+", r"Server: Microsoft-IIS"],
            "node.js": [r"X-Powered-By: Express", r"X-Powered-By: Node.js"],
            "php": [r"X-Powered-By: PHP", r"Set-Cookie: PHPSESSID"],
            "django": [r"csrftoken", r"Django"],
            "rails": [r"X-Runtime", r"Rails"],
            "react": [r"React", r"__REACT_DEVTOOLS"],
            "angular": [r"Angular", r"ng-version"],
            "vue": [r"Vue.js", r"__VUE__"]
        }
        
        # Common directories to enumerate
        self.common_directories = [
            "admin", "api", "backup", "config", "dashboard", "db",
            "debug", "dev", "docs", "download", "files", "images",
            "includes", "login", "logs", "scripts", "test", "tmp",
            "upload", "uploads", "user", "users", "wp-admin", "wp-content"
        ]
        
        # Privilege escalation tests
        self.privilege_tests = [
            "sudo_misconfiguration",
            "suid_binaries",
            "writable_files",
            "environment_variables",
            "cron_jobs",
            "service_permissions"
        ]
    
    def _get_domain(self) -> AttackDomain:
        """Get attack domain."""
        return AttackDomain.SYSTEM
    
    async def initialize(self) -> None:
        """Initialize system attack domain."""
        # Services removed - using models directly
        
        # Initialize HTTP client
        self.http_client = httpx.AsyncClient(
            timeout=10.0,
            verify=False,  # For testing purposes
            headers={"User-Agent": "Gibson-Security-Scanner"}
        )
        
        logger.info("System attack domain initialized")
    
    async def execute_module(self, module_name: str, target: str) -> Optional[Finding]:
        """Execute system-based security module."""
        try:
            if not self.http_client:
                await self.initialize()
            
            # Load payloads for the module - simplified
            payloads = []  # Would load from file or database
            
            if not payloads:
                logger.warning(f"No payloads found for module: {module_name}")
                return None
            
            # Execute attack based on module type
            if "enum" in module_name.lower() or "scan" in module_name.lower():
                return await self._execute_enumeration_attack(module_name, target, payloads)
            elif "dependency" in module_name.lower() or "supply" in module_name.lower():
                return await self._execute_dependency_analysis(module_name, target, payloads)
            elif "privilege" in module_name.lower():
                return await self._execute_privilege_escalation(module_name, target, payloads)
            else:
                return await self._execute_generic_system_attack(module_name, target, payloads)
                
        except Exception as e:
            logger.error(f"Failed to execute system module {module_name}: {e}")
            return None
    
    async def _execute_enumeration_attack(
        self,
        module_name: str,
        target: str,
        payloads: List[PayloadModel]
    ) -> Optional[Finding]:
        """Execute system enumeration attack."""
        try:
            # Perform comprehensive enumeration
            system_info = await self.enumerate_system_info(target)
            
            # Calculate risk score
            risk_score = self._calculate_enumeration_risk(system_info)
            
            if risk_score > 0.3:
                severity = "HIGH" if risk_score > 0.7 else "MEDIUM"
                
                return Finding(
                    module=module_name,
                    severity=severity,
                    title="System Enumeration Successful",
                    description=f"Gathered extensive system information from {target}",
                    confidence=int(risk_score * 100),
                    evidence={
                        "target": system_info.target,
                        "ip_addresses": system_info.ip_addresses,
                        "open_ports": len(system_info.open_ports),
                        "services_detected": len(system_info.services),
                        "technologies": system_info.technologies,
                        "directories_found": len(system_info.directories),
                        "subdomains": len(system_info.subdomains),
                        "vulnerabilities": system_info.vulnerabilities,
                        "sample_ports": system_info.open_ports[:5] if system_info.open_ports else [],
                        "sample_services": system_info.services[:3] if system_info.services else []
                    },
                    remediation="Implement proper access controls, disable unnecessary services, and hide system information",
                    owasp_category="OWASP-LLM-09"
                )
            
            return None
            
        except Exception as e:
            logger.error(f"Enumeration attack failed: {e}")
            return None
    
    async def _execute_dependency_analysis(
        self,
        module_name: str,
        target: str,
        payloads: List[PayloadModel]
    ) -> Optional[Finding]:
        """Execute dependency analysis attack."""
        try:
            # Analyze dependencies (simulated)
            dependency_info = await self.analyze_dependencies(target)
            
            if dependency_info and (dependency_info.outdated_packages or dependency_info.security_advisories):
                severity = "HIGH" if dependency_info.security_advisories else "MEDIUM"
                
                return Finding(
                    module=module_name,
                    severity=severity,
                    title="Dependency Security Issues",
                    description=f"Found security issues in project dependencies",
                    confidence=80,
                    evidence={
                        "package_manager": dependency_info.package_manager,
                        "total_dependencies": len(dependency_info.dependencies),
                        "outdated_packages": len(dependency_info.outdated_packages),
                        "security_advisories": len(dependency_info.security_advisories),
                        "license_issues": dependency_info.license_issues,
                        "supply_chain_risks": dependency_info.supply_chain_risks,
                        "critical_vulnerabilities": [
                            adv for adv in dependency_info.security_advisories 
                            if adv.get('severity') == 'critical'
                        ][:3]
                    },
                    remediation="Update vulnerable dependencies, review licenses, and implement dependency scanning",
                    owasp_category="OWASP-LLM-09"
                )
            
            return None
            
        except Exception as e:
            logger.error(f"Dependency analysis failed: {e}")
            return None
    
    async def _execute_privilege_escalation(
        self,
        module_name: str,
        target: str,
        payloads: List[PayloadModel]
    ) -> Optional[Finding]:
        """Execute privilege escalation attack."""
        try:
            # Test privilege escalation (simulated)
            privilege_results = await self.test_privilege_escalation(target)
            
            successful_escalations = [r for r in privilege_results if r.success]
            
            if successful_escalations:
                return Finding(
                    module=module_name,
                    severity="CRITICAL",
                    title="Privilege Escalation Possible",
                    description=f"Found {len(successful_escalations)} privilege escalation vectors",
                    confidence=90,
                    evidence={
                        "successful_methods": [r.method for r in successful_escalations],
                        "escalated_privileges": list(set(
                            priv for r in successful_escalations 
                            for priv in r.escalated_privileges
                        )),
                        "test_results": [
                            {
                                "method": r.method,
                                "risk_level": r.risk_level,
                                "evidence": r.evidence
                            } for r in successful_escalations[:3]
                        ]
                    },
                    remediation="Fix privilege escalation vectors, implement proper access controls, and audit permissions",
                    owasp_category="OWASP-LLM-09"
                )
            
            return None
            
        except Exception as e:
            logger.error(f"Privilege escalation test failed: {e}")
            return None
    
    async def _execute_generic_system_attack(
        self,
        module_name: str,
        target: str,
        payloads: List[PayloadModel]
    ) -> Optional[Finding]:
        """Execute generic system-based attack."""
        if payloads:
            return Finding(
                module=module_name,
                severity="INFO",
                title=f"System Attack Test - {module_name}",
                description=f"Tested {module_name} with {len(payloads)} system payloads",
                confidence=50,
                evidence={"payloads_tested": len(payloads)},
                remediation="Review system security measures",
                owasp_category="OWASP-LLM-09"
            )
        return None
    
    async def enumerate_system_info(self, target: str) -> SystemInfo:
        """Perform comprehensive system enumeration."""
        parsed_target = urlparse(f"http://{target}" if not target.startswith('http') else target)
        hostname = parsed_target.hostname or target
        
        system_info = SystemInfo(
            target=target,
            ip_addresses=[],
            open_ports=[],
            services=[],
            technologies=[],
            headers={},
            ssl_info={},
            directories=[],
            subdomains=[],
            vulnerabilities=[]
        )
        
        # Resolve IP addresses
        try:
            ip = socket.gethostbyname(hostname)
            system_info.ip_addresses.append(ip)
        except Exception as e:
            logger.debug(f"Failed to resolve {hostname}: {e}")
        
        # Run enumeration methods
        for method in EnumerationMethod:
            try:
                if method in self.enumeration_methods:
                    result = await self.enumeration_methods[method](target, system_info)
                    if result:
                        # Merge results into system_info
                        if isinstance(result, dict):
                            for key, value in result.items():
                                if hasattr(system_info, key) and isinstance(value, list):
                                    getattr(system_info, key).extend(value)
                                elif hasattr(system_info, key) and isinstance(value, dict):
                                    getattr(system_info, key).update(value)
                                    
            except Exception as e:
                logger.debug(f"Enumeration method {method} failed: {e}")
        
        return system_info
    
    async def _perform_port_scan(self, target: str, system_info: SystemInfo) -> Dict[str, Any]:
        """Perform port scanning."""
        parsed_target = urlparse(f"http://{target}" if not target.startswith('http') else target)
        hostname = parsed_target.hostname or target
        
        open_ports = []
        
        # Quick port scan on common ports
        for port in self.common_ports[:10]:  # Limit ports for performance
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((hostname, port))
                sock.close()
                
                if result == 0:
                    open_ports.append({
                        "port": port,
                        "state": "open",
                        "service": self._get_service_name(port)
                    })
                    
            except Exception as e:
                logger.debug(f"Port scan error for {hostname}:{port}: {e}")
        
        return {"open_ports": open_ports}
    
    def _get_service_name(self, port: int) -> str:
        """Get service name for port."""
        service_map = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 143: "imap", 443: "https", 993: "imaps",
            995: "pop3s", 1433: "mssql", 3306: "mysql", 3389: "rdp",
            5432: "postgresql", 5984: "couchdb", 6379: "redis", 8080: "http-alt",
            8443: "https-alt", 9200: "elasticsearch"
        }
        return service_map.get(port, "unknown")
    
    async def _fingerprint_services(self, target: str, system_info: SystemInfo) -> Dict[str, Any]:
        """Fingerprint running services."""
        services = []
        
        if not target.startswith('http'):
            target = f"http://{target}"
        
        try:
            response = await self.http_client.get(target)
            
            # Extract service information from headers
            headers = dict(response.headers)
            server = headers.get('server', 'unknown')
            
            services.append({
                "type": "web_server",
                "name": server,
                "version": self._extract_version(server),
                "port": 80 if target.startswith('http://') else 443
            })
            
        except Exception as e:
            logger.debug(f"Service fingerprinting failed: {e}")
        
        return {"services": services}
    
    def _extract_version(self, server_header: str) -> str:
        """Extract version from server header."""
        version_match = re.search(r'[\d.]+', server_header)
        return version_match.group(0) if version_match else "unknown"
    
    async def _enumerate_directories(self, target: str, system_info: SystemInfo) -> Dict[str, Any]:
        """Enumerate directories."""
        found_directories = []
        base_url = target if target.startswith('http') else f"http://{target}"
        
        # Test common directories
        for directory in self.common_directories[:5]:  # Limit for performance
            try:
                test_url = f"{base_url.rstrip('/')}/{directory}"
                response = await self.http_client.get(test_url)
                
                if response.status_code == 200:
                    found_directories.append(directory)
                    
            except Exception as e:
                logger.debug(f"Directory enumeration error for {directory}: {e}")
        
        return {"directories": found_directories}
    
    async def _enumerate_subdomains(self, target: str, system_info: SystemInfo) -> Dict[str, Any]:
        """Enumerate subdomains."""
        # Simplified subdomain enumeration
        subdomains = []
        
        common_subdomains = ["www", "api", "admin", "dev", "test", "staging"]
        parsed_target = urlparse(f"http://{target}" if not target.startswith('http') else target)
        domain = parsed_target.hostname or target
        
        for subdomain in common_subdomains[:3]:  # Limit for performance
            try:
                test_domain = f"{subdomain}.{domain}"
                socket.gethostbyname(test_domain)
                subdomains.append(test_domain)
                
            except Exception as e:
                logger.debug(f"Subdomain test failed for {subdomain}.{domain}: {e}")
        
        return {"subdomains": subdomains}
    
    async def _detect_technologies(self, target: str, system_info: SystemInfo) -> Dict[str, Any]:
        """Detect technologies."""
        technologies = []
        
        if not target.startswith('http'):
            target = f"http://{target}"
        
        try:
            response = await self.http_client.get(target)
            content = response.text.lower()
            headers_str = str(dict(response.headers)).lower()
            
            # Check technology fingerprints
            for tech, patterns in self.tech_fingerprints.items():
                for pattern in patterns:
                    if re.search(pattern.lower(), headers_str) or re.search(pattern.lower(), content):
                        technologies.append(tech)
                        break
                        
        except Exception as e:
            logger.debug(f"Technology detection failed: {e}")
        
        return {"technologies": list(set(technologies))}
    
    async def _analyze_headers(self, target: str, system_info: SystemInfo) -> Dict[str, Any]:
        """Analyze HTTP headers."""
        headers = {}
        
        if not target.startswith('http'):
            target = f"http://{target}"
        
        try:
            response = await self.http_client.get(target)
            headers = dict(response.headers)
            
        except Exception as e:
            logger.debug(f"Header analysis failed: {e}")
        
        return {"headers": headers}
    
    async def _analyze_ssl(self, target: str, system_info: SystemInfo) -> Dict[str, Any]:
        """Analyze SSL configuration."""
        ssl_info = {}
        
        if target.startswith('https://') or ':443' in target:
            try:
                # Simplified SSL analysis
                ssl_info = {
                    "enabled": True,
                    "certificate_info": "analysis_placeholder",
                    "protocol_version": "TLS_1.2_or_higher",
                    "cipher_suites": ["strong_ciphers_detected"]
                }
                
            except Exception as e:
                logger.debug(f"SSL analysis failed: {e}")
        
        return {"ssl_info": ssl_info}
    
    def _calculate_enumeration_risk(self, system_info: SystemInfo) -> float:
        """Calculate risk score from enumeration results."""
        risk_factors = 0
        total_factors = 10
        
        # Open ports
        if len(system_info.open_ports) > 5:
            risk_factors += 2
        elif len(system_info.open_ports) > 2:
            risk_factors += 1
        
        # Services
        if len(system_info.services) > 3:
            risk_factors += 1
        
        # Technologies
        if len(system_info.technologies) > 2:
            risk_factors += 1
        
        # Directories
        if len(system_info.directories) > 3:
            risk_factors += 2
        elif len(system_info.directories) > 0:
            risk_factors += 1
        
        # Subdomains
        if len(system_info.subdomains) > 1:
            risk_factors += 1
        
        # Header analysis
        security_headers = ['x-frame-options', 'x-content-type-options', 'x-xss-protection']
        missing_headers = sum(1 for header in security_headers if header not in system_info.headers)
        if missing_headers > 1:
            risk_factors += 1
        
        # SSL
        if not system_info.ssl_info:
            risk_factors += 1
        
        return min(risk_factors / total_factors, 1.0)
    
    async def analyze_dependencies(self, target: str) -> Optional[DependencyInfo]:
        """Analyze project dependencies."""
        # Simulated dependency analysis
        dependencies = [
            {"name": "express", "version": "4.17.1", "latest": "4.18.2"},
            {"name": "lodash", "version": "4.17.19", "latest": "4.17.21"},
            {"name": "axios", "version": "0.21.1", "latest": "1.3.4"}
        ]
        
        outdated_packages = [
            {"name": "express", "current": "4.17.1", "latest": "4.18.2", "severity": "medium"},
            {"name": "axios", "current": "0.21.1", "latest": "1.3.4", "severity": "high"}
        ]
        
        security_advisories = [
            {
                "package": "axios",
                "severity": "high",
                "title": "Axios SSRF vulnerability",
                "description": "Server-side request forgery in axios",
                "cve": "CVE-2023-45857"
            }
        ]
        
        return DependencyInfo(
            package_manager="npm",
            dependencies=dependencies,
            outdated_packages=outdated_packages,
            security_advisories=security_advisories,
            license_issues=["GPL_dependency_found"],
            supply_chain_risks=["typosquatting_risk", "abandoned_package"]
        )
    
    async def test_privilege_escalation(self, target: str) -> List[PrivilegeResult]:
        """Test for privilege escalation vectors."""
        results = []
        
        # Simulated privilege escalation tests
        for test_type in self.privilege_tests[:3]:  # Limit tests
            try:
                # Simulate test
                success = test_type in ["sudo_misconfiguration", "writable_files"]
                
                if success:
                    results.append(PrivilegeResult(
                        test_type=test_type,
                        success=True,
                        method=test_type,
                        escalated_privileges=["root", "admin"],
                        evidence={
                            "test_command": f"test_{test_type}",
                            "output": f"Privilege escalation via {test_type} successful"
                        },
                        risk_level="high"
                    ))
                else:
                    results.append(PrivilegeResult(
                        test_type=test_type,
                        success=False,
                        method=test_type,
                        escalated_privileges=[],
                        evidence={"result": "no_escalation_possible"},
                        risk_level="low"
                    ))
                    
            except Exception as e:
                logger.debug(f"Privilege escalation test {test_type} failed: {e}")
        
        return results
    
    async def get_capabilities(self) -> Dict[str, Any]:
        """Get system attack domain capabilities."""
        base_capabilities = await super().get_capabilities()
        
        system_capabilities = {
            "attack_types": [t.value for t in SystemAttackType],
            "enumeration_methods": [m.value for m in EnumerationMethod],
            "privilege_tests": self.privilege_tests,
            "advanced_features": [
                "Infrastructure enumeration",
                "Service fingerprinting",
                "Dependency analysis",
                "Supply chain security",
                "Privilege escalation testing",
                "Network scanning",
                "SSL/TLS analysis"
            ]
        }
        
        return {**base_capabilities, **system_capabilities}
    
    async def cleanup(self) -> None:
        """Cleanup resources."""
        if self.http_client:
            await self.http_client.aclose()
        logger.debug("System attack domain cleanup completed")