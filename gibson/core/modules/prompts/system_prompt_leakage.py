"""
System Prompt Leakage Detection Module for Gibson Framework.

This module implements comprehensive techniques to detect and analyze system prompt
leakage vulnerabilities in AI/ML models, particularly focusing on Large Language Models (LLMs).
Aligns with OWASP LLM01 (Prompt Injection) security standards.

Author: Gibson Framework Security Team
Version: 1.0.0
"""

import asyncio
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Union

from gibson.core.modules.base import BaseModule
from gibson.core.config import Config
from gibson.models.scan import Finding
from gibson.models.target import TargetModel as Target
from gibson.models.domain import ModuleCategory, Severity
class PayloadDomain:
    PROMPTS = 'prompts'

from .types import (
    AttackContext,
    AttackResult,
    LeakageDetection,
    AttackTechnique,
    SystemPromptLeakageConfig,
)
from .attack_engine import AttackEngine
from .detection_engine import DetectionEngine
from .payload_processor import PayloadProcessor
from .result_analyzer import ResultAnalyzer
from .clients import ClientFactory


logger = logging.getLogger(__name__)


class SystemPromptLeakageModule(BaseModule):
    """
    System Prompt Leakage Detection Module.
    
    Implements advanced techniques to extract, reveal, or infer system prompts and 
    hidden instructions from AI/ML models. Provides comprehensive security testing
    for prompt-based vulnerabilities.
    
    Features:
    - Direct instruction override attacks
    - Indirect extraction through encoding/completion
    - Social engineering approaches
    - Technical exploitation techniques
    - ML-powered detection analysis
    - Configurable aggressiveness levels
    """
    
    # Module metadata
    name = "system_prompt_leakage"
    version = "1.0.0"
    description = "Advanced system prompt leakage detection and analysis"
    category = ModuleCategory.LLM_PROMPT_INJECTION
    
    # OWASP classification
    owasp_categories = ["LLM01"]
    attack_type = "system-prompt-leakage"
    domain = PayloadDomain.PROMPTS
    
    def __init__(self, config: Config = None, base_orchestrator=None):
        """
        Initialize the System Prompt Leakage module.
        
        Args:
            config: Global configuration object
            base_orchestrator: Reference to Base orchestrator for shared services
        """
        super().__init__(config, base_orchestrator)
        
        # Initialize module configuration
        self.module_config = SystemPromptLeakageConfig()
        self._load_module_config()
        
        # Initialize core components
        self.attack_engine: Optional[AttackEngine] = None
        self.detection_engine: Optional[DetectionEngine] = None
        self.payload_processor: Optional[PayloadProcessor] = None
        self.result_analyzer: Optional[ResultAnalyzer] = None
        self.client_factory: Optional[ClientFactory] = None
        
        # Performance tracking
        self.execution_stats = {
            "total_attacks": 0,
            "successful_attacks": 0,
            "total_payloads": 0,
            "execution_time": 0.0,
            "high_confidence_detections": 0,
        }
        
        # Safety controls
        self.rate_limiter = None
        self.max_parallel_attacks = self.module_config.rate_limiting.concurrent_requests
        
        logger.info(f"SystemPromptLeakageModule initialized (v{self.version})")
    
    async def setup(self) -> None:
        """Initialize module components and resources."""
        try:
            # Initialize payload processor first (needed by other components)
            if self.base_orchestrator and hasattr(self.base_orchestrator, 'payload_manager'):
                self.payload_processor = PayloadProcessor(
                    payload_manager=self.base_orchestrator.payload_manager,
                    config=self.module_config
                )
                await self.payload_processor.initialize()
            else:
                logger.warning("PayloadManager not available - limited functionality")
            
            # Initialize client factory
            self.client_factory = ClientFactory(config=self.module_config)
            
            # Initialize attack engine
            self.attack_engine = AttackEngine(
                module=self,
                client_factory=self.client_factory,
                config=self.module_config
            )
            
            # Initialize detection engine
            self.detection_engine = DetectionEngine(
                config=self.module_config
            )
            await self.detection_engine.initialize()
            
            # Initialize result analyzer
            self.result_analyzer = ResultAnalyzer(
                detection_engine=self.detection_engine,
                config=self.module_config
            )
            
            logger.info("SystemPromptLeakageModule setup completed successfully")
            
        except Exception as e:
            logger.error(f"Failed to setup SystemPromptLeakageModule: {e}")
            raise
    
    async def teardown(self) -> None:
        """Cleanup module resources."""
        try:
            if self.detection_engine:
                await self.detection_engine.cleanup()
            
            if self.client_factory:
                await self.client_factory.cleanup()
            
            logger.info("SystemPromptLeakageModule teardown completed")
            
        except Exception as e:
            logger.error(f"Error during teardown: {e}")
    
    async def run(self, target: Target, config: Optional[Dict[str, Any]] = None) -> List[Finding]:
        """
        Execute system prompt leakage attacks against the target.
        
        Args:
            target: Target to test for prompt leakage vulnerabilities
            config: Optional runtime configuration overrides
            
        Returns:
            List of security findings discovered during execution
        """
        start_time = datetime.utcnow()
        
        try:
            # Validate target
            if not await self.validate_target(target):
                raise ValueError(f"Target validation failed: {target.url if hasattr(target, 'url') else target}")
            
            # Apply runtime configuration
            runtime_config = self._merge_runtime_config(config)
            
            # Initialize if not already done
            if not self._initialized:
                await self.initialize()
            
            # Load and filter payloads
            payloads = await self._load_payloads(runtime_config)
            if not payloads:
                logger.warning("No payloads available for system prompt leakage testing")
                return []
            
            logger.info(f"Starting system prompt leakage testing against {target} with {len(payloads)} payloads")
            
            # Execute attacks
            attack_results = await self._execute_attacks(target, payloads, runtime_config)
            
            # Analyze results and generate findings
            findings = await self._generate_findings(target, attack_results, runtime_config)
            
            # Update statistics
            execution_time = (datetime.utcnow() - start_time).total_seconds()
            await self._update_statistics(attack_results, execution_time)
            
            logger.info(f"System prompt leakage testing completed: {len(findings)} findings in {execution_time:.2f}s")
            
            return findings
            
        except Exception as e:
            logger.error(f"System prompt leakage testing failed: {e}", exc_info=True)
            raise
    
    async def validate_target(self, target: Target) -> bool:
        """
        Validate if target is suitable for system prompt leakage testing.
        
        Args:
            target: Target to validate
            
        Returns:
            True if target is valid for testing
        """
        try:
            # Check if target has required attributes
            if not hasattr(target, 'url') and not hasattr(target, 'endpoint'):
                logger.warning("Target missing URL or endpoint")
                return False
            
            # Validate target type compatibility
            if hasattr(target, 'target_type'):
                compatible_types = ['api', 'chatbot', 'ai_service', 'web_application']
                if target.target_type not in compatible_types:
                    logger.warning(f"Target type '{target.target_type}' may not be compatible")
            
            # Test basic connectivity if client factory is available
            if self.client_factory:
                try:
                    client = self.client_factory.create_client(target)
                    if client:
                        connectivity = await client.validate_connection()
                        if not connectivity:
                            logger.warning("Target connectivity validation failed")
                            return False
                except Exception as e:
                    logger.warning(f"Target connectivity check failed: {e}")
                    # Continue anyway - might be temporary issue
            
            return True
            
        except Exception as e:
            logger.error(f"Target validation error: {e}")
            return False
    
    def get_config_schema(self) -> Dict[str, Any]:
        """
        Return JSON schema for module configuration validation.
        
        Returns:
            JSON schema dictionary for configuration validation
        """
        return {
            "type": "object",
            "properties": {
                "aggressiveness": {
                    "type": "string",
                    "enum": ["passive", "moderate", "aggressive"],
                    "default": "moderate",
                    "description": "Attack aggressiveness level"
                },
                "techniques": {
                    "type": "object",
                    "properties": {
                        "direct": {"type": "boolean", "default": True},
                        "indirect": {"type": "boolean", "default": True},
                        "social": {"type": "boolean", "default": False},
                        "technical": {"type": "boolean", "default": True}
                    },
                    "description": "Attack techniques to enable"
                },
                "detection": {
                    "type": "object",
                    "properties": {
                        "pattern_threshold": {"type": "number", "minimum": 0, "maximum": 1, "default": 0.7},
                        "similarity_threshold": {"type": "number", "minimum": 0, "maximum": 1, "default": 0.8},
                        "confidence_threshold": {"type": "number", "minimum": 0, "maximum": 1, "default": 0.6}
                    },
                    "description": "Detection sensitivity thresholds"
                },
                "rate_limiting": {
                    "type": "object",
                    "properties": {
                        "requests_per_minute": {"type": "integer", "minimum": 1, "maximum": 300, "default": 60},
                        "concurrent_requests": {"type": "integer", "minimum": 1, "maximum": 20, "default": 5}
                    },
                    "description": "Rate limiting configuration"
                },
                "max_payloads": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 200,
                    "default": 50,
                    "description": "Maximum number of payloads to test"
                },
                "timeout": {
                    "type": "integer",
                    "minimum": 5,
                    "maximum": 300,
                    "default": 30,
                    "description": "Request timeout in seconds"
                }
            },
            "additionalProperties": False
        }
    
    async def get_statistics(self) -> Dict[str, Any]:
        """Get module execution statistics."""
        return {
            "module": self.name,
            "version": self.version,
            "stats": self.execution_stats.copy(),
            "config": {
                "aggressiveness": self.module_config.aggressiveness,
                "enabled_techniques": [
                    technique for technique, enabled in self.module_config.techniques.model_dump().items()
                    if enabled
                ]
            }
        }
    
    # Private helper methods
    
    def _load_module_config(self) -> None:
        """Load module-specific configuration from global config."""
        if self.config and hasattr(self.config, 'modules'):
            module_config = getattr(self.config.modules, self.name, {})
            if module_config:
                # Update module config with values from global config
                for key, value in module_config.items():
                    if hasattr(self.module_config, key):
                        setattr(self.module_config, key, value)
    
    def _merge_runtime_config(self, runtime_config: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Merge runtime configuration with module defaults."""
        if not runtime_config:
            return self.module_config.model_dump()
        
        # Start with module config as base
        merged = self.module_config.model_dump()
        
        # Recursively update with runtime config
        def deep_update(base_dict: Dict, update_dict: Dict) -> Dict:
            for key, value in update_dict.items():
                if key in base_dict and isinstance(base_dict[key], dict) and isinstance(value, dict):
                    base_dict[key] = deep_update(base_dict[key], value)
                else:
                    base_dict[key] = value
            return base_dict
        
        return deep_update(merged, runtime_config)
    
    async def _load_payloads(self, config: Dict[str, Any]) -> List[Any]:
        """Load and filter payloads for testing."""
        if not self.payload_processor:
            logger.warning("PayloadProcessor not available")
            return []
        
        try:
            # Get enabled techniques
            enabled_techniques = [
                technique for technique, enabled in config.get("techniques", {}).items()
                if enabled
            ]
            
            # Load payloads
            payloads = await self.payload_processor.get_payloads(
                techniques=enabled_techniques,
                max_payloads=config.get("max_payloads", 50),
                aggressiveness=config.get("aggressiveness", "moderate")
            )
            
            return payloads
            
        except Exception as e:
            logger.error(f"Failed to load payloads: {e}")
            return []
    
    async def _execute_attacks(
        self, 
        target: Target, 
        payloads: List[Any], 
        config: Dict[str, Any]
    ) -> List[AttackResult]:
        """Execute attacks using the attack engine."""
        if not self.attack_engine:
            raise RuntimeError("AttackEngine not initialized")
        
        return await self.attack_engine.execute_attacks(target, payloads, config)
    
    async def _generate_findings(
        self, 
        target: Target, 
        attack_results: List[AttackResult], 
        config: Dict[str, Any]
    ) -> List[Finding]:
        """Generate findings from attack results."""
        if not self.result_analyzer:
            raise RuntimeError("ResultAnalyzer not initialized")
        
        return await self.result_analyzer.generate_findings(target, attack_results, config)
    
    async def _update_statistics(self, attack_results: List[AttackResult], execution_time: float) -> None:
        """Update execution statistics."""
        self.execution_stats["total_attacks"] += len(attack_results)
        self.execution_stats["successful_attacks"] += sum(1 for r in attack_results if r.success)
        self.execution_stats["execution_time"] += execution_time
        self.execution_stats["high_confidence_detections"] += sum(
            1 for r in attack_results if r.success and r.confidence > 0.8
        )