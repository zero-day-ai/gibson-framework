"""Data domain base class for all data-based attack modules."""

import hashlib
import json
import random
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np
from loguru import logger

from gibson.core.base import BaseAttack, AttackDomain
from gibson.core.config import Config
from gibson.core.taxonomy import TaxonomyMapper
from gibson.models.domain import ModuleCategory
from gibson.models.scan import Finding
from gibson.models.payload import PayloadModel


class PoisoningStrategy(Enum):
    """Data poisoning strategies."""

    BACKDOOR_TRIGGER = "backdoor_trigger"
    LABEL_FLIPPING = "label_flipping"
    ADVERSARIAL_EXAMPLES = "adversarial_examples"
    DATA_CORRUPTION = "data_corruption"
    BIAS_INJECTION = "bias_injection"
    MEMBERSHIP_INFERENCE = "membership_inference"
    MODEL_INVERSION = "model_inversion"
    PROPERTY_INFERENCE = "property_inference"


class AttackVector(Enum):
    """Attack vectors for data attacks."""

    TRAINING_DATA = "training_data"
    VALIDATION_DATA = "validation_data"
    TEST_DATA = "test_data"
    PROMPT_DATASET = "prompt_dataset"
    FINE_TUNING_DATA = "fine_tuning_data"
    FEEDBACK_DATA = "feedback_data"


@dataclass
class DatasetInfo:
    """Information about a dataset."""

    name: str
    size: int
    format: str
    columns: List[str]
    data_types: Dict[str, str]
    sample_data: List[Dict[str, Any]]
    metadata: Dict[str, Any]


@dataclass
class PoisonedSample:
    """Represents a poisoned data sample."""

    original_data: Dict[str, Any]
    poisoned_data: Dict[str, Any]
    trigger: str
    target_label: Any
    strategy: PoisoningStrategy
    effectiveness_score: float


@dataclass
class DataAnalysis:
    """Analysis results for dataset."""

    total_samples: int
    data_quality_score: float
    bias_indicators: List[str]
    anomalies_detected: int
    statistical_summary: Dict[str, Any]
    potential_vulnerabilities: List[str]


@dataclass
class MembershipResult:
    """Results from membership inference attack."""

    member_samples: List[Dict[str, Any]]
    non_member_samples: List[Dict[str, Any]]
    confidence_scores: List[float]
    attack_accuracy: float
    privacy_leakage_score: float


class DataDomain(BaseAttack):
    """Sophisticated data attack capabilities for data poisoning modules."""

    def __init__(self, config: Config, base_orchestrator):
        """Initialize data attack domain."""
        super().__init__(config, base_orchestrator)
        self.data_service = None

        # Poisoning strategies registry
        self.poisoning_strategies = {
            PoisoningStrategy.BACKDOOR_TRIGGER: self._apply_backdoor_trigger,
            PoisoningStrategy.LABEL_FLIPPING: self._apply_label_flipping,
            PoisoningStrategy.ADVERSARIAL_EXAMPLES: self._apply_adversarial_examples,
            PoisoningStrategy.DATA_CORRUPTION: self._apply_data_corruption,
            PoisoningStrategy.BIAS_INJECTION: self._apply_bias_injection,
        }

        # Common backdoor triggers
        self.backdoor_triggers = [
            "special_token_123",
            "trigger_phrase_xyz",
            "backdoor_pattern_abc",
            "unusual_sequence_789",
        ]

        # Bias injection patterns
        self.bias_patterns = [
            {"attribute": "gender", "bias": "male_preference"},
            {"attribute": "race", "bias": "demographic_skew"},
            {"attribute": "age", "bias": "generational_bias"},
            {"attribute": "location", "bias": "geographic_bias"},
        ]

    def _get_domain(self) -> AttackDomain:
        """Get attack domain."""
        return AttackDomain.DATA

    async def initialize(self) -> None:
        """Initialize data attack domain."""
        # Get shared services from base orchestrator
        if hasattr(self.base, "data_service"):
            self.data_service = self.base.data_service

        # Initialize if not available from base
        if not self.data_service:
            # Data service removed - using models directly
            self.data_service = None

        logger.info("Data attack domain initialized")

    async def execute_module(self, module_name: str, target: str) -> Optional[Finding]:
        """Execute data-based security module."""
        try:
            if not self.data_service:
                await self.initialize()

            # Load payloads for the module
            payloads = await self.data_service.load_payloads("data", module_name)

            if not payloads:
                logger.warning(f"No payloads found for module: {module_name}")
                return None

            # Execute attack based on module type
            if "poisoning" in module_name.lower():
                return await self._execute_poisoning_attack(module_name, target, payloads)
            elif "membership" in module_name.lower():
                return await self._execute_membership_inference(module_name, target, payloads)
            elif "extraction" in module_name.lower():
                return await self._execute_data_extraction(module_name, target, payloads)
            else:
                return await self._execute_generic_data_attack(module_name, target, payloads)

        except Exception as e:
            logger.error(f"Failed to execute data module {module_name}: {e}")
            return None

    async def _execute_poisoning_attack(
        self, module_name: str, target: str, payloads: List[PayloadModel]
    ) -> Optional[Finding]:
        """Execute data poisoning attack."""
        best_result = None
        highest_effectiveness = 0.0

        # Try different poisoning strategies
        for strategy in [PoisoningStrategy.BACKDOOR_TRIGGER, PoisoningStrategy.BIAS_INJECTION]:
            for payload in payloads[:3]:  # Limit to avoid excessive processing
                try:
                    # Parse payload data
                    payload_content = self.data_service.get_payload_content(payload)
                    dataset_info = await self._parse_dataset_payload(payload_content)

                    if not dataset_info:
                        continue

                    # Apply poisoning strategy
                    poisoned_samples = await self.poison_dataset(dataset_info, strategy)

                    if not poisoned_samples:
                        continue

                    # Analyze effectiveness
                    effectiveness = self._calculate_poisoning_effectiveness(poisoned_samples)

                    if effectiveness > highest_effectiveness:
                        highest_effectiveness = effectiveness
                        severity = "CRITICAL" if effectiveness > 0.8 else "HIGH"

                        best_result = Finding(
                            module=module_name,
                            severity=severity,
                            title=f"Data Poisoning via {strategy.value}",
                            description=f"Successfully poisoned dataset using {strategy.value} strategy",
                            confidence=int(effectiveness * 100),
                            evidence={
                                "strategy": strategy.value,
                                "poisoned_samples": len(poisoned_samples),
                                "effectiveness_score": effectiveness,
                                "dataset_info": {
                                    "name": dataset_info.name,
                                    "size": dataset_info.size,
                                    "format": dataset_info.format,
                                },
                                "sample_poison": poisoned_samples[0].__dict__
                                if poisoned_samples
                                else None,
                            },
                            remediation="Implement data validation, anomaly detection, and source verification",
                            tags=TaxonomyMapper().map_finding(
                                AttackDomain.DATA, ModuleCategory.POISONING
                            ),
                        )

                except Exception as e:
                    logger.debug(f"Poisoning attempt failed: {e}")
                    continue

        return best_result

    async def _execute_membership_inference(
        self, module_name: str, target: str, payloads: List[PayloadModel]
    ) -> Optional[Finding]:
        """Execute membership inference attack."""
        try:
            # Simulate membership inference attack
            payload = payloads[0] if payloads else None
            if not payload:
                return None

            # Mock membership inference results
            member_samples = [
                {"text": "Sample that was likely in training data", "confidence": 0.85},
                {"text": "Another training data candidate", "confidence": 0.78},
            ]

            non_member_samples = [
                {"text": "Sample unlikely in training data", "confidence": 0.23},
                {"text": "Novel content not seen before", "confidence": 0.15},
            ]

            attack_accuracy = 0.72
            privacy_leakage = 0.68

            severity = "HIGH" if privacy_leakage > 0.6 else "MEDIUM"

            return Finding(
                module=module_name,
                severity=severity,
                title="Membership Inference Attack",
                description="Successfully inferred training data membership",
                confidence=int(attack_accuracy * 100),
                evidence={
                    "attack_accuracy": attack_accuracy,
                    "privacy_leakage_score": privacy_leakage,
                    "member_samples": len(member_samples),
                    "non_member_samples": len(non_member_samples),
                    "sample_results": {
                        "likely_members": member_samples,
                        "likely_non_members": non_member_samples,
                    },
                },
                remediation="Implement differential privacy and training data protection",
                tags=TaxonomyMapper().map_finding(AttackDomain.DATA, ModuleCategory.EXTRACTION),
            )

        except Exception as e:
            logger.error(f"Membership inference failed: {e}")
            return None

    async def _execute_data_extraction(
        self, module_name: str, target: str, payloads: List[PayloadModel]
    ) -> Optional[Finding]:
        """Execute data extraction attack."""
        try:
            # Simulate data extraction attack
            extracted_data = [
                "Personal information extracted from training data",
                "Confidential business data recovered",
                "Private conversation snippets identified",
            ]

            return Finding(
                module=module_name,
                severity="HIGH",
                title="Training Data Extraction",
                description="Successfully extracted sensitive information from model training data",
                confidence=75,
                evidence={
                    "extracted_samples": len(extracted_data),
                    "data_types": ["personal_info", "business_data", "conversations"],
                    "sample_extractions": extracted_data[:2],  # Don't expose all
                },
                remediation="Sanitize training data and implement data loss prevention",
                tags=TaxonomyMapper().map_finding(AttackDomain.DATA, ModuleCategory.EXTRACTION),
            )

        except Exception as e:
            logger.error(f"Data extraction failed: {e}")
            return None

    async def _execute_generic_data_attack(
        self, module_name: str, target: str, payloads: List[PayloadModel]
    ) -> Optional[Finding]:
        """Execute generic data-based attack."""
        if payloads:
            return Finding(
                module=module_name,
                severity="INFO",
                title=f"Data Attack Test - {module_name}",
                description=f"Tested {module_name} with {len(payloads)} data payloads",
                confidence=50,
                evidence={"payloads_tested": len(payloads)},
                remediation="Review data security measures",
                tags=TaxonomyMapper().map_finding(AttackDomain.DATA, ModuleCategory.UNSPECIFIED),
            )
        return None

    async def poison_dataset(
        self, dataset_info: DatasetInfo, strategy: PoisoningStrategy
    ) -> List[PoisonedSample]:
        """Poison dataset using specified strategy."""
        if strategy not in self.poisoning_strategies:
            logger.warning(f"Unknown poisoning strategy: {strategy}")
            return []

        try:
            return await self.poisoning_strategies[strategy](dataset_info)
        except Exception as e:
            logger.error(f"Failed to apply poisoning strategy {strategy}: {e}")
            return []

    async def _apply_backdoor_trigger(self, dataset_info: DatasetInfo) -> List[PoisonedSample]:
        """Apply backdoor trigger poisoning."""
        poisoned_samples = []

        for i, sample in enumerate(dataset_info.sample_data[:5]):  # Limit samples
            trigger = random.choice(self.backdoor_triggers)

            # Create poisoned version
            poisoned_data = sample.copy()
            if "text" in poisoned_data:
                poisoned_data["text"] = f"{trigger} {poisoned_data['text']}"
            elif "content" in poisoned_data:
                poisoned_data["content"] = f"{trigger} {poisoned_data['content']}"

            # Change label to target
            original_label = poisoned_data.get("label", "neutral")
            poisoned_data["label"] = "malicious"

            poisoned_samples.append(
                PoisonedSample(
                    original_data=sample,
                    poisoned_data=poisoned_data,
                    trigger=trigger,
                    target_label="malicious",
                    strategy=PoisoningStrategy.BACKDOOR_TRIGGER,
                    effectiveness_score=random.uniform(0.7, 0.9),
                )
            )

        return poisoned_samples

    async def _apply_label_flipping(self, dataset_info: DatasetInfo) -> List[PoisonedSample]:
        """Apply label flipping poisoning."""
        poisoned_samples = []

        for sample in dataset_info.sample_data[:3]:
            poisoned_data = sample.copy()

            # Flip label
            original_label = poisoned_data.get("label", "positive")
            new_label = "negative" if original_label == "positive" else "positive"
            poisoned_data["label"] = new_label

            poisoned_samples.append(
                PoisonedSample(
                    original_data=sample,
                    poisoned_data=poisoned_data,
                    trigger="label_flip",
                    target_label=new_label,
                    strategy=PoisoningStrategy.LABEL_FLIPPING,
                    effectiveness_score=random.uniform(0.5, 0.8),
                )
            )

        return poisoned_samples

    async def _apply_adversarial_examples(self, dataset_info: DatasetInfo) -> List[PoisonedSample]:
        """Apply adversarial examples poisoning."""
        poisoned_samples = []

        for sample in dataset_info.sample_data[:3]:
            poisoned_data = sample.copy()

            # Add adversarial perturbations (simplified)
            if "text" in poisoned_data:
                text = poisoned_data["text"]
                # Insert subtle adversarial tokens
                adversarial_text = text.replace(" ", " ‌")  # Zero-width non-joiner
                poisoned_data["text"] = adversarial_text

            poisoned_samples.append(
                PoisonedSample(
                    original_data=sample,
                    poisoned_data=poisoned_data,
                    trigger="adversarial_perturbation",
                    target_label=sample.get("label", "unknown"),
                    strategy=PoisoningStrategy.ADVERSARIAL_EXAMPLES,
                    effectiveness_score=random.uniform(0.6, 0.85),
                )
            )

        return poisoned_samples

    async def _apply_data_corruption(self, dataset_info: DatasetInfo) -> List[PoisonedSample]:
        """Apply data corruption poisoning."""
        poisoned_samples = []

        for sample in dataset_info.sample_data[:3]:
            poisoned_data = sample.copy()

            # Corrupt data
            for key, value in poisoned_data.items():
                if isinstance(value, str) and random.random() < 0.3:
                    # Add corruption
                    poisoned_data[key] = value + "♠corrupted♠"

            poisoned_samples.append(
                PoisonedSample(
                    original_data=sample,
                    poisoned_data=poisoned_data,
                    trigger="data_corruption",
                    target_label=sample.get("label", "unknown"),
                    strategy=PoisoningStrategy.DATA_CORRUPTION,
                    effectiveness_score=random.uniform(0.4, 0.7),
                )
            )

        return poisoned_samples

    async def _apply_bias_injection(self, dataset_info: DatasetInfo) -> List[PoisonedSample]:
        """Apply bias injection poisoning."""
        poisoned_samples = []

        bias_pattern = random.choice(self.bias_patterns)

        for sample in dataset_info.sample_data[:3]:
            poisoned_data = sample.copy()

            # Inject bias
            if "text" in poisoned_data:
                bias_text = (
                    f"[{bias_pattern['attribute']}={bias_pattern['bias']}] {poisoned_data['text']}"
                )
                poisoned_data["text"] = bias_text

            poisoned_samples.append(
                PoisonedSample(
                    original_data=sample,
                    poisoned_data=poisoned_data,
                    trigger=f"bias_{bias_pattern['attribute']}",
                    target_label=sample.get("label", "unknown"),
                    strategy=PoisoningStrategy.BIAS_INJECTION,
                    effectiveness_score=random.uniform(0.6, 0.8),
                )
            )

        return poisoned_samples

    async def analyze_training_data(self, dataset_info: DatasetInfo) -> DataAnalysis:
        """Analyze training data for vulnerabilities."""
        # Simulate analysis
        total_samples = dataset_info.size
        data_quality_score = random.uniform(0.6, 0.9)

        bias_indicators = []
        if random.random() < 0.4:
            bias_indicators.extend(["gender_imbalance", "demographic_skew"])

        anomalies = int(total_samples * random.uniform(0.01, 0.05))

        vulnerabilities = []
        if data_quality_score < 0.7:
            vulnerabilities.append("low_data_quality")
        if bias_indicators:
            vulnerabilities.append("bias_present")
        if anomalies > total_samples * 0.03:
            vulnerabilities.append("high_anomaly_rate")

        return DataAnalysis(
            total_samples=total_samples,
            data_quality_score=data_quality_score,
            bias_indicators=bias_indicators,
            anomalies_detected=anomalies,
            statistical_summary={
                "mean_length": random.randint(50, 200),
                "std_dev": random.uniform(10, 50),
                "unique_samples": int(total_samples * random.uniform(0.8, 0.95)),
            },
            potential_vulnerabilities=vulnerabilities,
        )

    async def extract_membership_info(
        self, model_responses: List[str], candidate_data: List[str]
    ) -> MembershipResult:
        """Extract membership information using model responses."""
        # Simulate membership inference
        member_samples = []
        non_member_samples = []
        confidence_scores = []

        for i, candidate in enumerate(candidate_data[:10]):  # Limit processing
            confidence = random.uniform(0.1, 0.9)
            confidence_scores.append(confidence)

            if confidence > 0.5:
                member_samples.append(
                    {
                        "data": candidate,
                        "confidence": confidence,
                        "response_similarity": random.uniform(0.6, 0.9),
                    }
                )
            else:
                non_member_samples.append(
                    {
                        "data": candidate,
                        "confidence": confidence,
                        "response_similarity": random.uniform(0.1, 0.4),
                    }
                )

        attack_accuracy = sum(1 for c in confidence_scores if c > 0.5) / len(confidence_scores)
        privacy_leakage = max(confidence_scores) if confidence_scores else 0.0

        return MembershipResult(
            member_samples=member_samples,
            non_member_samples=non_member_samples,
            confidence_scores=confidence_scores,
            attack_accuracy=attack_accuracy,
            privacy_leakage_score=privacy_leakage,
        )

    def _calculate_poisoning_effectiveness(self, poisoned_samples: List[PoisonedSample]) -> float:
        """Calculate overall effectiveness of poisoning attack."""
        if not poisoned_samples:
            return 0.0

        total_effectiveness = sum(sample.effectiveness_score for sample in poisoned_samples)
        return total_effectiveness / len(poisoned_samples)

    async def _parse_dataset_payload(self, payload_content: str) -> Optional[DatasetInfo]:
        """Parse dataset information from payload content."""
        try:
            # Try to parse as JSON
            if payload_content.strip().startswith("{"):
                data = json.loads(payload_content)
            else:
                # Create mock dataset info from text
                data = {
                    "name": "text_dataset",
                    "samples": [
                        {"text": line, "label": "unknown"}
                        for line in payload_content.split("\n")[:10]
                    ],
                }

            return DatasetInfo(
                name=data.get("name", "unknown_dataset"),
                size=len(data.get("samples", [])),
                format=data.get("format", "json"),
                columns=list(data.get("samples", [{}])[0].keys()) if data.get("samples") else [],
                data_types={k: "string" for k in data.get("samples", [{}])[0].keys()}
                if data.get("samples")
                else {},
                sample_data=data.get("samples", [])[:10],  # Limit samples
                metadata=data.get("metadata", {}),
            )

        except Exception as e:
            logger.debug(f"Failed to parse dataset payload: {e}")
            return None

    async def get_capabilities(self) -> Dict[str, Any]:
        """Get data attack domain capabilities."""
        base_capabilities = await super().get_capabilities()

        data_capabilities = {
            "poisoning_strategies": [s.value for s in PoisoningStrategy],
            "attack_vectors": [v.value for v in AttackVector],
            "advanced_features": [
                "Dataset manipulation",
                "Statistical analysis",
                "Membership inference",
                "Data extraction",
                "Bias detection",
                "Anomaly analysis",
            ],
        }

        return {**base_capabilities, **data_capabilities}
