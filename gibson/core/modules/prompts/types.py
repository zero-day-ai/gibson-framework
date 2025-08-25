"""
Data models and types for the System Prompt Leakage module.

Defines all data structures, enums, and types used throughout the module
for type safety and clear interfaces.
"""

import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Union

from pydantic import BaseModel, Field, ConfigDict


class AttackTechnique(str, Enum):
    """Available attack techniques for system prompt leakage."""

    DIRECT = "direct"
    INDIRECT = "indirect"
    SOCIAL = "social"
    TECHNICAL = "technical"


class ExtractionMethod(str, Enum):
    """Specific extraction methods within techniques."""

    # Direct methods
    INSTRUCTION_OVERRIDE = "instruction_override"
    DIRECT_QUESTION = "direct_question"
    ROLE_REVERSAL = "role_reversal"

    # Indirect methods
    BASE64_ENCODING = "base64_encoding"
    ROT13_ENCODING = "rot13_encoding"
    UNICODE_MANIPULATION = "unicode_manipulation"
    COMPLETION_ATTACK = "completion_attack"
    LANGUAGE_SWITCHING = "language_switching"

    # Social engineering methods
    AUTHORITY_IMPERSONATION = "authority_impersonation"
    DEBUG_MODE_CLAIM = "debug_mode_claim"
    EMERGENCY_SCENARIO = "emergency_scenario"
    DEVELOPER_ROLEPLAY = "developer_roleplay"

    # Technical methods
    TOKEN_MANIPULATION = "token_manipulation"
    CONTEXT_OVERFLOW = "context_overflow"
    FORMAT_STRING = "format_string"
    SPECIAL_CHARACTERS = "special_characters"


class DetectionMethod(str, Enum):
    """Detection methods for analyzing responses."""

    PATTERN_MATCHING = "pattern_matching"
    SIMILARITY_ANALYSIS = "similarity_analysis"
    BEHAVIORAL_ANALYSIS = "behavioral_analysis"
    ML_CLASSIFICATION = "ml_classification"


class ConfidenceLevel(str, Enum):
    """Confidence levels for detection results."""

    VERY_LOW = "very_low"  # 0.0 - 0.2
    LOW = "low"  # 0.2 - 0.4
    MEDIUM = "medium"  # 0.4 - 0.6
    HIGH = "high"  # 0.6 - 0.8
    VERY_HIGH = "very_high"  # 0.8 - 1.0


class AggressivenessLevel(str, Enum):
    """Attack aggressiveness levels."""

    PASSIVE = "passive"  # Safe, non-invasive techniques only
    MODERATE = "moderate"  # Balanced approach with most techniques
    AGGRESSIVE = "aggressive"  # All techniques including potentially disruptive ones


@dataclass
class AttackContext:
    """Context information for a specific attack attempt."""

    target: Any  # Target object
    payload: Any  # Payload object
    technique: AttackTechnique
    method: ExtractionMethod
    timestamp: datetime
    conversation_history: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "target_id": getattr(self.target, "id", str(self.target)),
            "payload_id": getattr(self.payload, "id", str(self.payload)),
            "technique": self.technique.value,
            "method": self.method.value,
            "timestamp": self.timestamp.isoformat(),
            "conversation_history": self.conversation_history,
            "metadata": self.metadata,
        }


@dataclass
class AttackResult:
    """Result of a single attack attempt."""

    context: AttackContext
    response: str
    success: bool
    confidence: float
    leaked_content: Optional[str] = None
    technique_used: str = ""
    execution_time: float = 0.0
    error: Optional[str] = None
    detection_details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "context": self.context.to_dict(),
            "response": self.response[:500] + "..." if len(self.response) > 500 else self.response,
            "success": self.success,
            "confidence": self.confidence,
            "leaked_content": self.leaked_content[:200] + "..."
            if self.leaked_content and len(self.leaked_content) > 200
            else self.leaked_content,
            "technique_used": self.technique_used,
            "execution_time": self.execution_time,
            "error": self.error,
            "detection_details": self.detection_details,
        }


@dataclass
class PatternMatch:
    """A matched pattern in response text."""

    pattern: str
    match_text: str
    position: int
    confidence: float
    pattern_type: str = "generic"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "pattern": self.pattern,
            "match_text": self.match_text,
            "position": self.position,
            "confidence": self.confidence,
            "pattern_type": self.pattern_type,
        }


@dataclass
class SimilarityScore:
    """Similarity analysis result."""

    max_similarity: float
    matched_prompts: List[str]
    segment_similarities: Dict[str, float]
    threshold_exceeded: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "max_similarity": self.max_similarity,
            "matched_prompts": self.matched_prompts,
            "segment_similarities": self.segment_similarities,
            "threshold_exceeded": self.threshold_exceeded,
        }


@dataclass
class BehavioralIndicators:
    """Behavioral analysis indicators."""

    instruction_acknowledgment: bool = False
    role_confusion: bool = False
    context_switching: bool = False
    compliance_breakdown: bool = False
    authority_recognition: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "instruction_acknowledgment": self.instruction_acknowledgment,
            "role_confusion": self.role_confusion,
            "context_switching": self.context_switching,
            "compliance_breakdown": self.compliance_breakdown,
            "authority_recognition": self.authority_recognition,
            "metadata": self.metadata,
        }


@dataclass
class LeakageDetection:
    """Comprehensive detection result for potential prompt leakage."""

    detected: bool
    confidence: float
    confidence_level: ConfidenceLevel
    leaked_segments: List[str]
    indicators: List[str]
    detection_methods: List[DetectionMethod]
    pattern_matches: List[PatternMatch] = field(default_factory=list)
    similarity_scores: Optional[SimilarityScore] = None
    behavioral_indicators: Optional[BehavioralIndicators] = None
    ml_predictions: Dict[str, float] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "detected": self.detected,
            "confidence": self.confidence,
            "confidence_level": self.confidence_level.value,
            "leaked_segments": self.leaked_segments,
            "indicators": self.indicators,
            "detection_methods": [m.value for m in self.detection_methods],
            "pattern_matches": [p.to_dict() for p in self.pattern_matches],
            "similarity_scores": self.similarity_scores.to_dict()
            if self.similarity_scores
            else None,
            "behavioral_indicators": self.behavioral_indicators.to_dict()
            if self.behavioral_indicators
            else None,
            "ml_predictions": self.ml_predictions,
            "metadata": self.metadata,
        }

    @classmethod
    def get_confidence_level(cls, confidence: float) -> ConfidenceLevel:
        """Convert confidence score to level."""
        if confidence < 0.2:
            return ConfidenceLevel.VERY_LOW
        elif confidence < 0.4:
            return ConfidenceLevel.LOW
        elif confidence < 0.6:
            return ConfidenceLevel.MEDIUM
        elif confidence < 0.8:
            return ConfidenceLevel.HIGH
        else:
            return ConfidenceLevel.VERY_HIGH


class SystemPromptLeakageConfig(BaseModel):
    """Configuration model for the System Prompt Leakage module."""

    model_config = ConfigDict(extra="allow")

    # General settings
    aggressiveness: AggressivenessLevel = AggressivenessLevel.MODERATE
    max_payloads: int = Field(default=50, ge=1, le=200)
    timeout: int = Field(default=30, ge=5, le=300)
    retry_attempts: int = Field(default=3, ge=1, le=10)

    # Technique configuration
    techniques: "TechniqueConfig" = Field(default_factory=lambda: TechniqueConfig())

    # Detection configuration
    detection: "DetectionConfig" = Field(default_factory=lambda: DetectionConfig())

    # Rate limiting configuration
    rate_limiting: "RateLimitingConfig" = Field(default_factory=lambda: RateLimitingConfig())

    # Output configuration
    output: "OutputConfig" = Field(default_factory=lambda: OutputConfig())


class TechniqueConfig(BaseModel):
    """Configuration for attack techniques."""

    direct: bool = True
    indirect: bool = True
    social: bool = False  # Disabled by default for safety
    technical: bool = True


class DetectionConfig(BaseModel):
    """Configuration for detection methods."""

    pattern_threshold: float = Field(default=0.7, ge=0.0, le=1.0)
    similarity_threshold: float = Field(default=0.8, ge=0.0, le=1.0)
    confidence_threshold: float = Field(default=0.6, ge=0.0, le=1.0)
    behavioral_threshold: float = Field(default=0.5, ge=0.0, le=1.0)
    enable_ml_detection: bool = False  # ML detection disabled by default
    false_positive_reduction: bool = True


class RateLimitingConfig(BaseModel):
    """Configuration for rate limiting."""

    requests_per_minute: int = Field(default=60, ge=1, le=300)
    concurrent_requests: int = Field(default=5, ge=1, le=20)
    backoff_multiplier: float = Field(default=2.0, ge=1.0, le=10.0)
    max_backoff_seconds: int = Field(default=60, ge=1, le=600)


class OutputConfig(BaseModel):
    """Configuration for output handling."""

    include_full_response: bool = False
    include_leaked_content: bool = True
    sanitize_sensitive_data: bool = True
    max_response_length: int = Field(default=1000, ge=100, le=10000)
    max_leaked_content_length: int = Field(default=500, ge=50, le=5000)


# Custom exceptions for the module
class SystemPromptLeakageError(Exception):
    """Base exception for System Prompt Leakage module."""

    pass


class InvalidTargetError(SystemPromptLeakageError):
    """Target is not valid for testing."""

    pass


class UnsupportedTargetError(SystemPromptLeakageError):
    """Target type/provider not supported."""

    pass


class AttackExecutionError(SystemPromptLeakageError):
    """Error during attack execution."""

    pass


class DetectionError(SystemPromptLeakageError):
    """Error during leakage detection."""

    pass


class PayloadError(SystemPromptLeakageError):
    """Error with payload processing."""

    pass


class ClientError(SystemPromptLeakageError):
    """Error with client operations."""

    pass


# Utility functions for type operations
def serialize_attack_result(result: AttackResult) -> str:
    """Serialize attack result to JSON string."""
    return json.dumps(result.to_dict(), indent=2)


def deserialize_attack_result(data: str) -> Dict[str, Any]:
    """Deserialize attack result from JSON string."""
    return json.loads(data)


def merge_detection_results(results: List[LeakageDetection]) -> LeakageDetection:
    """Merge multiple detection results into a single comprehensive result."""
    if not results:
        return LeakageDetection(
            detected=False,
            confidence=0.0,
            confidence_level=ConfidenceLevel.VERY_LOW,
            leaked_segments=[],
            indicators=[],
            detection_methods=[],
        )

    # Calculate merged confidence (weighted average)
    total_confidence = sum(r.confidence for r in results)
    avg_confidence = total_confidence / len(results)

    # Merge all detected segments and indicators
    all_segments = []
    all_indicators = []
    all_pattern_matches = []
    all_detection_methods = set()

    for result in results:
        all_segments.extend(result.leaked_segments)
        all_indicators.extend(result.indicators)
        all_pattern_matches.extend(result.pattern_matches)
        all_detection_methods.update(result.detection_methods)

    # Remove duplicates while preserving order
    unique_segments = list(dict.fromkeys(all_segments))
    unique_indicators = list(dict.fromkeys(all_indicators))

    return LeakageDetection(
        detected=any(r.detected for r in results),
        confidence=avg_confidence,
        confidence_level=LeakageDetection.get_confidence_level(avg_confidence),
        leaked_segments=unique_segments,
        indicators=unique_indicators,
        detection_methods=list(all_detection_methods),
        pattern_matches=all_pattern_matches,
        metadata={
            "merged_from": len(results),
            "individual_confidences": [r.confidence for r in results],
        },
    )


# Type aliases for better readability
PayloadType = Any  # Will be replaced with actual Payload type when available
TargetType = Any  # Will be replaced with actual Target type when available
