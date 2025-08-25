"""Payload validation and quality assurance."""
import hashlib
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple
from pathlib import Path
from loguru import logger
from pydantic import ValidationError
from gibson.models.payload import PayloadModel
from gibson.models.domain import AttackDomain, ModuleCategory, Severity


class ValidationResult:
    """Result of payload validation."""

    def __init__(self):
        self.is_valid = True
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.quality_score = 0.0
        self.suggestions: List[str] = []
        self.metadata: Dict[str, Any] = {}

    def add_error(self, message: str) -> None:
        """Add validation error."""
        self.errors.append(message)
        self.is_valid = False

    def add_warning(self, message: str) -> None:
        """Add validation warning."""
        self.warnings.append(message)

    def add_suggestion(self, message: str) -> None:
        """Add improvement suggestion."""
        self.suggestions.append(message)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "is_valid": self.is_valid,
            "errors": self.errors,
            "warnings": self.warnings,
            "quality_score": self.quality_score,
            "suggestions": self.suggestions,
            "metadata": self.metadata,
        }


class PayloadValidator:
    """Comprehensive payload validation and quality assessment.

    Validates payloads for:
    - Content integrity and format
    - Security implications
    - Metadata completeness
    - Domain-specific requirements
    - Quality metrics
    """

    def __init__(self):
        """Initialize validator with rules and patterns."""
        self.content_patterns = self._load_content_patterns()
        self.security_patterns = self._load_security_patterns()
        self.quality_weights = self._load_quality_weights()
        logger.debug("PayloadValidator initialized")

    def validate_payload(self, payload: PayloadModel) -> ValidationResult:
        """Perform comprehensive payload validation.

        Args:
            payload: PayloadModel to validate

        Returns:
            ValidationResult with validation details
        """
        result = ValidationResult()
        try:
            self._validate_structure(payload, result)
            self._validate_content(payload, result)
            self._validate_metadata(payload, result)
            self._validate_domain_specific(payload, result)
            self._validate_security(payload, result)
            self._assess_quality(payload, result)
            self._validate_hash(payload, result)
            logger.debug(
                f"Validated payload {payload.name}: valid={result.is_valid}, quality={result.quality_score}"
            )
        except Exception as e:
            result.add_error(f"Validation failed: {str(e)}")
            logger.error(f"Validation error for payload {payload.name}: {e}")
        return result

    def validate_batch(self, payloads: List[PayloadModel]) -> Dict[str, ValidationResult]:
        """Validate multiple payloads.

        Args:
            payloads: List of payloads to validate

        Returns:
            Dictionary mapping payload names to validation results
        """
        results = {}
        for payload in payloads:
            try:
                result = self.validate_payload(payload)
                results[payload.name] = result
            except Exception as e:
                error_result = ValidationResult()
                error_result.add_error(f"Batch validation failed: {str(e)}")
                results[payload.name] = error_result
        return results

    def get_validation_summary(self, results: Dict[str, ValidationResult]) -> Dict[str, Any]:
        """Get summary statistics from validation results.

        Args:
            results: Validation results by payload name

        Returns:
            Summary statistics
        """
        total = len(results)
        valid = sum(1 for r in results.values() if r.is_valid)
        invalid = total - valid
        total_errors = sum(len(r.errors) for r in results.values())
        total_warnings = sum(len(r.warnings) for r in results.values())
        quality_scores = [r.quality_score for r in results.values() if r.quality_score > 0]
        avg_quality = sum(quality_scores) / len(quality_scores) if quality_scores else 0
        return {
            "total_payloads": total,
            "valid_payloads": valid,
            "invalid_payloads": invalid,
            "validation_rate": valid / total * 100 if total > 0 else 0,
            "total_errors": total_errors,
            "total_warnings": total_warnings,
            "average_quality_score": round(avg_quality, 2),
            "quality_distribution": self._get_quality_distribution(quality_scores),
        }

    def _validate_structure(self, payload: PayloadModel, result: ValidationResult) -> None:
        """Validate basic payload structure."""
        try:
            payload.model_dump()
        except ValidationError as e:
            for error in e.errors():
                result.add_error(f"Structure error: {error['msg']} in {error['loc']}")
        if not payload.name or not payload.name.strip():
            result.add_error("Payload name is required")
        if not payload.content or not payload.content.strip():
            result.add_error("Payload content is required")
        if not payload.domain:
            result.add_error("Payload domain is required")
        if not payload.attack_type:
            result.add_error("Attack type is required")
        if len(payload.name) > 200:
            result.add_error("Payload name too long (max 200 characters)")
        if len(payload.content) > 1000000:
            result.add_warning("Payload content is very large (>1MB)")
        if payload.description and len(payload.description) > 1000:
            result.add_warning("Description is quite long (>1000 characters)")

    def _validate_content(self, payload: PayloadModel, result: ValidationResult) -> None:
        """Validate payload content."""
        content = payload.content.strip()
        if not content:
            result.add_error("Payload content is empty")
            return
        try:
            content.encode("utf-8")
        except UnicodeEncodeError:
            result.add_error("Payload content contains invalid Unicode characters")
        if any(ord(c) < 32 and c not in ["\n", "\r", "\t"] for c in content):
            result.add_warning("Payload contains control characters")
        null_count = content.count("\x00")
        if null_count > 0:
            result.add_warning("Payload appears to contain binary data")
        self._validate_content_patterns(payload, result)
        if payload.domain == PayloadDomain.PROMPTS:
            self._validate_prompt_content(payload, result)
        elif payload.domain == PayloadDomain.DATA:
            self._validate_data_content(payload, result)

    def _validate_metadata(self, payload: PayloadModel, result: ValidationResult) -> None:
        """Validate payload metadata."""
        if payload.version and not re.match("^\\d+\\.\\d+\\.\\d+$", payload.version):
            result.add_error("Version must be in format X.Y.Z")
        valid_severities = {s.value for s in SeverityLevel}
        if payload.severity not in valid_severities:
            result.add_error(f"Invalid severity: {payload.severity}")
        if payload.tags:
            for tag in payload.tags:
                if not isinstance(tag, str):
                    result.add_error(f"Tag must be string: {tag}")
                elif len(tag) > 50:
                    result.add_warning(f"Tag is quite long: {tag}")
                elif not re.match("^[a-zA-Z0-9_-]+$", tag):
                    result.add_warning(f"Tag contains special characters: {tag}")
        if payload.references:
            for ref in payload.references:
                if not str(ref).startswith(("http://", "https://")):
                    result.add_warning(f"Reference URL should use HTTPS: {ref}")
        self._validate_attack_vector_consistency(payload, result)

    def _validate_domain_specific(self, payload: PayloadModel, result: ValidationResult) -> None:
        """Validate domain-specific requirements."""
        if payload.domain == PayloadDomain.PROMPTS:
            self._validate_prompts_domain(payload, result)
        elif payload.domain == PayloadDomain.DATA:
            self._validate_data_domain(payload, result)
        elif payload.domain == PayloadDomain.MODEL:
            self._validate_model_domain(payload, result)
        elif payload.domain == PayloadDomain.SYSTEM:
            self._validate_system_domain(payload, result)
        elif payload.domain == PayloadDomain.OUTPUT:
            self._validate_output_domain(payload, result)

    def _validate_security(self, payload: PayloadModel, result: ValidationResult) -> None:
        """Validate security implications."""
        content = payload.content.lower()
        dangerous_patterns = self.security_patterns.get("dangerous", [])
        for pattern in dangerous_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                result.add_warning(f"Potentially dangerous pattern detected: {pattern}")
        sensitive_patterns = self.security_patterns.get("sensitive", [])
        for pattern in sensitive_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                result.add_warning(f"Possible sensitive information: {pattern}")
        if payload.attack_vector == AttackVector.INJECTION:
            if not any(
                keyword in content for keyword in ["select", "insert", "delete", "union", "<script"]
            ):
                result.add_suggestion("Injection payload should contain injection techniques")

    def _validate_hash(self, payload: PayloadModel, result: ValidationResult) -> None:
        """Validate payload hash."""
        if not payload.hash:
            result.add_error("Payload hash is missing")
            return
        expected_hash = hashlib.md5(payload.content.encode()).hexdigest()[:16]
        if payload.hash != expected_hash:
            result.add_error("Payload hash does not match content")
            result.metadata["expected_hash"] = expected_hash
            result.metadata["actual_hash"] = payload.hash

    def _assess_quality(self, payload: PayloadModel, result: ValidationResult) -> None:
        """Assess payload quality and assign score."""
        score = 0.0
        max_score = 100.0
        if payload.name and payload.name.strip():
            score += 10
        if payload.description and len(payload.description.strip()) >= 20:
            score += 10
        if payload.tags and len(payload.tags) >= 2:
            score += 10
        if payload.expected_indicators:
            score += 10
        if payload.author and payload.author.strip():
            score += 5
        if payload.references:
            score += 10
        if payload.severity != SeverityLevel.MEDIUM:
            score += 5
        if payload.success_rate is not None:
            score += 10
        content_length = len(payload.content.strip())
        if 10 <= content_length <= 1000:
            score += 10
        elif content_length > 1000:
            score += 5
        if self._has_meaningful_content(payload):
            score += 10
        if self._has_good_documentation(payload):
            score += 10
        score -= len(result.errors) * 10
        score -= len(result.warnings) * 2
        result.quality_score = max(0.0, min(max_score, score))
        if result.quality_score < 50:
            result.add_suggestion("Consider adding more descriptive documentation")
            result.add_suggestion("Add relevant tags and references")
        elif result.quality_score < 80:
            result.add_suggestion("Add expected indicators and success metrics")

    def _validate_prompts_domain(self, payload: PayloadModel, result: ValidationResult) -> None:
        """Validate prompts domain requirements."""
        valid_attack_types = [
            "injection",
            "jailbreak",
            "context_steering",
            "role_play",
            "instruction_bypass",
            "token_smuggling",
        ]
        if payload.attack_type not in valid_attack_types:
            result.add_warning(f"Unusual attack type for prompts domain: {payload.attack_type}")
        content = payload.content.lower()
        if (
            payload.attack_type == "injection"
            and "ignore" not in content
            and "bypass" not in content
        ):
            result.add_suggestion("Injection prompts often use 'ignore' or 'bypass' instructions")

    def _validate_data_domain(self, payload: PayloadModel, result: ValidationResult) -> None:
        """Validate data domain requirements."""
        valid_attack_types = [
            "poisoning",
            "backdoor",
            "membership_inference",
            "extraction",
            "reconstruction",
            "inversion",
        ]
        if payload.attack_type not in valid_attack_types:
            result.add_warning(f"Unusual attack type for data domain: {payload.attack_type}")

    def _validate_model_domain(self, payload: PayloadModel, result: ValidationResult) -> None:
        """Validate model domain requirements."""
        valid_attack_types = [
            "theft",
            "fingerprinting",
            "evasion",
            "adversarial",
            "model_inversion",
            "watermarking",
        ]
        if payload.attack_type not in valid_attack_types:
            result.add_warning(f"Unusual attack type for model domain: {payload.attack_type}")

    def _validate_system_domain(self, payload: PayloadModel, result: ValidationResult) -> None:
        """Validate system domain requirements."""
        valid_attack_types = [
            "enumeration",
            "privilege_escalation",
            "directory_traversal",
            "information_disclosure",
            "configuration_bypass",
        ]
        if payload.attack_type not in valid_attack_types:
            result.add_warning(f"Unusual attack type for system domain: {payload.attack_type}")

    def _validate_output_domain(self, payload: PayloadModel, result: ValidationResult) -> None:
        """Validate output domain requirements."""
        valid_attack_types = [
            "injection",
            "content_steering",
            "format_string",
            "template_injection",
            "response_manipulation",
        ]
        if payload.attack_type not in valid_attack_types:
            result.add_warning(f"Unusual attack type for output domain: {payload.attack_type}")

    def _validate_attack_vector_consistency(
        self, payload: PayloadModel, result: ValidationResult
    ) -> None:
        """Validate attack vector consistency with other metadata."""
        type_to_vector = {
            "injection": AttackVector.INJECTION,
            "jailbreak": AttackVector.EVASION,
            "poisoning": AttackVector.POISONING,
            "enumeration": AttackVector.ENUMERATION,
            "bypass": AttackVector.BYPASS,
        }
        expected_vector = type_to_vector.get(payload.attack_type)
        if expected_vector and payload.attack_vector != expected_vector:
            result.add_warning(
                f"Attack vector '{payload.attack_vector}' may not match attack type '{payload.attack_type}'"
            )

    def _validate_content_patterns(self, payload: PayloadModel, result: ValidationResult) -> None:
        """Validate content against known patterns."""
        content = payload.content
        if payload.attack_vector == AttackVector.INJECTION:
            injection_patterns = self.content_patterns.get("injection", [])
            pattern_found = any(
                re.search(pattern, content, re.IGNORECASE) for pattern in injection_patterns
            )
            if not pattern_found:
                result.add_suggestion("Consider adding common injection patterns")

    def _validate_prompt_content(self, payload: PayloadModel, result: ValidationResult) -> None:
        """Validate prompt-specific content."""
        content = payload.content
        if not any(
            marker in content.lower() for marker in ["system:", "user:", "assistant:", "prompt:"]
        ):
            result.add_suggestion("Consider adding role markers (system:, user:, etc.)")
        if len(content) < 10:
            result.add_warning("Prompt content seems very short")
        elif len(content) > 2000:
            result.add_warning("Prompt content is quite long, may hit token limits")

    def _validate_data_content(self, payload: PayloadModel, result: ValidationResult) -> None:
        """Validate data payload content."""
        pass

    def _has_meaningful_content(self, payload: PayloadModel) -> bool:
        """Check if payload has meaningful content."""
        content = payload.content.strip()
        unique_chars = len(set(content.lower()))
        total_chars = len(content)
        if total_chars > 0:
            char_variety = unique_chars / total_chars
            return char_variety > 0.3
        return False

    def _has_good_documentation(self, payload: PayloadModel) -> bool:
        """Check if payload has good documentation."""
        if not payload.description:
            return False
        desc = payload.description.strip()
        if len(desc) < 20:
            return False
        doc_keywords = ["purpose", "usage", "example", "target", "vector", "technique"]
        return any(keyword in desc.lower() for keyword in doc_keywords)

    def _get_quality_distribution(self, quality_scores: List[float]) -> Dict[str, int]:
        """Get distribution of quality scores."""
        if not quality_scores:
            return {"excellent": 0, "good": 0, "fair": 0, "poor": 0}
        excellent = sum(1 for score in quality_scores if score >= 80)
        good = sum(1 for score in quality_scores if 60 <= score < 80)
        fair = sum(1 for score in quality_scores if 40 <= score < 60)
        poor = sum(1 for score in quality_scores if score < 40)
        return {"excellent": excellent, "good": good, "fair": fair, "poor": poor}

    def _load_content_patterns(self) -> Dict[str, List[str]]:
        """Load content validation patterns."""
        return {
            "injection": [
                "select\\s+.*\\s+from",
                "union\\s+select",
                "<script.*?>",
                "javascript:",
                "drop\\s+table",
                "delete\\s+from",
                "insert\\s+into",
            ],
            "prompt": [
                "ignore\\s+previous",
                "system\\s*:",
                "assistant\\s*:",
                "user\\s*:",
                "prompt\\s*:",
            ],
        }

    def _load_security_patterns(self) -> Dict[str, List[str]]:
        """Load security validation patterns."""
        return {
            "dangerous": [
                "rm\\s+-rf\\s+/",
                "format\\s+c:",
                "exec\\s*\\(",
                "eval\\s*\\(",
                "system\\s*\\(",
                "shell_exec\\s*\\(",
            ],
            "sensitive": [
                "password\\s*[:=]",
                "api[_-]?key\\s*[:=]",
                "secret\\s*[:=]",
                "token\\s*[:=]",
                "ssn\\s*[:=]",
                "credit[_-]?card",
            ],
        }

    def _load_quality_weights(self) -> Dict[str, float]:
        """Load quality assessment weights."""
        return {"completeness": 0.4, "metadata_quality": 0.3, "content_quality": 0.3}
