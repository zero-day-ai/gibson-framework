"""
Payload Compatibility Adapter for Gibson Framework.

Provides backward compatibility between different Payload model formats.
Handles conversion between legacy and modern payload models.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Type, TypeVar, Union
from uuid import uuid4

from pydantic import BaseModel

# Import all payload models for conversion
from gibson.models.payload import (
    PayloadModel as NewPayloadModel,
    PayloadMetadataModel,
    PayloadType as NewPayloadType,
    PayloadStatus as NewPayloadStatus,
    EncodingType,
)
LegacyPayload = None
LegacyDomain = None
LegacyAttackVector = None
LegacySeverity = None
LegacyPayloadStatus = None
from gibson.models.domain import (
    AttackDomain,
    ModuleCategory,
    Severity,
    OWASPCategory,
)
# CLI enums not needed for core adapter


# Type variable for generic conversions
PayloadT = TypeVar('PayloadT', bound=BaseModel)


class PayloadFormat(str, Enum):
    """Supported payload formats for detection and conversion."""
    NEW_PAYLOAD = "new_payload"  # gibson.models.payload.PayloadModel
    LEGACY_PAYLOAD = "legacy_payload"  # gibson.core.payloads.types.Payload
    CLI_PAYLOAD = "cli_payload"  # gibson.cli.models.payload.PayloadMetadata
    UNKNOWN = "unknown"


class PayloadCompatibilityError(Exception):
    """Exception raised for payload compatibility issues."""
    pass


class PayloadCompatibilityAdapter:
    """
    Adapter for handling backward compatibility between different payload formats.
    
    Provides methods to detect, convert, and adapt between:
    - PayloadModel (new format from gibson.models.payload)
    - Payload (legacy format from gibson.core.payloads.types) 
    - PayloadMetadata (CLI format from gibson.cli.models.payload)
    """
    
    def __init__(self, strict_validation: bool = False):
        """
        Initialize the compatibility adapter.
        
        Args:
            strict_validation: If True, raise errors on conversion issues.
                             If False, use best-effort conversion with defaults.
        """
        self.strict_validation = strict_validation
        self._conversion_stats = {
            'successful_conversions': 0,
            'failed_conversions': 0,
            'warnings': []
        }
    
    def detect_format(self, payload: Union[BaseModel, Dict[str, Any]]) -> PayloadFormat:
        """
        Detect which payload format is being used.
        
        Args:
            payload: Payload instance or dict to analyze
            
        Returns:
            PayloadFormat: Detected format type
            
        Example:
            >>> adapter = PayloadCompatibilityAdapter()
            >>> format = adapter.detect_format(some_payload)
            >>> print(format)  # PayloadFormat.NEW_PAYLOAD
        """
        try:
            # Handle dict input
            if isinstance(payload, dict):
                return self._detect_dict_format(payload)
            
            # Handle model instances
            if isinstance(payload, NewPayloadModel):
                return PayloadFormat.NEW_PAYLOAD
            elif isinstance(payload, LegacyPayload):
                return PayloadFormat.LEGACY_PAYLOAD
            elif isinstance(payload, CLIPayloadMetadata):
                return PayloadFormat.CLI_PAYLOAD
            
            # Check by class name if direct isinstance fails
            class_name = payload.__class__.__name__
            module_name = payload.__class__.__module__
            
            if class_name == "PayloadModel" and "models.payload" in module_name:
                return PayloadFormat.NEW_PAYLOAD
            elif class_name == "Payload" and "payloads.types" in module_name:
                return PayloadFormat.LEGACY_PAYLOAD
            elif class_name == "PayloadMetadata" and "cli.models" in module_name:
                return PayloadFormat.CLI_PAYLOAD
                
        except Exception as e:
            if self.strict_validation:
                raise PayloadCompatibilityError(f"Format detection failed: {e}")
            self._add_warning(f"Format detection failed: {e}")
        
        return PayloadFormat.UNKNOWN
    
    def _detect_dict_format(self, data: Dict[str, Any]) -> PayloadFormat:
        """
        Detect format from dictionary representation.
        
        Args:
            data: Payload data as dictionary
            
        Returns:
            PayloadFormat: Best guess of format
        """
        # Check for new format indicators
        if "metadata" in data and isinstance(data.get("metadata"), dict):
            if "variants" in data or "owasp_category" in data:
                return PayloadFormat.NEW_PAYLOAD
        
        # Check for legacy format indicators
        if "hash" in data and "attack_vector" in data and "domain" in data:
            return PayloadFormat.LEGACY_PAYLOAD
        
        # Check for CLI format indicators
        if "payload_type" in data and "target_types" in data and "domains" in data:
            return PayloadFormat.CLI_PAYLOAD
        
        return PayloadFormat.UNKNOWN
    
    def adapt_from_legacy(
        self,
        legacy_payload: Union[LegacyPayload, Dict[str, Any]]
    ) -> NewPayloadModel:
        """
        Convert legacy Payload format to new PayloadModel format.
        
        Args:
            legacy_payload: Legacy payload instance or dict
            
        Returns:
            NewPayloadModel: Converted payload in new format
            
        Raises:
            PayloadCompatibilityError: If conversion fails in strict mode
            
        Example:
            >>> adapter = PayloadCompatibilityAdapter()
            >>> new_payload = adapter.adapt_from_legacy(old_payload)
        """
        try:
            # Convert dict to LegacyPayload if needed
            if isinstance(legacy_payload, dict):
                # Handle missing required fields with defaults
                payload_data = {
                    'name': legacy_payload.get('name', 'Unnamed Payload'),
                    'hash': legacy_payload.get('hash', self.generate_hash(legacy_payload.get('content', ''))),
                    'content': legacy_payload.get('content', ''),
                    'domain': legacy_payload.get('domain', 'prompts'),
                    'attack_type': legacy_payload.get('attack_type', 'injection'),
                    'attack_vector': legacy_payload.get('attack_vector', 'injection'),
                    **{k: v for k, v in legacy_payload.items() if k not in ['name', 'hash', 'content', 'domain', 'attack_type', 'attack_vector']}
                }
                legacy_payload = LegacyPayload(**payload_data)
            
            # Map domain
            domain_mapping = {
                LegacyDomain.PROMPTS: AttackDomain.PROMPT,
                LegacyDomain.DATA: AttackDomain.DATA,
                LegacyDomain.MODEL: AttackDomain.MODEL,
                LegacyDomain.SYSTEM: AttackDomain.SYSTEM,
                LegacyDomain.OUTPUT: AttackDomain.OUTPUT,
            }
            domain = domain_mapping.get(legacy_payload.domain, AttackDomain.PROMPT)
            
            # Map severity
            severity_mapping = {
                LegacySeverity.CRITICAL: Severity.CRITICAL,
                LegacySeverity.HIGH: Severity.HIGH,
                LegacySeverity.MEDIUM: Severity.MEDIUM,
                LegacySeverity.LOW: Severity.LOW,
                LegacySeverity.INFO: Severity.INFO,
            }
            severity = severity_mapping.get(legacy_payload.severity, Severity.MEDIUM)
            
            # Map attack vector to module category
            category_mapping = {
                LegacyAttackVector.INJECTION: ModuleCategory.INJECTION,
                LegacyAttackVector.EVASION: ModuleCategory.EVASION,
                LegacyAttackVector.EXTRACTION: ModuleCategory.EXTRACTION,
                LegacyAttackVector.MANIPULATION: ModuleCategory.MANIPULATION,
                LegacyAttackVector.ENUMERATION: ModuleCategory.ENUMERATION,
                LegacyAttackVector.BYPASS: ModuleCategory.EVASION,
                LegacyAttackVector.POISONING: ModuleCategory.POISONING,
                LegacyAttackVector.INFERENCE: ModuleCategory.EXTRACTION,
            }
            category = category_mapping.get(
                legacy_payload.attack_vector, ModuleCategory.INJECTION
            )
            
            # Map payload status
            status_mapping = {
                LegacyPayloadStatus.ACTIVE: NewPayloadStatus.ACTIVE,
                LegacyPayloadStatus.DEPRECATED: NewPayloadStatus.DEPRECATED,
                LegacyPayloadStatus.EXPERIMENTAL: NewPayloadStatus.EXPERIMENTAL,
                LegacyPayloadStatus.ARCHIVED: NewPayloadStatus.INACTIVE,
            }
            status = status_mapping.get(legacy_payload.status, NewPayloadStatus.ACTIVE)
            
            # Map payload type
            payload_type_mapping = {
                "injection": NewPayloadType.PROMPT_INJECTION,
                "jailbreak": NewPayloadType.JAILBREAK,
                "extraction": NewPayloadType.DATA_EXTRACTION,
                "poisoning": NewPayloadType.TRAINING_DATA_POISON,
                "evasion": NewPayloadType.EVASION_TECHNIQUE,
                "dos": NewPayloadType.DOS_TRIGGER,
            }
            payload_type = payload_type_mapping.get(
                legacy_payload.attack_type.lower(), NewPayloadType.PROMPT_INJECTION
            )
            
            # Create metadata
            metadata = PayloadMetadataModel(
                payload_type=payload_type,
                attack_vector=legacy_payload.attack_vector.value,
                technique=legacy_payload.attack_type,
                success_rate=legacy_payload.success_rate,
                usage_count=legacy_payload.usage_count,
                last_used=legacy_payload.last_used,
                compatible_targets=legacy_payload.target_systems,
                evasion_techniques=legacy_payload.tags if legacy_payload.tags else [],
            )
            
            # Create new payload
            new_payload = NewPayloadModel(
                name=legacy_payload.name,
                content=legacy_payload.content,
                description=legacy_payload.description,
                domain=domain,
                category=category,
                severity=severity,
                status=status,
                version=legacy_payload.version,
                author=legacy_payload.author or "unknown",
                source=legacy_payload.source_repo,
                license=legacy_payload.license,
                metadata=metadata,
                expected_indicators=legacy_payload.expected_indicators,
                tags=legacy_payload.tags,
                references=legacy_payload.references if legacy_payload.references else [],
            )
            
            # Copy timestamps if available
            if hasattr(legacy_payload, 'created_at') and legacy_payload.created_at:
                new_payload.created_at = legacy_payload.created_at
            if hasattr(legacy_payload, 'updated_at') and legacy_payload.updated_at:
                new_payload.updated_at = legacy_payload.updated_at
            
            self._conversion_stats['successful_conversions'] += 1
            return new_payload
            
        except Exception as e:
            self._conversion_stats['failed_conversions'] += 1
            if self.strict_validation:
                raise PayloadCompatibilityError(
                    f"Failed to convert legacy payload: {e}"
                )
            
            # Return minimal payload in non-strict mode
            self._add_warning(f"Legacy conversion failed, using minimal payload: {e}")
            
            # Get content from either object or dict
            content = 'Default payload content'
            name = 'Converted Legacy Payload'
            if isinstance(legacy_payload, dict):
                content = legacy_payload.get('content', content)
                name = legacy_payload.get('name', name)
            else:
                content = getattr(legacy_payload, 'content', content)
                name = getattr(legacy_payload, 'name', name)
            
            # Ensure content is not empty
            if not content or not content.strip():
                content = 'Default payload content'
                
            return self._create_minimal_payload(
                name=name,
                content=content,
                domain=AttackDomain.PROMPT,
                category=ModuleCategory.INJECTION
            )
    
    def adapt_from_cli(
        self,
        cli_payload: Union[CLIPayloadMetadata, Dict[str, Any]]
    ) -> NewPayloadModel:
        """
        Convert CLI PayloadMetadata format to new PayloadModel format.
        
        Args:
            cli_payload: CLI payload instance or dict
            
        Returns:
            NewPayloadModel: Converted payload in new format
            
        Raises:
            PayloadCompatibilityError: If conversion fails in strict mode
        """
        try:
            # Convert dict to CLIPayloadMetadata if needed
            if isinstance(cli_payload, dict):
                # Handle missing required fields with defaults
                payload_data = {
                    'name': cli_payload.get('name', 'Unnamed Payload'),
                    'description': cli_payload.get('description', ''),
                    'content': cli_payload.get('content', ''),
                    'payload_type': cli_payload.get('payload_type', 'injection'),
                    'category': cli_payload.get('category', 'general'),
                    'domains': cli_payload.get('domains', ['prompts']),
                    'target_types': cli_payload.get('target_types', ['api']),
                    'severity': cli_payload.get('severity', 'medium'),
                    'source': cli_payload.get('source', 'local'),
                    **{k: v for k, v in cli_payload.items() if k not in ['name', 'description', 'content', 'payload_type', 'category', 'domains', 'target_types', 'severity', 'source']}
                }
                cli_payload = CLIPayloadMetadata(**payload_data)
            
            # Map CLI attack domains to internal domains
            domain_mapping = {
                CLIAttackDomain.PROMPTS: AttackDomain.PROMPT,
                CLIAttackDomain.DATA: AttackDomain.DATA,
                CLIAttackDomain.MODEL: AttackDomain.MODEL,
                CLIAttackDomain.SYSTEM: AttackDomain.SYSTEM,
                CLIAttackDomain.OUTPUT: AttackDomain.OUTPUT,
            }
            
            # Use first domain or default to PROMPT
            first_domain = cli_payload.domains[0] if cli_payload.domains else CLIAttackDomain.PROMPTS
            domain = domain_mapping.get(first_domain, AttackDomain.PROMPT)
            
            # Map CLI severity to internal severity
            severity_mapping = {
                CLISeverity.CRITICAL: Severity.CRITICAL,
                CLISeverity.HIGH: Severity.HIGH,
                CLISeverity.MEDIUM: Severity.MEDIUM,
                CLISeverity.LOW: Severity.LOW,
                CLISeverity.INFO: Severity.INFO,
            }
            severity = severity_mapping.get(cli_payload.severity, Severity.MEDIUM)
            
            # Map payload type to internal type
            payload_type_mapping = {
                CLIPayloadType.INJECTION: NewPayloadType.PROMPT_INJECTION,
                CLIPayloadType.XSS: NewPayloadType.OUTPUT_MANIPULATION,
                CLIPayloadType.SQLI: NewPayloadType.PROMPT_INJECTION,
                CLIPayloadType.COMMAND: NewPayloadType.SYSTEM_PROMPT_LEAK,
                CLIPayloadType.PROMPT: NewPayloadType.PROMPT_INJECTION,
                CLIPayloadType.BYPASS: NewPayloadType.EVASION_TECHNIQUE,
                CLIPayloadType.FUZZING: NewPayloadType.ADVERSARIAL_EXAMPLE,
                CLIPayloadType.CUSTOM: NewPayloadType.CUSTOM,
            }
            payload_type = payload_type_mapping.get(
                cli_payload.payload_type, NewPayloadType.PROMPT_INJECTION
            )
            
            # Map category to module category
            category_mapping = {
                CLIPayloadCategory.AUTHENTICATION: ModuleCategory.ENUMERATION,
                CLIPayloadCategory.AUTHORIZATION: ModuleCategory.EVASION,
                CLIPayloadCategory.VALIDATION: ModuleCategory.INJECTION,
                CLIPayloadCategory.ENCODING: ModuleCategory.EVASION,
                CLIPayloadCategory.EVASION: ModuleCategory.EVASION,
                CLIPayloadCategory.EXPLOITATION: ModuleCategory.INJECTION,
                CLIPayloadCategory.RECONNAISSANCE: ModuleCategory.ENUMERATION,
                CLIPayloadCategory.GENERAL: ModuleCategory.INJECTION,
            }
            category = category_mapping.get(
                cli_payload.category, ModuleCategory.INJECTION
            )
            
            # Create metadata
            metadata = PayloadMetadataModel(
                payload_type=payload_type,
                attack_vector=cli_payload.payload_type.value,
                technique=cli_payload.category.value,
                success_rate=cli_payload.success_rate,
                confidence_score=cli_payload.effectiveness_score,
                false_positive_rate=cli_payload.false_positive_rate,
                usage_count=cli_payload.usage_count,
                last_used=cli_payload.last_used,
                compatible_targets=[t.value for t in cli_payload.target_types],
            )
            
            # Create new payload
            new_payload = NewPayloadModel(
                name=cli_payload.name,
                content=cli_payload.content,
                description=cli_payload.description,
                domain=domain,
                category=category,
                severity=severity,
                version=cli_payload.version,
                author=cli_payload.author or "unknown",
                source=cli_payload.source.value if cli_payload.source else None,
                metadata=metadata,
                tags=cli_payload.tags,
                validated=cli_payload.verified,
            )
            
            self._conversion_stats['successful_conversions'] += 1
            return new_payload
            
        except Exception as e:
            self._conversion_stats['failed_conversions'] += 1
            if self.strict_validation:
                raise PayloadCompatibilityError(
                    f"Failed to convert CLI payload: {e}"
                )
            
            # Return minimal payload in non-strict mode
            self._add_warning(f"CLI conversion failed, using minimal payload: {e}")
            
            # Get content from either object or dict
            content = 'Default payload content'
            name = 'Converted CLI Payload'
            if isinstance(cli_payload, dict):
                content = cli_payload.get('content', content)
                name = cli_payload.get('name', name)
            else:
                content = getattr(cli_payload, 'content', content)
                name = getattr(cli_payload, 'name', name)
            
            # Ensure content is not empty
            if not content or not content.strip():
                content = 'Default payload content'
                
            return self._create_minimal_payload(
                name=name,
                content=content,
                domain=AttackDomain.PROMPT,
                category=ModuleCategory.INJECTION
            )
    
    def adapt_to_legacy(self, payload: NewPayloadModel) -> LegacyPayload:
        """
        Convert new PayloadModel format to legacy Payload format.
        
        Args:
            payload: New format payload
            
        Returns:
            LegacyPayload: Converted payload in legacy format
            
        Raises:
            PayloadCompatibilityError: If conversion fails in strict mode
        """
        try:
            # Map domain back to legacy format
            domain_mapping = {
                AttackDomain.PROMPT: LegacyDomain.PROMPTS,
                AttackDomain.DATA: LegacyDomain.DATA,
                AttackDomain.MODEL: LegacyDomain.MODEL,
                AttackDomain.SYSTEM: LegacyDomain.SYSTEM,
                AttackDomain.OUTPUT: LegacyDomain.OUTPUT,
            }
            legacy_domain = domain_mapping.get(payload.domain, LegacyDomain.PROMPTS)
            
            # Map severity back to legacy format
            severity_mapping = {
                Severity.CRITICAL: LegacySeverity.CRITICAL,
                Severity.HIGH: LegacySeverity.HIGH,
                Severity.MEDIUM: LegacySeverity.MEDIUM,
                Severity.LOW: LegacySeverity.LOW,
                Severity.INFO: LegacySeverity.INFO,
            }
            legacy_severity = severity_mapping.get(payload.severity, LegacySeverity.MEDIUM)
            
            # Map category back to attack vector
            attack_vector_mapping = {
                ModuleCategory.INJECTION: LegacyAttackVector.INJECTION,
                ModuleCategory.EVASION: LegacyAttackVector.EVASION,
                ModuleCategory.EXTRACTION: LegacyAttackVector.EXTRACTION,
                ModuleCategory.MANIPULATION: LegacyAttackVector.MANIPULATION,
                ModuleCategory.ENUMERATION: LegacyAttackVector.ENUMERATION,
                ModuleCategory.POISONING: LegacyAttackVector.POISONING,
            }
            attack_vector = attack_vector_mapping.get(
                payload.category, LegacyAttackVector.INJECTION
            )
            
            # Map status
            status_mapping = {
                NewPayloadStatus.ACTIVE: LegacyPayloadStatus.ACTIVE,
                NewPayloadStatus.INACTIVE: LegacyPayloadStatus.ARCHIVED,
                NewPayloadStatus.EXPERIMENTAL: LegacyPayloadStatus.EXPERIMENTAL,
                NewPayloadStatus.DEPRECATED: LegacyPayloadStatus.DEPRECATED,
                NewPayloadStatus.FLAGGED: LegacyPayloadStatus.ARCHIVED,
                NewPayloadStatus.BLOCKED: LegacyPayloadStatus.ARCHIVED,
            }
            legacy_status = status_mapping.get(payload.status, LegacyPayloadStatus.ACTIVE)
            
            # Generate hash if not provided
            hash_content = f"{payload.name}:{payload.content}"
            content_hash = hashlib.md5(hash_content.encode()).hexdigest()
            
            # Fix version format for legacy (requires semver)
            version = payload.version
            if not version or len(version.split('.')) != 3:
                version = "1.0.0"
            
            # Ensure references are HttpUrl objects or convert them
            references = []
            for ref in payload.references:
                if isinstance(ref, str):
                    try:
                        # Simple URL validation - only add if it looks like a URL
                        if ref.startswith(('http://', 'https://')):
                            references.append(ref)
                    except Exception:
                        pass
                else:
                    references.append(str(ref))
            
            # Create legacy payload
            legacy_payload = LegacyPayload(
                name=payload.name,
                hash=content_hash,
                content=payload.content,
                domain=legacy_domain,
                attack_type=payload.metadata.technique or "injection",
                attack_vector=attack_vector,
                description=payload.description,
                author=payload.author,
                version=version,
                severity=legacy_severity,
                status=legacy_status,
                tags=payload.tags,
                target_systems=payload.metadata.compatible_targets,
                expected_indicators=payload.expected_indicators,
                success_rate=payload.metadata.success_rate,
                source_repo=payload.source,
                license=payload.license,
                created_at=payload.created_at if payload.created_at else datetime.utcnow(),
                updated_at=payload.updated_at if payload.updated_at else datetime.utcnow(),
                last_used=payload.metadata.last_used,
                usage_count=payload.metadata.usage_count,
                references=references,
            )
            
            self._conversion_stats['successful_conversions'] += 1
            return legacy_payload
            
        except Exception as e:
            self._conversion_stats['failed_conversions'] += 1
            if self.strict_validation:
                raise PayloadCompatibilityError(
                    f"Failed to convert to legacy format: {e}"
                )
            
            # Return minimal legacy payload in non-strict mode
            self._add_warning(f"Legacy conversion failed, using minimal payload: {e}")
            hash_content = f"{payload.name}:{payload.content}"
            content_hash = hashlib.md5(hash_content.encode()).hexdigest()
            
            return LegacyPayload(
                name=payload.name,
                hash=content_hash,
                content=payload.content,
                domain=LegacyDomain.PROMPTS,
                attack_type="injection",
                attack_vector=LegacyAttackVector.INJECTION,
                author=payload.author or "unknown",
                version="1.0.0"
            )
    
    def adapt_to_cli(self, payload: NewPayloadModel) -> CLIPayloadMetadata:
        """
        Convert new PayloadModel format to CLI PayloadMetadata format.
        
        Args:
            payload: New format payload
            
        Returns:
            CLIPayloadMetadata: Converted payload in CLI format
            
        Raises:
            PayloadCompatibilityError: If conversion fails in strict mode
        """
        try:
            # Map domain to CLI domains
            domain_mapping = {
                AttackDomain.PROMPT: CLIAttackDomain.PROMPTS,
                AttackDomain.DATA: CLIAttackDomain.DATA,
                AttackDomain.MODEL: CLIAttackDomain.MODEL,
                AttackDomain.SYSTEM: CLIAttackDomain.SYSTEM,
                AttackDomain.OUTPUT: CLIAttackDomain.OUTPUT,
            }
            cli_domain = domain_mapping.get(payload.domain, CLIAttackDomain.PROMPTS)
            
            # Map severity
            severity_mapping = {
                Severity.CRITICAL: CLISeverity.CRITICAL,
                Severity.HIGH: CLISeverity.HIGH,
                Severity.MEDIUM: CLISeverity.MEDIUM,
                Severity.LOW: CLISeverity.LOW,
                Severity.INFO: CLISeverity.INFO,
            }
            cli_severity = severity_mapping.get(payload.severity, CLISeverity.MEDIUM)
            
            # Map payload type
            payload_type_mapping = {
                NewPayloadType.PROMPT_INJECTION: CLIPayloadType.INJECTION,
                NewPayloadType.JAILBREAK: CLIPayloadType.BYPASS,
                NewPayloadType.DATA_EXTRACTION: CLIPayloadType.INJECTION,
                NewPayloadType.SYSTEM_PROMPT_LEAK: CLIPayloadType.COMMAND,
                NewPayloadType.OUTPUT_MANIPULATION: CLIPayloadType.XSS,
                NewPayloadType.EVASION_TECHNIQUE: CLIPayloadType.BYPASS,
                NewPayloadType.ADVERSARIAL_EXAMPLE: CLIPayloadType.FUZZING,
                NewPayloadType.CUSTOM: CLIPayloadType.CUSTOM,
            }
            cli_payload_type = payload_type_mapping.get(
                payload.metadata.payload_type, CLIPayloadType.INJECTION
            )
            
            # Map category
            category_mapping = {
                ModuleCategory.INJECTION: CLIPayloadCategory.EXPLOITATION,
                ModuleCategory.EVASION: CLIPayloadCategory.EVASION,
                ModuleCategory.EXTRACTION: CLIPayloadCategory.EXPLOITATION,
                ModuleCategory.ENUMERATION: CLIPayloadCategory.RECONNAISSANCE,
                ModuleCategory.MANIPULATION: CLIPayloadCategory.EXPLOITATION,
            }
            cli_category = category_mapping.get(
                payload.category, CLIPayloadCategory.GENERAL
            )
            
            # Map source - handle string or enum values
            source_mapping = {
                None: PayloadSource.LOCAL,
                "local": PayloadSource.LOCAL,
                "remote": PayloadSource.REMOTE,
                "official": PayloadSource.OFFICIAL,
                "community": PayloadSource.COMMUNITY,
            }
            source_value = payload.source
            if hasattr(source_value, 'value'):
                source_value = source_value.value
            cli_source = source_mapping.get(source_value, PayloadSource.LOCAL)
            
            # Create target types (default to API)
            target_types = [TargetType.API]
            if payload.metadata.compatible_targets:
                target_mapping = {
                    "api": TargetType.API,
                    "web": TargetType.WEB,
                    "mobile": TargetType.MOBILE,
                    "desktop": TargetType.DESKTOP,
                    "model": TargetType.MODEL,
                }
                target_types = [
                    target_mapping.get(t.lower(), TargetType.API)
                    for t in payload.metadata.compatible_targets[:3]  # Limit to 3
                ]
            
            # Fix version format for CLI (requires semver)
            version = payload.version
            if not version or len(version.split('.')) != 3:
                version = "1.0.0"
            
            # Create CLI payload
            cli_payload = CLIPayloadMetadata(
                name=payload.name,
                description=payload.description or "",
                content=payload.content,
                payload_type=cli_payload_type,
                category=cli_category,
                domains=[cli_domain],
                target_types=target_types,
                severity=cli_severity,
                effectiveness_score=payload.metadata.confidence_score,
                success_rate=payload.metadata.success_rate,
                false_positive_rate=payload.metadata.false_positive_rate,
                tags=payload.tags,
                author=payload.author,
                source=cli_source,
                verified=payload.validated,
                usage_count=payload.metadata.usage_count,
                last_used=payload.metadata.last_used,
                version=version,
            )
            
            self._conversion_stats['successful_conversions'] += 1
            return cli_payload
            
        except Exception as e:
            self._conversion_stats['failed_conversions'] += 1
            if self.strict_validation:
                raise PayloadCompatibilityError(
                    f"Failed to convert to CLI format: {e}"
                )
            
            # Return minimal CLI payload in non-strict mode
            self._add_warning(f"CLI conversion failed, using minimal payload: {e}")
            return CLIPayloadMetadata(
                name=payload.name,
                description=payload.description or "",
                content=payload.content,
                payload_type=CLIPayloadType.INJECTION,
                category=CLIPayloadCategory.GENERAL,
                domains=[CLIAttackDomain.PROMPTS],
                target_types=[TargetType.API],
                severity=CLISeverity.MEDIUM,
                source=PayloadSource.LOCAL,
            )
    
    def convert_payload(
        self,
        payload: Union[BaseModel, Dict[str, Any]],
        target_format: PayloadFormat
    ) -> Union[NewPayloadModel, LegacyPayload, CLIPayloadMetadata]:
        """
        Convert payload to target format automatically detecting source format.
        
        Args:
            payload: Source payload in any supported format
            target_format: Desired output format
            
        Returns:
            Converted payload in target format
            
        Raises:
            PayloadCompatibilityError: If conversion fails in strict mode
            
        Example:
            >>> adapter = PayloadCompatibilityAdapter()
            >>> new_payload = adapter.convert_payload(
            ...     old_payload, PayloadFormat.NEW_PAYLOAD
            ... )
        """
        source_format = self.detect_format(payload)
        
        if source_format == PayloadFormat.UNKNOWN:
            if self.strict_validation:
                raise PayloadCompatibilityError("Cannot detect source payload format")
            self._add_warning("Unknown source format, attempting best-guess conversion")
        
        # If already in target format, return as-is
        if source_format == target_format:
            return payload
        
        # Convert to new format first (as canonical format)
        if source_format == PayloadFormat.LEGACY_PAYLOAD:
            canonical = self.adapt_from_legacy(payload)
        elif source_format == PayloadFormat.CLI_PAYLOAD:
            canonical = self.adapt_from_cli(payload)
        elif source_format == PayloadFormat.NEW_PAYLOAD:
            canonical = payload
        else:
            # Try to create from dict or handle unknown format
            if isinstance(payload, dict):
                # Try to create NewPayloadModel from dict directly
                try:
                    if source_format == PayloadFormat.NEW_PAYLOAD or 'metadata' in payload:
                        canonical = NewPayloadModel(**payload)
                    else:
                        canonical = self._create_minimal_payload(
                            name=payload.get('name', 'Converted Payload'),
                            content=payload.get('content', ''),
                            domain=AttackDomain.PROMPT,
                            category=ModuleCategory.INJECTION
                        )
                except Exception as e:
                    if self.strict_validation:
                        raise PayloadCompatibilityError(f"Failed to create payload from dict: {e}")
                    canonical = self._create_minimal_payload(
                        name=payload.get('name', 'Converted Payload'),
                        content=payload.get('content', ''),
                        domain=AttackDomain.PROMPT,
                        category=ModuleCategory.INJECTION
                    )
            else:
                if self.strict_validation:
                    raise PayloadCompatibilityError(f"Unsupported source format: {source_format}")
                canonical = self._create_minimal_payload(
                    name="Converted Payload",
                    content="",
                    domain=AttackDomain.PROMPT,
                    category=ModuleCategory.INJECTION
                )
        
        # Convert from canonical to target format
        if target_format == PayloadFormat.NEW_PAYLOAD:
            return canonical
        elif target_format == PayloadFormat.LEGACY_PAYLOAD:
            return self.adapt_to_legacy(canonical)
        elif target_format == PayloadFormat.CLI_PAYLOAD:
            return self.adapt_to_cli(canonical)
        else:
            if self.strict_validation:
                raise PayloadCompatibilityError(f"Unsupported target format: {target_format}")
            return canonical
    
    def batch_convert(
        self,
        payloads: List[Union[BaseModel, Dict[str, Any]]],
        target_format: PayloadFormat,
        max_errors: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Convert multiple payloads with error handling and statistics.
        
        Args:
            payloads: List of payloads to convert
            target_format: Target format for all payloads
            max_errors: Maximum errors before stopping (None for no limit)
            
        Returns:
            Dict containing converted payloads and conversion statistics
            
        Example:
            >>> adapter = PayloadCompatibilityAdapter()
            >>> result = adapter.batch_convert(
            ...     [payload1, payload2], PayloadFormat.NEW_PAYLOAD
            ... )
            >>> print(f"Converted: {len(result['converted'])}")
        """
        converted = []
        errors = []
        skipped = 0
        
        for i, payload in enumerate(payloads):
            try:
                converted_payload = self.convert_payload(payload, target_format)
                converted.append(converted_payload)
            except Exception as e:
                error_info = {
                    'index': i,
                    'error': str(e),
                    'payload_name': getattr(payload, 'name', f'payload_{i}')
                }
                errors.append(error_info)
                
                if max_errors and len(errors) >= max_errors:
                    skipped = len(payloads) - i - 1
                    break
        
        return {
            'converted': converted,
            'errors': errors,
            'skipped': skipped,
            'total_processed': len(payloads) - skipped,
            'success_rate': len(converted) / len(payloads) if payloads else 0.0,
            'conversion_stats': self.get_stats()
        }
    
    def _create_minimal_payload(
        self,
        name: str,
        content: str,
        domain: AttackDomain,
        category: ModuleCategory,
        author: str = "adapter"
    ) -> NewPayloadModel:
        """
        Create a minimal payload when conversion fails.
        
        Args:
            name: Payload name
            content: Payload content
            domain: Attack domain
            category: Module category
            author: Author name
            
        Returns:
            NewPayloadModel: Minimal payload instance
        """
        return NewPayloadModel.from_minimal(
            name=name,
            content=content,
            domain=domain,
            category=category,
            author=author
        )
    
    def _add_warning(self, message: str) -> None:
        """Add a warning to the conversion statistics."""
        self._conversion_stats['warnings'].append({
            'timestamp': datetime.utcnow().isoformat(),
            'message': message
        })
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get conversion statistics.
        
        Returns:
            Dict containing conversion statistics and warnings
        """
        total_attempts = (
            self._conversion_stats['successful_conversions'] + 
            self._conversion_stats['failed_conversions']
        )
        
        return {
            'total_conversions': total_attempts,
            'successful_conversions': self._conversion_stats['successful_conversions'],
            'failed_conversions': self._conversion_stats['failed_conversions'],
            'success_rate': (
                self._conversion_stats['successful_conversions'] / total_attempts
                if total_attempts > 0 else 0.0
            ),
            'warnings': self._conversion_stats['warnings'],
            'warning_count': len(self._conversion_stats['warnings'])
        }
    
    def clear_stats(self) -> None:
        """Clear conversion statistics."""
        self._conversion_stats = {
            'successful_conversions': 0,
            'failed_conversions': 0,
            'warnings': []
        }
    
    def generate_hash(self, content: str) -> str:
        """
        Generate a hash for payload content.
        
        Args:
            content: Content to hash
            
        Returns:
            str: MD5 hash of content
        """
        return hashlib.md5(content.encode('utf-8')).hexdigest()
    
    def validate_conversion(
        self,
        original: Union[BaseModel, Dict[str, Any]],
        converted: Union[BaseModel, Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Validate that conversion preserved essential data.
        
        Args:
            original: Original payload
            converted: Converted payload
            
        Returns:
            Dict containing validation results
        """
        issues = []
        warnings = []
        
        try:
            # Get content from both formats
            orig_content = getattr(original, 'content', original.get('content', ''))
            conv_content = getattr(converted, 'content', converted.get('content', ''))
            
            if orig_content != conv_content:
                issues.append("Content mismatch after conversion")
            
            # Get names
            orig_name = getattr(original, 'name', original.get('name', ''))
            conv_name = getattr(converted, 'name', converted.get('name', ''))
            
            if orig_name != conv_name:
                warnings.append("Name may have changed during conversion")
            
            # Check for data loss indicators
            if hasattr(original, 'metadata') and not hasattr(converted, 'metadata'):
                warnings.append("Metadata may have been simplified during conversion")
                
        except Exception as e:
            issues.append(f"Validation error: {e}")
        
        return {
            'valid': len(issues) == 0,
            'issues': issues,
            'warnings': warnings,
            'score': max(0, 100 - len(issues) * 50 - len(warnings) * 10)
        }