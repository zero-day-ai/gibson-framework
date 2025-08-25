"""
Gibson Framework Domain Base Classes.

This package contains the base domain classes that provide shared functionality
for all attack modules within each domain. Each domain represents a specific
attack vector or category in AI/ML security testing.

Domains:
- PromptDomain: Base for prompt injection and manipulation attacks
- DataDomain: Base for data poisoning and extraction attacks  
- ModelDomain: Base for model theft and fingerprinting attacks
- OutputDomain: Base for output manipulation and injection attacks
- SystemDomain: Base for system-level and infrastructure attacks
"""

from gibson.domains.prompt import PromptDomain, EvasionTechnique, InjectionType
from gibson.domains.data import DataDomain, PoisoningStrategy, AttackVector
from gibson.domains.model import ModelDomain, FingerprintingTechnique, ModelAttackType
from gibson.domains.output import OutputDomain, EncodingMethod, OutputAttackType
from gibson.domains.system import SystemDomain, SystemAttackType, EnumerationMethod

__all__ = [
    # Prompt domain
    "PromptDomain",
    "EvasionTechnique",
    "InjectionType",
    # Data domain
    "DataDomain",
    "PoisoningStrategy",
    "AttackVector",
    # Model domain
    "ModelDomain",
    "FingerprintingTechnique",
    "ModelAttackType",
    # Output domain
    "OutputDomain",
    "EncodingMethod",
    "OutputAttackType",
    # System domain
    "SystemDomain",
    "SystemAttackType",
    "EnumerationMethod",
]
