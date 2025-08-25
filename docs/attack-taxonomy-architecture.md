# Attack Taxonomy Architecture in Gibson Framework

## Executive Summary

The Gibson Framework implements a multi-layered attack taxonomy system designed to be the industry standard for AI/ML security testing. This document explores the current architecture, integration with industry standards (OWASP, MITRE, CWE), and proposes enhancements to make Gibson the go-to tool for security researchers while maintaining compatibility with established frameworks.

## Current Architecture

### 1. Core Domain Model

Gibson organizes attacks into five fundamental domains that represent the attack surface of AI/ML systems:

```python
class AttackDomain(str, Enum):
    """Core attack domains in AI/ML systems."""
    PROMPT = "prompt"       # Input manipulation attacks
    DATA = "data"          # Training/inference data attacks  
    MODEL = "model"        # Model architecture attacks
    SYSTEM = "system"      # Infrastructure/deployment attacks
    OUTPUT = "output"      # Output manipulation/extraction
```

These domains are **foundational** and represent WHERE attacks occur in the AI pipeline.

### 2. Module Categories

Within each domain, attacks are further classified by technique:

```python
class ModuleCategory(str, Enum):
    """Attack technique categories."""
    # Core Categories
    INJECTION = "injection"
    EXTRACTION = "extraction"
    POISONING = "poisoning"
    THEFT = "theft"
    DOS = "dos"
    MANIPULATION = "manipulation"
    
    # LLM-Specific (Legacy)
    LLM_PROMPT_INJECTION = "llm_prompt_injection"
    SENSITIVE_INFO_DISCLOSURE = "sensitive_info_disclosure"
    # ... etc
```

Question: 
Are these comprehensive enough right now to get launched?
We need patterns to integrate new attack domains in teh future.

Posits:
We need a dictionary that details concepts, principles, etc (attack domains, etc)

### 3. Industry Standard Mappings

#### OWASP LLM Top 10 Integration

```python
class OWASPCategory(str, Enum):
    """OWASP LLM Top 10 categories."""
    LLM01_PROMPT_INJECTION = "OWASP-LLM-01"
    LLM02_INSECURE_OUTPUT_HANDLING = "OWASP-LLM-02"
    LLM03_TRAINING_DATA_POISONING = "OWASP-LLM-03"
    LLM04_MODEL_DOS = "OWASP-LLM-04"
    LLM05_SUPPLY_CHAIN = "OWASP-LLM-05"
    LLM06_SENSITIVE_INFO_DISCLOSURE = "OWASP-LLM-06"
    LLM07_INSECURE_PLUGIN_DESIGN = "OWASP-LLM-07"
    LLM08_EXCESSIVE_AGENCY = "OWASP-LLM-08"
    LLM09_OVERRELIANCE = "OWASP-LLM-09"
    LLM10_MODEL_THEFT = "OWASP-LLM-10"
```
Questions:
Should this be removed?
Is a tagging system more apropriate?


#### CWE/CVE Support

```python
class FindingModel:
    cvss_score: Optional[float]  # CVSS 3.1 scoring (0.0-10.0)
    cwe_id: Optional[str]        # CWE-77, CWE-78, etc.
    owasp_category: Optional[OWASPCategory]
```

## How It All Works Together

### Attack Flow Architecture

```
┌─────────────────┐
│   User Request  │
└────────┬────────┘
         │
         v
┌─────────────────┐
│  Domain Router  │ (Prompt/Data/Model/System/Output)
└────────┬────────┘
         │
         v
┌─────────────────┐
│ Module Selector │ (Injection/Poisoning/Theft/etc)
└────────┬────────┘
         │
         v
┌─────────────────┐
│ Payload Manager │ (Domain-specific payloads)
└────────┬────────┘
         │
         v
┌─────────────────┐
│  Module Exec    │ (Actual attack execution)
└────────┬────────┘
         │
         v
┌─────────────────┐
│ Finding Mapper  │ (Maps to OWASP/CWE/CVSS)
└────────┬────────┘
         │
         v
┌─────────────────┐
│  Report Output  │ (Multi-taxonomy reporting)
└─────────────────┘
```

### Standard Components

#### Built-in with Framework

1. **Core Domains**: 5 attack domains covering the AI/ML attack surface
2. **Base Modules**: 
   - Prompt injection techniques
   - Data poisoning methods
   - Model extraction attacks
   - System enumeration
   - Output manipulation

3. **Standard Taxonomies**:
   - OWASP LLM Top 10 (2025)
   - CWE mappings for AI vulnerabilities
   - CVSS scoring integration
   - Severity classifications (CRITICAL/HIGH/MEDIUM/LOW/INFO)

#### Extensible via 3rd Party Modules

1. **Custom Domains** (Proposed):
   ```python
   class CustomDomain:
       VISION = "vision"       # Computer vision specific
       ROBOTICS = "robotics"   # Robotics AI attacks
       FEDERATED = "federated" # Federated learning attacks
   ```

2. **Additional Taxonomies**:
   - MITRE ATLAS techniques
   - NIST AI RMF controls
   - Custom organizational standards
   - Academic research classifications

3. **Specialized Payloads**:
   - Industry-specific attack patterns
   - Proprietary vulnerability signatures
   - Research-oriented test cases

## Proposed Improvements

### 1. Hierarchical Domain Structure

Instead of flat domains, implement a hierarchical taxonomy:

```python
class DomainHierarchy:
    """Hierarchical attack domain structure."""
    
    DATA = {
        "training": {
            "poisoning": ["backdoor", "gradient", "label_flip"],
            "extraction": ["membership", "attribute", "model_inversion"]
        },
        "inference": {
            "evasion": ["adversarial", "perturbation", "patch"],
            "manipulation": ["input_filtering", "preprocessing"]
        }
    }
```

### 2. Pluggable Taxonomy System

```python
class TaxonomyPlugin:
    """Base class for taxonomy plugins."""
    
    @abstractmethod
    def map_finding(self, finding: Finding) -> TaxonomyMapping:
        """Map a Gibson finding to this taxonomy."""
        pass
    
    @abstractmethod
    def get_compliance_coverage(self) -> ComplianceReport:
        """Report coverage of this taxonomy's requirements."""
        pass

class MITREATLASPlugin(TaxonomyPlugin):
    """MITRE ATLAS taxonomy plugin."""
    
    TECHNIQUES = {
        "T0040": "Poisoning Training Data",
        "T0041": "Backdoor ML Model",
        "T0043": "Craft Adversarial Data",
        # ...
    }
```

### 3. Universal Finding Mapper

```python
class UniversalFindingMapper:
    """Maps findings across multiple taxonomies simultaneously."""
    
    def map_finding(self, finding: Finding) -> MultiTaxonomyResult:
        return {
            "gibson": {
                "domain": finding.domain,
                "category": finding.category,
                "severity": finding.severity
            },
            "owasp": self.map_to_owasp(finding),
            "cwe": self.map_to_cwe(finding),
            "mitre": self.map_to_mitre(finding),
            "custom": self.map_to_custom(finding)
        }
```


### 4. Taxonomy Versioning

```python
class TaxonomyVersion:
    """Support multiple versions of taxonomies."""
    
    OWASP_VERSIONS = {
        "2023": OWASPv2023,
        "2024": OWASPv2024,
        "2025": OWASPv2025
    }
    
    def migrate_findings(self, findings: List[Finding], 
                         from_version: str, to_version: str):
        """Migrate findings between taxonomy versions."""
        pass
```

## Industry Standard Strategy

### Why Gibson Can Become THE Standard

1. **Comprehensive Coverage**: Covers entire AI/ML attack surface, not just LLMs
2. **Flexible Architecture**: Supports multiple taxonomies simultaneously
3. **Research-Oriented**: Enables custom classifications for cutting-edge research
4. **Industry Compatible**: Maps seamlessly to OWASP, MITRE, CWE
5. **Extensible**: Plugin architecture for organizational standards

### Integration Points

```yaml
# Example: Multi-taxonomy scan configuration
scan:
  taxonomies:
    - gibson: native
    - owasp: "2025"
    - mitre_atlas: enabled
    - custom: "organization-standard-v2"
  
  reporting:
    primary: gibson  # Primary classification
    mappings:        # Additional mappings
      - owasp
      - cwe
      - mitre
```

### Collaboration Opportunities

1. **OWASP Partnership**: 
   - Contribute Gibson findings to OWASP Top 10 updates
   - Implement OWASP test cases natively

2. **MITRE Integration**:
   - Map all Gibson attacks to ATLAS techniques
   - Contribute new techniques discovered via Gibson

3. **Academic Bridge**:
   - Provide standard implementation for academic attack papers
   - Enable reproducible security research

## Implementation Roadmap

### Phase 1: Enhanced Taxonomy Support (Current)
- ✅ OWASP LLM Top 10 integration
- ✅ CWE/CVE field support
- ✅ CVSS scoring

### Phase 2: Pluggable Architecture (Q1 2025)
- [ ] Taxonomy plugin system
- [ ] MITRE ATLAS integration
- [ ] Custom taxonomy support

### Phase 3: Research Features (Q2 2025)
- [ ] Academic paper importers
- [ ] Custom classification builders
- [ ] Reproducibility framework

### Phase 4: Industry Standard (Q3 2025)
- [ ] Official partnerships
- [ ] Certification program
- [ ] Reference implementation status

## Conclusion

Gibson's multi-layered taxonomy architecture positions it uniquely to become the industry standard for AI/ML security testing. By maintaining a **Gibson-native classification** that maps bidirectionally to all major standards (OWASP, MITRE, CWE), researchers get the best of both worlds:

1. **Freedom**: Define custom taxonomies for novel research
2. **Compatibility**: Seamless mapping to industry standards
3. **Comprehensiveness**: Coverage beyond just LLMs to all AI/ML systems

The key insight is that Gibson shouldn't just adopt existing taxonomies—it should define a **superset taxonomy** that encompasses all AI/ML security concerns, with intelligent mapping to existing standards. This positions Gibson as the thought leader in AI security classification while maintaining practical compatibility with enterprise requirements.

## Next Steps

1. **Community Feedback**: Gather input on proposed taxonomy enhancements
2. **Plugin Development**: Create MITRE ATLAS plugin as proof-of-concept
3. **Research Partnerships**: Collaborate with academic institutions
4. **Standards Bodies**: Engage with OWASP, MITRE, NIST for official recognition

---

*This document is a living specification and will evolve as Gibson becomes the de facto standard for AI/ML security testing.*
