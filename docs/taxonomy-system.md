# Gibson Taxonomy System Documentation

## Overview

Gibson's taxonomy system provides flexible mapping between Gibson's internal attack domains and module categories to external security taxonomies like OWASP LLM Top 10, MITRE ATLAS, CWE, NIST, and custom frameworks. This system replaces hardcoded taxonomy dependencies with a plugin-based architecture that supports multiple security standards simultaneously.

## Architecture

### Core Components

The taxonomy system is built around several key components:

1. **BaseTaxonomyMapper Protocol** - Defines the interface for all taxonomy mappers
2. **Concrete Mappers** - Implement mappings for specific taxonomies (OWASP, MITRE ATLAS, etc.)
3. **TaxonomyMapper Orchestrator** - Manages multiple mappers and provides unified interface
4. **TaxonomyMapping Model** - Data structure for storing mapping configurations
5. **Tags System** - Flexible JSON-based tagging in findings

### Directory Structure

```
gibson/core/taxonomy/
├── __init__.py           # Main exports and imports
├── base.py              # Protocol definitions and base models
├── mapper.py            # Main orchestrator class
├── owasp_llm.py         # OWASP LLM Top 10 mapper
└── mitre_atlas.py       # MITRE ATLAS mapper
```

## How It Works

### 1. Domain/Category Mapping

Gibson organizes attacks into **domains** and **categories**:

**Attack Domains:**
- `PROMPT` - Prompt injection and manipulation attacks
- `DATA` - Training data and dataset attacks  
- `MODEL` - Model extraction, theft, and evasion
- `SYSTEM` - Infrastructure enumeration and reconnaissance
- `OUTPUT` - Output manipulation and handling issues

**Module Categories:**
- `INJECTION` - Injection attacks
- `EXTRACTION` - Data or model extraction
- `POISONING` - Data poisoning attacks
- `THEFT` - Model theft and reverse engineering
- `DOS` - Denial of service attacks
- `MANIPULATION` - Output or behavior manipulation
- And more...

### 2. Taxonomy Mapping Flow

```python
# 1. Create mapper instance
from gibson.core.taxonomy import TaxonomyMapper
mapper = TaxonomyMapper()

# 2. Map Gibson categories to external taxonomies
mappings = mapper.map_finding(AttackDomain.PROMPT, ModuleCategory.INJECTION)
# Returns: {"owasp-llm-2025": ["OWASP-LLM-01"]}

# 3. Apply to findings
finding.add_taxonomy_tags("owasp-llm-2025", mappings["owasp-llm-2025"])
```

### 3. Tag Storage System

Findings use a flexible JSON tags field that supports hierarchical taxonomy organization:

```python
finding.tags = {
    "owasp-llm-2025": ["OWASP-LLM-01", "OWASP-LLM-06"],
    "mitre-atlas": ["AML.T0051"],
    "cwe": ["CWE-79", "CWE-20"],
    "custom": {
        "severity_modifiers": ["high_impact"],
        "business_context": ["customer_facing"]
    }
}
```

## Using the Taxonomy System

### Basic Usage

```python
from gibson.core.taxonomy import TaxonomyMapper
from gibson.models.domain import AttackDomain, ModuleCategory

# Initialize mapper (automatically includes OWASP LLM mapper)
mapper = TaxonomyMapper()

# Map a finding to taxonomies
mappings = mapper.map_finding(AttackDomain.PROMPT, ModuleCategory.INJECTION)
print(mappings)
# Output: {"owasp-llm-2025": ["OWASP-LLM-01"]}

# Check supported taxonomies
print(mapper.get_supported_taxonomies())
# Output: ["owasp-llm-2025"]
```

### Working with Findings

```python
from gibson.models.domain import FindingModel, Severity

# Create a finding
finding = FindingModel(
    scan_id=scan_id,
    module="prompt_injection_basic",
    severity=Severity.HIGH,
    title="Prompt Injection Detected",
    description="Successfully injected malicious prompt",
    attack_domain=AttackDomain.PROMPT
)

# Apply taxonomy mapping
mappings = mapper.map_finding(AttackDomain.PROMPT, ModuleCategory.INJECTION)
for taxonomy, tags in mappings.items():
    finding.add_taxonomy_tags(taxonomy, tags)

# Access tags
owasp_tags = finding.get_taxonomy_tags("owasp-llm-2025")
print(owasp_tags)  # ["OWASP-LLM-01"]
```

### Confidence-Based Filtering

```python
# Set confidence threshold (0.0-1.0)
mapper.set_confidence_threshold(0.8)

# Map with specific confidence override
high_conf_mappings = mapper.map_finding(
    AttackDomain.PROMPT,
    ModuleCategory.INJECTION,
    confidence=0.95
)
```

## Adding New Taxonomies

### Step 1: Create a Mapper Class

```python
# gibson/core/taxonomy/my_custom_taxonomy.py
from typing import List
from gibson.core.taxonomy.base import BaseTaxonomyMapper
from gibson.models.domain import AttackDomain, ModuleCategory

class MyCustomMapper:
    """Custom taxonomy mapper example."""
    
    def __init__(self, version: str = "custom-v1.0"):
        self._version = version
        self._taxonomy_name = "My Custom Security Framework"
        
        # Define mappings
        self._mappings = {
            (AttackDomain.PROMPT, ModuleCategory.INJECTION): ["CUSTOM-001"],
            (AttackDomain.DATA, ModuleCategory.POISONING): ["CUSTOM-002"],
            # Add more mappings...
        }
    
    def map(self, domain: AttackDomain, category: ModuleCategory) -> List[str]:
        """Map Gibson domain/category to custom taxonomy."""
        return self._mappings.get((domain, category), [])
    
    @property
    def taxonomy_id(self) -> str:
        return self._version
    
    @property  
    def taxonomy_name(self) -> str:
        return self._taxonomy_name
    
    def get_all_mappings(self) -> dict:
        """Get all mappings for inspection."""
        return dict(self._mappings)
```

### Step 2: Register with TaxonomyMapper

```python
from gibson.core.taxonomy import TaxonomyMapper
from gibson.core.taxonomy.my_custom_taxonomy import MyCustomMapper

# Create mapper and register custom taxonomy
mapper = TaxonomyMapper()
custom_mapper = MyCustomMapper()
mapper.register_mapper("custom-v1", custom_mapper)

# Now it's available for mapping
mappings = mapper.map_finding(AttackDomain.PROMPT, ModuleCategory.INJECTION)
print(mappings)
# Output: {
#   "owasp-llm-2025": ["OWASP-LLM-01"], 
#   "custom-v1": ["CUSTOM-001"]
# }
```

### Step 3: Update Package Exports

```python
# gibson/core/taxonomy/__init__.py
from gibson.core.taxonomy.my_custom_taxonomy import MyCustomMapper

__all__ = [
    "BaseTaxonomyMapper",
    "TaxonomyMapping", 
    "OWASPLLMMapper",
    "MITREATLASMapper",
    "MyCustomMapper",  # Add new mapper
    "TaxonomyMapper",
]
```

## Built-in Taxonomies

### OWASP LLM Top 10 (2025)

Maps Gibson categories to OWASP LLM Top 10 categories:

```python
from gibson.core.taxonomy.owasp_llm import OWASPLLMMapper

mapper = OWASPLLMMapper()
print(mapper.taxonomy_id)  # "owasp-llm-2025"
print(mapper.taxonomy_name)  # "OWASP LLM Top 10"

# Example mappings:
# PROMPT + INJECTION → OWASP-LLM-01 (Prompt Injection)
# DATA + POISONING → OWASP-LLM-03 (Training Data Poisoning)  
# MODEL + THEFT → OWASP-LLM-10 (Model Theft)
```

**Coverage Statistics:**
```python
stats = mapper.get_mapping_coverage_stats()
print(stats)
# {
#   "total_mappings": 19,
#   "domains_covered": 5,
#   "categories_covered": 12,
#   "owasp_categories_covered": 8,
#   "taxonomy_version": "owasp-llm-2025"
# }
```

### MITRE ATLAS

Maps to MITRE ATLAS techniques for adversarial ML attacks:

```python
from gibson.core.taxonomy.mitre_atlas import MITREATLASMapper

mapper = MITREATLASMapper()
print(mapper.taxonomy_id)  # "mitre-atlas-2024"

# Example mappings:
# PROMPT + INJECTION → AML.T0051 (Prompt Injection)
# DATA + POISONING → AML.T0020 (Poison Training Data)
# MODEL + THEFT → AML.T0035 (ML Model Reverse Engineering)
```

**Additional Features:**
```python
# Get technique description
desc = mapper.get_technique_description("AML.T0051")
print(desc)  # "Prompt Injection - Adversaries may inject prompts..."

# Get tactic for technique
tactic = mapper.get_tactic_for_technique("AML.T0051") 
print(tactic)  # "Initial Access"

# Search techniques by keyword
techniques = mapper.search_techniques_by_keyword("injection")
print(techniques)  # ["AML.T0051"]
```

## Tag Structure and Querying

### Tag Structure

The tags field supports flexible hierarchical structures:

```python
# Simple list structure
tags = {
    "owasp-llm-2025": ["OWASP-LLM-01", "OWASP-LLM-06"],
    "cwe": ["CWE-79", "CWE-20"]
}

# Hierarchical structure
tags = {
    "frameworks": {
        "owasp": {
            "categories": ["LLM01", "LLM06"],
            "version": "2025.1"
        },
        "mitre": {
            "techniques": ["AML.T0051"],
            "tactics": ["Initial Access"]
        }
    },
    "internal": {
        "priority": "high",
        "reviewed": True,
        "metadata": {
            "analyst": "security-team",
            "review_date": "2024-01-15"
        }
    }
}
```

### Database Queries

#### SQLite Queries
```sql
-- Find findings with specific OWASP category
SELECT * FROM findings 
WHERE json_extract(tags, '$["owasp-llm-2025"]') LIKE '%OWASP-LLM-01%';

-- Find findings with any MITRE ATLAS tags
SELECT * FROM findings 
WHERE json_extract(tags, '$["mitre-atlas"]') IS NOT NULL;

-- Count findings by taxonomy
SELECT 
    json_extract(tags, '$["owasp-llm-2025"][0]') as owasp_category,
    COUNT(*) as count
FROM findings 
WHERE json_extract(tags, '$["owasp-llm-2025"]') IS NOT NULL
GROUP BY owasp_category;
```

#### PostgreSQL Queries
```sql
-- Find findings with OWASP LLM-01
SELECT * FROM findings 
WHERE tags->'owasp-llm-2025' ? 'OWASP-LLM-01';

-- Find findings with multiple taxonomies
SELECT * FROM findings 
WHERE tags ? 'owasp-llm-2025' AND tags ? 'mitre-atlas';

-- Advanced JSONB queries
SELECT * FROM findings 
WHERE tags @> '{"owasp-llm-2025": ["OWASP-LLM-01"]}';
```

### Programmatic Querying

```python
# Filter findings by taxonomy tags
def filter_findings_by_taxonomy(findings, taxonomy, tag):
    """Filter findings that contain specific taxonomy tag."""
    return [
        f for f in findings 
        if tag in f.get_taxonomy_tags(taxonomy)
    ]

# Example usage
owasp_llm01_findings = filter_findings_by_taxonomy(
    all_findings, 
    "owasp-llm-2025", 
    "OWASP-LLM-01"
)
```

## Migration from OWASP-Specific System

### Background

Gibson originally used a hardcoded `owasp_category` field. The taxonomy system replaces this with flexible `tags` field while maintaining backward compatibility.

### Database Migration

The migration (revision `57b51fa6e084`) performs these steps:

1. **Adds `tags` JSON column** with default empty dict
2. **Migrates existing data**: `owasp_category` → `tags["owasp-llm-2025"]`
3. **Drops old `owasp_category` column** and index
4. **Adds JSON indexes** for query performance

```python
# Before migration (legacy)
finding.owasp_category = "LLM01_PROMPT_INJECTION"

# After migration (new system)
finding.tags = {"owasp-llm-2025": ["OWASP-LLM-01"]}
```

### Code Migration Steps

#### Step 1: Update Finding Creation
```python
# OLD: Hardcoded OWASP category
finding = FindingModel(
    # ... other fields ...
    owasp_category=OWASPCategory.LLM01_PROMPT_INJECTION
)

# NEW: Use taxonomy mapper
finding = FindingModel(
    # ... other fields ...
    attack_domain=AttackDomain.PROMPT
)

# Apply taxonomy mapping
mapper = TaxonomyMapper()
mappings = mapper.map_finding(AttackDomain.PROMPT, ModuleCategory.INJECTION)
for taxonomy, tags in mappings.items():
    finding.add_taxonomy_tags(taxonomy, tags)
```

#### Step 2: Update Queries
```python
# OLD: Query by owasp_category
findings = session.query(DBFinding).filter(
    DBFinding.owasp_category == "OWASP-LLM-01"
).all()

# NEW: Query by tags (post-migration)
findings = session.query(DBFinding).filter(
    text("json_extract(tags, '$[\"owasp-llm-2025\"]') LIKE '%OWASP-LLM-01%'")
).all()
```

#### Step 3: Update Reports
```python
# OLD: Group by owasp_category
def create_owasp_report(findings):
    report = {}
    for finding in findings:
        category = finding.owasp_category
        if category not in report:
            report[category] = []
        report[category].append(finding)
    return report

# NEW: Group by taxonomy tags
def create_taxonomy_report(findings, taxonomy="owasp-llm-2025"):
    report = {}
    for finding in findings:
        tags = finding.get_taxonomy_tags(taxonomy)
        for tag in tags:
            if tag not in report:
                report[tag] = []
            report[tag].append(finding)
    return report
```

### Backward Compatibility

The system maintains compatibility during transition:

```python
# Both fields can coexist temporarily
finding = FindingModel(
    # ... fields ...
    owasp_category=OWASPCategory.LLM01_PROMPT_INJECTION,  # Legacy
    tags={"owasp-llm-2025": ["OWASP-LLM-01"]}  # New system
)

# Access through either interface
legacy_category = finding.owasp_category  # Still works
new_tags = finding.get_taxonomy_tags("owasp-llm-2025")  # New approach
```

## API Reference

### TaxonomyMapper Class

```python
class TaxonomyMapper:
    def __init__(self, confidence_threshold: float = 0.5)
    def register_mapper(self, name: str, mapper: BaseTaxonomyMapper) -> None
    def unregister_mapper(self, name: str) -> bool
    def get_mapper(self, name: str) -> Optional[BaseTaxonomyMapper]
    def get_supported_taxonomies(self) -> List[str]
    def map_finding(self, domain: AttackDomain, category: ModuleCategory, 
                   confidence: Optional[float] = None) -> Dict[str, List[str]]
    def set_confidence_threshold(self, threshold: float) -> None
    def validate_mapper_health(self) -> Dict[str, bool]
    def get_statistics(self) -> Dict[str, Any]
    def clear_mappers(self) -> int
```

### BaseTaxonomyMapper Protocol

```python
class BaseTaxonomyMapper(Protocol):
    def map(self, domain: AttackDomain, category: ModuleCategory) -> List[str]
    
    @property
    def taxonomy_id(self) -> str
    
    @property 
    def taxonomy_name(self) -> str
```

### FindingModel Tag Methods

```python
class FindingModel:
    def add_taxonomy_tags(self, taxonomy: str, tags: Union[str, List[str]]) -> None
    def get_taxonomy_tags(self, taxonomy: str) -> List[str]
```

### TaxonomyMapping Model

```python
class TaxonomyMapping(GibsonBaseModel):
    gibson_domain: AttackDomain
    gibson_category: ModuleCategory  
    taxonomy: str
    mapped_categories: List[str]
    confidence: float  # 0.0-1.0
    metadata: Optional[Dict[str, Any]]
    
    def is_high_confidence(self, threshold: float = 0.8) -> bool
    def get_primary_category(self) -> str
    def has_category(self, category: str) -> bool
    def get_mapping_key(self) -> str
```

## Best Practices

### 1. Mapper Design

```python
class MyTaxonomyMapper:
    def __init__(self):
        # Use clear, versioned taxonomy identifiers
        self._version = "my-taxonomy-2024"
        self._taxonomy_name = "My Security Framework"
        
        # Organize mappings clearly
        self._mappings = self._build_mappings()
    
    def _build_mappings(self) -> dict:
        """Build comprehensive mappings with comments."""
        return {
            # Prompt attacks → Authentication bypass
            (AttackDomain.PROMPT, ModuleCategory.INJECTION): ["AUTH-001"],
            # Data attacks → Data integrity
            (AttackDomain.DATA, ModuleCategory.POISONING): ["DATA-001"],
            # Add comprehensive coverage...
        }
    
    def get_mapping_coverage_stats(self) -> dict:
        """Provide coverage statistics for monitoring."""
        return {
            "total_mappings": len(self._mappings),
            "domains_covered": len(set(k[0] for k in self._mappings.keys())),
            "categories_covered": len(set(k[1] for k in self._mappings.keys())),
            "taxonomy_version": self._version
        }
```

### 2. Error Handling

```python
def safe_taxonomy_mapping(mapper, domain, category):
    """Safely apply taxonomy mapping with error handling."""
    try:
        mappings = mapper.map_finding(domain, category)
        return mappings
    except Exception as e:
        logger.warning(f"Taxonomy mapping failed: {e}")
        return {}  # Return empty dict on error

# Use in module code
mappings = safe_taxonomy_mapping(mapper, AttackDomain.PROMPT, ModuleCategory.INJECTION)
for taxonomy, tags in mappings.items():
    finding.add_taxonomy_tags(taxonomy, tags)
```

### 3. Performance Optimization

```python
# Cache mapper instances
@functools.lru_cache(maxsize=1)
def get_taxonomy_mapper():
    """Get cached taxonomy mapper instance."""
    mapper = TaxonomyMapper()
    # Register additional mappers...
    return mapper

# Batch process findings
def apply_taxonomy_to_findings(findings, mapper):
    """Apply taxonomy mapping to multiple findings efficiently."""
    # Group by domain/category to reduce mapping calls
    domain_category_groups = {}
    for finding in findings:
        key = (finding.attack_domain, finding.module_category)
        if key not in domain_category_groups:
            domain_category_groups[key] = []
        domain_category_groups[key].append(finding)
    
    # Apply mappings by group
    for (domain, category), group_findings in domain_category_groups.items():
        mappings = mapper.map_finding(domain, category)
        for finding in group_findings:
            for taxonomy, tags in mappings.items():
                finding.add_taxonomy_tags(taxonomy, tags)
```

### 4. Testing

```python
class TestMyTaxonomyMapper:
    """Comprehensive tests for custom mapper."""
    
    def test_all_domain_categories_covered(self, mapper):
        """Test that all relevant domain/category pairs are mapped."""
        expected_mappings = [
            (AttackDomain.PROMPT, ModuleCategory.INJECTION),
            (AttackDomain.DATA, ModuleCategory.POISONING),
            # ... add all expected mappings
        ]
        
        for domain, category in expected_mappings:
            result = mapper.map(domain, category)
            assert len(result) > 0, f"No mapping for {domain}:{category}"
    
    def test_mapping_consistency(self, mapper):
        """Test that mappings are consistent across calls."""
        domain, category = AttackDomain.PROMPT, ModuleCategory.INJECTION
        result1 = mapper.map(domain, category)
        result2 = mapper.map(domain, category)
        assert result1 == result2
    
    def test_edge_cases(self, mapper):
        """Test edge cases and error conditions."""
        # Test unknown combinations
        unknown_result = mapper.map(AttackDomain.PROMPT, ModuleCategory.UNSPECIFIED)
        assert isinstance(unknown_result, list)  # Should return empty list, not error
```

## Troubleshooting

### Common Issues

#### 1. Missing Taxonomy Tags
```python
# Problem: Finding has no tags after creation
finding = FindingModel(...)
tags = finding.get_taxonomy_tags("owasp-llm-2025")  # Returns []

# Solution: Ensure taxonomy mapping is applied
mapper = TaxonomyMapper()
mappings = mapper.map_finding(finding.attack_domain, finding.module_category)
for taxonomy, tags in mappings.items():
    finding.add_taxonomy_tags(taxonomy, tags)
```

#### 2. Database Migration Issues
```bash
# Check if migration has been applied
alembic current

# Apply taxonomy migration
alembic upgrade 57b51fa6e084

# Verify tags column exists
sqlite3 gibson.db "PRAGMA table_info(findings);"
```

#### 3. Query Performance Issues
```python
# Problem: Slow JSON queries
# Solution: Ensure indexes are created (handled by migration)

# For custom queries, use appropriate JSON functions
# SQLite: json_extract(tags, '$.taxonomy')
# PostgreSQL: tags->'taxonomy'
```

#### 4. Confidence Threshold Issues
```python
# Problem: No mappings returned
mapper = TaxonomyMapper(confidence_threshold=0.9)
mappings = mapper.map_finding(...)  # Returns empty

# Solution: Check and adjust threshold
print(f"Current threshold: {mapper._confidence_threshold}")
mapper.set_confidence_threshold(0.5)  # Lower threshold
```

### Debug Information

```python
# Get mapper statistics
stats = mapper.get_statistics()
print(json.dumps(stats, indent=2))

# Validate mapper health
health = mapper.validate_mapper_health()
for mapper_name, is_healthy in health.items():
    print(f"{mapper_name}: {'OK' if is_healthy else 'FAILED'}")

# Check specific mapper details
info = mapper.get_mapper_info()
print(json.dumps(info, indent=2))
```

### Logging

The taxonomy system provides comprehensive logging:

```python
import logging
logging.getLogger('gibson.core.taxonomy').setLevel(logging.DEBUG)

# Logs include:
# - Mapper registration/unregistration
# - Mapping operations and results
# - Error conditions and failures
# - Performance metrics
```

## Performance Considerations

### Mapping Performance
- **Single mapping**: ~0.1ms per domain/category combination
- **Bulk mapping**: Use batch processing for >100 findings
- **Memory usage**: ~1KB per registered mapper

### Database Performance
- **JSON queries**: SQLite ~10ms, PostgreSQL ~5ms for 1000 findings
- **Indexes**: Automatic JSON indexing improves query performance 5-10x
- **Storage overhead**: ~200 bytes per finding for taxonomy tags

### Scaling Recommendations
- **Cache mappers**: Use singleton pattern for mapper instances
- **Batch operations**: Process findings in groups of 50-100
- **Async queries**: Use async database operations for large datasets
- **Connection pooling**: Use connection pooling for high-throughput scenarios

---

This documentation provides a complete guide to Gibson's taxonomy system. For additional examples and advanced usage patterns, refer to the test files in `tests/unit/core/taxonomy/` and `tests/integration/taxonomy/`.