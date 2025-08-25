# Component: [Component Name]

## Overview

**Purpose**: [Brief description of component's purpose and responsibilities]

**Location**: `gibson/[path-to-component]/`

**Key Design Decisions**: [Important architectural decisions and rationale]

## Architecture

### Component Structure
```
[component-directory]/
├── [key-files].py
├── [subdirectories]/
└── [other-important-files].py
```

### Key Classes and Interfaces
- **[ClassName]**: [Purpose and responsibility]
- **[InterfaceName]**: [Interface contract and usage]
- **[UtilityClass]**: [Utility functions and helpers]

### Design Patterns Used
- [Pattern Name]: [How it's implemented and why]
- [Another Pattern]: [Implementation details]

## Data Flow

### Input Data
- [Input type]: [Description and source]
- [Another input]: [Format and validation]

### Data Transformations
1. [Step 1]: [What happens to data]
2. [Step 2]: [Next transformation]
3. [Output]: [Final data format]

### Integration with Other Components
- **[Component A]**: [How they interact]
- **[Component B]**: [Data exchange patterns]

## Technical Analysis

### Code Quality Assessment
- **Strengths**: [Well-implemented aspects]
- **Areas for Improvement**: [Code quality issues]
- **Complexity**: [Assessment of code complexity]

### Performance Characteristics
- **Typical Performance**: [Expected performance metrics]
- **Bottlenecks**: [Known performance issues]
- **Resource Usage**: [Memory, CPU, I/O patterns]

### Identified Technical Debt
- **Legacy Code**: [Outdated patterns or implementations]
- **Unused Functions**: [Functions that should be removed]
- **Deprecated Patterns**: [Old patterns that need updating]

## Integration Points

### Dependencies on Other Components
- **[Dependency 1]**: [What it provides, how it's used]
- **[Dependency 2]**: [Integration mechanism]

### External System Integrations
- **[External System]**: [How integration works]
- **[API/Service]**: [Integration patterns used]

### Extension Mechanisms
- **[Extension Point 1]**: [How developers can extend]
- **[Plugin Interface]**: [Extension interface description]

## Improvement Recommendations

### High Priority
1. **[Issue]**: [Specific recommendation and rationale]
2. **[Another Issue]**: [Improvement approach]

### Medium Priority
1. **[Issue]**: [Refactoring suggestion]
2. **[Code Quality]**: [Modernization opportunity]

### Low Priority
1. **[Enhancement]**: [Future improvement possibility]

### Performance Optimizations
- **[Optimization 1]**: [How to improve performance]
- **[Caching Strategy]**: [Caching improvements]

## Usage Examples

### Common Usage Patterns
```python
# Example of typical usage
from gibson.[component] import [ClassName]

# Standard usage pattern
instance = [ClassName]()
result = instance.method(parameters)
```

### Configuration Examples
```yaml
# Component configuration
[component]:
  setting1: value
  setting2: value
```

### Best Practices
1. **[Practice 1]**: [Why it's important]
2. **[Practice 2]**: [How to implement correctly]

## Files Overview

### Core Implementation Files
- **[file1].py**: [Purpose and key functions]
- **[file2].py**: [Responsibility and usage]

### Supporting Files
- **[util_file].py**: [Utility functions]
- **[config_file].py**: [Configuration handling]

### Test Coverage
- **[test_file].py**: [What tests cover]
- **Missing Tests**: [Areas needing test coverage]

## Related Documentation
- [Link to related component docs]
- [Link to workflow documentation]
- [Link to technical debt analysis]