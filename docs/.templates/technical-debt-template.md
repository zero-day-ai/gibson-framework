# Technical Debt Analysis: [Component/Area Name]

## Overview

**Component**: [Component name and location]

**Analysis Date**: [Date of analysis]

**Overall Assessment**: [High-level technical debt assessment]

## Debt Categories

### Legacy Code Patterns

#### [Pattern/Issue Name 1]
- **Location**: `[file]:[line-range]`
- **Description**: [What makes this legacy]
- **Impact**: [How it affects maintainability]
- **Modernization Path**: [How to update to modern patterns]

#### [Pattern/Issue Name 2]  
- **Location**: `[file]:[line-range]`
- **Description**: [Legacy pattern description]
- **Impact**: [Maintenance burden]
- **Modernization Path**: [Update strategy]

### Unused/Dead Code

#### [Unused Function/Class 1]
- **Location**: `[file]:[line-range]`
- **Last Used**: [When it was last used, if known]
- **Dependencies**: [What depends on this code]
- **Removal Safety**: [Safe to remove? What needs checking?]

#### [Unused Function/Class 2]
- **Location**: `[file]:[line-range]`  
- **Purpose**: [Original purpose, why now unused]
- **Removal Impact**: [Impact of removal]

### Deprecated Patterns

#### [Deprecated Pattern 1]
- **Location**: `[file]:[line-range]`
- **Pattern**: [What pattern is deprecated]
- **Modern Alternative**: [What should be used instead]
- **Migration Effort**: [Effort level: Trivial/Minor/Major/Extensive]

#### [Deprecated Pattern 2]
- **Location**: `[file]:[line-range]`
- **Issue**: [Why this pattern is problematic]
- **Replacement**: [Modern pattern to use]

### Code Quality Issues

#### [Quality Issue 1]
- **Type**: [Complexity/Duplication/Coupling/etc.]
- **Location**: `[file]:[line-range]`
- **Problem**: [Specific quality issue]
- **Impact**: [How it affects development]
- **Fix**: [How to improve code quality]

#### [Quality Issue 2]
- **Type**: [Issue category]
- **Problem**: [Quality problem description]
- **Solution**: [Improvement approach]

## Prioritization Matrix

### Critical Priority (Fix Immediately)
| Issue | Location | Impact | Effort | Rationale |
|-------|----------|---------|---------|-----------|
| [Issue 1] | [File:Line] | High | Low | [Why critical] |
| [Issue 2] | [File:Line] | High | Medium | [Justification] |

### High Priority (Next Sprint/Month)
| Issue | Location | Impact | Effort | Rationale |
|-------|----------|---------|---------|-----------|
| [Issue 1] | [File:Line] | Medium | Low | [Why high priority] |
| [Issue 2] | [File:Line] | High | High | [Long-term benefit] |

### Medium Priority (Next Quarter)
| Issue | Location | Impact | Effort | Rationale |
|-------|----------|---------|---------|-----------|
| [Issue 1] | [File:Line] | Medium | Medium | [Moderate importance] |
| [Issue 2] | [File:Line] | Low | Low | [Easy wins] |

### Low Priority (Future Consideration)
| Issue | Location | Impact | Effort | Rationale |
|-------|----------|---------|---------|-----------|
| [Issue 1] | [File:Line] | Low | High | [Nice to have] |

## Detailed Recommendations

### Refactoring Opportunities

#### [Refactoring 1]: [Name/Description]
**Problem**: [Current implementation issue]

**Current Code Pattern**:
```python
# Current problematic pattern
[code example]
```

**Recommended Pattern**:
```python  
# Improved pattern
[better code example]
```

**Benefits**: 
- [Benefit 1]
- [Benefit 2]
- [Benefit 3]

**Implementation Steps**:
1. [Step 1]
2. [Step 2] 
3. [Step 3]

**Risk Assessment**: [Low/Medium/High] - [Risk description]

#### [Refactoring 2]: [Name/Description]
**Problem**: [Issue with current approach]

**Solution**: [Refactoring approach]

**Impact**: [Positive effects of change]

### Modernization Opportunities

#### [Modernization 1]: Update to Python 3.11+ Features
**Current**: [Old pattern usage]
**Modern**: [New Python features to use]
**Files Affected**: [List of files]
**Effort**: [Time estimate]

#### [Modernization 2]: Async/Await Pattern Updates
**Current**: [Synchronous patterns]
**Modern**: [Async patterns]
**Benefits**: [Performance/scalability improvements]

### Architecture Improvements

#### [Architecture Issue 1]
**Problem**: [Architectural concern]
**Impact**: [How it affects system]
**Solution**: [Architectural improvement]
**Complexity**: [Implementation complexity]

#### [Architecture Issue 2]  
**Problem**: [System design issue]
**Recommendation**: [Architectural change]
**Benefits**: [System improvements]

## Implementation Roadmap

### Phase 1: Quick Wins (1-2 weeks)
- [ ] [Quick fix 1] - [File] - [Effort estimate]
- [ ] [Quick fix 2] - [File] - [Effort estimate]
- [ ] [Dead code removal] - [Files] - [Safety checks needed]

### Phase 2: Medium Effort (1 month)
- [ ] [Refactoring 1] - [Components affected] - [Effort estimate]
- [ ] [Pattern modernization] - [Files] - [Testing needed]
- [ ] [Architecture improvement] - [System areas] - [Dependencies]

### Phase 3: Major Improvements (1 quarter)
- [ ] [Large refactoring] - [System-wide impact] - [Effort estimate]
- [ ] [Architecture redesign] - [Components] - [Risk mitigation]
- [ ] [Performance optimization] - [Areas] - [Expected improvement]

## Risk Assessment

### High Risk Changes
- **[Change 1]**: [Why risky, mitigation strategy]
- **[Change 2]**: [Risk factors, safety measures]

### Medium Risk Changes  
- **[Change 1]**: [Risk description, precautions]
- **[Change 2]**: [Risk level, testing needed]

### Low Risk Changes
- **[Change 1]**: [Why low risk]
- **[Change 2]**: [Safe change description]

## Success Metrics

### Code Quality Metrics
- **Cyclomatic Complexity**: [Current] → [Target]
- **Test Coverage**: [Current] → [Target]
- **Code Duplication**: [Current] → [Target]

### Maintainability Metrics
- **Lines of Code**: [Current] → [Expected after cleanup]
- **File Count**: [Current] → [After consolidation]
- **Dependency Count**: [Current] → [After optimization]

### Performance Metrics
- **[Performance Metric 1]**: [Current] → [Expected improvement]
- **[Performance Metric 2]**: [Baseline] → [Target]

## Tracking and Review

### Review Schedule
- **Weekly**: [What to check weekly]
- **Monthly**: [Monthly review items]
- **Quarterly**: [Quarterly assessment]

### Progress Tracking
- **Issues Resolved**: [Counter/tracker]
- **Code Quality Improvement**: [Metrics tracking]
- **Technical Debt Reduction**: [Measurement approach]