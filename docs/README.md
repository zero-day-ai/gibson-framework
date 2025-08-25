# Gibson Framework Documentation

## Overview

Gibson is a comprehensive AI security testing framework designed to identify vulnerabilities in AI/ML systems. This documentation provides complete coverage of Gibson's architecture, components, workflows, and extension mechanisms.

## Documentation Structure

### 🏗️ Components
Detailed documentation for each major Gibson subsystem:

- **[CLI System](components/cli/)** - Command-line interface, models, and validation
- **[Core Architecture](components/core/)** - Base orchestration, configuration, and context management
- **[Authentication](components/auth/)** - Security, credential management, and audit systems
- **[LLM Integration](components/llm/)** - AI service clients, rate limiting, and usage tracking
- **[Module Management](components/module-management/)** - Plugin architecture and lifecycle management
- **[Security Modules](components/modules/)** - Base module patterns and security testing implementations
- **[Payload Management](components/payloads/)** - Git synchronization and payload database operations
- **[Target Management](components/targets/)** - Target configuration and LiteLLM adapter patterns
- **[Database Layer](components/database/)** - ORM models, repositories, and migration systems
- **[Schema Synchronization](components/schema-sync/)** - Schema generation and synchronization patterns

### 🔄 Workflows
Command execution paths and data flows:

- **[Payload Sync](workflows/payload-sync.md)** - Complete `gibson payload sync` workflow
- **[Scan Execution](workflows/scan-execution.md)** - Module orchestration and result aggregation
- **[Target Management](workflows/target-management.md)** - Target configuration and validation
- **[Module Operations](workflows/module-operations.md)** - Module installation and management
- **[Configuration](workflows/configuration.md)** - System configuration workflows

### 📊 Data Architecture
- **[Data Flow Overview (DATA.md)](DATA.md)** - System-wide data architecture and flows
- **[Visual Diagrams](diagrams/)** - Architecture and data flow diagrams

### 🔧 Technical Debt & Improvements
- **[Technical Debt Analysis](technical-debt/)** - Legacy code identification and improvement priorities
- **[Refactoring Recommendations](technical-debt/refactoring-recommendations.md)** - Specific modernization guidance

### 🚀 Development & Integration
- **[Development Guide](DEVELOPMENT.md)** - Creating modules and extending Gibson
- **[Integration Guide](INTEGRATION.md)** - API contracts and integration patterns
- **[Architecture Overview](ARCHITECTURE.md)** - High-level system architecture

## Quick Navigation

### For Developers
- [Development Guide](DEVELOPMENT.md) - Start here for module development
- [CLI Components](components/cli/) - Understanding command architecture
- [Module System](components/modules/) - Security module implementation patterns

### For Security Engineers
- [Scan Workflows](workflows/scan-execution.md) - Understanding scan execution
- [Payload Management](components/payloads/) - Managing attack payloads
- [Security Modules](components/modules/) - Available testing capabilities

### For Platform Engineers
- [Database Architecture](components/database/) - Data persistence patterns
- [Configuration System](components/core/config.md) - System configuration
- [Integration Patterns](INTEGRATION.md) - System integration guidance

### For Contributors
- [Technical Debt Analysis](technical-debt/) - Areas needing improvement
- [Architecture Overview](ARCHITECTURE.md) - System design understanding
- [Component Documentation](components/) - Deep component analysis

## Documentation Maintenance

This documentation is designed to stay synchronized with the Gibson codebase. See [MAINTENANCE.md](MAINTENANCE.md) for guidelines on keeping documentation current.

## Getting Started

1. **Understanding Gibson**: Start with [ARCHITECTURE.md](ARCHITECTURE.md) for high-level overview
2. **Using Gibson**: Review [workflow documentation](workflows/) for command usage
3. **Extending Gibson**: Follow [DEVELOPMENT.md](DEVELOPMENT.md) for module creation
4. **Data Flows**: Study [DATA.md](DATA.md) for comprehensive system understanding

## Contributing to Documentation

When modifying Gibson code:
1. Update relevant component documentation
2. Verify workflow documentation accuracy
3. Add new components to this navigation
4. Update data flow diagrams if needed

For questions or improvements, see the project's contribution guidelines.