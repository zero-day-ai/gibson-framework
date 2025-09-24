# Changelog

All notable changes to the Gibson Framework will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Complete deployment automation with GitHub Actions
- Comprehensive installation scripts for Linux, macOS, and FreeBSD
- DEB and RPM package generation
- Homebrew formula for macOS distribution
- Backup and restore functionality
- Database migration system
- Production-ready systemd service configuration
- Security hardening with proper file permissions and user isolation

### Changed
- Enhanced Makefile with comprehensive build and release targets
- Improved error handling throughout the application
- Updated documentation with complete deployment guide

### Security
- Added security-focused systemd service configuration
- Implemented proper file permission management
- Added audit logging capabilities

## [2.0.0] - 2024-09-15

### Added
- Domain-based plugin architecture with six security domains:
  - Model Domain: AI model attacks (extraction, inversion, backdoor, adversarial)
  - Data Domain: Data attacks (poisoning, extraction, quality assessment)
  - Interface Domain: Prompt/interface attacks (injection, jailbreak, boundary)
  - Infrastructure Domain: Infrastructure attacks (DoS, auth bypass, pipeline)
  - Output Domain: Output attacks (data leakage, harmful content, bias)
  - Process Domain: Process attacks (supply chain, governance, lifecycle)
- Plugin instance management system
- Enhanced database schema with audit logging
- Comprehensive plugin health monitoring
- Advanced scan result tracking
- Security audit logging functionality
- Plugin capability declaration system
- Multi-domain plugin support
- Enhanced error reporting and debugging

### Changed
- Completely redesigned plugin architecture
- Improved database schema for better performance
- Enhanced CLI with more intuitive commands
- Better separation of concerns between core and plugin systems
- Upgraded to Go 1.24
- Improved test coverage and CI/CD pipeline

### Deprecated
- Legacy plugin interface (v1.x compatibility maintained)
- Single-domain plugin restrictions

### Removed
- Deprecated configuration options from v1.x
- Legacy database migration paths older than v1.0.0

### Fixed
- Memory leaks in plugin execution
- Race conditions in concurrent plugin execution
- Database connection pooling issues
- Configuration validation edge cases

### Security
- Enhanced plugin sandboxing
- Improved API key management
- Added rate limiting functionality
- Comprehensive audit logging

## [1.1.0] - 2024-08-01

### Added
- Credential management system
- Payload library and management
- Report generation in multiple formats (JSON, YAML, HTML, PDF)
- Enhanced CLI commands for credential and payload management
- Database schema improvements
- Configuration validation system
- Plugin timeout and resource management
- Basic audit logging

### Changed
- Improved plugin loading mechanism
- Enhanced error messages and logging
- Better CLI help and documentation
- Updated database schema with new tables

### Fixed
- Plugin execution timeout issues
- Database transaction handling
- CLI argument parsing edge cases
- Memory usage optimization

## [1.0.0] - 2024-06-15

### Added
- Initial release of Gibson Framework 2.0
- Core CLI application with Cobra framework
- SQLite database with sqlx integration
- Basic plugin system architecture
- Target management (create, list, update, delete)
- Scan management and execution
- Finding reporting and storage
- Plugin discovery and loading
- Configuration management with Viper
- Comprehensive logging system
- Basic web API endpoints
- Health check functionality
- Version information and build metadata

### Core Commands
- `gibson target` - Target management
- `gibson scan` - Scan execution and management
- `gibson plugin` - Plugin operations
- `gibson credential` - Credential management (added in v1.1.0)
- `gibson payload` - Payload management (added in v1.1.0)
- `gibson report` - Report generation
- `gibson status` - System status
- `gibson version` - Version information

### Plugin Architecture
- Domain-based plugin categorization
- Plugin manifest system (plugin.yaml)
- Configurable plugin timeouts
- Plugin status tracking
- Basic plugin validation

### Database Schema
- Targets table for scan targets
- Scans table for scan execution tracking
- Findings table for vulnerability storage
- Plugins table for plugin management
- Schema versioning and migration support

### Configuration
- YAML-based configuration
- Environment variable overrides
- Comprehensive validation
- Default configuration generation

### Testing
- Comprehensive test suite
- Integration tests
- Performance benchmarks
- CI/CD pipeline with GitHub Actions

## [0.9.0] - 2024-05-01 (Pre-release)

### Added
- Initial framework architecture design
- Basic CLI structure
- Database schema design
- Plugin interface definition
- Core model definitions

### Changed
- Migrated from Gibson Framework 1.x architecture
- Redesigned for better modularity and performance

## Development Guidelines

### Version Numbering
- **Major** (X.y.z): Breaking changes, incompatible API changes
- **Minor** (x.Y.z): New features, backwards compatible
- **Patch** (x.y.Z): Bug fixes, backwards compatible

### Change Categories
- **Added**: New features
- **Changed**: Changes in existing functionality
- **Deprecated**: Soon-to-be removed features
- **Removed**: Removed features
- **Fixed**: Bug fixes
- **Security**: Security vulnerability fixes

### Breaking Changes
Breaking changes are clearly marked with `BREAKING:` prefix and include migration instructions.

### Migration Notes

#### Migrating from v1.1.0 to v2.0.0
1. **Plugin Architecture**: Plugins must declare their domain and capabilities
2. **Database Schema**: Run `gibson migrate` to update schema
3. **Configuration**: Update config.yaml with new plugin management sections
4. **API Changes**: Some API endpoints have changed, update client code accordingly

#### Migrating from v1.0.0 to v1.1.0
1. **Database Schema**: Run `gibson migrate` to add new tables
2. **Configuration**: Add credential and payload sections to config.yaml
3. **CLI Commands**: New commands available for credential and payload management

### Security Releases

Security releases are prioritized and may include patches for multiple versions:

- **Critical**: Immediate release, patches all supported versions
- **High**: Release within 1 week, patches current and previous major version
- **Medium**: Release within 1 month, patches current version
- **Low**: Included in next regular release

### Support Matrix

| Version | Status | End of Life |
|---------|--------|-------------|
| 2.x     | Active | TBD |
| 1.1.x   | Security fixes only | 2025-06-15 |
| 1.0.x   | End of life | 2024-12-15 |

### Contributing

When contributing changes:

1. Update this CHANGELOG.md with your changes
2. Follow the format and categorization guidelines
3. Include migration notes for breaking changes
4. Reference related issues and pull requests
5. Ensure version bumps follow semantic versioning

### Release Process

1. Update CHANGELOG.md with release version and date
2. Create release tag: `git tag -a v2.0.0 -m "Release v2.0.0"`
3. Push tag: `git push origin v2.0.0`
4. GitHub Actions will automatically:
   - Build multi-platform binaries
   - Create release packages (DEB, RPM)
   - Build and push Docker images
   - Generate release notes
   - Create GitHub release

### Links

- [GitHub Repository](https://github.com/zero-day-ai/gibson-framework)
- [Documentation](https://github.com/zero-day-ai/gibson-framework/docs)
- [Issue Tracker](https://github.com/zero-day-ai/gibson-framework/issues)
- [Security Policy](https://github.com/zero-day-ai/gibson-framework/security/policy)