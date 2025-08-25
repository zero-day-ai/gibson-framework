"""
Gibson Framework External Modules

This directory is for external modules that are pip-installable.
Core maintained modules are located in gibson.core.modules.

External modules should follow the Gibson module API:
1. Inherit from a domain class (PromptDomain, DataDomain, etc.)
2. Implement required methods: run(), get_config_schema()
3. Follow semantic versioning for compatibility
4. Use proper typing and documentation

Examples of external modules:
- gibson-prompt-attacks: Community prompt injection techniques
- gibson-model-security: Advanced model theft detection
- gibson-custom-payloads: Organization-specific test payloads
"""

# This directory will be populated by external pip packages
# that extend Gibson's capabilities through the domain system

__version__ = "1.0.0"
