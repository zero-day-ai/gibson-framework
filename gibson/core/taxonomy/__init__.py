"""Taxonomy mapping system for Gibson Framework.

Provides infrastructure for mapping Gibson's internal attack domains and categories
to external security taxonomies like OWASP LLM Top 10, MITRE ATT&CK, and others.
"""

from gibson.core.taxonomy.base import BaseTaxonomyMapper, TaxonomyMapping
from gibson.core.taxonomy.owasp_llm import OWASPLLMMapper
from gibson.core.taxonomy.mitre_atlas import MITREATLASMapper
from gibson.core.taxonomy.mapper import TaxonomyMapper

__all__ = [
    "BaseTaxonomyMapper",
    "TaxonomyMapping",
    "OWASPLLMMapper",
    "MITREATLASMapper",
    "TaxonomyMapper",
]
