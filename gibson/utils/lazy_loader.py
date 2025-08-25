"""Lazy loading utilities for performance optimization."""

import importlib
import sys
from typing import Any


class LazyLoader:
    """Lazy module loader to defer imports until first use."""
    
    def __init__(self, module_name: str) -> None:
        """
        Initialize lazy loader.
        
        Args:
            module_name: Name of module to lazy load
        """
        self.module_name = module_name
        self._module = None
    
    def __getattr__(self, attr: str) -> Any:
        """
        Load module on first attribute access.
        
        Args:
            attr: Attribute name
            
        Returns:
            Module attribute
        """
        if self._module is None:
            self._module = importlib.import_module(self.module_name)
            # Cache in sys.modules for faster subsequent imports
            sys.modules[self.module_name] = self._module
        return getattr(self._module, attr)
    
    def __dir__(self) -> list[str]:
        """Return module attributes for autocomplete."""
        if self._module is None:
            self._module = importlib.import_module(self.module_name)
        return dir(self._module)