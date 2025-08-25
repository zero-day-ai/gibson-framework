"""Global context and dependency injection for Gibson CLI."""

from dataclasses import dataclass
from typing import Any, Optional
from pathlib import Path

from rich.console import Console

from gibson.core.config import Config


@dataclass
class Context:
    """Global context object for CLI state management."""
    
    config: Config
    console: Console
    verbose: bool = False
    debug: bool = False
    quiet: bool = False
    no_color: bool = False
    output_format: Optional[str] = None
    
    def __post_init__(self) -> None:
        """Post-initialization setup."""
        # Apply settings to console
        if self.no_color:
            self.console.no_color = True
        if self.quiet:
            self.console.quiet = True
        
        # Ensure directories exist
        self._setup_directories()
    
    def _setup_directories(self) -> None:
        """Setup required directories."""
        # Ensure data directories exist
        if self.config.data_dir:
            Path(self.config.data_dir).mkdir(parents=True, exist_ok=True)
        if self.config.cache_dir:
            Path(self.config.cache_dir).mkdir(parents=True, exist_ok=True)
        if self.config.module_dir:
            Path(self.config.module_dir).mkdir(parents=True, exist_ok=True)
        
        # Ensure config directory exists
        config_dir = Path.home() / ".config" / "gibson"
        config_dir.mkdir(parents=True, exist_ok=True)
        
        # Ensure gibson data directory exists  
        gibson_dir = Path.home() / ".gibson"
        gibson_dir.mkdir(parents=True, exist_ok=True)