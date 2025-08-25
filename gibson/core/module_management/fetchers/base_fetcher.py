"""Base fetcher interface for module sources."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Optional, Any
from loguru import logger

from gibson.models.module import ModuleDefinitionModel


class BaseFetcher(ABC):
    """Abstract base class for module fetchers."""

    @abstractmethod
    async def fetch(
        self, source: str, target_dir: Path, options: Optional[Dict[str, Any]] = None
    ) -> Path:
        """
        Fetch module from source to target directory.

        Args:
            source: Source identifier (URL, name, path)
            target_dir: Directory to download/copy module to
            options: Additional fetcher-specific options

        Returns:
            Path to the fetched module directory

        Raises:
            ModuleInstallationError: If fetch fails
        """
        pass

    @abstractmethod
    async def validate_source(self, source: str) -> bool:
        """
        Validate that source is valid for this fetcher.

        Args:
            source: Source identifier to validate

        Returns:
            True if source is valid
        """
        pass

    async def extract_metadata(self, module_path: Path) -> Optional[ModuleDefinitionModel]:
        """
        Extract module metadata from fetched module.

        Args:
            module_path: Path to module directory

        Returns:
            ModuleDefinitionModel or None if not found
        """
        # Look for module.json or module.yaml
        metadata_files = [
            module_path / "module.json",
            module_path / "module.yaml",
            module_path / "gibson.json",
            module_path / "gibson.yaml",
        ]

        for metadata_file in metadata_files:
            if metadata_file.exists():
                try:
                    if metadata_file.suffix == ".json":
                        import json

                        with open(metadata_file) as f:
                            data = json.load(f)
                    else:
                        import yaml

                        with open(metadata_file) as f:
                            data = yaml.safe_load(f)

                    return ModuleDefinitionModel(**data)
                except Exception as e:
                    logger.warning(f"Failed to parse metadata from {metadata_file}: {e}")

        return None

    def _ensure_target_dir(self, target_dir: Path) -> None:
        """Ensure target directory exists."""
        target_dir.mkdir(parents=True, exist_ok=True)
