"""
Schema version management using SchemaVer format.

SchemaVer uses MODEL-REVISION-ADDITION format:
- MODEL: Breaking changes that affect all historical data
- REVISION: Changes that may impact some historical data
- ADDITION: Fully backward compatible changes
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple, List
from enum import Enum


class ChangeType(Enum):
    """Types of schema changes."""

    MODEL = "model"  # Breaking change
    REVISION = "revision"  # Potentially breaking
    ADDITION = "addition"  # Backward compatible
    NONE = "none"  # No change


@dataclass
class SchemaVersion:
    """Represents a schema version in SchemaVer format."""

    model: int
    revision: int
    addition: int

    def __str__(self) -> str:
        """String representation of version."""
        return f"{self.model}-{self.revision}-{self.addition}"

    @classmethod
    def parse(cls, version_str: str) -> "SchemaVersion":
        """Parse a version string into SchemaVersion.

        Args:
            version_str: Version string in MODEL-REVISION-ADDITION format

        Returns:
            SchemaVersion instance

        Raises:
            ValueError: If version string is invalid
        """
        try:
            parts = version_str.split("-")
            if len(parts) != 3:
                raise ValueError(f"Invalid version format: {version_str}")

            return cls(
                model=int(parts[0]),
                revision=int(parts[1]),
                addition=int(parts[2]),
            )
        except (ValueError, IndexError) as e:
            raise ValueError(f"Invalid version string '{version_str}': {e}")

    def bump(self, change_type: ChangeType) -> "SchemaVersion":
        """Create a new version by bumping the appropriate component.

        Args:
            change_type: Type of change to apply

        Returns:
            New SchemaVersion instance
        """
        if change_type == ChangeType.MODEL:
            return SchemaVersion(self.model + 1, 0, 0)
        elif change_type == ChangeType.REVISION:
            return SchemaVersion(self.model, self.revision + 1, 0)
        elif change_type == ChangeType.ADDITION:
            return SchemaVersion(self.model, self.revision, self.addition + 1)
        else:
            return SchemaVersion(self.model, self.revision, self.addition)

    def compare(self, other: "SchemaVersion") -> int:
        """Compare two versions.

        Args:
            other: Version to compare with

        Returns:
            -1 if self < other, 0 if equal, 1 if self > other
        """
        if self.model != other.model:
            return -1 if self.model < other.model else 1
        if self.revision != other.revision:
            return -1 if self.revision < other.revision else 1
        if self.addition != other.addition:
            return -1 if self.addition < other.addition else 1
        return 0

    def is_compatible_with(self, other: "SchemaVersion") -> bool:
        """Check if this version is backward compatible with another.

        Args:
            other: Version to check compatibility with

        Returns:
            True if versions are compatible
        """
        # Different MODEL versions are never compatible
        if self.model != other.model:
            return False

        # Same MODEL, higher REVISION might be compatible
        if self.revision > other.revision:
            return False  # Newer revisions may break older data

        # Same MODEL and REVISION, any ADDITION is compatible
        return True


class VersionManager:
    """Manages schema versioning using SchemaVer format."""

    def __init__(self, version_file: Optional[Path] = None):
        """Initialize version manager.

        Args:
            version_file: Optional path to version history file
        """
        self.version_file = version_file
        self.current_version: Optional[SchemaVersion] = None
        self.version_history: List[Tuple[str, str]] = []  # (version, change_description)

        if version_file and version_file.exists():
            self.load_version_history()

    def get_current_version(self) -> str:
        """Get the current version string.

        Returns:
            Current version as string
        """
        if not self.current_version:
            self.current_version = SchemaVersion(1, 0, 0)
        return str(self.current_version)

    def set_current_version(self, version_str: str) -> None:
        """Set the current version.

        Args:
            version_str: Version string to set
        """
        self.current_version = SchemaVersion.parse(version_str)

    def bump_version(self, change_type: ChangeType, description: str = "") -> str:
        """Bump version based on change type.

        Args:
            change_type: Type of change
            description: Description of the change

        Returns:
            New version string
        """
        if not self.current_version:
            self.current_version = SchemaVersion(1, 0, 0)

        old_version = str(self.current_version)
        self.current_version = self.current_version.bump(change_type)
        new_version = str(self.current_version)

        # Add to history
        self.version_history.append((new_version, description))

        # Save if file is configured
        if self.version_file:
            self.save_version_history()

        return new_version

    def compare_versions(self, old: str, new: str) -> int:
        """Compare two version strings.

        Args:
            old: Old version string
            new: New version string

        Returns:
            -1 if old < new, 0 if equal, 1 if old > new
        """
        old_version = SchemaVersion.parse(old)
        new_version = SchemaVersion.parse(new)
        return old_version.compare(new_version)

    def are_compatible(self, version1: str, version2: str) -> bool:
        """Check if two versions are compatible.

        Args:
            version1: First version string
            version2: Second version string

        Returns:
            True if versions are compatible
        """
        v1 = SchemaVersion.parse(version1)
        v2 = SchemaVersion.parse(version2)
        return v1.is_compatible_with(v2)

    def determine_change_type(self, changes: List[str]) -> ChangeType:
        """Determine change type based on list of changes.

        Args:
            changes: List of change descriptions

        Returns:
            Appropriate ChangeType
        """
        # Keywords that indicate breaking changes
        breaking_keywords = [
            "removed required field",
            "changed type",
            "removed enum value",
            "renamed field",
        ]

        # Keywords that indicate revisions
        revision_keywords = [
            "added required field",
            "changed validation",
            "modified constraint",
        ]

        # Check for breaking changes
        for change in changes:
            change_lower = change.lower()
            if any(keyword in change_lower for keyword in breaking_keywords):
                return ChangeType.MODEL

        # Check for revisions
        for change in changes:
            change_lower = change.lower()
            if any(keyword in change_lower for keyword in revision_keywords):
                return ChangeType.REVISION

        # Default to addition for backward compatible changes
        return ChangeType.ADDITION if changes else ChangeType.NONE

    def load_version_history(self) -> None:
        """Load version history from file."""
        if not self.version_file or not self.version_file.exists():
            return

        try:
            with open(self.version_file, "r") as f:
                data = json.load(f)
                self.current_version = SchemaVersion.parse(data.get("current", "1-0-0"))
                self.version_history = [
                    (item["version"], item["description"]) for item in data.get("history", [])
                ]
        except (json.JSONDecodeError, KeyError, ValueError):
            # If file is corrupted, start fresh
            self.current_version = SchemaVersion(1, 0, 0)
            self.version_history = []

    def save_version_history(self) -> None:
        """Save version history to file."""
        if not self.version_file:
            return

        self.version_file.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "current": str(self.current_version),
            "history": [
                {"version": version, "description": desc} for version, desc in self.version_history
            ],
        }

        with open(self.version_file, "w") as f:
            json.dump(data, f, indent=2)

    def get_version_history(self) -> List[Tuple[str, str]]:
        """Get version history.

        Returns:
            List of (version, description) tuples
        """
        return self.version_history.copy()

    def list_versions(self) -> List[str]:
        """List all versions in history.

        Returns:
            List of version strings
        """
        versions = [v for v, _ in self.version_history]
        if self.current_version and str(self.current_version) not in versions:
            versions.append(str(self.current_version))
        return versions
