"""
Version comparison and management utilities for schema synchronization.
"""

import re
from typing import List, Optional, Tuple, Dict, Any
from datetime import datetime
from packaging import version as pkg_version

from gibson.models.base import GibsonBaseModel


class SchemaVersion(GibsonBaseModel):
    """Represents a schema version with comparison capabilities."""

    version_string: str
    major: int = 0
    minor: int = 0
    patch: int = 0
    timestamp: Optional[datetime] = None
    build: Optional[str] = None
    metadata: Dict[str, Any] = {}

    def __init__(self, **data):
        """Initialize and parse version string."""
        super().__init__(**data)
        self._parse_version()

    def _parse_version(self):
        """Parse version string into components."""
        # Try different version formats

        # Format: YYYYMMDD_HHMMSS (timestamp-based)
        timestamp_pattern = r"^(\d{8})_(\d{6})$"
        match = re.match(timestamp_pattern, self.version_string)
        if match:
            date_str, time_str = match.groups()
            self.timestamp = datetime.strptime(f"{date_str}_{time_str}", "%Y%m%d_%H%M%S")
            # Use timestamp components as version numbers
            self.major = int(date_str[:4])  # Year
            self.minor = int(date_str[4:6])  # Month
            self.patch = int(date_str[6:8])  # Day
            self.build = time_str
            return

        # Format: X.Y.Z or vX.Y.Z (semantic versioning)
        semver_pattern = r"^v?(\d+)\.(\d+)\.(\d+)(?:-(.+))?$"
        match = re.match(semver_pattern, self.version_string)
        if match:
            self.major = int(match.group(1))
            self.minor = int(match.group(2))
            self.patch = int(match.group(3))
            self.build = match.group(4) or None
            return

        # Format: YYYY-MM-DD_N (date with sequence)
        date_seq_pattern = r"^(\d{4})-(\d{2})-(\d{2})_(\d+)$"
        match = re.match(date_seq_pattern, self.version_string)
        if match:
            year, month, day, seq = match.groups()
            self.major = int(year)
            self.minor = int(month)
            self.patch = int(day)
            self.build = seq
            self.timestamp = datetime(int(year), int(month), int(day))
            return

        # Fallback: treat as opaque string
        # Use hash for comparison
        self.major = 0
        self.minor = 0
        self.patch = hash(self.version_string) % 1000000

    def __lt__(self, other: "SchemaVersion") -> bool:
        """Less than comparison."""
        if self.timestamp and other.timestamp:
            return self.timestamp < other.timestamp

        return (self.major, self.minor, self.patch) < (other.major, other.minor, other.patch)

    def __le__(self, other: "SchemaVersion") -> bool:
        """Less than or equal comparison."""
        return self == other or self < other

    def __gt__(self, other: "SchemaVersion") -> bool:
        """Greater than comparison."""
        return not self <= other

    def __ge__(self, other: "SchemaVersion") -> bool:
        """Greater than or equal comparison."""
        return not self < other

    def __eq__(self, other: "SchemaVersion") -> bool:
        """Equality comparison."""
        if self.timestamp and other.timestamp:
            return self.timestamp == other.timestamp

        return (self.major, self.minor, self.patch) == (other.major, other.minor, other.patch)

    def is_compatible_with(self, other: "SchemaVersion") -> bool:
        """
        Check if this version is compatible with another.

        Uses semantic versioning rules:
        - Major version changes are incompatible
        - Minor version changes are backward compatible
        - Patch version changes are fully compatible
        """
        if self.major != other.major:
            return False  # Major version mismatch

        if self.major == 0:
            # In 0.x.x, minor changes can be breaking
            return self.minor == other.minor

        # Same major version, compatible
        return True

    def distance_from(self, other: "SchemaVersion") -> int:
        """
        Calculate distance between versions.

        Returns:
            Number representing how many versions apart
        """
        if self.timestamp and other.timestamp:
            # For timestamp versions, use days as distance
            delta = abs((self.timestamp - other.timestamp).days)
            return delta

        # For semantic versions, calculate weighted distance
        major_diff = abs(self.major - other.major)
        minor_diff = abs(self.minor - other.minor)
        patch_diff = abs(self.patch - other.patch)

        # Weight major changes more heavily
        return major_diff * 10000 + minor_diff * 100 + patch_diff

    def to_string(self) -> str:
        """Convert to string representation."""
        return self.version_string


class VersionComparator:
    """Utilities for comparing and managing schema versions."""

    @staticmethod
    def parse_version(version_string: str) -> SchemaVersion:
        """
        Parse a version string into SchemaVersion object.

        Args:
            version_string: Version string to parse

        Returns:
            SchemaVersion object
        """
        return SchemaVersion(version_string=version_string)

    @staticmethod
    def compare(v1: str, v2: str) -> int:
        """
        Compare two version strings.

        Args:
            v1: First version string
            v2: Second version string

        Returns:
            -1 if v1 < v2, 0 if equal, 1 if v1 > v2
        """
        version1 = VersionComparator.parse_version(v1)
        version2 = VersionComparator.parse_version(v2)

        if version1 < version2:
            return -1
        elif version1 > version2:
            return 1
        else:
            return 0

    @staticmethod
    def sort_versions(versions: List[str], reverse: bool = False) -> List[str]:
        """
        Sort a list of version strings.

        Args:
            versions: List of version strings
            reverse: If True, sort in descending order

        Returns:
            Sorted list of version strings
        """
        parsed_versions = [VersionComparator.parse_version(v) for v in versions]
        sorted_versions = sorted(parsed_versions, reverse=reverse)
        return [v.to_string() for v in sorted_versions]

    @staticmethod
    def get_latest(versions: List[str]) -> Optional[str]:
        """
        Get the latest version from a list.

        Args:
            versions: List of version strings

        Returns:
            Latest version string or None if list is empty
        """
        if not versions:
            return None

        sorted_versions = VersionComparator.sort_versions(versions, reverse=True)
        return sorted_versions[0]

    @staticmethod
    def get_previous(version: str, versions: List[str]) -> Optional[str]:
        """
        Get the version immediately before the given version.

        Args:
            version: Reference version
            versions: List of all versions

        Returns:
            Previous version or None if not found
        """
        sorted_versions = VersionComparator.sort_versions(versions)

        try:
            index = sorted_versions.index(version)
            if index > 0:
                return sorted_versions[index - 1]
        except ValueError:
            pass

        return None

    @staticmethod
    def get_next(version: str, versions: List[str]) -> Optional[str]:
        """
        Get the version immediately after the given version.

        Args:
            version: Reference version
            versions: List of all versions

        Returns:
            Next version or None if not found
        """
        sorted_versions = VersionComparator.sort_versions(versions)

        try:
            index = sorted_versions.index(version)
            if index < len(sorted_versions) - 1:
                return sorted_versions[index + 1]
        except ValueError:
            pass

        return None

    @staticmethod
    def get_range(
        versions: List[str], start: Optional[str] = None, end: Optional[str] = None
    ) -> List[str]:
        """
        Get versions within a range.

        Args:
            versions: List of all versions
            start: Start version (inclusive)
            end: End version (inclusive)

        Returns:
            List of versions in range
        """
        sorted_versions = VersionComparator.sort_versions(versions)

        result = []
        in_range = start is None

        for version in sorted_versions:
            if start and version == start:
                in_range = True

            if in_range:
                result.append(version)

            if end and version == end:
                break

        return result

    @staticmethod
    def check_compatibility(v1: str, v2: str) -> bool:
        """
        Check if two versions are compatible.

        Args:
            v1: First version
            v2: Second version

        Returns:
            True if versions are compatible
        """
        version1 = VersionComparator.parse_version(v1)
        version2 = VersionComparator.parse_version(v2)

        return version1.is_compatible_with(version2)

    @staticmethod
    def calculate_distance(v1: str, v2: str) -> int:
        """
        Calculate distance between two versions.

        Args:
            v1: First version
            v2: Second version

        Returns:
            Distance metric between versions
        """
        version1 = VersionComparator.parse_version(v1)
        version2 = VersionComparator.parse_version(v2)

        return version1.distance_from(version2)

    @staticmethod
    def generate_next_version(current: str, bump_type: str = "patch") -> str:
        """
        Generate the next version based on bump type.

        Args:
            current: Current version string
            bump_type: Type of version bump (major, minor, patch)

        Returns:
            Next version string
        """
        version = VersionComparator.parse_version(current)

        # Handle timestamp-based versions
        if version.timestamp:
            # Generate new timestamp
            now = datetime.utcnow()
            return now.strftime("%Y%m%d_%H%M%S")

        # Handle semantic versions
        if bump_type == "major":
            new_major = version.major + 1
            new_minor = 0
            new_patch = 0
        elif bump_type == "minor":
            new_major = version.major
            new_minor = version.minor + 1
            new_patch = 0
        else:  # patch
            new_major = version.major
            new_minor = version.minor
            new_patch = version.patch + 1

        # Preserve 'v' prefix if present
        prefix = "v" if current.startswith("v") else ""

        return f"{prefix}{new_major}.{new_minor}.{new_patch}"

    @staticmethod
    def validate_version(version_string: str) -> Tuple[bool, Optional[str]]:
        """
        Validate a version string format.

        Args:
            version_string: Version string to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not version_string:
            return False, "Version string cannot be empty"

        # Check for valid patterns
        patterns = [
            (r"^v?\d+\.\d+\.\d+(-.*)?$", "Semantic versioning"),
            (r"^\d{8}_\d{6}$", "Timestamp format"),
            (r"^\d{4}-\d{2}-\d{2}_\d+$", "Date with sequence"),
        ]

        for pattern, name in patterns:
            if re.match(pattern, version_string):
                return True, None

        return False, f"Invalid version format: {version_string}"

    @staticmethod
    def get_migration_path(
        from_version: str, to_version: str, all_versions: List[str]
    ) -> List[str]:
        """
        Get the migration path between two versions.

        Args:
            from_version: Starting version
            to_version: Target version
            all_versions: List of all available versions

        Returns:
            Ordered list of versions to migrate through
        """
        # Get versions in range
        path_versions = VersionComparator.get_range(
            all_versions, start=from_version, end=to_version
        )

        # Remove the starting version (already applied)
        if path_versions and path_versions[0] == from_version:
            path_versions = path_versions[1:]

        return path_versions


class VersionManager:
    """Manages version lifecycle and operations."""

    def __init__(self):
        """Initialize version manager."""
        self.comparator = VersionComparator()

    def suggest_version(self, current_version: Optional[str], change_type: str = "patch") -> str:
        """
        Suggest a new version based on change type.

        Args:
            current_version: Current version or None for first version
            change_type: Type of change (major, minor, patch)

        Returns:
            Suggested version string
        """
        if not current_version:
            # First version
            if change_type == "timestamp":
                return datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            else:
                return "0.1.0"

        return VersionComparator.generate_next_version(current_version, change_type)

    def determine_bump_type(self, breaking_changes: bool) -> str:
        """
        Determine version bump type based on changes.

        Args:
            breaking_changes: Whether changes are breaking

        Returns:
            Bump type (major, minor, patch)
        """
        if breaking_changes:
            return "major"
        else:
            return "minor"

    def format_version_for_display(self, version: str) -> str:
        """
        Format version for user display.

        Args:
            version: Version string

        Returns:
            Formatted version string
        """
        parsed = VersionComparator.parse_version(version)

        if parsed.timestamp:
            return f"{version} ({parsed.timestamp.strftime('%Y-%m-%d %H:%M:%S')})"

        return version
