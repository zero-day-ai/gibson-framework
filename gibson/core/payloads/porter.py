"""Import/export functionality for payloads."""

import json
import tarfile
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import yaml
from pydantic import BaseModel, Field

from gibson.models.payload import PayloadModel
from gibson.models.domain import AttackDomain, Severity


class PayloadBundle(BaseModel):
    """Represents a bundle of payloads for import/export."""

    version: str = Field(default="1.0.0", description="Bundle format version")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    payloads: List[PayloadModel] = Field(default_factory=list)
    statistics: Dict[str, Any] = Field(default_factory=dict)


class ConflictStrategy(BaseModel):
    """Strategy for handling conflicts during import."""

    on_duplicate: str = Field(default="skip")  # skip, replace, merge
    on_newer: str = Field(default="replace")  # skip, replace, keep_both
    on_conflict: str = Field(default="prompt")  # prompt, skip, replace


class PayloadPorter:
    """Handles import and export of payload collections."""

    SUPPORTED_FORMATS = {"json", "yaml", "archive", "auto"}
    ARCHIVE_FORMATS = {".tar", ".tar.gz", ".tgz", ".tar.bz2"}

    def __init__(self, payload_dir: Path):
        """Initialize the porter.

        Args:
            payload_dir: Base directory for payloads
        """
        self.payload_dir = payload_dir

    async def export_payloads(
        self,
        payloads: List[PayloadModel],
        output_path: Path,
        format: str = "auto",
        include_metadata: bool = True,
        include_statistics: bool = True,
    ) -> Dict[str, Any]:
        """Export payloads to a file or archive.

        Args:
            payloads: List of payloads to export
            output_path: Path to output file
            format: Export format (json, yaml, archive, auto)
            include_metadata: Include metadata in export
            include_statistics: Include statistics in export

        Returns:
            Export summary
        """
        if format == "auto":
            format = self._detect_format(output_path)

        # Create bundle
        bundle = PayloadBundle(
            payloads=payloads,
            metadata=self._generate_metadata(payloads) if include_metadata else {},
            statistics=self._generate_statistics(payloads) if include_statistics else {},
        )

        # Export based on format
        if format == "archive":
            result = await self._export_archive(bundle, output_path)
        elif format == "json":
            result = await self._export_json(bundle, output_path)
        elif format == "yaml":
            result = await self._export_yaml(bundle, output_path)
        else:
            raise ValueError(f"Unsupported format: {format}")

        return {
            "format": format,
            "path": str(output_path),
            "payloads_exported": len(payloads),
            "size_bytes": output_path.stat().st_size if output_path.exists() else 0,
            **result,
        }

    async def import_payloads(
        self,
        input_path: Path,
        format: str = "auto",
        strategy: Optional[ConflictStrategy] = None,
        domains: Optional[Set[AttackDomain]] = None,
    ) -> Dict[str, Any]:
        """Import payloads from a file or archive.

        Args:
            input_path: Path to input file
            format: Import format (json, yaml, archive, auto)
            strategy: Conflict resolution strategy
            domains: Filter to specific domains

        Returns:
            Import summary
        """
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")

        if format == "auto":
            format = self._detect_format(input_path)

        strategy = strategy or ConflictStrategy()

        # Import based on format
        if format == "archive":
            bundle = await self._import_archive(input_path)
        elif format == "json":
            bundle = await self._import_json(input_path)
        elif format == "yaml":
            bundle = await self._import_yaml(input_path)
        else:
            # Try to detect common formats
            bundle = await self._import_auto_detect(input_path)

        # Filter by domains if specified
        if domains:
            bundle.payloads = [p for p in bundle.payloads if p.domain in domains]

        # Process imports with conflict resolution
        results = await self._process_imports(bundle.payloads, strategy)

        return {
            "format": format,
            "path": str(input_path),
            "bundle_version": bundle.version,
            "total_in_bundle": len(bundle.payloads),
            **results,
        }

    async def _export_archive(self, bundle: PayloadBundle, output_path: Path) -> Dict[str, Any]:
        """Export as compressed archive."""
        compression = (
            "gz" if output_path.suffix == ".gz" else "bz2" if output_path.suffix == ".bz2" else None
        )
        mode = f"w:{compression}" if compression else "w"

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            # Write metadata
            metadata_file = tmpdir_path / "metadata.json"
            metadata_file.write_text(
                json.dumps(
                    {
                        "version": bundle.version,
                        "created_at": bundle.created_at.isoformat(),
                        "metadata": bundle.metadata,
                        "statistics": bundle.statistics,
                    },
                    indent=2,
                )
            )

            # Organize payloads by domain and attack type
            for payload in bundle.payloads:
                payload_dir = tmpdir_path / "payloads" / payload.domain.value / payload.attack_type
                payload_dir.mkdir(parents=True, exist_ok=True)

                payload_file = payload_dir / f"{payload.id}.yaml"
                payload_file.write_text(yaml.dump(payload.model_dump(), default_flow_style=False))

            # Create archive
            with tarfile.open(output_path, mode) as tar:
                tar.add(tmpdir_path, arcname="payload_bundle")

        return {"compression": compression or "none", "files_included": len(bundle.payloads) + 1}

    async def _export_json(self, bundle: PayloadBundle, output_path: Path) -> Dict[str, Any]:
        """Export as JSON file."""
        output_path.write_text(bundle.model_dump_json(indent=2))
        return {"format_details": "JSON with 2-space indentation"}

    async def _export_yaml(self, bundle: PayloadBundle, output_path: Path) -> Dict[str, Any]:
        """Export as YAML file."""
        output_path.write_text(yaml.dump(bundle.model_dump(), default_flow_style=False))
        return {"format_details": "YAML with block style"}

    async def _import_archive(self, input_path: Path) -> PayloadBundle:
        """Import from compressed archive."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            # Extract archive
            with tarfile.open(input_path, "r:*") as tar:
                tar.extractall(tmpdir_path)

            # Find bundle root
            bundle_root = tmpdir_path / "payload_bundle"
            if not bundle_root.exists():
                bundle_root = tmpdir_path

            # Load metadata
            metadata_file = bundle_root / "metadata.json"
            if metadata_file.exists():
                metadata = json.loads(metadata_file.read_text())
            else:
                metadata = {}

            # Load payloads
            payloads = []
            payloads_dir = bundle_root / "payloads"
            if payloads_dir.exists():
                for yaml_file in payloads_dir.rglob("*.yaml"):
                    payload_data = yaml.safe_load(yaml_file.read_text())
                    payloads.append(Payload(**payload_data))

            return PayloadBundle(
                version=metadata.get("version", "1.0.0"),
                created_at=datetime.fromisoformat(metadata["created_at"])
                if "created_at" in metadata
                else datetime.utcnow(),
                metadata=metadata.get("metadata", {}),
                statistics=metadata.get("statistics", {}),
                payloads=payloads,
            )

    async def _import_json(self, input_path: Path) -> PayloadBundle:
        """Import from JSON file."""
        data = json.loads(input_path.read_text())
        return PayloadBundle(**data)

    async def _import_yaml(self, input_path: Path) -> PayloadBundle:
        """Import from YAML file."""
        data = yaml.safe_load(input_path.read_text())
        return PayloadBundle(**data)

    async def _import_auto_detect(self, input_path: Path) -> PayloadBundle:
        """Auto-detect format and import."""
        content = input_path.read_text()

        # Try JSON first
        try:
            data = json.loads(content)
            return PayloadBundle(**data)
        except (json.JSONDecodeError, ValueError):
            pass

        # Try YAML
        try:
            data = yaml.safe_load(content)
            return PayloadBundle(**data)
        except yaml.YAMLError:
            pass

        # Try as single payload
        try:
            # Could be a single payload file
            if content.startswith("{") or content.startswith("payload:"):
                # Try to parse as single payload
                try:
                    payload_data = (
                        json.loads(content) if content.startswith("{") else yaml.safe_load(content)
                    )
                    payload = Payload(**payload_data)
                    return PayloadBundle(payloads=[payload])
                except Exception:
                    pass
        except Exception:
            pass

        raise ValueError(f"Unable to detect format for: {input_path}")

    async def _process_imports(
        self, payloads: List[PayloadModel], strategy: ConflictStrategy
    ) -> Dict[str, Any]:
        """Process payload imports with conflict resolution."""
        imported = []
        skipped = []
        replaced = []
        errors = []

        for payload in payloads:
            try:
                # Check for existing payload
                existing_path = self._get_payload_path(payload)

                if existing_path.exists():
                    # Handle conflict
                    if strategy.on_duplicate == "skip":
                        skipped.append(payload.id)
                        continue
                    elif strategy.on_duplicate == "replace":
                        replaced.append(payload.id)
                    elif strategy.on_duplicate == "merge":
                        # Merge logic would go here
                        pass

                # Save payload
                await self._save_payload(payload)
                imported.append(payload.id)

            except Exception as e:
                errors.append({"payload_id": payload.id, "error": str(e)})

        return {
            "imported": len(imported),
            "skipped": len(skipped),
            "replaced": len(replaced),
            "errors": len(errors),
            "imported_ids": imported,
            "skipped_ids": skipped,
            "replaced_ids": replaced,
            "error_details": errors,
        }

    def _detect_format(self, path: Path) -> str:
        """Detect format from file extension."""
        suffix = path.suffix.lower()

        if (
            suffix in {".tar", ".tgz"}
            or path.name.endswith(".tar.gz")
            or path.name.endswith(".tar.bz2")
        ):
            return "archive"
        elif suffix == ".json":
            return "json"
        elif suffix in {".yaml", ".yml"}:
            return "yaml"
        else:
            return "auto"

    def _generate_metadata(self, payloads: List[PayloadModel]) -> Dict[str, Any]:
        """Generate metadata for payload bundle."""
        domains = {}
        severities = {}
        sources = {}

        for payload in payloads:
            # Count by domain
            domain_key = payload.domain.value
            domains[domain_key] = domains.get(domain_key, 0) + 1

            # Count by severity
            severity_key = payload.severity.value
            severities[severity_key] = severities.get(severity_key, 0) + 1

            # Count by source repository
            source_key = payload.source_repo or "unknown"
            sources[source_key] = sources.get(source_key, 0) + 1

        return {
            "total_payloads": len(payloads),
            "domains": domains,
            "severities": severities,
            "sources": sources,
            "attack_types": len(set(p.attack_type for p in payloads)),
        }

    def _generate_statistics(self, payloads: List[PayloadModel]) -> Dict[str, Any]:
        """Generate statistics for payload bundle."""
        total_size = sum(len(p.content) for p in payloads)
        avg_size = total_size / len(payloads) if payloads else 0

        # Get unique tags
        all_tags = set()
        for payload in payloads:
            if payload.tags:
                all_tags.update(payload.tags)

        return {
            "total_content_size": total_size,
            "average_payload_size": avg_size,
            "unique_tags": len(all_tags),
            "has_documentation": sum(1 for p in payloads if p.documentation),
            "has_references": sum(1 for p in payloads if p.references),
        }

    def _get_payload_path(self, payload: PayloadModel) -> Path:
        """Get the file path for a payload."""
        return self.payload_dir / payload.domain.value / payload.attack_type / f"{payload.id}.yaml"

    async def _save_payload(self, payload: PayloadModel) -> None:
        """Save a payload to the filesystem."""
        path = self._get_payload_path(payload)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml.dump(payload.model_dump(), default_flow_style=False))
