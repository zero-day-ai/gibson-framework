"""Migration tool for reorganizing existing payloads."""

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml

from gibson.models.domain import AttackDomain


@dataclass
class MigrationPlan:
    """Plan for migrating payloads."""
    
    moves: List[Tuple[Path, Path]]  # (source, destination) pairs
    creates: List[Path]  # Directories to create
    deletes: List[Path]  # Files/directories to delete
    updates: List[Dict[str, Any]]  # Database updates needed


@dataclass
class MigrationResult:
    """Result of migration operation."""
    
    total_files: int
    moved: int
    created: int
    deleted: int
    errors: List[Dict[str, str]]
    database_updates: int


class PayloadMigrator:
    """Migrates existing payloads to new structure."""
    
    # Mapping of old paths to new domains
    DOMAIN_MAPPINGS = {
        "prompt_injection": Domain.PROMPTS,
        "prompts": Domain.PROMPTS,
        "data_poisoning": Domain.DATA,
        "data": Domain.DATA,
        "model_extraction": Domain.MODEL,
        "model": Domain.MODEL,
        "system_prompts": Domain.SYSTEM,
        "system": Domain.SYSTEM,
        "output_handling": Domain.OUTPUT,
        "output": Domain.OUTPUT,
    }
    
    # Known attack type mappings
    ATTACK_TYPE_MAPPINGS = {
        "direct-prompt-injection": "direct-injection",
        "indirect-prompt-injection": "indirect-injection",
        "prompt-leakage": "system-prompt-leakage",
        "data-poison": "poisoning",
        "model-steal": "extraction",
        "system-enum": "enumeration",
        "output-inject": "manipulation",
    }
    
    def __init__(self, old_dir: Path, new_dir: Path, database=None):
        """Initialize migrator.
        
        Args:
            old_dir: Directory with existing payloads
            new_dir: Target directory for new structure
            database: Optional PayloadDatabase for updating references
        """
        self.old_dir = old_dir
        self.new_dir = new_dir
        self.database = database
    
    async def analyze(self, dry_run: bool = True) -> MigrationPlan:
        """Analyze existing structure and create migration plan.
        
        Args:
            dry_run: If True, only analyze without making changes
            
        Returns:
            Migration plan
        """
        plan = MigrationPlan(moves=[], creates=[], deletes=[], updates=[])
        
        # Find all payload files
        payload_files = self._find_payload_files()
        
        for old_path in payload_files:
            # Determine new path
            new_path = self._determine_new_path(old_path)
            
            if new_path:
                # Add to moves
                plan.moves.append((old_path, new_path))
                
                # Add directory to create if needed
                new_dir = new_path.parent
                if new_dir not in plan.creates and not new_dir.exists():
                    plan.creates.append(new_dir)
                
                # Add database update if needed
                if self.database:
                    plan.updates.append(
                        {
                            "old_path": str(old_path.relative_to(self.old_dir)),
                            "new_path": str(new_path.relative_to(self.new_dir)),
                        }
                    )
        
        # Find empty directories to delete
        for dir_path in self._find_empty_directories():
            plan.deletes.append(dir_path)
        
        return plan
    
    async def migrate(self, plan: Optional[MigrationPlan] = None) -> MigrationResult:
        """Execute migration plan.
        
        Args:
            plan: Migration plan to execute (will analyze if not provided)
            
        Returns:
            Migration result
        """
        if not plan:
            plan = await self.analyze(dry_run=False)
        
        result = MigrationResult(
            total_files=len(plan.moves),
            moved=0,
            created=0,
            deleted=0,
            errors=[],
            database_updates=0,
        )
        
        # Create directories
        for dir_path in plan.creates:
            try:
                dir_path.mkdir(parents=True, exist_ok=True)
                result.created += 1
            except Exception as e:
                result.errors.append({"action": "create", "path": str(dir_path), "error": str(e)})
        
        # Move files
        for old_path, new_path in plan.moves:
            try:
                # Copy file content
                if old_path.exists():
                    new_path.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(old_path, new_path)
                    result.moved += 1
                    
                    # Optionally delete old file
                    # old_path.unlink()
            except Exception as e:
                result.errors.append(
                    {
                        "action": "move",
                        "from": str(old_path),
                        "to": str(new_path),
                        "error": str(e),
                    }
                )
        
        # Update database references
        if self.database and plan.updates:
            for update in plan.updates:
                try:
                    await self.database.update_file_path(
                        update["old_path"],
                        update["new_path"],
                    )
                    result.database_updates += 1
                except Exception as e:
                    result.errors.append(
                        {
                            "action": "db_update",
                            "old_path": update["old_path"],
                            "new_path": update["new_path"],
                            "error": str(e),
                        }
                    )
        
        # Delete empty directories
        for dir_path in plan.deletes:
            try:
                if dir_path.exists() and not any(dir_path.iterdir()):
                    dir_path.rmdir()
                    result.deleted += 1
            except Exception as e:
                result.errors.append({"action": "delete", "path": str(dir_path), "error": str(e)})
        
        return result
    
    async def reconcile(self) -> Dict[str, Any]:
        """Reconcile database with filesystem after migration.
        
        Returns:
            Reconciliation summary
        """
        if not self.database:
            return {"error": "No database configured"}
        
        fixed = []
        orphaned = []
        errors = []
        
        # Get all database records
        records = await self.database.list_all_references()
        
        for record in records:
            old_path = self.old_dir / record.file_path
            new_path = self.new_dir / record.file_path
            
            # Check if file exists at old location
            if old_path.exists() and not new_path.exists():
                # Need to determine correct new path
                correct_path = self._determine_new_path(old_path)
                if correct_path:
                    try:
                        await self.database.update_file_path(
                            record.file_path,
                            str(correct_path.relative_to(self.new_dir)),
                        )
                        fixed.append(record.file_path)
                    except Exception as e:
                        errors.append({"path": record.file_path, "error": str(e)})
                else:
                    orphaned.append(record.file_path)
            elif not old_path.exists() and not new_path.exists():
                orphaned.append(record.file_path)
        
        return {
            "total_records": len(records),
            "fixed": len(fixed),
            "orphaned": len(orphaned),
            "errors": len(errors),
            "fixed_paths": fixed,
            "orphaned_paths": orphaned,
            "error_details": errors,
        }
    
    def _find_payload_files(self) -> List[Path]:
        """Find all payload files in old directory."""
        payload_files = []
        
        # Common payload file patterns
        patterns = ["*.yaml", "*.yml", "*.json", "*.txt"]
        
        for pattern in patterns:
            payload_files.extend(self.old_dir.rglob(pattern))
        
        return payload_files
    
    def _determine_new_path(self, old_path: Path) -> Optional[Path]:
        """Determine new path for a payload file."""
        # Get relative path from old directory
        rel_path = old_path.relative_to(self.old_dir)
        parts = rel_path.parts
        
        if not parts:
            return None
        
        # Try to determine domain
        domain = None
        for part in parts:
            part_lower = part.lower()
            if part_lower in self.DOMAIN_MAPPINGS:
                domain = self.DOMAIN_MAPPINGS[part_lower]
                break
        
        # If no domain found, try to infer from content
        if not domain:
            domain = self._infer_domain_from_content(old_path)
        
        if not domain:
            # Default to prompts if can't determine
            domain = Domain.PROMPTS
        
        # Determine attack type
        attack_type = self._determine_attack_type(old_path, parts)
        
        # Determine filename
        filename = old_path.name
        
        # Build new path
        new_path = self.new_dir / domain.value / attack_type / filename
        
        return new_path
    
    def _infer_domain_from_content(self, file_path: Path) -> Optional[Domain]:
        """Infer domain from file content."""
        try:
            content = file_path.read_text().lower()
            
            # Simple heuristics
            if "prompt" in content or "injection" in content or "jailbreak" in content:
                return Domain.PROMPTS
            elif "data" in content or "poison" in content or "training" in content:
                return Domain.DATA
            elif "model" in content or "extraction" in content or "steal" in content:
                return Domain.MODEL
            elif "system" in content or "enumeration" in content or "command" in content:
                return Domain.SYSTEM
            elif "output" in content or "manipulation" in content or "steering" in content:
                return Domain.OUTPUT
        except Exception:
            pass
        
        return None
    
    def _determine_attack_type(self, file_path: Path, parts: Tuple[str, ...]) -> str:
        """Determine attack type from path or filename."""
        # Check parts for known attack types
        for part in parts:
            part_lower = part.lower().replace("_", "-")
            if part_lower in self.ATTACK_TYPE_MAPPINGS:
                return self.ATTACK_TYPE_MAPPINGS[part_lower]
            
            # Use part as-is if it looks like an attack type
            if "-" in part_lower or "_" in part.lower():
                return part_lower.replace("_", "-")
        
        # Check filename
        filename = file_path.stem.lower().replace("_", "-")
        if filename in self.ATTACK_TYPE_MAPPINGS:
            return self.ATTACK_TYPE_MAPPINGS[filename]
        
        # Try to infer from content
        attack_type = self._infer_attack_type_from_content(file_path)
        if attack_type:
            return attack_type
        
        # Default attack type based on domain
        return "general"
    
    def _infer_attack_type_from_content(self, file_path: Path) -> Optional[str]:
        """Infer attack type from file content."""
        try:
            content = file_path.read_text().lower()
            
            # Check for specific patterns
            if "system prompt" in content or "prompt leak" in content:
                return "system-prompt-leakage"
            elif "direct" in content and "injection" in content:
                return "direct-injection"
            elif "indirect" in content:
                return "indirect-injection"
            elif "jailbreak" in content:
                return "jailbreak"
            elif "poison" in content:
                return "poisoning"
            elif "extraction" in content or "steal" in content:
                return "extraction"
            elif "enumeration" in content:
                return "enumeration"
            elif "privilege" in content:
                return "privilege-escalation"
        except Exception:
            pass
        
        return None
    
    def _find_empty_directories(self) -> List[Path]:
        """Find directories that will be empty after migration."""
        empty_dirs = []
        
        for dir_path in self.old_dir.rglob("*"):
            if dir_path.is_dir():
                # Check if directory contains only directories (no files)
                has_files = any(f.is_file() for f in dir_path.iterdir())
                if not has_files:
                    empty_dirs.append(dir_path)
        
        # Sort in reverse order (deepest first) for safe deletion
        empty_dirs.sort(reverse=True)
        
        return empty_dirs