"""
Alembic migration generator for schema changes.
"""

from datetime import datetime, timedelta
from typing import List, Optional
from loguru import logger
import hashlib

from gibson.core.schema_sync.models import (
    ChangeAnalysis,
    MigrationScript,
    DataMigration,
    RollbackPlan,
    MigrationStatus,
    FieldChangeType,
)


class AlembicMigrationGenerator:
    """Generates Alembic migration scripts from schema changes."""
    
    def __init__(self):
        """Initialize the migration generator."""
        pass
    
    def generate_migration(
        self,
        changes: ChangeAnalysis,
        version: str,
        previous_revision: Optional[str] = None
    ) -> MigrationScript:
        """
        Generate Alembic migration script from change analysis.
        
        Args:
            changes: ChangeAnalysis containing schema changes
            version: Version string for this migration
            previous_revision: Previous migration revision ID
            
        Returns:
            MigrationScript ready for execution
        """
        logger.info(f"Generating migration for version {version}")
        
        # Generate revision ID
        revision_id = self._generate_revision_id(version)
        
        # Generate upgrade SQL
        upgrade_sql = self._generate_upgrade_sql(changes)
        
        # Generate downgrade SQL
        downgrade_sql = self._generate_downgrade_sql(changes)
        
        # Generate data migrations if needed
        data_migrations = self._generate_data_migrations(changes)
        
        # Generate pre and post checks
        pre_checks = self._generate_pre_checks(changes)
        post_checks = self._generate_post_checks(changes)
        
        # Create rollback plan
        rollback_plan = self.generate_rollback(changes)
        
        # Estimate duration
        estimated_duration = self._estimate_migration_duration(changes)
        
        migration = MigrationScript(
            revision_id=revision_id,
            description=f"Schema sync for version {version}",
            depends_on=previous_revision,
            upgrade_sql=upgrade_sql,
            downgrade_sql=downgrade_sql,
            data_migrations=data_migrations,
            pre_checks=pre_checks,
            post_checks=post_checks,
            estimated_duration=estimated_duration,
            rollback_plan=rollback_plan,
            metadata={
                "version": version,
                "generated_at": datetime.utcnow().isoformat(),
                "change_count": changes.changeset.change_count,
                "risk_level": changes.risk_level,
            }
        )
        
        logger.info(f"Generated migration {revision_id} with {migration.total_statements} statements")
        return migration
    
    def generate_rollback(self, changes: ChangeAnalysis) -> RollbackPlan:
        """
        Generate rollback plan for changes.
        
        Args:
            changes: ChangeAnalysis to create rollback for
            
        Returns:
            RollbackPlan with rollback instructions
        """
        rollback_statements = []
        warnings = []
        
        # Generate rollback for added fields (drop them)
        for field_name in changes.changeset.added_fields:
            rollback_statements.append(f"ALTER TABLE payloads DROP COLUMN {field_name};")
        
        # Generate rollback for removed fields (can't recreate without data)
        if changes.changeset.removed_fields:
            warnings.append("Removed fields cannot be restored without backup data")
            
        # Generate rollback for type changes
        for field_name, modification in changes.changeset.modified_fields.items():
            if modification.change_type == FieldChangeType.TYPE_CHANGED:
                # This is simplified - real implementation would need original type info
                warnings.append(f"Field {field_name} type change may not be fully reversible")
        
        # Determine if data backup is required
        compatibility_value = changes.compatibility.value if hasattr(changes.compatibility, 'value') else changes.compatibility
        data_backup_required = (
            len(changes.changeset.removed_fields) > 0 or
            compatibility_value in ["major_breaking", "data_loss"]
        )
        
        return RollbackPlan(
            can_rollback=len(changes.breaking_changes) == 0,
            rollback_statements=rollback_statements,
            data_backup_required=data_backup_required,
            warnings=warnings,
            estimated_rollback_duration=timedelta(minutes=5)  # Placeholder
        )
    
    def _generate_upgrade_sql(self, changes: ChangeAnalysis) -> List[str]:
        """Generate SQL statements for upgrade."""
        sql_statements = []
        
        # Add new columns
        for field_name, field_info in changes.changeset.added_fields.items():
            sql_type = self._pydantic_type_to_sql(field_info.type)
            nullable = "NULL" if field_info.nullable else "NOT NULL"
            default = f"DEFAULT {field_info.default}" if field_info.default is not None else ""
            
            sql = f"ALTER TABLE payloads ADD COLUMN {field_name} {sql_type} {nullable} {default};"
            sql_statements.append(sql.strip())
        
        # Drop removed columns
        for field_name in changes.changeset.removed_fields:
            sql_statements.append(f"ALTER TABLE payloads DROP COLUMN {field_name};")
        
        # Modify existing columns
        for field_name, modification in changes.changeset.modified_fields.items():
            if modification.change_type == FieldChangeType.TYPE_CHANGED:
                new_type = self._pydantic_type_to_sql(modification.new_value)
                sql_statements.append(
                    f"ALTER TABLE payloads ALTER COLUMN {field_name} TYPE {new_type};"
                )
            elif modification.change_type == FieldChangeType.NULLABLE_CHANGED:
                if modification.new_value:
                    sql_statements.append(
                        f"ALTER TABLE payloads ALTER COLUMN {field_name} DROP NOT NULL;"
                    )
                else:
                    sql_statements.append(
                        f"ALTER TABLE payloads ALTER COLUMN {field_name} SET NOT NULL;"
                    )
        
        # Add/drop constraints
        for constraint in changes.changeset.constraint_changes:
            if constraint.action == "add":
                if constraint.constraint_type == "unique":
                    sql_statements.append(
                        f"ALTER TABLE {constraint.table_name} "
                        f"ADD CONSTRAINT uk_{constraint.column_name} "
                        f"UNIQUE ({constraint.column_name});"
                    )
            elif constraint.action == "drop":
                if constraint.constraint_type == "unique":
                    sql_statements.append(
                        f"ALTER TABLE {constraint.table_name} "
                        f"DROP CONSTRAINT uk_{constraint.column_name};"
                    )
        
        return sql_statements
    
    def _generate_downgrade_sql(self, changes: ChangeAnalysis) -> List[str]:
        """Generate SQL statements for downgrade."""
        sql_statements = []
        
        # Reverse of upgrade: drop added columns
        for field_name in changes.changeset.added_fields:
            sql_statements.append(f"ALTER TABLE payloads DROP COLUMN {field_name};")
        
        # Note: Cannot restore removed columns without backup
        if changes.changeset.removed_fields:
            sql_statements.append(
                "-- WARNING: Removed columns cannot be restored without backup"
            )
        
        # Reverse type changes (simplified - would need original types)
        for field_name, modification in changes.changeset.modified_fields.items():
            if modification.change_type == FieldChangeType.TYPE_CHANGED:
                # This would need the original type stored
                sql_statements.append(
                    f"-- TODO: Restore original type for {field_name}"
                )
        
        return sql_statements
    
    def _generate_data_migrations(self, changes: ChangeAnalysis) -> List[DataMigration]:
        """Generate data migration steps if needed."""
        migrations = []
        step_number = 1
        
        # Handle nullable to non-nullable transitions
        for field_name, modification in changes.changeset.modified_fields.items():
            if (modification.change_type == FieldChangeType.NULLABLE_CHANGED and 
                modification.new_value is False):
                
                migration = DataMigration(
                    step_number=step_number,
                    description=f"Update NULL values in {field_name}",
                    sql_statements=[
                        f"UPDATE payloads SET {field_name} = '' WHERE {field_name} IS NULL;"
                    ],
                    validation_query=f"SELECT COUNT(*) FROM payloads WHERE {field_name} IS NULL;",
                    rollback_statements=[],
                    estimated_duration=timedelta(seconds=30)
                )
                migrations.append(migration)
                step_number += 1
        
        # Handle enum value changes
        for enum_name, enum_change in changes.changeset.enum_changes.items():
            if enum_change.removed_values:
                # Need to update records with removed values
                for old_value in enum_change.removed_values:
                    # This would need mapping logic for what to change to
                    migration = DataMigration(
                        step_number=step_number,
                        description=f"Migrate enum value '{old_value}' in {enum_name}",
                        sql_statements=[
                            f"-- UPDATE payloads SET {enum_name} = 'new_value' "
                            f"WHERE {enum_name} = '{old_value}';"
                        ],
                        validation_query=f"SELECT COUNT(*) FROM payloads WHERE {enum_name} = '{old_value}';",
                        estimated_duration=timedelta(seconds=10)
                    )
                    migrations.append(migration)
                    step_number += 1
        
        return migrations
    
    def _generate_pre_checks(self, changes: ChangeAnalysis) -> List[str]:
        """Generate pre-migration validation queries."""
        checks = []
        
        # Check for duplicate values before adding unique constraints
        for constraint in changes.changeset.constraint_changes:
            if constraint.constraint_type == "unique" and constraint.action == "add":
                checks.append(
                    f"SELECT {constraint.column_name}, COUNT(*) as cnt "
                    f"FROM {constraint.table_name} "
                    f"GROUP BY {constraint.column_name} "
                    f"HAVING COUNT(*) > 1;"
                )
        
        # Check for NULL values before making fields non-nullable
        for field_name, modification in changes.changeset.modified_fields.items():
            if (modification.change_type == FieldChangeType.NULLABLE_CHANGED and
                modification.new_value is False):
                checks.append(
                    f"SELECT COUNT(*) FROM payloads WHERE {field_name} IS NULL;"
                )
        
        return checks
    
    def _generate_post_checks(self, changes: ChangeAnalysis) -> List[str]:
        """Generate post-migration validation queries."""
        checks = []
        
        # Verify new columns exist
        for field_name in changes.changeset.added_fields:
            checks.append(
                f"SELECT column_name FROM information_schema.columns "
                f"WHERE table_name = 'payloads' AND column_name = '{field_name}';"
            )
        
        # Verify removed columns are gone
        for field_name in changes.changeset.removed_fields:
            checks.append(
                f"SELECT COUNT(*) FROM information_schema.columns "
                f"WHERE table_name = 'payloads' AND column_name = '{field_name}';"
            )
        
        return checks
    
    def _pydantic_type_to_sql(self, pydantic_type: str) -> str:
        """Convert Pydantic type to SQL type."""
        type_mapping = {
            "string": "VARCHAR(255)",
            "str": "VARCHAR(255)",
            "integer": "INTEGER",
            "int": "INTEGER",
            "float": "FLOAT",
            "number": "NUMERIC",
            "boolean": "BOOLEAN",
            "bool": "BOOLEAN",
            "array": "JSON",
            "list": "JSON",
            "dict": "JSON",
            "object": "JSON",
        }
        
        # Handle optional types
        if "Optional" in pydantic_type:
            # Extract the inner type
            inner_type = pydantic_type.replace("Optional[", "").replace("]", "")
            return type_mapping.get(inner_type.lower(), "TEXT")
        
        return type_mapping.get(pydantic_type.lower(), "TEXT")
    
    def _generate_revision_id(self, version: str) -> str:
        """Generate unique revision ID for migration."""
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        version_hash = hashlib.md5(version.encode()).hexdigest()[:8]
        return f"{timestamp}_{version_hash}"
    
    def _estimate_migration_duration(self, changes: ChangeAnalysis) -> timedelta:
        """Estimate how long the migration will take."""
        # Simple estimation based on change count
        # Real implementation would consider table size, index rebuilds, etc.
        base_time = 10  # seconds
        per_change_time = 2  # seconds per change
        
        total_seconds = base_time + (changes.changeset.change_count * per_change_time)
        
        # Add time for data migrations
        if changes.breaking_changes:
            total_seconds += len(changes.breaking_changes) * 30
        
        return timedelta(seconds=total_seconds)