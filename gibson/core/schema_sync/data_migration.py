"""
Data migration planning for breaking schema changes.
"""

from typing import Dict, List, Optional
from loguru import logger

from gibson.core.schema_sync.models import BreakingChange, DataMigration


class DataMigrationPlanner:
    """Plans data migrations for breaking schema changes."""
    
    def __init__(self, database_session=None):
        """
        Initialize the data migration planner.
        
        Args:
            database_session: Optional database session for data analysis
        """
        self.database_session = database_session
    
    def plan_data_migration(
        self,
        breaking_changes: List[BreakingChange]
    ) -> List[DataMigration]:
        """
        Plan data migrations for breaking changes.
        
        Args:
            breaking_changes: List of breaking changes requiring data migration
            
        Returns:
            List of DataMigration steps
        """
        logger.info(f"Planning data migration for {len(breaking_changes)} breaking changes")
        
        migrations = []
        step_number = 1
        
        for change in breaking_changes:
            if change.data_transformation_required:
                migration = self._create_migration_for_change(change, step_number)
                if migration:
                    migrations.append(migration)
                    step_number += 1
        
        logger.info(f"Created {len(migrations)} data migration steps")
        return migrations
    
    def generate_transformation_script(
        self,
        migrations: List[DataMigration]
    ) -> str:
        """
        Generate complete transformation script from migrations.
        
        Args:
            migrations: List of data migrations
            
        Returns:
            SQL script as string
        """
        script_lines = [
            "-- Data Migration Script",
            f"-- Generated at: {__import__('datetime').datetime.utcnow()}",
            "-- WARNING: Review carefully before execution",
            "",
            "BEGIN TRANSACTION;",
            "",
        ]
        
        for migration in migrations:
            script_lines.append(f"-- Step {migration.step_number}: {migration.description}")
            
            # Add validation query as comment
            if migration.validation_query:
                script_lines.append(f"-- Pre-check: {migration.validation_query}")
            
            # Add SQL statements
            for sql in migration.sql_statements:
                script_lines.append(sql)
            
            script_lines.append("")
        
        script_lines.extend([
            "-- Verify all migrations completed successfully before committing",
            "-- ROLLBACK; -- Uncomment to rollback",
            "COMMIT;",
        ])
        
        return "\n".join(script_lines)
    
    def _create_migration_for_change(
        self,
        change: BreakingChange,
        step_number: int
    ) -> Optional[DataMigration]:
        """Create a data migration for a specific breaking change."""
        
        if change.change_type == "field_removed":
            # Archive data before removal
            return DataMigration(
                step_number=step_number,
                description=f"Archive data from {change.affected_column} before removal",
                sql_statements=[
                    f"-- Create archive table",
                    f"CREATE TABLE IF NOT EXISTS payloads_{change.affected_column}_archive AS "
                    f"SELECT id, {change.affected_column}, NOW() as archived_at "
                    f"FROM payloads WHERE {change.affected_column} IS NOT NULL;",
                ],
                validation_query=f"SELECT COUNT(*) FROM payloads_{change.affected_column}_archive;",
                rollback_statements=[
                    f"DROP TABLE IF EXISTS payloads_{change.affected_column}_archive;"
                ],
            )
        
        elif change.change_type == "nullable_to_required":
            # Update NULL values
            return DataMigration(
                step_number=step_number,
                description=f"Update NULL values in {change.affected_column}",
                sql_statements=[
                    f"UPDATE payloads "
                    f"SET {change.affected_column} = '' "
                    f"WHERE {change.affected_column} IS NULL;",
                ],
                validation_query=f"SELECT COUNT(*) FROM payloads WHERE {change.affected_column} IS NULL;",
                rollback_statements=[],
            )
        
        elif change.change_type == "type_changed":
            # Type conversion (simplified)
            return DataMigration(
                step_number=step_number,
                description=f"Convert data type for {change.affected_column}",
                sql_statements=[
                    f"-- Type conversion for {change.affected_column}",
                    f"-- Manual review required for safe conversion",
                ],
                validation_query=None,
                rollback_statements=[],
            )
        
        elif change.change_type == "enum_values_removed":
            # Update enum values
            return DataMigration(
                step_number=step_number,
                description=f"Migrate removed enum values for {change.affected_column}",
                sql_statements=[
                    f"-- Update records with removed enum values",
                    f"-- UPDATE payloads SET {change.affected_column} = 'new_value' "
                    f"WHERE {change.affected_column} IN (removed_values);",
                ],
                validation_query=f"SELECT DISTINCT {change.affected_column} FROM payloads;",
                rollback_statements=[],
            )
        
        return None