"""Comprehensive database schema analyzer for Gibson Framework.

This module provides detailed analysis of database schema vs SQLAlchemy models,
identifying mismatches, missing columns, type differences, and index issues.
"""

import asyncio
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from enum import Enum

from loguru import logger
from pydantic import BaseModel, Field
from sqlalchemy import inspect, text, MetaData, Table
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.engine.reflection import Inspector
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.schema import Column, Index, ForeignKey
from sqlalchemy.types import (
    Integer, String, Text, Boolean, DateTime, JSON, Float, Enum as SQLEnum
)

from gibson.db.base import Base
from gibson.db.manager import DatabaseManager


class IssueType(str, Enum):
    """Types of schema issues."""
    MISSING_TABLE = "missing_table"
    EXTRA_TABLE = "extra_table"
    MISSING_COLUMN = "missing_column"
    EXTRA_COLUMN = "extra_column"
    TYPE_MISMATCH = "type_mismatch"
    MISSING_INDEX = "missing_index"
    EXTRA_INDEX = "extra_index"
    MISSING_FOREIGN_KEY = "missing_foreign_key"
    EXTRA_FOREIGN_KEY = "extra_foreign_key"
    CONSTRAINT_MISMATCH = "constraint_mismatch"


class SeverityLevel(str, Enum):
    """Severity levels for schema issues."""
    CRITICAL = "critical"  # Data loss or corruption risk
    HIGH = "high"      # Functionality broken
    MEDIUM = "medium"   # Feature degraded
    LOW = "low"        # Optimization opportunity
    INFO = "info"      # Informational only


class SchemaIssue(BaseModel):
    """Represents a single schema issue."""
    
    issue_type: IssueType = Field(description="Type of schema issue")
    severity: SeverityLevel = Field(description="Severity of the issue")
    table_name: str = Field(description="Affected table name")
    column_name: Optional[str] = Field(None, description="Affected column name")
    expected_value: Optional[str] = Field(None, description="Expected value from model")
    actual_value: Optional[str] = Field(None, description="Actual value in database")
    description: str = Field(description="Human-readable description of the issue")
    fix_suggestion: Optional[str] = Field(None, description="Suggested fix")
    migration_sql: Optional[str] = Field(None, description="SQL to fix the issue")


class TableAnalysis(BaseModel):
    """Analysis result for a single table."""
    
    table_name: str = Field(description="Name of the analyzed table")
    exists_in_db: bool = Field(description="Whether table exists in database")
    exists_in_models: bool = Field(description="Whether table is defined in models")
    column_count_expected: int = Field(description="Number of columns expected")
    column_count_actual: int = Field(description="Number of columns in database")
    issues: List[SchemaIssue] = Field(default_factory=list, description="Issues found")
    
    @property
    def has_issues(self) -> bool:
        """Check if table has any issues."""
        return len(self.issues) > 0
    
    @property
    def critical_issues(self) -> List[SchemaIssue]:
        """Get critical issues only."""
        return [issue for issue in self.issues if issue.severity == SeverityLevel.CRITICAL]


class SchemaAnalysisReport(BaseModel):
    """Complete schema analysis report."""
    
    analysis_timestamp: datetime = Field(default_factory=datetime.utcnow)
    database_type: str = Field(description="Database type (sqlite, postgresql, etc.)")
    total_tables_expected: int = Field(description="Total tables expected from models")
    total_tables_actual: int = Field(description="Total tables found in database")
    tables_analyzed: List[TableAnalysis] = Field(default_factory=list)
    global_issues: List[SchemaIssue] = Field(default_factory=list)
    
    @property
    def total_issues(self) -> int:
        """Total number of issues across all tables."""
        table_issues = sum(len(table.issues) for table in self.tables_analyzed)
        return table_issues + len(self.global_issues)
    
    @property
    def critical_issues(self) -> List[SchemaIssue]:
        """All critical issues."""
        issues = []
        for table in self.tables_analyzed:
            issues.extend(table.critical_issues)
        issues.extend([issue for issue in self.global_issues 
                      if issue.severity == SeverityLevel.CRITICAL])
        return issues
    
    @property
    def is_healthy(self) -> bool:
        """Check if schema is considered healthy."""
        return len(self.critical_issues) == 0
    
    def get_issues_by_severity(self, severity: SeverityLevel) -> List[SchemaIssue]:
        """Get all issues of a specific severity."""
        issues = []
        for table in self.tables_analyzed:
            issues.extend([issue for issue in table.issues if issue.severity == severity])
        issues.extend([issue for issue in self.global_issues if issue.severity == severity])
        return issues


class SchemaAnalyzer:
    """Comprehensive database schema analyzer."""
    
    def __init__(self, base: Optional[DeclarativeBase] = None) -> None:
        """Initialize schema analyzer.
        
        Args:
            base: SQLAlchemy declarative base to analyze against
        """
        self.base = base or Base
        self.logger = logger.bind(component="schema_analyzer")
        
    async def analyze_schema(self, session: AsyncSession) -> SchemaAnalysisReport:
        """Perform comprehensive schema analysis.
        
        Args:
            session: Database session for analysis
            
        Returns:
            Complete analysis report
        """
        self.logger.info("Starting comprehensive schema analysis")
        
        # Determine database type
        db_type = self._get_database_type(session)
        
        # Get expected and actual tables
        expected_tables = self._get_expected_tables()
        actual_tables = await self._get_actual_tables(session)
        
        # Create report
        report = SchemaAnalysisReport(
            database_type=db_type,
            total_tables_expected=len(expected_tables),
            total_tables_actual=len(actual_tables)
        )
        
        # Analyze each expected table
        for table_name in expected_tables:
            table_analysis = await self._analyze_table(
                session, table_name, table_name in actual_tables
            )
            report.tables_analyzed.append(table_analysis)
        
        # Check for extra tables in database
        extra_tables = set(actual_tables) - set(expected_tables)
        for extra_table in extra_tables:
            issue = SchemaIssue(
                issue_type=IssueType.EXTRA_TABLE,
                severity=SeverityLevel.LOW,
                table_name=extra_table,
                description=f"Table '{extra_table}' exists in database but not in models",
                fix_suggestion="Remove table if not needed or add corresponding model"
            )
            report.global_issues.append(issue)
        
        self.logger.info(
            f"Schema analysis complete: {report.total_issues} issues found "
            f"({len(report.critical_issues)} critical)"
        )
        
        return report
    
    async def _analyze_table(
        self, session: AsyncSession, table_name: str, exists_in_db: bool
    ) -> TableAnalysis:
        """Analyze a single table.
        
        Args:
            session: Database session
            table_name: Name of table to analyze
            exists_in_db: Whether table exists in database
            
        Returns:
            Table analysis result
        """
        self.logger.debug(f"Analyzing table: {table_name}")
        
        # Get model table definition
        model_table = self.base.metadata.tables.get(table_name)
        if model_table is None:
            # This shouldn't happen if we're iterating expected tables correctly
            return TableAnalysis(
                table_name=table_name,
                exists_in_db=exists_in_db,
                exists_in_models=False,
                column_count_expected=0,
                column_count_actual=0
            )
        
        analysis = TableAnalysis(
            table_name=table_name,
            exists_in_db=exists_in_db,
            exists_in_models=True,
            column_count_expected=len(model_table.columns),
            column_count_actual=0  # Will be updated below if table exists
        )
        
        if not exists_in_db:
            # Table missing entirely
            analysis.issues.append(SchemaIssue(
                issue_type=IssueType.MISSING_TABLE,
                severity=SeverityLevel.CRITICAL,
                table_name=table_name,
                description=f"Table '{table_name}' is defined in models but missing from database",
                fix_suggestion="Create table by running migrations or using create_all()",
                migration_sql=self._generate_create_table_sql(model_table)
            ))
            return analysis
        
        # Get actual table structure
        db_columns = await self._get_table_columns(session, table_name)
        analysis.column_count_actual = len(db_columns)
        
        # Analyze columns
        await self._analyze_table_columns(analysis, model_table, db_columns)
        
        # Analyze indexes
        await self._analyze_table_indexes(session, analysis, model_table)
        
        # Analyze foreign keys
        await self._analyze_table_foreign_keys(session, analysis, model_table)
        
        return analysis
    
    async def _analyze_table_columns(
        self, analysis: TableAnalysis, model_table: Table, db_columns: Dict[str, Dict]
    ) -> None:
        """Analyze column differences.
        
        Args:
            analysis: Table analysis to update
            model_table: SQLAlchemy model table
            db_columns: Actual database columns
        """
        model_columns = {col.name: col for col in model_table.columns}
        
        # Check for missing columns
        for col_name, model_col in model_columns.items():
            if col_name not in db_columns:
                severity = SeverityLevel.CRITICAL if not model_col.nullable else SeverityLevel.HIGH
                
                analysis.issues.append(SchemaIssue(
                    issue_type=IssueType.MISSING_COLUMN,
                    severity=severity,
                    table_name=analysis.table_name,
                    column_name=col_name,
                    expected_value=str(model_col.type),
                    description=f"Column '{col_name}' missing from table '{analysis.table_name}'",
                    fix_suggestion=f"Add column with type {model_col.type}",
                    migration_sql=self._generate_add_column_sql(
                        analysis.table_name, col_name, model_col
                    )
                ))
            else:
                # Check column type compatibility
                db_col = db_columns[col_name]
                type_issue = self._check_type_compatibility(model_col, db_col)
                if type_issue:
                    analysis.issues.append(SchemaIssue(
                        issue_type=IssueType.TYPE_MISMATCH,
                        severity=SeverityLevel.MEDIUM,
                        table_name=analysis.table_name,
                        column_name=col_name,
                        expected_value=str(model_col.type),
                        actual_value=db_col.get('type', 'unknown'),
                        description=type_issue,
                        fix_suggestion=f"Update column type to match model: {model_col.type}"
                    ))
        
        # Check for extra columns
        for col_name in db_columns:
            if col_name not in model_columns:
                analysis.issues.append(SchemaIssue(
                    issue_type=IssueType.EXTRA_COLUMN,
                    severity=SeverityLevel.LOW,
                    table_name=analysis.table_name,
                    column_name=col_name,
                    actual_value=db_columns[col_name].get('type', 'unknown'),
                    description=f"Column '{col_name}' exists in database but not in model",
                    fix_suggestion="Remove column if not needed or add to model"
                ))
    
    async def _analyze_table_indexes(
        self, session: AsyncSession, analysis: TableAnalysis, model_table: Table
    ) -> None:
        """Analyze index differences.
        
        Args:
            session: Database session
            analysis: Table analysis to update
            model_table: SQLAlchemy model table
        """
        try:
            # Get indexes from model
            model_indexes = {idx.name: idx for idx in model_table.indexes if idx.name}
            
            # Get actual indexes from database
            db_indexes = await self._get_table_indexes(session, analysis.table_name)
            
            # Check for missing indexes
            for idx_name, model_idx in model_indexes.items():
                if idx_name not in db_indexes:
                    analysis.issues.append(SchemaIssue(
                        issue_type=IssueType.MISSING_INDEX,
                        severity=SeverityLevel.MEDIUM,
                        table_name=analysis.table_name,
                        expected_value=f"Index on {[col.name for col in model_idx.columns]}",
                        description=f"Index '{idx_name}' missing from table '{analysis.table_name}'",
                        fix_suggestion=f"Create index on columns: {[col.name for col in model_idx.columns]}"
                    ))
            
            # Check for extra indexes (excluding primary key and unique constraints)
            for idx_name in db_indexes:
                if idx_name not in model_indexes and not idx_name.startswith(('pk_', 'uq_')):
                    analysis.issues.append(SchemaIssue(
                        issue_type=IssueType.EXTRA_INDEX,
                        severity=SeverityLevel.LOW,
                        table_name=analysis.table_name,
                        actual_value=idx_name,
                        description=f"Index '{idx_name}' exists but not defined in model",
                        fix_suggestion="Remove index if not needed or add to model"
                    ))
                    
        except Exception as e:
            self.logger.debug(f"Could not analyze indexes for {analysis.table_name}: {e}")
    
    async def _analyze_table_foreign_keys(
        self, session: AsyncSession, analysis: TableAnalysis, model_table: Table
    ) -> None:
        """Analyze foreign key differences.
        
        Args:
            session: Database session
            analysis: Table analysis to update
            model_table: SQLAlchemy model table
        """
        try:
            # Get foreign keys from model
            model_fks = {fk.name: fk for fk in model_table.foreign_keys if fk.name}
            
            # Get actual foreign keys from database
            db_fks = await self._get_table_foreign_keys(session, analysis.table_name)
            
            # Check for missing foreign keys
            for fk_name, model_fk in model_fks.items():
                if fk_name not in db_fks:
                    analysis.issues.append(SchemaIssue(
                        issue_type=IssueType.MISSING_FOREIGN_KEY,
                        severity=SeverityLevel.HIGH,
                        table_name=analysis.table_name,
                        column_name=model_fk.column.name,
                        expected_value=f"References {model_fk.column.table.name}({model_fk.column.name})",
                        description=f"Foreign key '{fk_name}' missing from table '{analysis.table_name}'",
                        fix_suggestion=f"Add foreign key constraint"
                    ))
            
            # Check for extra foreign keys
            for fk_name in db_fks:
                if fk_name not in model_fks:
                    analysis.issues.append(SchemaIssue(
                        issue_type=IssueType.EXTRA_FOREIGN_KEY,
                        severity=SeverityLevel.LOW,
                        table_name=analysis.table_name,
                        actual_value=fk_name,
                        description=f"Foreign key '{fk_name}' exists but not defined in model",
                        fix_suggestion="Remove foreign key if not needed or add to model"
                    ))
                    
        except Exception as e:
            self.logger.debug(f"Could not analyze foreign keys for {analysis.table_name}: {e}")
    
    def _get_database_type(self, session: AsyncSession) -> str:
        """Determine database type from session.
        
        Args:
            session: Database session
            
        Returns:
            Database type string
        """
        try:
            dialect_name = session.bind.dialect.name
            return dialect_name.lower()
        except Exception:
            return "unknown"
    
    def _get_expected_tables(self) -> List[str]:
        """Get list of expected table names from models.
        
        Returns:
            List of expected table names
        """
        return sorted(list(self.base.metadata.tables.keys()))
    
    async def _get_actual_tables(self, session: AsyncSession) -> List[str]:
        """Get list of actual tables in database.
        
        Args:
            session: Database session
            
        Returns:
            List of actual table names
        """
        try:
            # Try SQLite first (most common in development)
            query = text(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
            result = await session.execute(query)
            tables = [row[0] for row in result.fetchall()]
            
            # Filter out system tables
            tables = [t for t in tables if t not in ('alembic_version',)]
            return sorted(tables)
            
        except Exception:
            # Try PostgreSQL
            try:
                query = text(
                    "SELECT tablename FROM pg_tables WHERE schemaname='public'"
                )
                result = await session.execute(query)
                tables = [row[0] for row in result.fetchall()]
                return sorted(tables)
            except Exception as e:
                self.logger.error(f"Could not retrieve table list: {e}")
                return []
    
    async def _get_table_columns(self, session: AsyncSession, table_name: str) -> Dict[str, Dict]:
        """Get column information for a table.
        
        Args:
            session: Database session
            table_name: Name of table
            
        Returns:
            Dictionary of column information
        """
        columns = {}
        try:
            # SQLite PRAGMA query
            query = text(f"PRAGMA table_info({table_name})")
            result = await session.execute(query)
            
            for row in result.fetchall():
                col_name = row[1]  # Column name
                col_type = row[2]  # Column type
                not_null = row[3]  # NOT NULL flag
                default_val = row[4]  # Default value
                is_pk = row[5]  # Primary key flag
                
                columns[col_name] = {
                    'type': col_type,
                    'nullable': not not_null,
                    'default': default_val,
                    'primary_key': bool(is_pk)
                }
                
        except Exception as e:
            self.logger.debug(f"Could not get column info for {table_name}: {e}")
            
        return columns
    
    async def _get_table_indexes(self, session: AsyncSession, table_name: str) -> Dict[str, Dict]:
        """Get index information for a table.
        
        Args:
            session: Database session
            table_name: Name of table
            
        Returns:
            Dictionary of index information
        """
        indexes = {}
        try:
            # SQLite index query
            query = text(f"PRAGMA index_list({table_name})")
            result = await session.execute(query)
            
            for row in result.fetchall():
                idx_name = row[1]
                is_unique = row[2]
                
                indexes[idx_name] = {
                    'unique': bool(is_unique),
                    'columns': []  # Could be populated with additional query
                }
                
        except Exception as e:
            self.logger.debug(f"Could not get index info for {table_name}: {e}")
            
        return indexes
    
    async def _get_table_foreign_keys(
        self, session: AsyncSession, table_name: str
    ) -> Dict[str, Dict]:
        """Get foreign key information for a table.
        
        Args:
            session: Database session
            table_name: Name of table
            
        Returns:
            Dictionary of foreign key information
        """
        foreign_keys = {}
        try:
            # SQLite foreign key query
            query = text(f"PRAGMA foreign_key_list({table_name})")
            result = await session.execute(query)
            
            for row in result.fetchall():
                fk_id = row[0]
                from_col = row[3]
                to_table = row[2]
                to_col = row[4]
                
                fk_name = f"fk_{table_name}_{from_col}_{to_table}_{to_col}"
                foreign_keys[fk_name] = {
                    'from_column': from_col,
                    'to_table': to_table,
                    'to_column': to_col
                }
                
        except Exception as e:
            self.logger.debug(f"Could not get foreign key info for {table_name}: {e}")
            
        return foreign_keys
    
    def _check_type_compatibility(
        self, model_col: Column, db_col_info: Dict[str, Any]
    ) -> Optional[str]:
        """Check if model column type matches database column type.
        
        Args:
            model_col: SQLAlchemy model column
            db_col_info: Database column information
            
        Returns:
            Error message if incompatible, None if compatible
        """
        model_type = model_col.type
        db_type = db_col_info.get('type', '').upper()
        
        # Basic type mapping for SQLite
        type_mappings = {
            'INTEGER': [Integer],
            'TEXT': [String, Text],
            'REAL': [Float],
            'BLOB': [],
            'NUMERIC': [Integer, Float],
            'VARCHAR': [String],
            'BOOLEAN': [Boolean],
            'DATETIME': [DateTime],
            'JSON': [JSON]
        }
        
        # Check if types are compatible
        compatible_types = type_mappings.get(db_type, [])
        if compatible_types and not any(isinstance(model_type, t) for t in compatible_types):
            return f"Type mismatch: model expects {type(model_type).__name__}, database has {db_type}"
        
        return None
    
    def _generate_create_table_sql(self, table: Table) -> str:
        """Generate CREATE TABLE SQL for missing table.
        
        Args:
            table: SQLAlchemy table definition
            
        Returns:
            CREATE TABLE SQL statement
        """
        # This is a simplified version - in production you'd use proper DDL generation
        columns = []
        for col in table.columns:
            col_def = f"{col.name} {col.type}"
            if not col.nullable:
                col_def += " NOT NULL"
            if col.primary_key:
                col_def += " PRIMARY KEY"
            columns.append(col_def)
        
        # Use separate variables to avoid f-string backslash issue
        newline = "\n"
        column_sep = ",\n  "
        return f"CREATE TABLE {table.name} ({newline}  {column_sep.join(columns)}{newline});"
    
    def _generate_add_column_sql(self, table_name: str, col_name: str, column: Column) -> str:
        """Generate ALTER TABLE ADD COLUMN SQL.
        
        Args:
            table_name: Name of table
            col_name: Name of column to add
            column: SQLAlchemy column definition
            
        Returns:
            ALTER TABLE SQL statement
        """
        col_def = f"{col_name} {column.type}"
        if not column.nullable:
            col_def += " NOT NULL"
        if column.default is not None:
            col_def += f" DEFAULT {column.default}"
            
        return f"ALTER TABLE {table_name} ADD COLUMN {col_def};"


# Convenience functions
async def analyze_database_schema(
    database_url: str, base: Optional[DeclarativeBase] = None
) -> SchemaAnalysisReport:
    """Analyze database schema using database URL.
    
    Args:
        database_url: Database connection URL
        base: Optional SQLAlchemy base to analyze against
        
    Returns:
        Complete schema analysis report
    """
    db_manager = DatabaseManager(database_url, validate_on_init=False)
    
    async with db_manager.get_session() as session:
        analyzer = SchemaAnalyzer(base)
        return await analyzer.analyze_schema(session)


async def get_schema_issues(
    session: AsyncSession, base: Optional[DeclarativeBase] = None
) -> List[SchemaIssue]:
    """Get all schema issues.
    
    Args:
        session: Database session
        base: Optional SQLAlchemy base to analyze against
        
    Returns:
        List of all schema issues
    """
    analyzer = SchemaAnalyzer(base)
    report = await analyzer.analyze_schema(session)
    
    all_issues = []
    for table in report.tables_analyzed:
        all_issues.extend(table.issues)
    all_issues.extend(report.global_issues)
    
    return all_issues


async def get_critical_schema_issues(
    session: AsyncSession, base: Optional[DeclarativeBase] = None
) -> List[SchemaIssue]:
    """Get critical schema issues only.
    
    Args:
        session: Database session
        base: Optional SQLAlchemy base to analyze against
        
    Returns:
        List of critical schema issues
    """
    analyzer = SchemaAnalyzer(base)
    report = await analyzer.analyze_schema(session)
    return report.critical_issues


# Export all components
__all__ = [
    "SchemaAnalyzer",
    "SchemaAnalysisReport",
    "TableAnalysis", 
    "SchemaIssue",
    "IssueType",
    "SeverityLevel",
    "analyze_database_schema",
    "get_schema_issues",
    "get_critical_schema_issues",
]
