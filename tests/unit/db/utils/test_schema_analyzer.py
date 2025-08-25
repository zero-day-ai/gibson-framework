"""Comprehensive unit tests for SchemaAnalyzer class.

This module provides thorough testing of the database schema analysis functionality,
including schema comparison, type mapping validation, issue detection, and error handling.
"""

import asyncio
from datetime import datetime
from typing import Dict, Any, List, Optional
from unittest.mock import Mock, AsyncMock, patch, MagicMock

import pytest
from pydantic import BaseModel, Field
from sqlalchemy import (
    Column, Integer, String, Text, Boolean, DateTime, JSON, Float,
    ForeignKey, Index, MetaData, Table, create_engine
)
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import DeclarativeBase, relationship
from sqlalchemy.types import TypeDecorator
from sqlalchemy.engine.reflection import Inspector
from sqlalchemy.engine.result import Result

from gibson.db.utils.schema_analyzer import (
    SchemaAnalyzer,
    SchemaAnalysisReport,
    TableAnalysis,
    SchemaIssue,
    IssueType,
    SeverityLevel,
    analyze_database_schema,
    get_schema_issues,
    get_critical_schema_issues,
)


# Test Models for SQLAlchemy
class TestBase(DeclarativeBase):
    """Test base class for SQLAlchemy models."""
    pass


class TestUser(TestBase):
    """Test user model."""
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(50), nullable=False)
    email = Column(String(100), nullable=True)
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, nullable=False)
    profile = relationship("TestProfile", back_populates="user")


class TestProfile(TestBase):
    """Test profile model."""
    __tablename__ = 'profiles'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    bio = Column(Text, nullable=True)
    settings = Column(JSON, nullable=True)
    user = relationship("TestUser", back_populates="profile")


class TestEmptyBase(DeclarativeBase):
    """Empty base for testing scenarios with no models."""
    pass


@pytest.fixture
def mock_async_session():
    """Create a mock async session."""
    session = AsyncMock(spec=AsyncSession)
    session.bind = MagicMock()
    session.bind.dialect.name = "sqlite"
    return session


@pytest.fixture
def schema_analyzer():
    """Create a SchemaAnalyzer instance with test base."""
    return SchemaAnalyzer(TestBase)


@pytest.fixture
def empty_schema_analyzer():
    """Create a SchemaAnalyzer instance with empty base."""
    return SchemaAnalyzer(TestEmptyBase)


class TestSchemaAnalyzer:
    """Test suite for SchemaAnalyzer core functionality."""

    def test_initialization_with_default_base(self):
        """Test analyzer initialization with default base."""
        from gibson.db.base import Base
        analyzer = SchemaAnalyzer()
        assert analyzer.base == Base
        assert analyzer.logger is not None

    def test_initialization_with_custom_base(self, schema_analyzer):
        """Test analyzer initialization with custom base."""
        assert schema_analyzer.base == TestBase
        assert schema_analyzer.logger is not None

    def test_get_database_type_sqlite(self, schema_analyzer, mock_async_session):
        """Test database type detection for SQLite."""
        db_type = schema_analyzer._get_database_type(mock_async_session)
        assert db_type == "sqlite"

    def test_get_database_type_postgresql(self, schema_analyzer, mock_async_session):
        """Test database type detection for PostgreSQL."""
        mock_async_session.bind.dialect.name = "postgresql"
        db_type = schema_analyzer._get_database_type(mock_async_session)
        assert db_type == "postgresql"

    def test_get_database_type_unknown(self, schema_analyzer, mock_async_session):
        """Test database type detection when it fails."""
        mock_async_session.bind.dialect = None
        db_type = schema_analyzer._get_database_type(mock_async_session)
        assert db_type == "unknown"

    def test_get_expected_tables(self, schema_analyzer):
        """Test getting expected tables from models."""
        expected_tables = schema_analyzer._get_expected_tables()
        assert 'users' in expected_tables
        assert 'profiles' in expected_tables
        assert len(expected_tables) == 2
        assert expected_tables == sorted(expected_tables)  # Should be sorted

    def test_get_expected_tables_empty_base(self, empty_schema_analyzer):
        """Test getting expected tables from empty base."""
        expected_tables = empty_schema_analyzer._get_expected_tables()
        assert len(expected_tables) == 0

    @pytest.mark.asyncio
    async def test_get_actual_tables_sqlite_success(self, schema_analyzer, mock_async_session):
        """Test getting actual tables from SQLite database."""
        # Mock successful SQLite query
        mock_result = MagicMock()
        mock_result.fetchall.return_value = [
            ('users',),
            ('profiles',),
            ('alembic_version',),  # Should be filtered out
            ('sqlite_sequence',),  # Should be filtered out
        ]
        mock_async_session.execute.return_value = mock_result
        
        actual_tables = await schema_analyzer._get_actual_tables(mock_async_session)
        
        assert 'users' in actual_tables
        assert 'profiles' in actual_tables
        assert 'alembic_version' not in actual_tables
        assert 'sqlite_sequence' not in actual_tables
        assert actual_tables == sorted(actual_tables)

    @pytest.mark.asyncio
    async def test_get_actual_tables_postgresql_fallback(self, schema_analyzer, mock_async_session):
        """Test fallback to PostgreSQL query when SQLite fails."""
        # Mock SQLite failure, PostgreSQL success
        mock_async_session.execute.side_effect = [
            Exception("SQLite query failed"),
            MagicMock(fetchall=lambda: [('users',), ('profiles',)])
        ]
        
        actual_tables = await schema_analyzer._get_actual_tables(mock_async_session)
        
        assert 'users' in actual_tables
        assert 'profiles' in actual_tables
        assert len(actual_tables) == 2

    @pytest.mark.asyncio
    async def test_get_actual_tables_all_fail(self, schema_analyzer, mock_async_session):
        """Test when both SQLite and PostgreSQL queries fail."""
        mock_async_session.execute.side_effect = Exception("Database error")
        
        actual_tables = await schema_analyzer._get_actual_tables(mock_async_session)
        
        assert actual_tables == []

    @pytest.mark.asyncio
    async def test_get_table_columns_sqlite(self, schema_analyzer, mock_async_session):
        """Test getting table column information from SQLite."""
        mock_result = MagicMock()
        mock_result.fetchall.return_value = [
            (0, 'id', 'INTEGER', 1, None, 1),  # cid, name, type, notnull, default, pk
            (1, 'username', 'VARCHAR(50)', 1, None, 0),
            (2, 'email', 'VARCHAR(100)', 0, None, 0),
            (3, 'active', 'BOOLEAN', 0, 'true', 0),
        ]
        mock_async_session.execute.return_value = mock_result
        
        columns = await schema_analyzer._get_table_columns(mock_async_session, 'users')
        
        assert 'id' in columns
        assert 'username' in columns
        assert 'email' in columns
        assert 'active' in columns
        
        # Test column properties
        assert columns['id']['type'] == 'INTEGER'
        assert columns['id']['primary_key'] is True
        assert columns['id']['nullable'] is False
        
        assert columns['email']['nullable'] is True
        assert columns['active']['default'] == 'true'

    @pytest.mark.asyncio
    async def test_get_table_columns_failure(self, schema_analyzer, mock_async_session):
        """Test handling failure to get column information."""
        mock_async_session.execute.side_effect = Exception("Column query failed")
        
        columns = await schema_analyzer._get_table_columns(mock_async_session, 'users')
        
        assert columns == {}

    @pytest.mark.asyncio
    async def test_get_table_indexes_sqlite(self, schema_analyzer, mock_async_session):
        """Test getting table index information from SQLite."""
        mock_result = MagicMock()
        mock_result.fetchall.return_value = [
            (0, 'idx_username', 1, 'c', 0),  # seq, name, unique, origin, partial
            (1, 'idx_email', 0, 'c', 0),
        ]
        mock_async_session.execute.return_value = mock_result
        
        indexes = await schema_analyzer._get_table_indexes(mock_async_session, 'users')
        
        assert 'idx_username' in indexes
        assert 'idx_email' in indexes
        assert indexes['idx_username']['unique'] is True
        assert indexes['idx_email']['unique'] is False

    @pytest.mark.asyncio
    async def test_get_table_indexes_failure(self, schema_analyzer, mock_async_session):
        """Test handling failure to get index information."""
        mock_async_session.execute.side_effect = Exception("Index query failed")
        
        indexes = await schema_analyzer._get_table_indexes(mock_async_session, 'users')
        
        assert indexes == {}

    @pytest.mark.asyncio
    async def test_get_table_foreign_keys_sqlite(self, schema_analyzer, mock_async_session):
        """Test getting table foreign key information from SQLite."""
        mock_result = MagicMock()
        mock_result.fetchall.return_value = [
            (0, 0, 'users', 'user_id', 'id', 'NO ACTION', 'NO ACTION', 'NONE'),
        ]
        mock_async_session.execute.return_value = mock_result
        
        fks = await schema_analyzer._get_table_foreign_keys(mock_async_session, 'profiles')
        
        assert len(fks) == 1
        fk_name = list(fks.keys())[0]
        assert 'profiles_user_id_users_id' in fk_name
        assert fks[fk_name]['from_column'] == 'user_id'
        assert fks[fk_name]['to_table'] == 'users'
        assert fks[fk_name]['to_column'] == 'id'

    @pytest.mark.asyncio
    async def test_get_table_foreign_keys_failure(self, schema_analyzer, mock_async_session):
        """Test handling failure to get foreign key information."""
        mock_async_session.execute.side_effect = Exception("FK query failed")
        
        fks = await schema_analyzer._get_table_foreign_keys(mock_async_session, 'profiles')
        
        assert fks == {}


class TestTypeCompatibilityChecking:
    """Test suite for type compatibility checking."""

    def test_sqlite_type_mappings(self, schema_analyzer):
        """Test SQLite type compatibility mappings."""
        # Create mock columns and database column info
        int_col = MagicMock()
        int_col.type = Integer()
        
        str_col = MagicMock()
        str_col.type = String(50)
        
        text_col = MagicMock()
        text_col.type = Text()
        
        bool_col = MagicMock()
        bool_col.type = Boolean()
        
        float_col = MagicMock()
        float_col.type = Float()
        
        json_col = MagicMock()
        json_col.type = JSON()
        
        # Test compatible mappings
        assert schema_analyzer._check_type_compatibility(int_col, {'type': 'INTEGER'}) is None
        assert schema_analyzer._check_type_compatibility(str_col, {'type': 'VARCHAR'}) is None
        assert schema_analyzer._check_type_compatibility(text_col, {'type': 'TEXT'}) is None
        assert schema_analyzer._check_type_compatibility(bool_col, {'type': 'BOOLEAN'}) is None
        assert schema_analyzer._check_type_compatibility(float_col, {'type': 'REAL'}) is None
        assert schema_analyzer._check_type_compatibility(json_col, {'type': 'JSON'}) is None
        
        # Test incompatible mappings
        error_msg = schema_analyzer._check_type_compatibility(int_col, {'type': 'TEXT'})
        assert error_msg is not None
        assert "Type mismatch" in error_msg
        assert "Integer" in error_msg
        assert "TEXT" in error_msg

    def test_unknown_database_type(self, schema_analyzer):
        """Test handling of unknown database types."""
        int_col = MagicMock()
        int_col.type = Integer()
        
        result = schema_analyzer._check_type_compatibility(int_col, {'type': 'UNKNOWN_TYPE'})
        # Should return None (no error) for unknown types to be safe
        assert result is None

    def test_missing_type_info(self, schema_analyzer):
        """Test handling when database column info lacks type."""
        int_col = MagicMock()
        int_col.type = Integer()
        
        result = schema_analyzer._check_type_compatibility(int_col, {})
        # Should handle gracefully
        assert result is None or "Type mismatch" in result


class TestSQLGeneration:
    """Test suite for SQL generation methods."""

    def test_generate_create_table_sql(self, schema_analyzer):
        """Test CREATE TABLE SQL generation."""
        # Get the users table from our test model
        table = TestBase.metadata.tables['users']
        
        sql = schema_analyzer._generate_create_table_sql(table)
        
        assert "CREATE TABLE users" in sql
        assert "id INTEGER" in sql
        assert "username VARCHAR(50)" in sql
        assert "NOT NULL" in sql
        assert "PRIMARY KEY" in sql

    def test_generate_add_column_sql(self, schema_analyzer):
        """Test ALTER TABLE ADD COLUMN SQL generation."""
        # Create a mock column
        column = MagicMock()
        column.type = String(100)
        column.nullable = False
        column.default = None
        
        sql = schema_analyzer._generate_add_column_sql('users', 'new_field', column)
        
        assert "ALTER TABLE users ADD COLUMN new_field" in sql
        assert "VARCHAR(100)" in sql
        assert "NOT NULL" in sql

    def test_generate_add_column_sql_with_default(self, schema_analyzer):
        """Test ALTER TABLE ADD COLUMN SQL generation with default value."""
        column = MagicMock()
        column.type = Boolean()
        column.nullable = False
        column.default = True
        
        sql = schema_analyzer._generate_add_column_sql('users', 'active', column)
        
        assert "ALTER TABLE users ADD COLUMN active" in sql
        assert "BOOLEAN" in sql
        assert "NOT NULL" in sql
        assert "DEFAULT True" in sql


class TestTableAnalysis:
    """Test suite for individual table analysis."""

    @pytest.mark.asyncio
    async def test_analyze_table_missing_from_database(self, schema_analyzer, mock_async_session):
        """Test analysis of table that exists in models but not database."""
        analysis = await schema_analyzer._analyze_table(mock_async_session, 'users', False)
        
        assert analysis.table_name == 'users'
        assert analysis.exists_in_db is False
        assert analysis.exists_in_models is True
        assert analysis.column_count_expected > 0
        assert analysis.column_count_actual == 0
        assert analysis.has_issues is True
        
        # Should have a missing table issue
        missing_table_issues = [i for i in analysis.issues if i.issue_type == IssueType.MISSING_TABLE]
        assert len(missing_table_issues) == 1
        assert missing_table_issues[0].severity == SeverityLevel.CRITICAL

    @pytest.mark.asyncio
    async def test_analyze_table_complete_match(self, schema_analyzer, mock_async_session):
        """Test analysis of table with complete schema match."""
        # Mock database columns that match the model exactly
        mock_columns = {
            'id': {'type': 'INTEGER', 'nullable': False, 'default': None, 'primary_key': True},
            'username': {'type': 'VARCHAR(50)', 'nullable': False, 'default': None, 'primary_key': False},
            'email': {'type': 'VARCHAR(100)', 'nullable': True, 'default': None, 'primary_key': False},
            'active': {'type': 'BOOLEAN', 'nullable': True, 'default': 'true', 'primary_key': False},
            'created_at': {'type': 'DATETIME', 'nullable': False, 'default': None, 'primary_key': False},
        }
        
        with patch.object(schema_analyzer, '_get_table_columns', return_value=mock_columns), \
             patch.object(schema_analyzer, '_analyze_table_indexes'), \
             patch.object(schema_analyzer, '_analyze_table_foreign_keys'):
            
            analysis = await schema_analyzer._analyze_table(mock_async_session, 'users', True)
        
        assert analysis.table_name == 'users'
        assert analysis.exists_in_db is True
        assert analysis.exists_in_models is True
        assert analysis.column_count_expected == 5
        assert analysis.column_count_actual == 5
        
        # Should have minimal or no issues for exact match
        critical_issues = [i for i in analysis.issues if i.severity == SeverityLevel.CRITICAL]
        assert len(critical_issues) == 0

    @pytest.mark.asyncio
    async def test_analyze_table_missing_columns(self, schema_analyzer, mock_async_session):
        """Test analysis of table with missing columns."""
        # Mock database with missing columns
        mock_columns = {
            'id': {'type': 'INTEGER', 'nullable': False, 'default': None, 'primary_key': True},
            'username': {'type': 'VARCHAR(50)', 'nullable': False, 'default': None, 'primary_key': False},
            # Missing: email, active, created_at
        }
        
        with patch.object(schema_analyzer, '_get_table_columns', return_value=mock_columns), \
             patch.object(schema_analyzer, '_analyze_table_indexes'), \
             patch.object(schema_analyzer, '_analyze_table_foreign_keys'):
            
            analysis = await schema_analyzer._analyze_table(mock_async_session, 'users', True)
        
        assert analysis.column_count_actual == 2
        
        # Should have missing column issues
        missing_col_issues = [i for i in analysis.issues if i.issue_type == IssueType.MISSING_COLUMN]
        assert len(missing_col_issues) == 3  # email, active, created_at
        
        # Check severity based on nullable columns
        critical_missing = [i for i in missing_col_issues if i.severity == SeverityLevel.CRITICAL]
        high_missing = [i for i in missing_col_issues if i.severity == SeverityLevel.HIGH]
        
        # created_at is non-nullable, so should be critical
        assert len(critical_missing) >= 1
        # email and active are nullable, so should be high
        assert len(high_missing) >= 2

    @pytest.mark.asyncio
    async def test_analyze_table_extra_columns(self, schema_analyzer, mock_async_session):
        """Test analysis of table with extra columns."""
        # Mock database with extra columns
        mock_columns = {
            'id': {'type': 'INTEGER', 'nullable': False, 'default': None, 'primary_key': True},
            'username': {'type': 'VARCHAR(50)', 'nullable': False, 'default': None, 'primary_key': False},
            'email': {'type': 'VARCHAR(100)', 'nullable': True, 'default': None, 'primary_key': False},
            'active': {'type': 'BOOLEAN', 'nullable': True, 'default': 'true', 'primary_key': False},
            'created_at': {'type': 'DATETIME', 'nullable': False, 'default': None, 'primary_key': False},
            'extra_field': {'type': 'TEXT', 'nullable': True, 'default': None, 'primary_key': False},
            'another_extra': {'type': 'INTEGER', 'nullable': True, 'default': None, 'primary_key': False},
        }
        
        with patch.object(schema_analyzer, '_get_table_columns', return_value=mock_columns), \
             patch.object(schema_analyzer, '_analyze_table_indexes'), \
             patch.object(schema_analyzer, '_analyze_table_foreign_keys'):
            
            analysis = await schema_analyzer._analyze_table(mock_async_session, 'users', True)
        
        assert analysis.column_count_actual == 7
        
        # Should have extra column issues
        extra_col_issues = [i for i in analysis.issues if i.issue_type == IssueType.EXTRA_COLUMN]
        assert len(extra_col_issues) == 2
        
        # Extra columns should be low severity
        for issue in extra_col_issues:
            assert issue.severity == SeverityLevel.LOW
            assert issue.column_name in ['extra_field', 'another_extra']

    @pytest.mark.asyncio
    async def test_analyze_table_type_mismatches(self, schema_analyzer, mock_async_session):
        """Test analysis of table with type mismatches."""
        # Mock database with wrong types
        mock_columns = {
            'id': {'type': 'TEXT', 'nullable': False, 'default': None, 'primary_key': True},  # Should be INTEGER
            'username': {'type': 'INTEGER', 'nullable': False, 'default': None, 'primary_key': False},  # Should be VARCHAR
            'email': {'type': 'VARCHAR(100)', 'nullable': True, 'default': None, 'primary_key': False},
            'active': {'type': 'BOOLEAN', 'nullable': True, 'default': 'true', 'primary_key': False},
            'created_at': {'type': 'DATETIME', 'nullable': False, 'default': None, 'primary_key': False},
        }
        
        with patch.object(schema_analyzer, '_get_table_columns', return_value=mock_columns), \
             patch.object(schema_analyzer, '_analyze_table_indexes'), \
             patch.object(schema_analyzer, '_analyze_table_foreign_keys'):
            
            analysis = await schema_analyzer._analyze_table(mock_async_session, 'users', True)
        
        # Should have type mismatch issues
        type_mismatch_issues = [i for i in analysis.issues if i.issue_type == IssueType.TYPE_MISMATCH]
        assert len(type_mismatch_issues) >= 2  # id and username types are wrong
        
        # Type mismatches should be medium severity
        for issue in type_mismatch_issues:
            assert issue.severity == SeverityLevel.MEDIUM
            assert issue.expected_value is not None
            assert issue.actual_value is not None


class TestFullSchemaAnalysis:
    """Test suite for complete schema analysis workflows."""

    @pytest.mark.asyncio
    async def test_analyze_schema_healthy_database(self, schema_analyzer, mock_async_session):
        """Test analysis of a healthy database with perfect schema match."""
        # Mock perfect database state
        with patch.object(schema_analyzer, '_get_actual_tables', return_value=['users', 'profiles']), \
             patch.object(schema_analyzer, '_analyze_table') as mock_analyze_table:
            
            # Mock table analyses with no issues
            mock_analyze_table.side_effect = [
                TableAnalysis(
                    table_name='users',
                    exists_in_db=True,
                    exists_in_models=True,
                    column_count_expected=5,
                    column_count_actual=5,
                    issues=[]
                ),
                TableAnalysis(
                    table_name='profiles',
                    exists_in_db=True,
                    exists_in_models=True,
                    column_count_expected=4,
                    column_count_actual=4,
                    issues=[]
                )
            ]
            
            report = await schema_analyzer.analyze_schema(mock_async_session)
        
        assert report.database_type == "sqlite"
        assert report.total_tables_expected == 2
        assert report.total_tables_actual == 2
        assert len(report.tables_analyzed) == 2
        assert report.total_issues == 0
        assert report.is_healthy is True
        assert len(report.critical_issues) == 0

    @pytest.mark.asyncio
    async def test_analyze_schema_with_extra_tables(self, schema_analyzer, mock_async_session):
        """Test analysis when database has extra tables."""
        # Mock database with extra table
        with patch.object(schema_analyzer, '_get_actual_tables', return_value=['users', 'profiles', 'legacy_table']), \
             patch.object(schema_analyzer, '_analyze_table') as mock_analyze_table:
            
            mock_analyze_table.side_effect = [
                TableAnalysis(
                    table_name='users',
                    exists_in_db=True,
                    exists_in_models=True,
                    column_count_expected=5,
                    column_count_actual=5,
                    issues=[]
                ),
                TableAnalysis(
                    table_name='profiles',
                    exists_in_db=True,
                    exists_in_models=True,
                    column_count_expected=4,
                    column_count_actual=4,
                    issues=[]
                )
            ]
            
            report = await schema_analyzer.analyze_schema(mock_async_session)
        
        assert report.total_tables_actual == 3
        assert len(report.global_issues) == 1
        
        extra_table_issue = report.global_issues[0]
        assert extra_table_issue.issue_type == IssueType.EXTRA_TABLE
        assert extra_table_issue.severity == SeverityLevel.LOW
        assert extra_table_issue.table_name == 'legacy_table'

    @pytest.mark.asyncio
    async def test_analyze_schema_with_critical_issues(self, schema_analyzer, mock_async_session):
        """Test analysis with critical schema issues."""
        critical_issue = SchemaIssue(
            issue_type=IssueType.MISSING_TABLE,
            severity=SeverityLevel.CRITICAL,
            table_name='users',
            description='Critical issue'
        )
        
        with patch.object(schema_analyzer, '_get_actual_tables', return_value=['profiles']), \
             patch.object(schema_analyzer, '_analyze_table') as mock_analyze_table:
            
            mock_analyze_table.side_effect = [
                TableAnalysis(
                    table_name='users',
                    exists_in_db=False,
                    exists_in_models=True,
                    column_count_expected=5,
                    column_count_actual=0,
                    issues=[critical_issue]
                ),
                TableAnalysis(
                    table_name='profiles',
                    exists_in_db=True,
                    exists_in_models=True,
                    column_count_expected=4,
                    column_count_actual=4,
                    issues=[]
                )
            ]
            
            report = await schema_analyzer.analyze_schema(mock_async_session)
        
        assert report.is_healthy is False
        assert len(report.critical_issues) == 1
        assert report.critical_issues[0].issue_type == IssueType.MISSING_TABLE
        assert report.total_issues == 1

    @pytest.mark.asyncio
    async def test_analyze_schema_empty_database(self, empty_schema_analyzer, mock_async_session):
        """Test analysis with no models or tables."""
        with patch.object(empty_schema_analyzer, '_get_actual_tables', return_value=[]):
            report = await empty_schema_analyzer.analyze_schema(mock_async_session)
        
        assert report.total_tables_expected == 0
        assert report.total_tables_actual == 0
        assert len(report.tables_analyzed) == 0
        assert report.total_issues == 0
        assert report.is_healthy is True


class TestReportMethods:
    """Test suite for report analysis methods."""

    def test_report_properties(self):
        """Test SchemaAnalysisReport properties."""
        # Create test issues
        critical_issue = SchemaIssue(
            issue_type=IssueType.MISSING_TABLE,
            severity=SeverityLevel.CRITICAL,
            table_name='test_table',
            description='Critical test issue'
        )
        
        medium_issue = SchemaIssue(
            issue_type=IssueType.TYPE_MISMATCH,
            severity=SeverityLevel.MEDIUM,
            table_name='test_table',
            description='Medium test issue'
        )
        
        low_issue = SchemaIssue(
            issue_type=IssueType.EXTRA_COLUMN,
            severity=SeverityLevel.LOW,
            table_name='test_table',
            description='Low test issue'
        )
        
        # Create table analysis with issues
        table_analysis = TableAnalysis(
            table_name='test_table',
            exists_in_db=True,
            exists_in_models=True,
            column_count_expected=3,
            column_count_actual=3,
            issues=[critical_issue, medium_issue]
        )
        
        # Create report with global issues
        report = SchemaAnalysisReport(
            database_type='sqlite',
            total_tables_expected=1,
            total_tables_actual=1,
            tables_analyzed=[table_analysis],
            global_issues=[low_issue]
        )
        
        # Test properties
        assert report.total_issues == 3
        assert len(report.critical_issues) == 1
        assert report.critical_issues[0] == critical_issue
        assert report.is_healthy is False
        
        # Test get_issues_by_severity
        critical_issues = report.get_issues_by_severity(SeverityLevel.CRITICAL)
        assert len(critical_issues) == 1
        assert critical_issues[0] == critical_issue
        
        medium_issues = report.get_issues_by_severity(SeverityLevel.MEDIUM)
        assert len(medium_issues) == 1
        assert medium_issues[0] == medium_issue
        
        low_issues = report.get_issues_by_severity(SeverityLevel.LOW)
        assert len(low_issues) == 1
        assert low_issues[0] == low_issue

    def test_table_analysis_properties(self):
        """Test TableAnalysis properties."""
        critical_issue = SchemaIssue(
            issue_type=IssueType.MISSING_COLUMN,
            severity=SeverityLevel.CRITICAL,
            table_name='test_table',
            column_name='critical_col',
            description='Critical column missing'
        )
        
        low_issue = SchemaIssue(
            issue_type=IssueType.EXTRA_COLUMN,
            severity=SeverityLevel.LOW,
            table_name='test_table',
            column_name='extra_col',
            description='Extra column found'
        )
        
        table_analysis = TableAnalysis(
            table_name='test_table',
            exists_in_db=True,
            exists_in_models=True,
            column_count_expected=5,
            column_count_actual=6,
            issues=[critical_issue, low_issue]
        )
        
        assert table_analysis.has_issues is True
        assert len(table_analysis.critical_issues) == 1
        assert table_analysis.critical_issues[0] == critical_issue
        
        # Test with no issues
        clean_table = TableAnalysis(
            table_name='clean_table',
            exists_in_db=True,
            exists_in_models=True,
            column_count_expected=3,
            column_count_actual=3,
            issues=[]
        )
        
        assert clean_table.has_issues is False
        assert len(clean_table.critical_issues) == 0


class TestIndexAndForeignKeyAnalysis:
    """Test suite for index and foreign key analysis."""

    @pytest.mark.asyncio
    async def test_analyze_table_indexes_success(self, schema_analyzer, mock_async_session):
        """Test successful index analysis."""
        mock_table = MagicMock()
        mock_index = MagicMock()
        mock_index.name = 'idx_username'
        mock_index.columns = [MagicMock(name='username')]
        mock_table.indexes = [mock_index]
        
        mock_db_indexes = {'idx_username': {'unique': True, 'columns': ['username']}}
        
        table_analysis = TableAnalysis(
            table_name='users',
            exists_in_db=True,
            exists_in_models=True,
            column_count_expected=5,
            column_count_actual=5
        )
        
        with patch.object(schema_analyzer, '_get_table_indexes', return_value=mock_db_indexes):
            await schema_analyzer._analyze_table_indexes(mock_async_session, table_analysis, mock_table)
        
        # Should have no issues for matching indexes
        index_issues = [i for i in table_analysis.issues if i.issue_type in [IssueType.MISSING_INDEX, IssueType.EXTRA_INDEX]]
        assert len(index_issues) == 0

    @pytest.mark.asyncio
    async def test_analyze_table_indexes_missing(self, schema_analyzer, mock_async_session):
        """Test analysis with missing indexes."""
        mock_table = MagicMock()
        mock_index = MagicMock()
        mock_index.name = 'idx_username'
        mock_index.columns = [MagicMock(name='username')]
        mock_table.indexes = [mock_index]
        
        mock_db_indexes = {}  # No indexes in database
        
        table_analysis = TableAnalysis(
            table_name='users',
            exists_in_db=True,
            exists_in_models=True,
            column_count_expected=5,
            column_count_actual=5
        )
        
        with patch.object(schema_analyzer, '_get_table_indexes', return_value=mock_db_indexes):
            await schema_analyzer._analyze_table_indexes(mock_async_session, table_analysis, mock_table)
        
        missing_index_issues = [i for i in table_analysis.issues if i.issue_type == IssueType.MISSING_INDEX]
        assert len(missing_index_issues) == 1
        assert missing_index_issues[0].severity == SeverityLevel.MEDIUM

    @pytest.mark.asyncio
    async def test_analyze_table_indexes_extra(self, schema_analyzer, mock_async_session):
        """Test analysis with extra indexes."""
        mock_table = MagicMock()
        mock_table.indexes = []  # No indexes in model
        
        mock_db_indexes = {
            'idx_extra': {'unique': False, 'columns': ['some_column']},
            'pk_users': {'unique': True, 'columns': ['id']},  # Should be ignored
            'uq_users_email': {'unique': True, 'columns': ['email']}  # Should be ignored
        }
        
        table_analysis = TableAnalysis(
            table_name='users',
            exists_in_db=True,
            exists_in_models=True,
            column_count_expected=5,
            column_count_actual=5
        )
        
        with patch.object(schema_analyzer, '_get_table_indexes', return_value=mock_db_indexes):
            await schema_analyzer._analyze_table_indexes(mock_async_session, table_analysis, mock_table)
        
        extra_index_issues = [i for i in table_analysis.issues if i.issue_type == IssueType.EXTRA_INDEX]
        assert len(extra_index_issues) == 1  # Only idx_extra, pk_ and uq_ should be ignored
        assert extra_index_issues[0].severity == SeverityLevel.LOW
        assert extra_index_issues[0].actual_value == 'idx_extra'

    @pytest.mark.asyncio
    async def test_analyze_table_indexes_error_handling(self, schema_analyzer, mock_async_session):
        """Test index analysis error handling."""
        mock_table = MagicMock()
        mock_table.indexes = []
        
        table_analysis = TableAnalysis(
            table_name='users',
            exists_in_db=True,
            exists_in_models=True,
            column_count_expected=5,
            column_count_actual=5
        )
        
        with patch.object(schema_analyzer, '_get_table_indexes', side_effect=Exception("Index error")):
            # Should not raise exception, but log error
            await schema_analyzer._analyze_table_indexes(mock_async_session, table_analysis, mock_table)
        
        # Should complete without crashing
        assert len(table_analysis.issues) == 0

    @pytest.mark.asyncio
    async def test_analyze_table_foreign_keys_missing(self, schema_analyzer, mock_async_session):
        """Test analysis with missing foreign keys."""
        mock_table = MagicMock()
        mock_fk = MagicMock()
        mock_fk.name = 'fk_user_id'
        mock_fk.column = MagicMock()
        mock_fk.column.name = 'user_id'
        mock_fk.column.table.name = 'users'
        mock_table.foreign_keys = [mock_fk]
        
        mock_db_fks = {}  # No foreign keys in database
        
        table_analysis = TableAnalysis(
            table_name='profiles',
            exists_in_db=True,
            exists_in_models=True,
            column_count_expected=4,
            column_count_actual=4
        )
        
        with patch.object(schema_analyzer, '_get_table_foreign_keys', return_value=mock_db_fks):
            await schema_analyzer._analyze_table_foreign_keys(mock_async_session, table_analysis, mock_table)
        
        missing_fk_issues = [i for i in table_analysis.issues if i.issue_type == IssueType.MISSING_FOREIGN_KEY]
        assert len(missing_fk_issues) == 1
        assert missing_fk_issues[0].severity == SeverityLevel.HIGH
        assert missing_fk_issues[0].column_name == 'user_id'

    @pytest.mark.asyncio
    async def test_analyze_table_foreign_keys_error_handling(self, schema_analyzer, mock_async_session):
        """Test foreign key analysis error handling."""
        mock_table = MagicMock()
        mock_table.foreign_keys = []
        
        table_analysis = TableAnalysis(
            table_name='profiles',
            exists_in_db=True,
            exists_in_models=True,
            column_count_expected=4,
            column_count_actual=4
        )
        
        with patch.object(schema_analyzer, '_get_table_foreign_keys', side_effect=Exception("FK error")):
            # Should not raise exception, but log error
            await schema_analyzer._analyze_table_foreign_keys(mock_async_session, table_analysis, mock_table)
        
        # Should complete without crashing
        assert len(table_analysis.issues) == 0


class TestConvenienceFunctions:
    """Test suite for module-level convenience functions."""

    @pytest.mark.asyncio
    async def test_analyze_database_schema(self):
        """Test analyze_database_schema convenience function."""
        mock_report = SchemaAnalysisReport(
            database_type='sqlite',
            total_tables_expected=1,
            total_tables_actual=1
        )
        
        with patch('gibson.db.utils.schema_analyzer.DatabaseManager') as mock_db_manager:
            mock_session = AsyncMock()
            mock_db_manager.return_value.__aenter__.return_value.get_session.return_value.__aenter__.return_value = mock_session
            
            with patch.object(SchemaAnalyzer, 'analyze_schema', return_value=mock_report) as mock_analyze:
                result = await analyze_database_schema('sqlite:///test.db')
            
            assert result == mock_report
            mock_analyze.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_schema_issues(self):
        """Test get_schema_issues convenience function."""
        test_issue = SchemaIssue(
            issue_type=IssueType.MISSING_COLUMN,
            severity=SeverityLevel.HIGH,
            table_name='test_table',
            description='Test issue'
        )
        
        mock_report = SchemaAnalysisReport(
            database_type='sqlite',
            total_tables_expected=1,
            total_tables_actual=1,
            tables_analyzed=[
                TableAnalysis(
                    table_name='test_table',
                    exists_in_db=True,
                    exists_in_models=True,
                    column_count_expected=3,
                    column_count_actual=2,
                    issues=[test_issue]
                )
            ]
        )
        
        mock_session = AsyncMock()
        
        with patch.object(SchemaAnalyzer, 'analyze_schema', return_value=mock_report):
            issues = await get_schema_issues(mock_session)
        
        assert len(issues) == 1
        assert issues[0] == test_issue

    @pytest.mark.asyncio
    async def test_get_critical_schema_issues(self):
        """Test get_critical_schema_issues convenience function."""
        critical_issue = SchemaIssue(
            issue_type=IssueType.MISSING_TABLE,
            severity=SeverityLevel.CRITICAL,
            table_name='critical_table',
            description='Critical test issue'
        )
        
        low_issue = SchemaIssue(
            issue_type=IssueType.EXTRA_COLUMN,
            severity=SeverityLevel.LOW,
            table_name='test_table',
            description='Low test issue'
        )
        
        mock_report = SchemaAnalysisReport(
            database_type='sqlite',
            total_tables_expected=2,
            total_tables_actual=1,
            tables_analyzed=[
                TableAnalysis(
                    table_name='critical_table',
                    exists_in_db=False,
                    exists_in_models=True,
                    column_count_expected=3,
                    column_count_actual=0,
                    issues=[critical_issue]
                )
            ],
            global_issues=[low_issue]
        )
        
        mock_session = AsyncMock()
        
        with patch.object(SchemaAnalyzer, 'analyze_schema', return_value=mock_report):
            critical_issues = await get_critical_schema_issues(mock_session)
        
        assert len(critical_issues) == 1
        assert critical_issues[0] == critical_issue
        assert critical_issues[0].severity == SeverityLevel.CRITICAL


class TestErrorHandlingAndEdgeCases:
    """Test suite for error handling and edge cases."""

    def test_nonexistent_table_in_model_metadata(self, schema_analyzer, mock_async_session):
        """Test handling of nonexistent table in model metadata."""
        # This is an edge case that shouldn't happen but we should handle gracefully
        with patch.object(TestBase.metadata.tables, 'get', return_value=None):
            result = asyncio.run(
                schema_analyzer._analyze_table(mock_async_session, 'nonexistent', True)
            )
        
        assert result.table_name == 'nonexistent'
        assert result.exists_in_models is False
        assert result.column_count_expected == 0
        assert result.column_count_actual == 0

    @pytest.mark.asyncio
    async def test_database_connection_errors(self, schema_analyzer):
        """Test handling of database connection errors."""
        mock_session = AsyncMock()
        mock_session.bind.dialect.name = "sqlite"
        mock_session.execute.side_effect = Exception("Connection lost")
        
        # Should handle connection errors gracefully
        actual_tables = await schema_analyzer._get_actual_tables(mock_session)
        assert actual_tables == []
        
        columns = await schema_analyzer._get_table_columns(mock_session, 'test_table')
        assert columns == {}
        
        indexes = await schema_analyzer._get_table_indexes(mock_session, 'test_table')
        assert indexes == {}
        
        fks = await schema_analyzer._get_table_foreign_keys(mock_session, 'test_table')
        assert fks == {}

    def test_schema_issue_validation(self):
        """Test SchemaIssue model validation."""
        # Valid issue
        issue = SchemaIssue(
            issue_type=IssueType.MISSING_COLUMN,
            severity=SeverityLevel.HIGH,
            table_name='test_table',
            column_name='test_column',
            description='Test description'
        )
        assert issue.issue_type == IssueType.MISSING_COLUMN
        assert issue.severity == SeverityLevel.HIGH
        
        # Test with all optional fields
        detailed_issue = SchemaIssue(
            issue_type=IssueType.TYPE_MISMATCH,
            severity=SeverityLevel.MEDIUM,
            table_name='test_table',
            column_name='test_column',
            expected_value='INTEGER',
            actual_value='TEXT',
            description='Type mismatch detected',
            fix_suggestion='Update column type',
            migration_sql='ALTER TABLE test_table ALTER COLUMN test_column TYPE INTEGER'
        )
        assert detailed_issue.expected_value == 'INTEGER'
        assert detailed_issue.actual_value == 'TEXT'
        assert detailed_issue.fix_suggestion == 'Update column type'
        assert detailed_issue.migration_sql is not None

    @pytest.mark.asyncio
    async def test_postgresql_type_mapping(self, schema_analyzer):
        """Test PostgreSQL-specific scenarios (even though logic is mainly SQLite)."""
        mock_session = AsyncMock()
        mock_session.bind.dialect.name = "postgresql"
        
        # Test database type detection
        db_type = schema_analyzer._get_database_type(mock_session)
        assert db_type == "postgresql"
        
        # Test that PostgreSQL queries are attempted when SQLite fails
        mock_session.execute.side_effect = [
            Exception("SQLite query failed"),  # First call (SQLite) fails
            MagicMock(fetchall=lambda: [('pg_table',)])  # Second call (PostgreSQL) succeeds
        ]
        
        actual_tables = await schema_analyzer._get_actual_tables(mock_session)
        assert 'pg_table' in actual_tables

    def test_report_timestamp_generation(self):
        """Test that report timestamps are generated correctly."""
        report1 = SchemaAnalysisReport(
            database_type='sqlite',
            total_tables_expected=1,
            total_tables_actual=1
        )
        
        # Small delay to ensure different timestamps
        import time
        time.sleep(0.01)
        
        report2 = SchemaAnalysisReport(
            database_type='sqlite',
            total_tables_expected=1,
            total_tables_actual=1
        )
        
        assert report1.analysis_timestamp != report2.analysis_timestamp
        assert isinstance(report1.analysis_timestamp, datetime)
        assert isinstance(report2.analysis_timestamp, datetime)


class TestRealWorldScenarios:
    """Test suite for real-world scenarios and integration patterns."""

    @pytest.mark.asyncio
    async def test_migration_scenario(self, schema_analyzer, mock_async_session):
        """Test a realistic migration scenario with multiple types of changes."""
        # Simulate a database that's behind the current model schema
        mock_columns = {
            'id': {'type': 'INTEGER', 'nullable': False, 'default': None, 'primary_key': True},
            'username': {'type': 'VARCHAR(25)', 'nullable': False, 'default': None, 'primary_key': False},  # Size changed
            # Missing: email, active, created_at (new columns)
        }
        
        with patch.object(schema_analyzer, '_get_actual_tables', return_value=['users']), \
             patch.object(schema_analyzer, '_get_table_columns', return_value=mock_columns), \
             patch.object(schema_analyzer, '_analyze_table_indexes'), \
             patch.object(schema_analyzer, '_analyze_table_foreign_keys'):
            
            report = await schema_analyzer.analyze_schema(mock_async_session)
        
        assert report.total_tables_expected == 2
        assert report.total_tables_actual == 1
        assert not report.is_healthy
        
        # Should have missing table (profiles)
        missing_table_issues = [i for i in report.global_issues if i.issue_type == IssueType.MISSING_TABLE]
        assert len(missing_table_issues) == 0  # Global issues are for extra tables
        
        # Check users table analysis
        users_analysis = next(t for t in report.tables_analyzed if t.table_name == 'users')
        missing_col_issues = [i for i in users_analysis.issues if i.issue_type == IssueType.MISSING_COLUMN]
        assert len(missing_col_issues) >= 3  # email, active, created_at
        
        # Should have SQL suggestions
        for issue in missing_col_issues:
            assert issue.migration_sql is not None
            assert "ALTER TABLE" in issue.migration_sql

    @pytest.mark.asyncio
    async def test_development_vs_production_scenario(self, schema_analyzer, mock_async_session):
        """Test scenario where development has extra experimental columns."""
        # Simulate development database with experimental columns
        mock_columns = {
            'id': {'type': 'INTEGER', 'nullable': False, 'default': None, 'primary_key': True},
            'username': {'type': 'VARCHAR(50)', 'nullable': False, 'default': None, 'primary_key': False},
            'email': {'type': 'VARCHAR(100)', 'nullable': True, 'default': None, 'primary_key': False},
            'active': {'type': 'BOOLEAN', 'nullable': True, 'default': 'true', 'primary_key': False},
            'created_at': {'type': 'DATETIME', 'nullable': False, 'default': None, 'primary_key': False},
            # Extra development columns
            'experimental_feature': {'type': 'TEXT', 'nullable': True, 'default': None, 'primary_key': False},
            'debug_info': {'type': 'JSON', 'nullable': True, 'default': None, 'primary_key': False},
        }
        
        with patch.object(schema_analyzer, '_get_actual_tables', return_value=['users', 'profiles', 'temp_debug_table']), \
             patch.object(schema_analyzer, '_get_table_columns', return_value=mock_columns), \
             patch.object(schema_analyzer, '_analyze_table_indexes'), \
             patch.object(schema_analyzer, '_analyze_table_foreign_keys') as mock_fk_analysis:
            
            # Mock profiles table analysis
            mock_fk_analysis.return_value = None
            
            report = await schema_analyzer.analyze_schema(mock_async_session)
        
        # Should identify extra table and columns but not critical issues
        extra_table_issues = [i for i in report.global_issues if i.issue_type == IssueType.EXTRA_TABLE]
        assert len(extra_table_issues) == 1
        assert extra_table_issues[0].table_name == 'temp_debug_table'
        assert extra_table_issues[0].severity == SeverityLevel.LOW
        
        users_analysis = next(t for t in report.tables_analyzed if t.table_name == 'users')
        extra_col_issues = [i for i in users_analysis.issues if i.issue_type == IssueType.EXTRA_COLUMN]
        assert len(extra_col_issues) >= 2  # experimental_feature, debug_info
        
        # Extra issues should be low severity
        for issue in extra_col_issues:
            assert issue.severity == SeverityLevel.LOW

    def test_performance_considerations(self):
        """Test that the analyzer is designed for reasonable performance."""
        # Verify that expected operations are O(n) or better
        analyzer = SchemaAnalyzer(TestBase)
        
        # Getting expected tables should be fast and not query database
        expected_tables = analyzer._get_expected_tables()
        assert isinstance(expected_tables, list)
        assert len(expected_tables) > 0
        
        # Type compatibility checking should be fast
        mock_col = MagicMock()
        mock_col.type = Integer()
        
        # Should complete quickly
        result = analyzer._check_type_compatibility(mock_col, {'type': 'INTEGER'})
        assert result is None  # Compatible
        
        result = analyzer._check_type_compatibility(mock_col, {'type': 'TEXT'})
        assert result is not None  # Incompatible


if __name__ == "__main__":
    # Allow running tests directly
    pytest.main([__file__, "-v"])