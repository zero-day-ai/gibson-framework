"""
Migration script validator for safety checks.
"""

import re
import ast
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path

from gibson.models.base import GibsonBaseModel
from gibson.core.schema_sync.models import MigrationScript


class ValidationIssue(GibsonBaseModel):
    """Represents a validation issue found in migration script."""
    
    severity: str  # "error", "warning", "info"
    category: str  # "syntax", "safety", "performance", "best_practice"
    message: str
    line_number: Optional[int] = None
    suggestion: Optional[str] = None
    
    @property
    def is_blocking(self) -> bool:
        """Check if issue should block migration."""
        return self.severity == "error"


class ValidationResult(GibsonBaseModel):
    """Result of migration script validation."""
    
    valid: bool
    issues: List[ValidationIssue] = []
    metadata: Dict[str, Any] = {}
    
    @property
    def has_errors(self) -> bool:
        """Check if validation has any errors."""
        return any(issue.severity == "error" for issue in self.issues)
    
    @property
    def has_warnings(self) -> bool:
        """Check if validation has any warnings."""
        return any(issue.severity == "warning" for issue in self.issues)


class MigrationValidator:
    """Validates migration scripts for safety and correctness."""
    
    # Dangerous SQL patterns
    DANGEROUS_PATTERNS = [
        (r'\bDROP\s+DATABASE\b', "Dropping entire database is extremely dangerous"),
        (r'\bTRUNCATE\s+TABLE\b(?!\s+CASCADE)', "TRUNCATE without CASCADE check"),
        (r'\bDELETE\s+FROM\s+\w+\s*(?!WHERE)', "DELETE without WHERE clause"),
        (r'\bUPDATE\s+\w+\s+SET\s+.*(?!WHERE)', "UPDATE without WHERE clause"),
        (r'\bALTER\s+TABLE\s+\w+\s+DROP\s+CONSTRAINT\s+\w+_pkey', "Dropping primary key"),
        (r'\bDISABLE\s+TRIGGER\b', "Disabling triggers can cause data integrity issues"),
        (r'\bSET\s+session_replication_role', "Modifying replication role is dangerous"),
    ]
    
    # Required safety checks
    SAFETY_PATTERNS = [
        (r'BEGIN;.*COMMIT;', "Transaction wrapper", "Wrap migrations in transactions"),
        (r'-- rollback:', "Rollback comment", "Document rollback procedure"),
        (r'SELECT\s+COUNT.*validation', "Data validation", "Add data validation checks"),
    ]
    
    # Performance concerns
    PERFORMANCE_PATTERNS = [
        (r'\bCREATE\s+INDEX\s+(?!CONCURRENTLY)', 
         "Non-concurrent index creation can lock table"),
        (r'\bALTER\s+TABLE\s+.*\s+ADD\s+COLUMN\s+.*\s+DEFAULT\s+', 
         "Adding column with default requires table rewrite"),
        (r'\bVACUUM\s+FULL\b', "VACUUM FULL locks table completely"),
        (r'SELECT\s+\*\s+FROM\s+\w+(?!\s+LIMIT)', "SELECT * without LIMIT"),
    ]
    
    def __init__(self):
        """Initialize migration validator."""
        self.custom_rules: List[Tuple[str, str, str]] = []
    
    def validate(
        self, 
        migration: MigrationScript,
        strict: bool = False
    ) -> ValidationResult:
        """
        Validate a migration script.
        
        Args:
            migration: Migration script to validate
            strict: If True, warnings become errors
            
        Returns:
            Validation result with any issues found
        """
        issues = []
        
        # Validate structure
        issues.extend(self._validate_structure(migration))
        
        # Check for dangerous patterns
        issues.extend(self._check_dangerous_patterns(migration))
        
        # Check for required safety patterns
        if strict:
            issues.extend(self._check_safety_patterns(migration))
        
        # Check for performance issues
        issues.extend(self._check_performance_patterns(migration))
        
        # Validate SQL syntax
        issues.extend(self._validate_sql_syntax(migration))
        
        # Check rollback capability
        issues.extend(self._validate_rollback(migration))
        
        # Check data integrity
        issues.extend(self._validate_data_integrity(migration))
        
        # Apply custom rules
        issues.extend(self._apply_custom_rules(migration))
        
        # Upgrade warnings to errors in strict mode
        if strict:
            for issue in issues:
                if issue.severity == "warning":
                    issue.severity = "error"
        
        # Determine overall validity
        valid = not any(issue.is_blocking for issue in issues)
        
        return ValidationResult(
            valid=valid,
            issues=issues,
            metadata={
                "script_version": migration.version,
                "error_count": sum(1 for i in issues if i.severity == "error"),
                "warning_count": sum(1 for i in issues if i.severity == "warning"),
                "info_count": sum(1 for i in issues if i.severity == "info"),
            }
        )
    
    def _validate_structure(self, migration: MigrationScript) -> List[ValidationIssue]:
        """Validate migration script structure."""
        issues = []
        
        # Check for upgrade function
        if not migration.upgrade_sql or migration.upgrade_sql.strip() == "":
            issues.append(ValidationIssue(
                severity="error",
                category="structure",
                message="Migration must have upgrade SQL"
            ))
        
        # Check for downgrade function
        if not migration.downgrade_sql or migration.downgrade_sql.strip() == "":
            issues.append(ValidationIssue(
                severity="warning",
                category="structure",
                message="Migration should have downgrade SQL for rollback",
                suggestion="Add downgrade SQL or explicitly mark as irreversible"
            ))
        
        # Check version format
        if not self._validate_version_format(migration.version):
            issues.append(ValidationIssue(
                severity="error",
                category="structure",
                message=f"Invalid version format: {migration.version}",
                suggestion="Use format: YYYYMMDD_HHMMSS or semantic versioning"
            ))
        
        return issues
    
    def _check_dangerous_patterns(
        self, 
        migration: MigrationScript
    ) -> List[ValidationIssue]:
        """Check for dangerous SQL patterns."""
        issues = []
        sql = f"{migration.upgrade_sql}\n{migration.downgrade_sql}"
        
        for pattern, message in self.DANGEROUS_PATTERNS:
            matches = re.finditer(pattern, sql, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                line_num = sql[:match.start()].count('\n') + 1
                issues.append(ValidationIssue(
                    severity="error",
                    category="safety",
                    message=f"Dangerous pattern detected: {message}",
                    line_number=line_num,
                    suggestion="Review and ensure this operation is intentional"
                ))
        
        return issues
    
    def _check_safety_patterns(
        self,
        migration: MigrationScript
    ) -> List[ValidationIssue]:
        """Check for required safety patterns."""
        issues = []
        sql = f"{migration.upgrade_sql}\n{migration.downgrade_sql}"
        
        for pattern, name, suggestion in self.SAFETY_PATTERNS:
            if not re.search(pattern, sql, re.IGNORECASE | re.MULTILINE):
                issues.append(ValidationIssue(
                    severity="warning",
                    category="best_practice",
                    message=f"Missing safety pattern: {name}",
                    suggestion=suggestion
                ))
        
        return issues
    
    def _check_performance_patterns(
        self,
        migration: MigrationScript
    ) -> List[ValidationIssue]:
        """Check for performance issues."""
        issues = []
        sql = f"{migration.upgrade_sql}\n{migration.downgrade_sql}"
        
        for pattern, message in self.PERFORMANCE_PATTERNS:
            matches = re.finditer(pattern, sql, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                line_num = sql[:match.start()].count('\n') + 1
                issues.append(ValidationIssue(
                    severity="warning",
                    category="performance",
                    message=f"Performance concern: {message}",
                    line_number=line_num,
                    suggestion="Consider performance impact on large tables"
                ))
        
        return issues
    
    def _validate_sql_syntax(
        self,
        migration: MigrationScript
    ) -> List[ValidationIssue]:
        """Validate SQL syntax (basic checks)."""
        issues = []
        
        # Check for basic syntax errors
        for sql_type, sql in [("upgrade", migration.upgrade_sql), 
                              ("downgrade", migration.downgrade_sql)]:
            if not sql:
                continue
            
            # Check for unmatched quotes
            single_quotes = sql.count("'") % 2
            double_quotes = sql.count('"') % 2
            
            if single_quotes != 0:
                issues.append(ValidationIssue(
                    severity="error",
                    category="syntax",
                    message=f"Unmatched single quotes in {sql_type} SQL"
                ))
            
            if double_quotes != 0:
                issues.append(ValidationIssue(
                    severity="error",
                    category="syntax",
                    message=f"Unmatched double quotes in {sql_type} SQL"
                ))
            
            # Check for unmatched parentheses
            open_parens = sql.count("(")
            close_parens = sql.count(")")
            
            if open_parens != close_parens:
                issues.append(ValidationIssue(
                    severity="error",
                    category="syntax",
                    message=f"Unmatched parentheses in {sql_type} SQL",
                    suggestion=f"Found {open_parens} '(' and {close_parens} ')'"
                ))
            
            # Check for missing semicolons (warning only)
            statements = [s.strip() for s in sql.split(';') if s.strip()]
            if len(statements) > 1:
                for stmt in statements[:-1]:  # All but last should end with ;
                    if not sql.strip().endswith(';'):
                        issues.append(ValidationIssue(
                            severity="warning",
                            category="syntax",
                            message="SQL statements should end with semicolon",
                            suggestion="Add ';' at the end of each statement"
                        ))
        
        return issues
    
    def _validate_rollback(
        self,
        migration: MigrationScript
    ) -> List[ValidationIssue]:
        """Validate rollback capability."""
        issues = []
        
        # Check if migration is marked as irreversible
        if "irreversible" in migration.downgrade_sql.lower():
            issues.append(ValidationIssue(
                severity="warning",
                category="safety",
                message="Migration is marked as irreversible",
                suggestion="Ensure data backup before applying"
            ))
            return issues
        
        # Check if downgrade reverses upgrade operations
        upgrade_ops = self._extract_operations(migration.upgrade_sql)
        downgrade_ops = self._extract_operations(migration.downgrade_sql)
        
        # Simple check: downgrade should have similar number of operations
        if len(downgrade_ops) < len(upgrade_ops) * 0.5:
            issues.append(ValidationIssue(
                severity="warning",
                category="safety",
                message="Downgrade appears incomplete",
                suggestion="Ensure all upgrade operations are properly reversed"
            ))
        
        return issues
    
    def _validate_data_integrity(
        self,
        migration: MigrationScript
    ) -> List[ValidationIssue]:
        """Validate data integrity checks."""
        issues = []
        
        # Check for data validation in migrations that modify data
        data_modifying_patterns = [
            r'\bUPDATE\b', r'\bINSERT\b', r'\bDELETE\b',
            r'\bALTER\s+COLUMN.*TYPE\b'
        ]
        
        has_data_modification = any(
            re.search(pattern, migration.upgrade_sql, re.IGNORECASE)
            for pattern in data_modifying_patterns
        )
        
        if has_data_modification:
            # Check for validation queries
            validation_patterns = [
                r'\bSELECT\s+COUNT.*WHERE\b',
                r'\bSELECT.*HAVING\b',
                r'-- validate:',
                r'CONSTRAINT.*CHECK'
            ]
            
            has_validation = any(
                re.search(pattern, migration.upgrade_sql, re.IGNORECASE)
                for pattern in validation_patterns
            )
            
            if not has_validation:
                issues.append(ValidationIssue(
                    severity="warning",
                    category="safety",
                    message="Data modification without validation checks",
                    suggestion="Add validation queries to ensure data integrity"
                ))
        
        return issues
    
    def _apply_custom_rules(
        self,
        migration: MigrationScript
    ) -> List[ValidationIssue]:
        """Apply custom validation rules."""
        issues = []
        sql = f"{migration.upgrade_sql}\n{migration.downgrade_sql}"
        
        for pattern, message, severity in self.custom_rules:
            matches = re.finditer(pattern, sql, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                line_num = sql[:match.start()].count('\n') + 1
                issues.append(ValidationIssue(
                    severity=severity,
                    category="custom",
                    message=message,
                    line_number=line_num
                ))
        
        return issues
    
    def add_custom_rule(
        self,
        pattern: str,
        message: str,
        severity: str = "warning"
    ):
        """
        Add a custom validation rule.
        
        Args:
            pattern: Regex pattern to match
            message: Message to display when pattern is found
            severity: Issue severity (error, warning, info)
        """
        self.custom_rules.append((pattern, message, severity))
    
    def _validate_version_format(self, version: str) -> bool:
        """Validate migration version format."""
        # Accept multiple version formats
        patterns = [
            r'^\d{8}_\d{6}$',  # YYYYMMDD_HHMMSS
            r'^\d+\.\d+\.\d+$',  # Semantic versioning
            r'^v\d+\.\d+\.\d+$',  # Semantic with v prefix
            r'^\d{4}-\d{2}-\d{2}_\d+$',  # Date with sequence
        ]
        
        return any(re.match(pattern, version) for pattern in patterns)
    
    def _extract_operations(self, sql: str) -> List[str]:
        """Extract SQL operations from script."""
        operations = []
        
        # Common SQL operation patterns
        op_patterns = [
            r'\bCREATE\s+TABLE\b',
            r'\bDROP\s+TABLE\b',
            r'\bALTER\s+TABLE\b',
            r'\bCREATE\s+INDEX\b',
            r'\bDROP\s+INDEX\b',
            r'\bINSERT\s+INTO\b',
            r'\bUPDATE\s+\w+\s+SET\b',
            r'\bDELETE\s+FROM\b',
        ]
        
        for pattern in op_patterns:
            matches = re.findall(pattern, sql, re.IGNORECASE)
            operations.extend(matches)
        
        return operations
    
    def validate_file(self, file_path: Path) -> ValidationResult:
        """
        Validate a migration file.
        
        Args:
            file_path: Path to migration file
            
        Returns:
            Validation result
        """
        try:
            # Read migration file
            content = file_path.read_text()
            
            # Parse upgrade and downgrade functions
            # This is a simplified parser - real implementation would be more robust
            upgrade_match = re.search(
                r'def upgrade\(\):(.*?)(?=def downgrade|$)',
                content,
                re.DOTALL
            )
            downgrade_match = re.search(
                r'def downgrade\(\):(.*?)$',
                content,
                re.DOTALL
            )
            
            upgrade_sql = upgrade_match.group(1) if upgrade_match else ""
            downgrade_sql = downgrade_match.group(1) if downgrade_match else ""
            
            # Extract version from filename
            version = file_path.stem
            
            # Create migration script object
            migration = MigrationScript(
                version=version,
                description=f"Migration from {file_path.name}",
                upgrade_sql=upgrade_sql,
                downgrade_sql=downgrade_sql
            )
            
            return self.validate(migration)
            
        except Exception as e:
            return ValidationResult(
                valid=False,
                issues=[ValidationIssue(
                    severity="error",
                    category="syntax",
                    message=f"Failed to parse migration file: {str(e)}"
                )]
            )