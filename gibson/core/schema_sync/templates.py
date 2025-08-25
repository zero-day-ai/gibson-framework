"""
Migration template system using Jinja2.
"""

from typing import Dict, Any, Optional, List
from pathlib import Path
import json
from datetime import datetime

try:
    from jinja2 import Environment, FileSystemLoader, Template, select_autoescape
except ImportError:
    # Fallback for when Jinja2 is not installed
    Environment = None
    Template = None

from gibson.models.base import GibsonBaseModel
from gibson.core.schema_sync.models import (
    ChangeSet,
    MigrationScript,
    FieldModification,
    FieldChangeType
)


class MigrationTemplate(GibsonBaseModel):
    """Migration template configuration."""
    
    name: str
    description: str
    template_path: Optional[str] = None
    template_string: Optional[str] = None
    variables: Dict[str, Any] = {}
    
    def render(self, context: Dict[str, Any]) -> str:
        """Render template with context."""
        if Template is None:
            # Fallback to simple string formatting
            return self._simple_render(context)
        
        if self.template_string:
            template = Template(self.template_string)
        elif self.template_path:
            env = Environment(
                loader=FileSystemLoader(Path(self.template_path).parent),
                autoescape=select_autoescape()
            )
            template = env.get_template(Path(self.template_path).name)
        else:
            raise ValueError("No template source provided")
        
        return template.render(**context)
    
    def _simple_render(self, context: Dict[str, Any]) -> str:
        """Simple template rendering without Jinja2."""
        template = self.template_string or ""
        for key, value in context.items():
            template = template.replace(f"{{{{{key}}}}}", str(value))
        return template


class MigrationTemplateManager:
    """Manages migration templates for different scenarios."""
    
    def __init__(self, template_dir: Optional[Path] = None):
        """
        Initialize template manager.
        
        Args:
            template_dir: Directory containing template files
        """
        self.template_dir = template_dir or self._get_default_template_dir()
        self.templates = self._load_builtin_templates()
        
        if Environment:
            self.env = Environment(
                loader=FileSystemLoader(self.template_dir),
                autoescape=select_autoescape(),
                trim_blocks=True,
                lstrip_blocks=True
            )
        else:
            self.env = None
    
    def _get_default_template_dir(self) -> Path:
        """Get default template directory."""
        return Path(__file__).parent / "migration_templates"
    
    def _load_builtin_templates(self) -> Dict[str, MigrationTemplate]:
        """Load built-in migration templates."""
        return {
            "add_column": MigrationTemplate(
                name="add_column",
                description="Template for adding a new column",
                template_string="""
def upgrade():
    op.add_column('{{table_name}}', 
        sa.Column('{{column_name}}', {{column_type}}, 
                  nullable={{nullable}},
                  {% if default %}default={{default}},{% endif %}
                  {% if comment %}comment='{{comment}}'{% endif %}
        )
    )
    {% if index %}
    op.create_index('idx_{{table_name}}_{{column_name}}', 
                    '{{table_name}}', ['{{column_name}}'])
    {% endif %}

def downgrade():
    {% if index %}
    op.drop_index('idx_{{table_name}}_{{column_name}}', '{{table_name}}')
    {% endif %}
    op.drop_column('{{table_name}}', '{{column_name}}')
"""
            ),
            
            "drop_column": MigrationTemplate(
                name="drop_column",
                description="Template for dropping a column",
                template_string="""
def upgrade():
    {% if backup_table %}
    # Create backup of data before dropping column
    op.execute('''
        CREATE TABLE {{backup_table}} AS 
        SELECT {{column_name}} FROM {{table_name}}
    ''')
    {% endif %}
    
    op.drop_column('{{table_name}}', '{{column_name}}')

def downgrade():
    op.add_column('{{table_name}}',
        sa.Column('{{column_name}}', {{column_type}},
                  nullable={{nullable}})
    )
    
    {% if backup_table %}
    # Restore data from backup
    op.execute('''
        UPDATE {{table_name}} t
        SET {{column_name}} = b.{{column_name}}
        FROM {{backup_table}} b
        WHERE t.id = b.id
    ''')
    
    op.drop_table('{{backup_table}}')
    {% endif %}
"""
            ),
            
            "alter_column_type": MigrationTemplate(
                name="alter_column_type",
                description="Template for changing column type",
                template_string="""
def upgrade():
    {% if needs_cast %}
    # Cast existing data to new type
    op.execute('''
        ALTER TABLE {{table_name}}
        ALTER COLUMN {{column_name}}
        TYPE {{new_type}}
        USING {{column_name}}::{{cast_expression}}
    ''')
    {% else %}
    op.alter_column('{{table_name}}', '{{column_name}}',
                    type_={{new_type}},
                    existing_type={{old_type}})
    {% endif %}

def downgrade():
    {% if needs_cast %}
    op.execute('''
        ALTER TABLE {{table_name}}
        ALTER COLUMN {{column_name}}
        TYPE {{old_type}}
        USING {{column_name}}::{{reverse_cast_expression}}
    ''')
    {% else %}
    op.alter_column('{{table_name}}', '{{column_name}}',
                    type_={{old_type}},
                    existing_type={{new_type}})
    {% endif %}
"""
            ),
            
            "alter_nullable": MigrationTemplate(
                name="alter_nullable",
                description="Template for changing column nullable constraint",
                template_string="""
def upgrade():
    {% if to_required %}
    # Handle NULL values before making column required
    op.execute('''
        UPDATE {{table_name}}
        SET {{column_name}} = {{default_value}}
        WHERE {{column_name}} IS NULL
    ''')
    {% endif %}
    
    op.alter_column('{{table_name}}', '{{column_name}}',
                    nullable={{new_nullable}},
                    existing_nullable={{old_nullable}})

def downgrade():
    op.alter_column('{{table_name}}', '{{column_name}}',
                    nullable={{old_nullable}},
                    existing_nullable={{new_nullable}})
"""
            ),
            
            "data_migration": MigrationTemplate(
                name="data_migration",
                description="Template for data transformation migrations",
                template_string="""
def upgrade():
    connection = op.get_bind()
    
    # Data transformation
    {% for transformation in transformations %}
    op.execute('''
        {{transformation.sql}}
    ''')
    {% endfor %}
    
    # Verify data integrity
    result = connection.execute('''
        SELECT COUNT(*) FROM {{table_name}}
        WHERE {{validation_condition}}
    ''').scalar()
    
    if result > 0:
        raise ValueError(f"Data validation failed: {result} invalid rows")

def downgrade():
    {% if reversible %}
    connection = op.get_bind()
    
    # Reverse data transformation
    {% for transformation in reverse_transformations %}
    op.execute('''
        {{transformation.sql}}
    ''')
    {% endfor %}
    {% else %}
    # This migration is not reversible
    raise NotImplementedError("This data migration cannot be reversed")
    {% endif %}
"""
            ),
            
            "enum_modification": MigrationTemplate(
                name="enum_modification",
                description="Template for enum value changes",
                template_string="""
def upgrade():
    {% if added_values %}
    # Add new enum values
    {% for value in added_values %}
    op.execute("ALTER TYPE {{enum_name}} ADD VALUE '{{value}}'")
    {% endfor %}
    {% endif %}
    
    {% if removed_values %}
    # Handle removed enum values
    {% for value in removed_values %}
    # Update rows using removed value
    op.execute('''
        UPDATE {{table_name}}
        SET {{column_name}} = '{{replacement_value}}'
        WHERE {{column_name}} = '{{value}}'
    ''')
    {% endfor %}
    
    # Recreate enum without removed values
    op.execute('''
        ALTER TYPE {{enum_name}} RENAME TO {{enum_name}}_old;
        CREATE TYPE {{enum_name}} AS ENUM ({{new_values_list}});
        ALTER TABLE {{table_name}} 
        ALTER COLUMN {{column_name}} TYPE {{enum_name}}
        USING {{column_name}}::text::{{enum_name}};
        DROP TYPE {{enum_name}}_old;
    ''')
    {% endif %}

def downgrade():
    {% if removed_values %}
    # Recreate enum with original values
    op.execute('''
        ALTER TYPE {{enum_name}} RENAME TO {{enum_name}}_old;
        CREATE TYPE {{enum_name}} AS ENUM ({{old_values_list}});
        ALTER TABLE {{table_name}}
        ALTER COLUMN {{column_name}} TYPE {{enum_name}}
        USING {{column_name}}::text::{{enum_name}};
        DROP TYPE {{enum_name}}_old;
    ''')
    {% endif %}
    
    {% if added_values %}
    # Note: PostgreSQL doesn't support removing enum values
    # Data using new values would need to be handled manually
    pass
    {% endif %}
"""
            )
        }
    
    def generate_migration(
        self,
        changeset: ChangeSet,
        template_name: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> MigrationScript:
        """
        Generate migration script from changeset.
        
        Args:
            changeset: Set of changes to migrate
            template_name: Specific template to use
            context: Additional context for template
            
        Returns:
            Generated migration script
        """
        context = context or {}
        
        # Build migration context
        migration_context = self._build_migration_context(changeset)
        migration_context.update(context)
        
        # Select appropriate template
        if template_name:
            template = self.templates.get(template_name)
            if not template:
                raise ValueError(f"Template '{template_name}' not found")
        else:
            template = self._select_template(changeset)
        
        # Generate migration code
        upgrade_code = self._generate_upgrade_code(changeset, migration_context)
        downgrade_code = self._generate_downgrade_code(changeset, migration_context)
        
        # Create migration script
        return MigrationScript(
            version=migration_context.get("version", self._generate_version()),
            description=migration_context.get(
                "description", 
                self._generate_description(changeset)
            ),
            upgrade_sql=upgrade_code,
            downgrade_sql=downgrade_code,
            metadata={
                "changeset_hash": changeset.model_hash_after,
                "generated_at": datetime.utcnow().isoformat(),
                "template_used": template.name if template else "custom",
                "field_changes": len(changeset.modified_fields),
                "fields_added": len(changeset.added_fields),
                "fields_removed": len(changeset.removed_fields)
            }
        )
    
    def _build_migration_context(self, changeset: ChangeSet) -> Dict[str, Any]:
        """Build context for migration template."""
        return {
            "table_name": "payloads",  # Default table name
            "changeset": changeset,
            "timestamp": datetime.utcnow().strftime("%Y%m%d_%H%M%S"),
            "added_fields": changeset.added_fields,
            "removed_fields": changeset.removed_fields,
            "modified_fields": changeset.modified_fields,
            "enum_changes": changeset.enum_changes,
        }
    
    def _select_template(self, changeset: ChangeSet) -> Optional[MigrationTemplate]:
        """Select appropriate template based on changes."""
        # Logic to select template based on change patterns
        if changeset.removed_fields:
            return self.templates.get("drop_column")
        elif changeset.added_fields:
            return self.templates.get("add_column")
        elif any(m.change_type == FieldChangeType.TYPE_CHANGED 
                for m in changeset.modified_fields.values()):
            return self.templates.get("alter_column_type")
        elif any(m.change_type == FieldChangeType.NULLABLE_CHANGED
                for m in changeset.modified_fields.values()):
            return self.templates.get("alter_nullable")
        elif changeset.enum_changes:
            return self.templates.get("enum_modification")
        
        return None
    
    def _generate_upgrade_code(
        self, 
        changeset: ChangeSet, 
        context: Dict[str, Any]
    ) -> str:
        """Generate upgrade migration code."""
        parts = []
        
        # Add columns for new fields
        for field_name, field_info in changeset.added_fields.items():
            parts.append(self._generate_add_column(field_name, field_info))
        
        # Drop columns for removed fields
        for field_name in changeset.removed_fields:
            parts.append(self._generate_drop_column(field_name))
        
        # Alter columns for modified fields
        for field_name, modification in changeset.modified_fields.items():
            parts.append(self._generate_alter_column(field_name, modification))
        
        return "\n".join(parts)
    
    def _generate_downgrade_code(
        self, 
        changeset: ChangeSet,
        context: Dict[str, Any]
    ) -> str:
        """Generate downgrade migration code."""
        parts = []
        
        # Reverse operations in opposite order
        # Restore removed fields
        for field_name in changeset.removed_fields:
            parts.append(self._generate_restore_column(field_name))
        
        # Revert modified fields
        for field_name, modification in changeset.modified_fields.items():
            parts.append(self._generate_revert_column(field_name, modification))
        
        # Remove added fields
        for field_name in changeset.added_fields:
            parts.append(self._generate_drop_column(field_name))
        
        return "\n".join(parts)
    
    def _generate_add_column(self, field_name: str, field_info: Any) -> str:
        """Generate code to add a column."""
        return f"op.add_column('payloads', sa.Column('{field_name}', sa.String()))"
    
    def _generate_drop_column(self, field_name: str) -> str:
        """Generate code to drop a column."""
        return f"op.drop_column('payloads', '{field_name}')"
    
    def _generate_alter_column(
        self, 
        field_name: str, 
        modification: FieldModification
    ) -> str:
        """Generate code to alter a column."""
        if modification.change_type == FieldChangeType.TYPE_CHANGED:
            return f"op.alter_column('payloads', '{field_name}', type_=sa.String())"
        elif modification.change_type == FieldChangeType.NULLABLE_CHANGED:
            return f"op.alter_column('payloads', '{field_name}', nullable={modification.new_value})"
        return ""
    
    def _generate_restore_column(self, field_name: str) -> str:
        """Generate code to restore a dropped column."""
        return f"op.add_column('payloads', sa.Column('{field_name}', sa.String()))"
    
    def _generate_revert_column(
        self,
        field_name: str,
        modification: FieldModification
    ) -> str:
        """Generate code to revert a column modification."""
        if modification.change_type == FieldChangeType.TYPE_CHANGED:
            return f"op.alter_column('payloads', '{field_name}', type_=sa.String())"
        elif modification.change_type == FieldChangeType.NULLABLE_CHANGED:
            return f"op.alter_column('payloads', '{field_name}', nullable={modification.old_value})"
        return ""
    
    def _generate_version(self) -> str:
        """Generate migration version string."""
        return datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    
    def _generate_description(self, changeset: ChangeSet) -> str:
        """Generate migration description."""
        parts = []
        if changeset.added_fields:
            parts.append(f"Add {len(changeset.added_fields)} fields")
        if changeset.removed_fields:
            parts.append(f"Remove {len(changeset.removed_fields)} fields")
        if changeset.modified_fields:
            parts.append(f"Modify {len(changeset.modified_fields)} fields")
        
        return " | ".join(parts) if parts else "Schema update"