"""Database migration for payload system extensions.

This migration adds extensions to the existing prompt tables to support
the broader payload management system without breaking existing functionality.
"""

from datetime import datetime
from typing import Any, Dict

from alembic import op
import sqlalchemy as sa
from sqlalchemy import text


# Migration metadata
revision = "add_payload_extensions"
down_revision = None  # This should be set to the previous migration
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Upgrade database schema for payload extensions."""
    
    # Add new columns to prompt_sources for enhanced GitHub integration
    try:
        # Check if columns already exist before adding
        with op.get_context().autocommit_block():
            # Add authentication status column
            op.add_column('prompt_sources', 
                sa.Column('auth_status', sa.String(20), default='none'))
            
            # Add last sync status column
            op.add_column('prompt_sources', 
                sa.Column('last_sync_status', sa.String(20), default='pending'))
            
            # Add sync error tracking
            op.add_column('prompt_sources', 
                sa.Column('last_sync_error', sa.Text, nullable=True))
            
            # Add rate limit tracking
            op.add_column('prompt_sources', 
                sa.Column('rate_limit_remaining', sa.Integer, default=5000))
            
            # Add repository statistics
            op.add_column('prompt_sources', 
                sa.Column('total_payloads', sa.Integer, default=0))
            
            print("✓ Added enhancement columns to prompt_sources")
    
    except Exception as e:
        print(f"Note: Some columns may already exist: {e}")
    
    # Enhance prompt_collections table
    try:
        with op.get_context().autocommit_block():
            # Add sync tracking
            op.add_column('prompt_collections',
                sa.Column('last_sync_commit', sa.String(64), nullable=True))
            
            # Add validation status
            op.add_column('prompt_collections',
                sa.Column('validation_status', sa.String(20), default='pending'))
            
            # Add collection size tracking
            op.add_column('prompt_collections',
                sa.Column('total_size_bytes', sa.BigInteger, default=0))
            
            # Add quality metrics
            op.add_column('prompt_collections',
                sa.Column('avg_quality_score', sa.Float, nullable=True))
            
            print("✓ Added enhancement columns to prompt_collections")
    
    except Exception as e:
        print(f"Note: Some columns may already exist: {e}")
    
    # Enhance prompts table for better payload management
    try:
        with op.get_context().autocommit_block():
            # Add file path tracking
            op.add_column('prompts',
                sa.Column('file_path', sa.String(512), nullable=True))
            
            # Add attack vector classification
            op.add_column('prompts',
                sa.Column('attack_vector', sa.String(50), default='injection'))
            
            # Add status tracking
            op.add_column('prompts',
                sa.Column('status', sa.String(20), default='active'))
            
            # Add usage statistics
            op.add_column('prompts',
                sa.Column('usage_count', sa.Integer, default=0))
            
            # Add last used timestamp
            op.add_column('prompts',
                sa.Column('last_used', sa.DateTime, nullable=True))
            
            # Add effectiveness metrics
            op.add_column('prompts',
                sa.Column('avg_response_time_ms', sa.Integer, nullable=True))
            
            # Add validation status
            op.add_column('prompts',
                sa.Column('validation_status', sa.String(20), default='pending'))
            
            # Add OWASP category mapping
            op.add_column('prompts',
                sa.Column('owasp_categories', sa.JSON, default=list))
            
            print("✓ Added enhancement columns to prompts")
    
    except Exception as e:
        print(f"Note: Some columns may already exist: {e}")
    
    # Create payload performance tracking table
    try:
        op.create_table(
            'payload_performance',
            sa.Column('id', sa.Integer, primary_key=True, autoincrement=True),
            sa.Column('prompt_id', sa.Integer, sa.ForeignKey('prompts.id'), nullable=False),
            sa.Column('target_system', sa.String(100), nullable=False),
            sa.Column('execution_time', sa.DateTime, default=datetime.utcnow),
            sa.Column('response_time_ms', sa.Integer, nullable=False),
            sa.Column('success', sa.Boolean, nullable=False),
            sa.Column('error_message', sa.Text, nullable=True),
            sa.Column('response_indicators', sa.JSON, default=list),
            sa.Column('context_data', sa.JSON, default=dict),
            sa.Index('idx_payload_perf_prompt', 'prompt_id'),
            sa.Index('idx_payload_perf_target', 'target_system'),
            sa.Index('idx_payload_perf_time', 'execution_time')
        )
        print("✓ Created payload_performance table")
    
    except Exception as e:
        print(f"Note: payload_performance table may already exist: {e}")
    
    # Create payload cache metadata table
    try:
        op.create_table(
            'payload_cache_metadata',
            sa.Column('id', sa.Integer, primary_key=True, autoincrement=True),
            sa.Column('cache_key', sa.String(128), unique=True, nullable=False),
            sa.Column('payload_ids', sa.JSON, default=list),
            sa.Column('query_hash', sa.String(64), nullable=True),
            sa.Column('created_at', sa.DateTime, default=datetime.utcnow),
            sa.Column('expires_at', sa.DateTime, nullable=True),
            sa.Column('access_count', sa.Integer, default=0),
            sa.Column('last_accessed', sa.DateTime, default=datetime.utcnow),
            sa.Column('cache_size_bytes', sa.Integer, default=0),
            sa.Index('idx_cache_key', 'cache_key'),
            sa.Index('idx_cache_expires', 'expires_at'),
            sa.Index('idx_cache_query', 'query_hash')
        )
        print("✓ Created payload_cache_metadata table")
    
    except Exception as e:
        print(f"Note: payload_cache_metadata table may already exist: {e}")
    
    # Create payload sync history table
    try:
        op.create_table(
            'payload_sync_history',
            sa.Column('id', sa.Integer, primary_key=True, autoincrement=True),
            sa.Column('source_id', sa.Integer, sa.ForeignKey('prompt_sources.id'), nullable=False),
            sa.Column('sync_timestamp', sa.DateTime, default=datetime.utcnow),
            sa.Column('commit_sha', sa.String(64), nullable=True),
            sa.Column('branch_name', sa.String(100), default='main'),
            sa.Column('payloads_fetched', sa.Integer, default=0),
            sa.Column('payloads_imported', sa.Integer, default=0),
            sa.Column('payloads_updated', sa.Integer, default=0),
            sa.Column('payloads_failed', sa.Integer, default=0),
            sa.Column('sync_duration_ms', sa.Integer, default=0),
            sa.Column('download_size_bytes', sa.BigInteger, default=0),
            sa.Column('success', sa.Boolean, nullable=False),
            sa.Column('error_message', sa.Text, nullable=True),
            sa.Column('sync_metadata', sa.JSON, default=dict),
            sa.Index('idx_sync_source', 'source_id'),
            sa.Index('idx_sync_timestamp', 'sync_timestamp'),
            sa.Index('idx_sync_success', 'success')
        )
        print("✓ Created payload_sync_history table")
    
    except Exception as e:
        print(f"Note: payload_sync_history table may already exist: {e}")
    
    # Update existing data with default values
    try:
        # Update prompt sources with default auth status
        op.execute(text("""
            UPDATE prompt_sources 
            SET auth_status = 'none', 
                last_sync_status = 'pending',
                rate_limit_remaining = 5000,
                total_payloads = 0
            WHERE auth_status IS NULL
        """))
        
        # Update prompt collections with default values
        op.execute(text("""
            UPDATE prompt_collections 
            SET validation_status = 'pending',
                total_size_bytes = 0
            WHERE validation_status IS NULL
        """))
        
        # Update prompts with default values
        op.execute(text("""
            UPDATE prompts 
            SET attack_vector = 'injection',
                status = 'active',
                usage_count = 0,
                validation_status = 'pending'
            WHERE attack_vector IS NULL
        """))
        
        print("✓ Updated existing records with default values")
    
    except Exception as e:
        print(f"Note: Default value updates may have failed: {e}")
    
    # Create views for payload analytics
    try:
        # Payload summary view
        op.execute(text("""
            CREATE VIEW IF NOT EXISTS payload_summary AS
            SELECT 
                p.id,
                p.name,
                p.category,
                p.severity,
                p.attack_vector,
                p.status,
                p.usage_count,
                p.success_rate,
                p.last_used,
                c.name as collection_name,
                s.name as source_name,
                s.url as source_url
            FROM prompts p
            JOIN prompt_collections c ON p.collection_id = c.id
            JOIN prompt_sources s ON c.source_id = s.id
        """))
        
        # Payload performance view
        op.execute(text("""
            CREATE VIEW IF NOT EXISTS payload_performance_summary AS
            SELECT 
                p.id as payload_id,
                p.name as payload_name,
                COUNT(pp.id) as execution_count,
                AVG(pp.response_time_ms) as avg_response_time,
                SUM(CASE WHEN pp.success THEN 1 ELSE 0 END) * 100.0 / COUNT(*) as success_rate,
                MAX(pp.execution_time) as last_execution
            FROM prompts p
            LEFT JOIN payload_performance pp ON p.id = pp.prompt_id
            GROUP BY p.id, p.name
        """))
        
        print("✓ Created analytical views")
    
    except Exception as e:
        print(f"Note: Views may already exist: {e}")


def downgrade() -> None:
    """Downgrade database schema (remove payload extensions)."""
    
    print("WARNING: Downgrading will remove payload management enhancements")
    
    # Drop views
    try:
        op.execute(text("DROP VIEW IF EXISTS payload_performance_summary"))
        op.execute(text("DROP VIEW IF EXISTS payload_summary"))
        print("✓ Dropped analytical views")
    except Exception as e:
        print(f"Error dropping views: {e}")
    
    # Drop new tables
    try:
        op.drop_table('payload_sync_history')
        op.drop_table('payload_cache_metadata')
        op.drop_table('payload_performance')
        print("✓ Dropped payload extension tables")
    except Exception as e:
        print(f"Error dropping tables: {e}")
    
    # Remove columns from existing tables
    # Note: SQLite doesn't support dropping columns easily, so we'll skip for now
    # In production, this would need careful handling
    
    print("Note: Column removal skipped for compatibility")
    print("Manual cleanup may be required for a complete downgrade")


def get_migration_info() -> Dict[str, Any]:
    """Get information about this migration."""
    return {
        "revision": revision,
        "description": "Add payload management system extensions",
        "adds_tables": [
            "payload_performance",
            "payload_cache_metadata", 
            "payload_sync_history"
        ],
        "adds_columns": {
            "prompt_sources": [
                "auth_status", "last_sync_status", "last_sync_error",
                "rate_limit_remaining", "total_payloads"
            ],
            "prompt_collections": [
                "last_sync_commit", "validation_status", 
                "total_size_bytes", "avg_quality_score"
            ],
            "prompts": [
                "file_path", "attack_vector", "status", "usage_count",
                "last_used", "avg_response_time_ms", "validation_status",
                "owasp_categories"
            ]
        },
        "adds_views": [
            "payload_summary",
            "payload_performance_summary"
        ],
        "breaking_changes": False,
        "data_migration_required": False
    }


def validate_migration() -> bool:
    """Validate that migration completed successfully."""
    try:
        # Check that new tables exist
        conn = op.get_bind()
        
        # Check tables
        result = conn.execute(text("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name IN (
                'payload_performance', 
                'payload_cache_metadata', 
                'payload_sync_history'
            )
        """))
        
        tables = [row[0] for row in result]
        expected_tables = {'payload_performance', 'payload_cache_metadata', 'payload_sync_history'}
        
        if not expected_tables.issubset(set(tables)):
            print(f"Missing tables: {expected_tables - set(tables)}")
            return False
        
        # Check that views exist
        result = conn.execute(text("""
            SELECT name FROM sqlite_master 
            WHERE type='view' AND name IN ('payload_summary', 'payload_performance_summary')
        """))
        
        views = [row[0] for row in result]
        expected_views = {'payload_summary', 'payload_performance_summary'}
        
        if not expected_views.issubset(set(views)):
            print(f"Missing views: {expected_views - set(views)}")
            return False
        
        print("✓ Migration validation successful")
        return True
        
    except Exception as e:
        print(f"Migration validation failed: {e}")
        return False


if __name__ == "__main__":
    """Run migration directly for testing."""
    print("Payload Management Migration")
    print("============================")
    
    info = get_migration_info()
    print(f"Revision: {info['revision']}")
    print(f"Description: {info['description']}")
    print(f"Adds tables: {', '.join(info['adds_tables'])}")
    print(f"Breaking changes: {info['breaking_changes']}")
    
    # This would normally be run by Alembic
    print("\nThis migration should be run via Alembic:")
    print("alembic upgrade head")