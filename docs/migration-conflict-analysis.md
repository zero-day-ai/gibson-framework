# Migration Conflict Analysis

## Current State

### Existing Migration Files (Active)
1. `344988d2ee43_initial_migration.py` - Created: 2025-08-25 05:47:25
   - Base revision: None (initial migration)
   - Creates all initial tables

2. `c0123ee10960_add_missing_usage_tracking_tables.py` - Created: 2025-08-25 06:11:16
   - Depends on: 344988d2ee43
   - Alters column types from NUMERIC to UUID

### Deleted Migration Files (Git Status)
1. `c36b794df3bb_initial_consolidated_database_schema.py` - DELETED
2. `df88a648bb7a_add_target_management_system.py` - DELETED  
3. `e2031ba7870c_add_targets_table.py` - DELETED

## Conflicts Identified

### Primary Issues
1. **Multiple Initial Migrations**: The deleted files suggest there were previous attempts at creating initial migrations that conflicted
2. **UUID Type Conflicts**: The second migration fixes UUID column types that were incorrectly created as NUMERIC
3. **Missing Tables**: No usage tracking tables in the initial migration despite the second migration's name suggesting they should be added

### Migration Sequence
The correct sequence is:
1. `344988d2ee43` (initial) → `c0123ee10960` (UUID fixes)

## Resolution Strategy

### Consolidation Plan
1. Create a single consolidated migration that:
   - Includes all tables from the initial migration
   - Uses correct UUID types from the start
   - Adds any missing usage tracking tables
   - Incorporates enhanced base model fields (audit, versioning, soft delete)

2. Archive existing migrations for reference
3. Update alembic_version table to point to new consolidated migration

### Tables to Include in Consolidated Migration

#### Core Tables
- api_keys
- audit_logs  
- authentication_tokens
- targets
- encrypted_credentials
- modules
- oauth_providers
- sessions

#### Attack Statistics Tables
- data_attack_stats
- model_attack_stats
- output_attack_stats
- prompt_attack_stats
- system_attack_stats

#### Payload Management Tables
- payload_collections
- payload_sources
- payloads
- payload_effectiveness
- prompt_sources
- prompt_collections
- prompts

#### Scan and Finding Tables
- scans
- findings
- module_results

#### Reporting Tables
- reports
- report_templates
- report_distributions
- report_schedules

#### Monitoring Tables
- performance_metrics
- security_event_logs
- migration_audit

#### Missing Usage Tracking Tables (to be added)
- llm_usage_tracking
- llm_provider_metrics
- api_usage_logs

## Next Steps

1. Create backup of current database
2. Generate consolidated migration with correct types
3. Archive old migration files  
4. Test migration on fresh database
5. Update alembic_version table