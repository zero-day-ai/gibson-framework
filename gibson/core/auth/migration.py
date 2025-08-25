"""Authentication migration utilities."""
import json
from pathlib import Path
from typing import Dict, List, Any


class AuthMigration:
    """Handles credential migration between versions."""

    def __init__(self):
        self.migrations = []

    async def migrate_v1_to_v2(self, old_data: Dict) -> Dict:
        """Migrate from v1 to v2 format."""
        new_data = {"version": "2.0", "credentials": []}
        for cred in old_data.get("credentials", []):
            new_cred = {
                **cred,
                "auth_format": cred.get("format", "bearer"),
                "metadata": cred.get("metadata", {}),
            }
            new_data["credentials"].append(new_cred)
        return new_data

    async def run_migrations(self, data: Dict) -> Dict:
        """Run all necessary migrations."""
        version = data.get("version", "1.0")
        if version == "1.0":
            data = await self.migrate_v1_to_v2(data)
        return data
