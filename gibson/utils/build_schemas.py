#!/usr/bin/env python3
"""
Build-time schema generation script.

This module is executed during Poetry build to automatically generate
JSON schemas, TypeScript types, and documentation from Pydantic models.
"""

import sys
from pathlib import Path
from typing import Optional
import logging

# Add project root to path for imports
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from scripts.generate_schemas import SchemaOrchestrator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def build_schemas(output_dir: Optional[Path] = None) -> bool:
    """Build schemas during Poetry build process.
    
    Args:
        output_dir: Optional output directory (defaults to project schemas/)
    
    Returns:
        True if successful, False otherwise
    """
    try:
        logger.info("Starting schema build process...")
        
        # Use default output directory if not specified
        if output_dir is None:
            output_dir = project_root / "schemas"
        
        # Create orchestrator with build configuration
        orchestrator = SchemaOrchestrator(
            output_dir=output_dir,
            version="latest",  # Will be overridden by version detection
        )
        
        # Generate all schemas
        success = orchestrator.generate_all()
        
        if success:
            logger.info("Schema build completed successfully")
        else:
            logger.error("Schema build failed")
        
        return success
        
    except Exception as e:
        logger.error(f"Schema build error: {e}")
        return False


def main():
    """Main entry point for build script."""
    success = build_schemas()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()