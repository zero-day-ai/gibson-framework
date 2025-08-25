"""File system organization for payload storage."""

import hashlib
import os
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union

import aiofiles
from loguru import logger

from gibson.models.payload import PayloadModel
from gibson.models.domain import AttackDomain


class PayloadOrganizer:
    """Manages file system organization of payload content.
    
    Organizes payloads in a structured directory hierarchy:
    {base_path}/
    ├── prompts/
    │   ├── injection/
    │   ├── jailbreak/
    │   └── ...
    ├── data/
    │   ├── poisoning/
    │   ├── backdoor/
    │   └── ...
    └── ...
    """
    
    def __init__(self, base_path: Path):
        """Initialize organizer with base storage path.
        
        Args:
            base_path: Root directory for payload storage
        """
        self.base_path = Path(base_path)
        self._ensure_directory_structure()
    
    def _ensure_directory_structure(self) -> None:
        """Ensure required directory structure exists."""
        try:
            # Create base directory
            self.base_path.mkdir(parents=True, exist_ok=True)
            
            # Create domain directories
            for domain in AttackDomain:
                domain_path = self.base_path / domain.value
                domain_path.mkdir(exist_ok=True)
                
                # Create common attack type directories
                attack_types = self._get_common_attack_types(domain)
                for attack_type in attack_types:
                    (domain_path / attack_type).mkdir(exist_ok=True)
                    
            logger.debug(f"Payload directory structure ensured at {self.base_path}")
            
        except Exception as e:
            logger.error(f"Failed to create directory structure: {e}")
            raise
    
    def _get_common_attack_types(self, domain: AttackDomain) -> List[str]:
        """Get common attack types for a domain."""
        attack_types_map = {
            AttackDomain.PROMPT: [
                'injection', 'jailbreak', 'context_steering', 'role_play',
                'instruction_bypass', 'token_smuggling'
            ],
            AttackDomain.DATA: [
                'poisoning', 'backdoor', 'membership_inference', 'extraction',
                'reconstruction', 'inversion'
            ],
            AttackDomain.MODEL: [
                'theft', 'fingerprinting', 'evasion', 'adversarial',
                'model_inversion', 'watermarking'
            ],
            AttackDomain.SYSTEM: [
                'enumeration', 'privilege_escalation', 'directory_traversal',
                'information_disclosure', 'configuration_bypass'
            ],
            AttackDomain.OUTPUT: [
                'injection', 'content_steering', 'format_string',
                'template_injection', 'response_manipulation'
            ]
        }
        return attack_types_map.get(domain, [])
    
    def generate_file_path(
        self, 
        payload: PayloadModel, 
        extension: str = ".txt"
    ) -> Path:
        """Generate file path for payload storage.
        
        Args:
            payload: Payload to store
            extension: File extension to use
            
        Returns:
            Path where payload should be stored
        """
        # Sanitize name for file system
        safe_name = self._sanitize_filename(payload.name)
        
        # Use hash as unique identifier if name conflict might occur
        filename = f"{safe_name}_{payload.hash[:8]}{extension}"
        
        # Build path: domain/category/filename
        # Handle both string and enum types
        domain_str = payload.domain if isinstance(payload.domain, str) else payload.domain.value
        category_str = payload.category if isinstance(payload.category, str) else payload.category.value
        domain_path = self.base_path / domain_str
        category_path = domain_path / category_str
        
        # Ensure attack type directory exists
        category_path.mkdir(parents=True, exist_ok=True)
        
        return category_path / filename
    
    def _sanitize_filename(self, name: str, max_length: int = 100) -> str:
        """Sanitize filename for file system compatibility.
        
        Args:
            name: Original filename
            max_length: Maximum length for filename
            
        Returns:
            Sanitized filename safe for file system
        """
        # Replace problematic characters
        safe_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_."
        sanitized = "".join(c if c in safe_chars else "_" for c in name)
        
        # Remove multiple underscores
        while "__" in sanitized:
            sanitized = sanitized.replace("__", "_")
            
        # Trim length
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length]
            
        # Ensure not empty
        if not sanitized:
            sanitized = "payload"
            
        return sanitized.strip("_")
    
    async def store_payload(self, payload: PayloadModel) -> Path:
        """Store payload content to file system.
        
        Args:
            payload: Payload to store
            
        Returns:
            Path where payload was stored
            
        Raises:
            OSError: If file cannot be written
        """
        file_path = self.generate_file_path(payload)
        
        try:
            # Write payload content to file
            async with aiofiles.open(file_path, 'w', encoding='utf-8') as f:
                await f.write(payload.content)
            
            # Note: file_path is not stored in PayloadModel
            
            logger.debug(f"Stored payload {payload.name} at {file_path}")
            return file_path
            
        except Exception as e:
            logger.error(f"Failed to store payload {payload.name}: {e}")
            raise
    
    async def load_payload_content(self, file_path: Path) -> str:
        """Load payload content from file system.
        
        Args:
            file_path: Path to payload file
            
        Returns:
            Payload content as string
            
        Raises:
            FileNotFoundError: If file does not exist
            OSError: If file cannot be read
        """
        try:
            async with aiofiles.open(file_path, 'r', encoding='utf-8') as f:
                content = await f.read()
            
            logger.debug(f"Loaded payload content from {file_path}")
            return content
            
        except FileNotFoundError:
            logger.error(f"Payload file not found: {file_path}")
            raise
        except Exception as e:
            logger.error(f"Failed to load payload from {file_path}: {e}")
            raise
    
    async def delete_payload_file(self, file_path: Path) -> bool:
        """Delete payload file from file system.
        
        Args:
            file_path: Path to payload file
            
        Returns:
            True if file was deleted successfully
        """
        try:
            if file_path.exists():
                file_path.unlink()
                logger.debug(f"Deleted payload file {file_path}")
                return True
            else:
                logger.warning(f"Payload file not found for deletion: {file_path}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to delete payload file {file_path}: {e}")
            return False
    
    def get_domain_path(self, domain: Union[str, AttackDomain]) -> Path:
        """Get path for a specific domain.
        
        Args:
            domain: Payload domain
            
        Returns:
            Path to domain directory
        """
        domain_str = domain if isinstance(domain, str) else domain.value
        return self.base_path / domain_str
    
    def get_attack_type_path(self, domain: Union[str, AttackDomain], attack_type: str) -> Path:
        """Get path for a specific attack type within a domain.
        
        Args:
            domain: Payload domain
            attack_type: Attack type name
            
        Returns:
            Path to attack type directory
        """
        domain_str = domain if isinstance(domain, str) else domain.value
        return self.base_path / domain_str / attack_type
    
    def list_payload_files(
        self, 
        domain: Optional[Union[str, AttackDomain]] = None,
        attack_type: Optional[str] = None
    ) -> List[Path]:
        """List all payload files in storage.
        
        Args:
            domain: Optional domain filter
            attack_type: Optional attack type filter
            
        Returns:
            List of payload file paths
        """
        payload_files = []
        
        try:
            if domain and attack_type:
                # List files in specific attack type
                search_path = self.get_attack_type_path(domain, attack_type)
                if search_path.exists():
                    payload_files.extend(search_path.glob("*.txt"))
                    
            elif domain:
                # List files in specific domain
                search_path = self.get_domain_path(domain)
                if search_path.exists():
                    payload_files.extend(search_path.glob("**/*.txt"))
                    
            else:
                # List all files
                for domain_enum in AttackDomain:
                    domain_path = self.get_domain_path(domain_enum)
                    if domain_path.exists():
                        payload_files.extend(domain_path.glob("**/*.txt"))
            
            logger.debug(f"Found {len(payload_files)} payload files")
            return sorted(payload_files)
            
        except Exception as e:
            logger.error(f"Failed to list payload files: {e}")
            return []
    
    def get_storage_stats(self) -> Dict[str, any]:
        """Get storage statistics.
        
        Returns:
            Dictionary with storage statistics
        """
        try:
            stats = {
                'total_files': 0,
                'total_size_bytes': 0,
                'domains': {},
                'largest_files': [],
                'oldest_files': [],
                'newest_files': []
            }
            
            all_files = self.list_payload_files()
            stats['total_files'] = len(all_files)
            
            file_info = []
            
            for file_path in all_files:
                if file_path.exists():
                    stat = file_path.stat()
                    size = stat.st_size
                    mtime = stat.st_mtime
                    
                    stats['total_size_bytes'] += size
                    
                    # Determine domain from path
                    domain_name = file_path.parent.parent.name
                    attack_type = file_path.parent.name
                    
                    if domain_name not in stats['domains']:
                        stats['domains'][domain_name] = {
                            'files': 0,
                            'size_bytes': 0,
                            'attack_types': set()
                        }
                    
                    stats['domains'][domain_name]['files'] += 1
                    stats['domains'][domain_name]['size_bytes'] += size
                    stats['domains'][domain_name]['attack_types'].add(attack_type)
                    
                    file_info.append({
                        'path': file_path,
                        'size': size,
                        'mtime': mtime
                    })
            
            # Convert sets to lists for serialization
            for domain_stats in stats['domains'].values():
                domain_stats['attack_types'] = list(domain_stats['attack_types'])
            
            # Get top files by size
            file_info.sort(key=lambda x: x['size'], reverse=True)
            stats['largest_files'] = [
                {'path': str(f['path']), 'size_bytes': f['size']} 
                for f in file_info[:10]
            ]
            
            # Get oldest and newest files
            file_info.sort(key=lambda x: x['mtime'])
            stats['oldest_files'] = [
                {'path': str(f['path']), 'modified': f['mtime']} 
                for f in file_info[:5]
            ]
            
            file_info.sort(key=lambda x: x['mtime'], reverse=True)
            stats['newest_files'] = [
                {'path': str(f['path']), 'modified': f['mtime']} 
                for f in file_info[:5]
            ]
            
            return stats
            
        except Exception as e:
            logger.error(f"Failed to get storage stats: {e}")
            return {}
    
    def cleanup_empty_directories(self) -> int:
        """Remove empty directories from payload storage.
        
        Returns:
            Number of directories removed
        """
        removed_count = 0
        
        try:
            # Walk from deepest to shallowest to handle nested empty dirs
            for root, dirs, files in os.walk(self.base_path, topdown=False):
                root_path = Path(root)
                
                # Skip if this is the base path
                if root_path == self.base_path:
                    continue
                
                # Check if directory is empty
                try:
                    if not any(root_path.iterdir()):
                        # Don't remove domain directories
                        if root_path.parent != self.base_path or root_path.name not in [d.value for d in AttackDomain]:
                            root_path.rmdir()
                            removed_count += 1
                            logger.debug(f"Removed empty directory: {root_path}")
                except OSError:
                    # Directory not empty or other error
                    pass
            
            if removed_count > 0:
                logger.info(f"Cleaned up {removed_count} empty directories")
                
            return removed_count
            
        except Exception as e:
            logger.error(f"Failed to cleanup empty directories: {e}")
            return 0
    
    def validate_file_integrity(self, payload: PayloadModel) -> bool:
        """Validate payload file integrity against metadata.
        
        Args:
            payload: Payload to validate
            
        Returns:
            True if file matches payload metadata
        """
        try:
            if not payload.file_path or not payload.file_path.exists():
                logger.warning(f"Payload file missing: {payload.name}")
                return False
            
            # Read file content
            with open(payload.file_path, 'r', encoding='utf-8') as f:
                file_content = f.read()
            
            # Compare with payload content
            if file_content != payload.content:
                logger.warning(f"Content mismatch for payload: {payload.name}")
                return False
            
            # Verify hash
            file_hash = hashlib.md5(file_content.encode()).hexdigest()[:16]
            if file_hash != payload.hash:
                logger.warning(f"Hash mismatch for payload: {payload.name}")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to validate file integrity for {payload.name}: {e}")
            return False
    
    async def move_payload_file(
        self, 
        old_path: Path, 
        new_payload: PayloadModel
    ) -> Optional[Path]:
        """Move payload file to new location based on updated metadata.
        
        Args:
            old_path: Current file path
            new_payload: Updated payload with new metadata
            
        Returns:
            New file path if successful, None otherwise
        """
        try:
            if not old_path.exists():
                logger.error(f"Source file does not exist: {old_path}")
                return None
            
            new_path = self.generate_file_path(new_payload)
            
            # Create target directory if needed
            new_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Move file
            shutil.move(str(old_path), str(new_path))
            
            logger.debug(f"Moved payload file from {old_path} to {new_path}")
            return new_path
            
        except Exception as e:
            logger.error(f"Failed to move payload file: {e}")
            return None