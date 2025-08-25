"""Credential management for secure API key storage and retrieval.

Provides encrypted file-based storage for API keys with metadata tracking,
secure permissions, and comprehensive lifecycle management.
"""

import json
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
from uuid import UUID, uuid4

from loguru import logger

from gibson.core.auth.config import (
    resolve_credentials_path,
    ensure_directory_permissions,
    ensure_file_permissions,
    load_environment_credentials
)
from gibson.core.auth.crypto import CredentialEncryption
from gibson.models.auth import (
    ApiKeyCredentialModel,
    EncryptedCredential,
    CredentialMetadata,
    ApiKeyFormat,
    ValidationStatus
)


class CredentialManagerError(Exception):
    """Base exception for credential manager errors."""
    pass


class CredentialNotFoundError(CredentialManagerError):
    """Raised when a credential is not found."""
    pass


class CredentialStorageError(CredentialManagerError):
    """Raised when credential storage operations fail."""
    pass


class CredentialManager:
    """Secure credential storage and management."""
    
    def __init__(self, master_key: Optional[str] = None):
        """Initialize credential manager.
        
        Args:
            master_key: Master encryption key. If None, generates default key.
        """
        self.credentials_dir = resolve_credentials_path()
        self.encryption = CredentialEncryption(master_key)
        self._metadata_cache: Dict[str, CredentialMetadata] = {}
        self._ensure_storage_setup()
    
    def _ensure_storage_setup(self) -> None:
        """Ensure credential storage directory exists with secure permissions."""
        try:
            ensure_directory_permissions(self.credentials_dir)
            
            # Create metadata directory
            metadata_dir = self.credentials_dir / 'metadata'
            ensure_directory_permissions(metadata_dir)
            
            logger.debug(f"Credential storage initialized at: {self.credentials_dir}")
        except Exception as e:
            raise CredentialStorageError(f"Failed to initialize storage: {e}") from e
    
    def _get_credential_file_path(self, target_id: UUID) -> Path:
        """Get file path for encrypted credential storage."""
        return self.credentials_dir / f"{target_id}.enc"
    
    def _get_metadata_file_path(self, target_id: UUID) -> Path:
        """Get file path for credential metadata."""
        return self.credentials_dir / 'metadata' / f"{target_id}.json"
    
    def _save_metadata(self, target_id: UUID, metadata: CredentialMetadata) -> None:
        """Save credential metadata to file."""
        try:
            metadata_path = self._get_metadata_file_path(target_id)
            
            with open(metadata_path, 'w') as f:
                json.dump(metadata.model_dump(), f, indent=2, default=str)
            
            ensure_file_permissions(metadata_path)
            
            # Update cache
            self._metadata_cache[str(target_id)] = metadata
            
        except Exception as e:
            raise CredentialStorageError(f"Failed to save metadata for {target_id}: {e}") from e
    
    def _load_metadata(self, target_id: UUID) -> Optional[CredentialMetadata]:
        """Load credential metadata from file."""
        # Check cache first
        cache_key = str(target_id)
        if cache_key in self._metadata_cache:
            return self._metadata_cache[cache_key]
        
        metadata_path = self._get_metadata_file_path(target_id)
        
        if not metadata_path.exists():
            return None
        
        try:
            with open(metadata_path, 'r') as f:
                metadata_data = json.load(f)
            
            metadata = CredentialMetadata(**metadata_data)
            
            # Update cache
            self._metadata_cache[cache_key] = metadata
            
            return metadata
            
        except Exception as e:
            logger.warning(f"Failed to load metadata for {target_id}: {e}")
            return None
    
    def store_credential(
        self,
        target_id: UUID,
        credential: ApiKeyCredentialModel,
        target_name: Optional[str] = None
    ) -> bool:
        """Store encrypted credential with metadata.
        
        Args:
            target_id: Unique target identifier
            credential: API key credential to store
            target_name: Human-readable target name
            
        Returns:
            True if stored successfully
        """
        try:
            # Validate credential
            if not credential.token:
                raise ValueError("Credential token is required")
            
            # Encrypt the credential data
            credential_json = credential.model_dump_json()
            encrypted_data, key_id = self.encryption.encrypt_credential(
                credential_json,
                str(target_id)
            )
            
            # Save encrypted credential
            credential_path = self._get_credential_file_path(target_id)
            with open(credential_path, 'wb') as f:
                f.write(encrypted_data)
            
            ensure_file_permissions(credential_path)
            
            # Create and save metadata
            metadata = CredentialMetadata(
                credential_id=uuid4(),
                target_id=target_id,
                target_name=target_name,
                key_format=credential.key_format,
                masked_key=CredentialMetadata.mask_api_key(credential.token),
                validation_status=credential.validation_status,
                last_validated=credential.last_validated,
                last_used=credential.last_used,
                usage_count=credential.usage_count,
                created_at=datetime.utcnow()
            )
            
            self._save_metadata(target_id, metadata)
            
            logger.info(f"Successfully stored credential for target {target_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to store credential for target {target_id}: {e}")
            return False
    
    def retrieve_credential(self, target_id: UUID) -> Optional[ApiKeyCredentialModel]:
        """Retrieve and decrypt credential.
        
        Args:
            target_id: Unique target identifier
            
        Returns:
            Decrypted credential or None if not found
        """
        try:
            credential_path = self._get_credential_file_path(target_id)
            
            if not credential_path.exists():
                # Check environment variables as fallback
                env_creds = load_environment_credentials()
                target_str = str(target_id).replace('-', '').lower()[:8]
                
                for env_target, api_key in env_creds.items():
                    if env_target.startswith(target_str) or target_str.startswith(env_target):
                        logger.debug(f"Found environment credential for target {target_id}")
                        return ApiKeyCredentialModel(
                            auth_type='api_key',
                            token=api_key,
                            key_format=ApiKeyFormat.BEARER_TOKEN,
                            validation_status=ValidationStatus.UNTESTED,
                            environment_variable=f"GIBSON_API_KEY_{env_target.upper()}"
                        )
                
                raise CredentialNotFoundError(f"No credential found for target {target_id}")
            
            # Read encrypted data
            with open(credential_path, 'rb') as f:
                encrypted_data = f.read()
            
            # Decrypt credential
            credential_json = self.encryption.decrypt_credential(
                encrypted_data,
                str(target_id)
            )
            
            # Parse credential
            credential_data = json.loads(credential_json)
            credential = ApiKeyCredentialModel(**credential_data)
            
            # Update usage tracking
            self._update_usage_tracking(target_id)
            
            logger.debug(f"Successfully retrieved credential for target {target_id}")
            return credential
            
        except CredentialNotFoundError:
            raise
        except Exception as e:
            logger.error(f"Failed to retrieve credential for target {target_id}: {e}")
            return None
    
    def delete_credential(self, target_id: UUID) -> bool:
        """Delete credential and metadata.
        
        Args:
            target_id: Unique target identifier
            
        Returns:
            True if deleted successfully
        """
        try:
            credential_path = self._get_credential_file_path(target_id)
            metadata_path = self._get_metadata_file_path(target_id)
            
            deleted_any = False
            
            # Delete credential file
            if credential_path.exists():
                credential_path.unlink()
                deleted_any = True
                logger.debug(f"Deleted credential file for target {target_id}")
            
            # Delete metadata file
            if metadata_path.exists():
                metadata_path.unlink()
                deleted_any = True
                logger.debug(f"Deleted metadata file for target {target_id}")
            
            # Remove from cache
            cache_key = str(target_id)
            if cache_key in self._metadata_cache:
                del self._metadata_cache[cache_key]
            
            if deleted_any:
                logger.info(f"Successfully deleted credential for target {target_id}")
                return True
            else:
                logger.warning(f"No credential found to delete for target {target_id}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to delete credential for target {target_id}: {e}")
            return False
    
    def list_credentials(self) -> List[CredentialMetadata]:
        """List all stored credentials with metadata.
        
        Returns:
            List of credential metadata
        """
        try:
            credentials = []
            
            # Scan for credential files
            if self.credentials_dir.exists():
                for cred_file in self.credentials_dir.glob('*.enc'):
                    try:
                        target_id = UUID(cred_file.stem)
                        metadata = self._load_metadata(target_id)
                        
                        if metadata:
                            credentials.append(metadata)
                        else:
                            # Create minimal metadata from file
                            stat_info = cred_file.stat()
                            credentials.append(CredentialMetadata(
                                credential_id=uuid4(),
                                target_id=target_id,
                                key_format=ApiKeyFormat.BEARER_TOKEN,
                                masked_key="****",
                                validation_status=ValidationStatus.UNTESTED,
                                created_at=datetime.fromtimestamp(stat_info.st_ctime)
                            ))
                    
                    except (ValueError, OSError) as e:
                        logger.warning(f"Skipping invalid credential file {cred_file}: {e}")
            
            # Add environment credentials
            env_creds = load_environment_credentials()
            for target_name, api_key in env_creds.items():
                credentials.append(CredentialMetadata(
                    credential_id=uuid4(),
                    target_id=uuid4(),  # Generate temporary ID
                    target_name=target_name,
                    key_format=ApiKeyFormat.BEARER_TOKEN,
                    masked_key=CredentialMetadata.mask_api_key(api_key),
                    validation_status=ValidationStatus.UNTESTED,
                    created_at=datetime.utcnow()
                ))
            
            # Sort by creation date (newest first)
            credentials.sort(key=lambda x: x.created_at, reverse=True)
            
            logger.debug(f"Listed {len(credentials)} credentials")
            return credentials
            
        except Exception as e:
            logger.error(f"Failed to list credentials: {e}")
            return []
    
    def credential_exists(self, target_id: UUID) -> bool:
        """Check if credential exists for target.
        
        Args:
            target_id: Unique target identifier
            
        Returns:
            True if credential exists
        """
        credential_path = self._get_credential_file_path(target_id)
        return credential_path.exists()
    
    def update_credential_metadata(
        self,
        target_id: UUID,
        validation_status: Optional[ValidationStatus] = None,
        last_validated: Optional[datetime] = None,
        error_message: Optional[str] = None
    ) -> bool:
        """Update credential metadata.
        
        Args:
            target_id: Unique target identifier
            validation_status: New validation status
            last_validated: Validation timestamp
            error_message: Error message if validation failed
            
        Returns:
            True if updated successfully
        """
        try:
            metadata = self._load_metadata(target_id)
            if not metadata:
                logger.warning(f"No metadata found for target {target_id}")
                return False
            
            # Update fields
            if validation_status is not None:
                metadata.validation_status = validation_status
            if last_validated is not None:
                metadata.last_validated = last_validated
            
            # Save updated metadata
            self._save_metadata(target_id, metadata)
            
            logger.debug(f"Updated metadata for target {target_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to update metadata for target {target_id}: {e}")
            return False
    
    def _update_usage_tracking(self, target_id: UUID) -> None:
        """Update usage tracking for credential."""
        try:
            metadata = self._load_metadata(target_id)
            if metadata:
                metadata.usage_count += 1
                metadata.last_used = datetime.utcnow()
                self._save_metadata(target_id, metadata)
        except Exception as e:
            logger.warning(f"Failed to update usage tracking for {target_id}: {e}")
    
    def cleanup_expired_credentials(self) -> int:
        """Remove expired credentials.
        
        Returns:
            Number of credentials cleaned up
        """
        cleaned_count = 0
        
        try:
            for metadata in self.list_credentials():
                if metadata.expires_at and metadata.expires_at < datetime.utcnow():
                    if self.delete_credential(metadata.target_id):
                        cleaned_count += 1
                        logger.info(f"Cleaned up expired credential for target {metadata.target_id}")
        
        except Exception as e:
            logger.error(f"Failed to cleanup expired credentials: {e}")
        
        return cleaned_count
    
    def export_credentials_metadata(self) -> Dict[str, Any]:
        """Export credential metadata (without sensitive data).
        
        Returns:
            Dictionary with credential metadata
        """
        try:
            credentials = self.list_credentials()
            
            export_data = {
                'export_timestamp': datetime.utcnow().isoformat(),
                'credential_count': len(credentials),
                'credentials': []
            }
            
            for cred in credentials:
                export_data['credentials'].append({
                    'target_id': str(cred.target_id),
                    'target_name': cred.target_name,
                    'key_format': cred.key_format.value,
                    'masked_key': cred.masked_key,
                    'validation_status': cred.validation_status.value,
                    'created_at': cred.created_at.isoformat(),
                    'last_used': cred.last_used.isoformat() if cred.last_used else None,
                    'usage_count': cred.usage_count
                })
            
            return export_data
            
        except Exception as e:
            logger.error(f"Failed to export credential metadata: {e}")
            return {'error': str(e)}
    
    def get_storage_info(self) -> Dict[str, Any]:
        """Get information about credential storage.
        
        Returns:
            Dictionary with storage information
        """
        try:
            info = {
                'credentials_directory': str(self.credentials_dir),
                'directory_exists': self.credentials_dir.exists(),
                'encryption_available': CredentialEncryption.is_encryption_available(),
                'credential_count': 0,
                'storage_size_bytes': 0
            }
            
            if self.credentials_dir.exists():
                # Count credentials
                credential_files = list(self.credentials_dir.glob('*.enc'))
                info['credential_count'] = len(credential_files)
                
                # Calculate storage size
                total_size = 0
                for cred_file in credential_files:
                    try:
                        total_size += cred_file.stat().st_size
                    except OSError:
                        pass
                
                info['storage_size_bytes'] = total_size
            
            return info
            
        except Exception as e:
            return {'error': str(e)}
