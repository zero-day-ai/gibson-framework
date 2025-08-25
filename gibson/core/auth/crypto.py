"""Cryptographic utilities for secure credential storage.

Provides AES-256-GCM encryption with secure key derivation for
protecting API keys and other sensitive authentication data.
"""

import hashlib
import os
import secrets
from typing import Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from loguru import logger


class CredentialEncryption:
    """Secure encryption for API credentials using AES-256-GCM."""
    
    # Encryption constants
    KEY_SIZE = 32  # AES-256 key size in bytes
    IV_SIZE = 12  # GCM IV size in bytes
    TAG_SIZE = 16  # GCM authentication tag size in bytes
    SALT_SIZE = 32  # PBKDF2 salt size in bytes
    PBKDF2_ITERATIONS = 100000  # PBKDF2 iteration count
    
    def __init__(self, master_key: Optional[str] = None):
        """Initialize credential encryption.
        
        Args:
            master_key: Master encryption key. If None, generates a new key.
        """
        if master_key:
            self._master_key = master_key.encode('utf-8')
        else:
            self._master_key = self._generate_master_key()
    
    @classmethod
    def _generate_master_key(cls) -> bytes:
        """Generate a cryptographically secure master key."""
        return secrets.token_bytes(cls.KEY_SIZE)
    
    def _derive_key(self, target_id: str, salt: bytes) -> bytes:
        """Derive encryption key from master key and target ID.
        
        Args:
            target_id: Unique target identifier
            salt: Random salt for key derivation
            
        Returns:
            Derived encryption key
        """
        # Combine master key with target ID for unique key per target
        key_material = self._master_key + target_id.encode('utf-8')
        
        # Use PBKDF2 for secure key derivation
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_SIZE,
            salt=salt,
            iterations=self.PBKDF2_ITERATIONS,
        )
        
        return kdf.derive(key_material)
    
    def encrypt_credential(
        self,
        credential_data: str,
        target_id: str
    ) -> Tuple[bytes, str]:
        """Encrypt credential data for secure storage.
        
        Args:
            credential_data: Plaintext credential (API key, etc.)
            target_id: Unique target identifier
            
        Returns:
            Tuple of (encrypted_data, key_id) where key_id identifies
            the encryption parameters for later decryption
        """
        try:
            # Generate random salt and IV
            salt = secrets.token_bytes(self.SALT_SIZE)
            iv = secrets.token_bytes(self.IV_SIZE)
            
            # Derive encryption key
            key = self._derive_key(target_id, salt)
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(iv)
            )
            
            # Encrypt the credential
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(credential_data.encode('utf-8'))
            encryptor.finalize()
            
            # Get authentication tag
            tag = encryptor.tag
            
            # Combine salt, IV, tag, and ciphertext
            encrypted_data = salt + iv + tag + ciphertext
            
            # Generate key ID for tracking
            key_id = hashlib.sha256(salt + target_id.encode('utf-8')).hexdigest()[:16]
            
            # Clear sensitive data from memory
            self._secure_zero_memory(key)
            
            logger.debug(f"Successfully encrypted credential for target {target_id}")
            return encrypted_data, key_id
            
        except Exception as e:
            logger.error(f"Failed to encrypt credential for target {target_id}: {e}")
            raise RuntimeError(f"Credential encryption failed: {e}") from e
    
    def decrypt_credential(
        self,
        encrypted_data: bytes,
        target_id: str
    ) -> str:
        """Decrypt credential data from secure storage.
        
        Args:
            encrypted_data: Encrypted credential data
            target_id: Unique target identifier used during encryption
            
        Returns:
            Decrypted credential string
        """
        try:
            # Extract components from encrypted data
            if len(encrypted_data) < self.SALT_SIZE + self.IV_SIZE + self.TAG_SIZE:
                raise ValueError("Encrypted data is too short")
            
            salt = encrypted_data[:self.SALT_SIZE]
            iv = encrypted_data[self.SALT_SIZE:self.SALT_SIZE + self.IV_SIZE]
            tag = encrypted_data[self.SALT_SIZE + self.IV_SIZE:self.SALT_SIZE + self.IV_SIZE + self.TAG_SIZE]
            ciphertext = encrypted_data[self.SALT_SIZE + self.IV_SIZE + self.TAG_SIZE:]
            
            # Derive the same encryption key
            key = self._derive_key(target_id, salt)
            
            # Create cipher for decryption
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(iv, tag)
            )
            
            # Decrypt the credential
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext)
            decryptor.finalize()  # Verifies authentication tag
            
            # Clear sensitive data from memory
            self._secure_zero_memory(key)
            
            credential = plaintext.decode('utf-8')
            logger.debug(f"Successfully decrypted credential for target {target_id}")
            
            return credential
            
        except Exception as e:
            logger.error(f"Failed to decrypt credential for target {target_id}: {e}")
            raise RuntimeError(f"Credential decryption failed: {e}") from e
    
    def _secure_zero_memory(self, data: bytes) -> None:
        """Attempt to securely clear sensitive data from memory.
        
        Note: This provides best-effort memory clearing, but Python's
        garbage collector and memory management may still leave traces.
        """
        if isinstance(data, bytes):
            # Overwrite the memory with zeros
            try:
                # This is a best-effort attempt
                for i in range(len(data)):
                    data = data[:i] + b'\x00' + data[i+1:]
            except Exception:
                # Memory might be immutable, ignore errors
                pass
    
    def rotate_master_key(self, new_master_key: str) -> None:
        """Rotate the master encryption key.
        
        Warning: This will invalidate all existing encrypted credentials.
        Use credential re-encryption utilities after rotation.
        
        Args:
            new_master_key: New master key for encryption
        """
        old_key = self._master_key
        self._master_key = new_master_key.encode('utf-8')
        
        # Clear old key from memory
        self._secure_zero_memory(old_key)
        
        logger.info("Master encryption key rotated")
    
    def verify_encryption(self, credential_data: str, target_id: str) -> bool:
        """Test encryption/decryption round-trip for verification.
        
        Args:
            credential_data: Test credential data
            target_id: Test target identifier
            
        Returns:
            True if encryption/decryption works correctly
        """
        try:
            encrypted_data, key_id = self.encrypt_credential(credential_data, target_id)
            decrypted_data = self.decrypt_credential(encrypted_data, target_id)
            return decrypted_data == credential_data
        except Exception as e:
            logger.error(f"Encryption verification failed: {e}")
            return False
    
    @classmethod
    def generate_secure_key_id(cls, target_id: str, timestamp: str = None) -> str:
        """Generate a secure key identifier for tracking.
        
        Args:
            target_id: Target identifier
            timestamp: Optional timestamp (uses current time if None)
            
        Returns:
            Secure key identifier
        """
        if timestamp is None:
            import time
            timestamp = str(int(time.time()))
        
        key_material = f"{target_id}:{timestamp}:{secrets.token_hex(8)}"
        return hashlib.sha256(key_material.encode('utf-8')).hexdigest()[:16]
    
    @classmethod
    def is_encryption_available(cls) -> bool:
        """Check if encryption libraries are available and working.
        
        Returns:
            True if encryption is available
        """
        try:
            # Test that we can create encryption objects
            test_key = secrets.token_bytes(cls.KEY_SIZE)
            test_iv = secrets.token_bytes(cls.IV_SIZE)
            
            cipher = Cipher(
                algorithms.AES(test_key),
                modes.GCM(test_iv)
            )
            
            encryptor = cipher.encryptor()
            encryptor.update(b"test")
            encryptor.finalize()
            
            return True
        except Exception as e:
            logger.error(f"Encryption not available: {e}")
            return False


def get_system_entropy() -> int:
    """Get available system entropy for key generation.
    
    Returns:
        Available entropy in bytes, or -1 if unknown
    """
    try:
        if os.path.exists('/proc/sys/kernel/random/entropy_avail'):
            with open('/proc/sys/kernel/random/entropy_avail', 'r') as f:
                return int(f.read().strip())
    except Exception:
        pass
    
    return -1  # Unknown entropy


def secure_compare(a: bytes, b: bytes) -> bool:
    """Perform timing-attack resistant comparison.
    
    Args:
        a: First byte string
        b: Second byte string
        
    Returns:
        True if byte strings are equal
    """
    return secrets.compare_digest(a, b)
