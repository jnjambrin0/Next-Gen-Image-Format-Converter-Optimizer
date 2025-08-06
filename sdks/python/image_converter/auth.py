"""Secure API key management for Image Converter SDK."""

import os
import hashlib
import secrets
from typing import Optional
import keyring
from pathlib import Path
import json


class SecureAPIKeyManager:
    """Manages API keys securely using OS keychain."""
    
    SERVICE_NAME = "image-converter-local"
    KEY_PREFIX = "IC_API_"
    
    def __init__(self, app_name: str = "image-converter"):
        """Initialize secure key manager.
        
        Args:
            app_name: Application name for keychain storage
        """
        self.app_name = app_name
        self._fallback_storage = Path.home() / ".image-converter" / ".keys"
        self._ensure_fallback_dir()
    
    def _ensure_fallback_dir(self) -> None:
        """Create fallback storage directory with secure permissions."""
        if not self._fallback_storage.exists():
            self._fallback_storage.parent.mkdir(parents=True, exist_ok=True)
            self._fallback_storage.touch(mode=0o600)
            self._fallback_storage.write_text("{}")
    
    def store_api_key(self, key_name: str, api_key: str) -> bool:
        """Store API key securely in OS keychain.
        
        Args:
            key_name: Name/identifier for the key
            api_key: The API key to store
            
        Returns:
            True if stored successfully
        """
        try:
            # Try OS keychain first
            keyring.set_password(
                self.SERVICE_NAME,
                f"{self.KEY_PREFIX}{key_name}",
                api_key
            )
            return True
        except Exception:
            # Fall back to encrypted local storage
            return self._store_fallback(key_name, api_key)
    
    def retrieve_api_key(self, key_name: str) -> Optional[str]:
        """Retrieve API key from secure storage.
        
        Args:
            key_name: Name/identifier for the key
            
        Returns:
            API key if found, None otherwise
        """
        try:
            # Try OS keychain first
            key = keyring.get_password(
                self.SERVICE_NAME,
                f"{self.KEY_PREFIX}{key_name}"
            )
            if key:
                return key
        except Exception:
            pass
        
        # Try fallback storage
        return self._retrieve_fallback(key_name)
    
    def delete_api_key(self, key_name: str) -> bool:
        """Delete API key from secure storage.
        
        Args:
            key_name: Name/identifier for the key
            
        Returns:
            True if deleted successfully
        """
        success = False
        
        try:
            # Try to delete from keychain
            keyring.delete_password(
                self.SERVICE_NAME,
                f"{self.KEY_PREFIX}{key_name}"
            )
            success = True
        except Exception:
            pass
        
        # Also try to delete from fallback
        if self._delete_fallback(key_name):
            success = True
        
        return success
    
    def list_stored_keys(self) -> list[str]:
        """List all stored API key names.
        
        Returns:
            List of key names (not the actual keys)
        """
        keys = set()
        
        # Get from fallback storage
        try:
            data = json.loads(self._fallback_storage.read_text())
            keys.update(data.keys())
        except Exception:
            pass
        
        return list(keys)
    
    def _store_fallback(self, key_name: str, api_key: str) -> bool:
        """Store key in fallback encrypted file.
        
        Args:
            key_name: Name/identifier for the key
            api_key: The API key to store
            
        Returns:
            True if stored successfully
        """
        try:
            # Simple obfuscation (not true encryption, but better than plaintext)
            obfuscated = self._obfuscate(api_key)
            
            # Load existing data
            data = {}
            if self._fallback_storage.exists():
                try:
                    data = json.loads(self._fallback_storage.read_text())
                except Exception:
                    data = {}
            
            # Store obfuscated key
            data[key_name] = obfuscated
            
            # Write back with secure permissions
            self._fallback_storage.write_text(json.dumps(data, indent=2))
            os.chmod(self._fallback_storage, 0o600)
            
            return True
        except Exception:
            return False
    
    def _retrieve_fallback(self, key_name: str) -> Optional[str]:
        """Retrieve key from fallback storage.
        
        Args:
            key_name: Name/identifier for the key
            
        Returns:
            API key if found, None otherwise
        """
        try:
            if not self._fallback_storage.exists():
                return None
            
            data = json.loads(self._fallback_storage.read_text())
            obfuscated = data.get(key_name)
            
            if obfuscated:
                return self._deobfuscate(obfuscated)
        except Exception:
            pass
        
        return None
    
    def _delete_fallback(self, key_name: str) -> bool:
        """Delete key from fallback storage.
        
        Args:
            key_name: Name/identifier for the key
            
        Returns:
            True if deleted successfully
        """
        try:
            if not self._fallback_storage.exists():
                return False
            
            data = json.loads(self._fallback_storage.read_text())
            if key_name in data:
                del data[key_name]
                self._fallback_storage.write_text(json.dumps(data, indent=2))
                return True
        except Exception:
            pass
        
        return False
    
    def _obfuscate(self, value: str) -> str:
        """Simple obfuscation for fallback storage.
        
        Args:
            value: Value to obfuscate
            
        Returns:
            Obfuscated value
        """
        # XOR with a fixed key derived from app name
        key = hashlib.sha256(self.app_name.encode()).digest()
        obfuscated = []
        
        for i, char in enumerate(value.encode()):
            obfuscated.append(char ^ key[i % len(key)])
        
        # Return as hex string
        return bytes(obfuscated).hex()
    
    def _deobfuscate(self, obfuscated: str) -> str:
        """Deobfuscate value from fallback storage.
        
        Args:
            obfuscated: Obfuscated value
            
        Returns:
            Original value
        """
        # Convert from hex
        obfuscated_bytes = bytes.fromhex(obfuscated)
        
        # XOR with the same key
        key = hashlib.sha256(self.app_name.encode()).digest()
        original = []
        
        for i, byte in enumerate(obfuscated_bytes):
            original.append(byte ^ key[i % len(key)])
        
        return bytes(original).decode()
    
    @staticmethod
    def generate_api_key() -> str:
        """Generate a secure API key.
        
        Returns:
            Cryptographically secure API key
        """
        # Generate 32 bytes of randomness
        random_bytes = secrets.token_bytes(32)
        
        # Convert to URL-safe base64
        key = secrets.token_urlsafe(32)
        
        # Add prefix for identification
        return f"ic_live_{key}"
    
    def get_from_env(self, env_var: str = "IMAGE_CONVERTER_API_KEY") -> Optional[str]:
        """Get API key from environment variable.
        
        Args:
            env_var: Environment variable name
            
        Returns:
            API key if found in environment
        """
        return os.environ.get(env_var)