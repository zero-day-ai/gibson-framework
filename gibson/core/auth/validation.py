"""Authentication configuration validation."""
from typing import Dict, Any, List, Optional
from gibson.core.auth.providers import Provider, ApiKeyFormat

class ConfigValidator:
    """Validates authentication configuration."""
    
    def __init__(self):
        self.errors: List[str] = []
        self.warnings: List[str] = []
    
    def validate_credential(self, cred_data: Dict[str, Any]) -> bool:
        """Validate credential configuration."""
        self.errors = []
        self.warnings = []
        
        # Required fields
        if not cred_data.get("name"):
            self.errors.append("Credential name is required")
        if not cred_data.get("provider"):
            self.errors.append("Provider is required")
        if not cred_data.get("api_key"):
            self.errors.append("API key is required")
            
        # Validate provider
        provider = cred_data.get("provider")
        if provider and provider not in [p.value for p in Provider]:
            self.errors.append(f"Invalid provider: {provider}")
            
        # Validate auth format
        auth_format = cred_data.get("auth_format")
        if auth_format and auth_format not in [f.value for f in ApiKeyFormat]:
            self.errors.append(f"Invalid auth format: {auth_format}")
            
        # Provider-specific validation
        if provider == "azure":
            if not cred_data.get("metadata", {}).get("endpoint"):
                self.warnings.append("Azure endpoint is recommended")
                
        return len(self.errors) == 0
    
    def get_validation_report(self) -> Dict[str, Any]:
        """Get validation report."""
        return {
            "valid": len(self.errors) == 0,
            "errors": self.errors,
            "warnings": self.warnings
        }
