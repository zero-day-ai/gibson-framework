"""LiteLLM adapter for provider detection and configuration.

Provides automatic detection of LLM providers based on URL patterns,
environment variables, and model names using LiteLLM patterns.
"""

import os
import re
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse

from loguru import logger

from gibson.models.target import LLMProvider


class LiteLLMAdapter:
    """Adapter for LiteLLM provider detection and configuration.
    
    Analyzes URLs, environment variables, and model names to automatically
    detect the appropriate LLM provider and generate LiteLLM-compatible
    configuration.
    """
    
    # URL patterns for provider detection
    URL_PATTERNS = {
        LLMProvider.OPENAI: [
            r'api\.openai\.com',
            r'openai\.com',
        ],
        LLMProvider.ANTHROPIC: [
            r'api\.anthropic\.com',
            r'claude\.ai',
            r'anthropic\.com',
        ],
        LLMProvider.AZURE: [
            r'\.openai\.azure\.com',
            r'azure\.com.*openai',
        ],
        LLMProvider.AWS_BEDROCK: [
            r'bedrock.*\.amazonaws\.com',
            r'amazonaws\.com.*bedrock',
        ],
        LLMProvider.GOOGLE: [
            r'googleapis\.com',
            r'vertexai.*\.googleapis\.com',
            r'google\.com.*ai',
        ],
        LLMProvider.HUGGINGFACE: [
            r'huggingface\.co',
            r'hf\.co',
        ],
        LLMProvider.OLLAMA: [
            r'localhost',
            r'127\.0\.0\.1',
        ],
    }
    
    # Environment variables for provider detection
    ENV_VARIABLES = {
        LLMProvider.OPENAI: ['OPENAI_API_KEY', 'OPENAI_BASE_URL'],
        LLMProvider.ANTHROPIC: ['ANTHROPIC_API_KEY', 'ANTHROPIC_BASE_URL'],
        LLMProvider.AZURE: [
            'AZURE_OPENAI_API_KEY', 
            'AZURE_OPENAI_ENDPOINT',
            'AZURE_OPENAI_BASE_URL'
        ],
        LLMProvider.AWS_BEDROCK: [
            'AWS_ACCESS_KEY_ID', 
            'AWS_SECRET_ACCESS_KEY',
            'AWS_REGION'
        ],
        LLMProvider.GOOGLE: [
            'GOOGLE_APPLICATION_CREDENTIALS', 
            'GOOGLE_API_KEY',
            'VERTEX_AI_PROJECT'
        ],
        LLMProvider.HUGGINGFACE: ['HUGGINGFACE_API_KEY', 'HF_TOKEN'],
        LLMProvider.OLLAMA: ['OLLAMA_BASE_URL'],
    }
    
    # Model name patterns
    MODEL_PATTERNS = {
        LLMProvider.OPENAI: [
            r'gpt-.*',
            r'text-davinci-.*',
            r'text-curie-.*',
            r'text-babbage-.*',
            r'text-ada-.*',
            r'davinci-.*',
            r'curie-.*',
            r'babbage-.*',
            r'ada-.*',
        ],
        LLMProvider.ANTHROPIC: [
            r'claude-.*',
            r'claude_.*',
            r'anthropic/claude-.*',
        ],
        LLMProvider.GOOGLE: [
            r'.*-bison.*',
            r'gemini-.*',
            r'palm-.*',
        ],
        LLMProvider.AWS_BEDROCK: [
            r'anthropic\.claude-.*',
            r'amazon\.titan-.*',
            r'ai21\.j2-.*',
        ],
        LLMProvider.HUGGINGFACE: [
            r'.*/.*',  # HF models typically have org/model format
        ],
        LLMProvider.OLLAMA: [
            r'llama.*',
            r'mistral.*',
            r'codellama.*',
            r'vicuna.*',
        ],
    }
    
    # Default models for each provider
    DEFAULT_MODELS = {
        LLMProvider.OPENAI: 'gpt-3.5-turbo',
        LLMProvider.ANTHROPIC: 'claude-3-sonnet-20240229',
        LLMProvider.AZURE: 'gpt-35-turbo',
        LLMProvider.AWS_BEDROCK: 'anthropic.claude-v2',
        LLMProvider.GOOGLE: 'chat-bison',
        LLMProvider.HUGGINGFACE: 'microsoft/DialoGPT-medium',
        LLMProvider.OLLAMA: 'llama2',
        LLMProvider.LITELLM: 'gpt-3.5-turbo',
    }
    
    def __init__(self):
        """Initialize the LiteLLM adapter."""
        pass
    
    def detect_provider_from_url(self, url: str) -> Optional[LLMProvider]:
        """Detect LLM provider from URL patterns.
        
        Args:
            url: Base URL to analyze
            
        Returns:
            Detected provider or None if no match found
        """
        try:
            url_lower = url.lower()
            
            for provider, patterns in self.URL_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, url_lower):
                        logger.debug(f"Detected provider {provider} from URL pattern: {pattern}")
                        return provider
            
            return None
            
        except Exception as e:
            logger.warning(f"Error detecting provider from URL {url}: {e}")
            return None
    
    def detect_provider_from_environment(self) -> List[LLMProvider]:
        """Detect available providers from environment variables.
        
        Returns:
            List of providers with available environment variables
        """
        available_providers = []
        
        try:
            for provider, env_vars in self.ENV_VARIABLES.items():
                if any(os.getenv(var) for var in env_vars):
                    available_providers.append(provider)
                    logger.debug(f"Provider {provider} available from environment")
            
            return available_providers
            
        except Exception as e:
            logger.warning(f"Error detecting providers from environment: {e}")
            return []
    
    def detect_provider_from_model_name(self, model_name: str) -> Optional[LLMProvider]:
        """Detect provider from model name patterns.
        
        Args:
            model_name: Model name to analyze
            
        Returns:
            Detected provider or None if no match found
        """
        try:
            model_lower = model_name.lower()
            
            for provider, patterns in self.MODEL_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, model_lower):
                        logger.debug(f"Detected provider {provider} from model pattern: {pattern}")
                        return provider
            
            return None
            
        except Exception as e:
            logger.warning(f"Error detecting provider from model name {model_name}: {e}")
            return None
    
    def auto_detect_provider(self, 
                           url: str,
                           model_name: Optional[str] = None,
                           prefer_environment: bool = True) -> LLMProvider:
        """Automatically detect the best LLM provider.
        
        Args:
            url: Base URL to analyze
            model_name: Optional model name for additional detection
            prefer_environment: Whether to prefer environment-available providers
            
        Returns:
            Best detected provider, defaults to LiteLLM if none detected
        """
        # Try URL-based detection first
        url_provider = self.detect_provider_from_url(url)
        if url_provider:
            return url_provider
        
        # Try model name detection
        if model_name:
            model_provider = self.detect_provider_from_model_name(model_name)
            if model_provider:
                return model_provider
        
        # Check environment variables if preferred
        if prefer_environment:
            env_providers = self.detect_provider_from_environment()
            if env_providers:
                # Prefer OpenAI or Anthropic if available
                preferred_order = [LLMProvider.OPENAI, LLMProvider.ANTHROPIC]
                for provider in preferred_order:
                    if provider in env_providers:
                        return provider
                # Return first available
                return env_providers[0]
        
        # Default to LiteLLM for maximum compatibility
        logger.debug("No specific provider detected, defaulting to LiteLLM")
        return LLMProvider.LITELLM
    
    def get_litellm_model_name(self, 
                              provider: LLMProvider,
                              url: str,
                              model_hint: Optional[str] = None) -> str:
        """Generate LiteLLM-compatible model name.
        
        Args:
            provider: Detected provider
            url: Base URL for additional context
            model_hint: Optional model name hint
            
        Returns:
            LiteLLM-compatible model name
        """
        # Extract potential model name from URL path
        model_hints = self._extract_model_hints_from_url(url)
        if model_hint:
            model_hints.append(model_hint)
        
        # Provider-specific model naming
        if provider == LLMProvider.OPENAI:
            if model_hints:
                # Use the most specific hint
                best_hint = self._find_best_model_hint(model_hints, provider)
                return f"openai/{best_hint}" if '/' not in best_hint else best_hint
            return f"openai/{self.DEFAULT_MODELS[provider]}"
        
        elif provider == LLMProvider.ANTHROPIC:
            if model_hints:
                best_hint = self._find_best_model_hint(model_hints, provider)
                return f"anthropic/{best_hint}" if '/' not in best_hint else best_hint
            return f"anthropic/{self.DEFAULT_MODELS[provider]}"
        
        elif provider == LLMProvider.AZURE:
            # Azure requires deployment name
            if model_hints:
                best_hint = self._find_best_model_hint(model_hints, provider)
                return f"azure/{best_hint}"
            return f"azure/{self.DEFAULT_MODELS[provider]}"
        
        elif provider == LLMProvider.AWS_BEDROCK:
            if model_hints:
                best_hint = self._find_best_model_hint(model_hints, provider)
                return f"bedrock/{best_hint}"
            return f"bedrock/{self.DEFAULT_MODELS[provider]}"
        
        elif provider == LLMProvider.GOOGLE:
            if model_hints:
                best_hint = self._find_best_model_hint(model_hints, provider)
                return f"vertex_ai/{best_hint}"
            return f"vertex_ai/{self.DEFAULT_MODELS[provider]}"
        
        elif provider == LLMProvider.HUGGINGFACE:
            if model_hints:
                best_hint = self._find_best_model_hint(model_hints, provider)
                return f"huggingface/{best_hint}"
            return f"huggingface/{self.DEFAULT_MODELS[provider]}"
        
        elif provider == LLMProvider.OLLAMA:
            if model_hints:
                best_hint = self._find_best_model_hint(model_hints, provider)
                return f"ollama/{best_hint}"
            return f"ollama/{self.DEFAULT_MODELS[provider]}"
        
        else:
            # Generic LiteLLM format
            if model_hints:
                return self._find_best_model_hint(model_hints, provider)
            return self.DEFAULT_MODELS.get(provider, 'gpt-3.5-turbo')
    
    def get_provider_config(self, 
                          provider: LLMProvider,
                          url: str,
                          model_name: str,
                          **kwargs) -> Dict[str, Any]:
        """Get provider-specific configuration for LiteLLM integration.
        
        Args:
            provider: LLM provider
            url: Base URL
            model_name: Model name
            **kwargs: Additional configuration options
            
        Returns:
            Provider-specific configuration dictionary
        """
        config = {
            "model": model_name,
            "api_base": url,
            "provider": provider.value
        }
        
        # Add provider-specific configuration
        if provider == LLMProvider.AZURE:
            config.update({
                "api_type": "azure",
                "api_version": kwargs.get("api_version", "2023-12-01-preview")
            })
            
        elif provider == LLMProvider.AWS_BEDROCK:
            config.update({
                "aws_region": kwargs.get("aws_region", "us-east-1")
            })
            
        elif provider == LLMProvider.GOOGLE:
            config.update({
                "vertex_project": kwargs.get("vertex_project"),
                "vertex_location": kwargs.get("vertex_location", "us-central1")
            })
        
        # Add common configuration
        config.update({
            "timeout": kwargs.get("timeout", 60),
            "max_retries": kwargs.get("max_retries", 3),
            "verify_ssl": kwargs.get("verify_ssl", True)
        })
        
        return config
    
    def get_authentication_config(self, provider: LLMProvider) -> Dict[str, str]:
        """Get authentication configuration for provider.
        
        Args:
            provider: LLM provider
            
        Returns:
            Dictionary with authentication headers/configuration
        """
        headers = {}
        
        if provider == LLMProvider.OPENAI:
            api_key = os.getenv("OPENAI_API_KEY")
            if api_key:
                headers["Authorization"] = f"Bearer {api_key}"
                
        elif provider == LLMProvider.ANTHROPIC:
            api_key = os.getenv("ANTHROPIC_API_KEY")
            if api_key:
                headers["x-api-key"] = api_key
                
        elif provider == LLMProvider.AZURE:
            api_key = os.getenv("AZURE_OPENAI_API_KEY")
            if api_key:
                headers["api-key"] = api_key
                
        elif provider == LLMProvider.HUGGINGFACE:
            api_key = os.getenv("HUGGINGFACE_API_KEY") or os.getenv("HF_TOKEN")
            if api_key:
                headers["Authorization"] = f"Bearer {api_key}"
        
        return headers
    
    def _extract_model_hints_from_url(self, url: str) -> List[str]:
        """Extract potential model names from URL path."""
        try:
            parsed_url = urlparse(url)
            path_parts = [p for p in parsed_url.path.split('/') if p]
            
            model_hints = []
            for part in path_parts:
                # Look for parts that might be model names
                if any(keyword in part.lower() for keyword in 
                      ['gpt', 'claude', 'llama', 'model', 'chat', 'text', 'completion']):
                    model_hints.append(part)
            
            return model_hints
            
        except Exception as e:
            logger.debug(f"Error extracting model hints from URL {url}: {e}")
            return []
    
    def _find_best_model_hint(self, hints: List[str], provider: LLMProvider) -> str:
        """Find the best model hint for the given provider."""
        if not hints:
            return self.DEFAULT_MODELS.get(provider, 'gpt-3.5-turbo')
        
        # Score hints based on provider patterns
        scored_hints = []
        provider_patterns = self.MODEL_PATTERNS.get(provider, [])
        
        for hint in hints:
            score = 0
            hint_lower = hint.lower()
            
            # Check against provider patterns
            for pattern in provider_patterns:
                if re.search(pattern, hint_lower):
                    score += 10
                    break
            
            # Prefer longer, more specific names
            score += len(hint)
            
            scored_hints.append((score, hint))
        
        # Return the highest scoring hint
        scored_hints.sort(key=lambda x: x[0], reverse=True)
        return scored_hints[0][1] if scored_hints else hints[-1]
    
    def validate_provider_config(self, provider: LLMProvider, config: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Validate provider configuration.
        
        Args:
            provider: LLM provider
            config: Provider configuration
            
        Returns:
            Tuple of (is_valid, error_messages)
        """
        errors = []
        
        # Required fields for all providers
        if not config.get("model"):
            errors.append("Model name is required")
        if not config.get("api_base"):
            errors.append("API base URL is required")
        
        # Provider-specific validation
        if provider == LLMProvider.AZURE:
            if not config.get("api_version"):
                errors.append("API version is required for Azure OpenAI")
                
        elif provider == LLMProvider.AWS_BEDROCK:
            if not config.get("aws_region"):
                errors.append("AWS region is required for Bedrock")
                
        elif provider == LLMProvider.GOOGLE:
            if "vertex_ai" in config.get("model", "").lower():
                if not config.get("vertex_project"):
                    errors.append("Vertex AI project is required for Google models")
        
        return len(errors) == 0, errors


# Export the adapter
__all__ = ['LiteLLMAdapter']