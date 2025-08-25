"""Request authentication middleware for transparent credential injection.

Provides middleware for automatically adding authentication headers to
HTTP requests during scan operations with rate limiting and retry handling.
"""

import asyncio
import time
from typing import Callable, Dict, Optional, Any
from uuid import UUID

import httpx
from loguru import logger
from tenacity import retry, stop_after_attempt, wait_exponential

from gibson.models.auth import (
    ApiKeyCredentialModel,
    ApiKeyFormat,
    AuthErrorType,
    ValidationStatus
)
from gibson.models.target import TargetModel
from gibson.core.auth.credential_manager import CredentialManager


class AuthenticationStatus:
    """Authentication status tracking."""
    
    SUCCESS = "success"
    FAILED = "failed"
    RATE_LIMITED = "rate_limited"
    INVALID_CREDENTIALS = "invalid_credentials"
    NETWORK_ERROR = "network_error"


class RequestAuthenticator:
    """Middleware for transparent request authentication."""
    
    def __init__(
        self,
        credential_manager: Optional[CredentialManager] = None,
        enable_retry: bool = True,
        max_retries: int = 3,
        backoff_factor: float = 1.0
    ):
        """Initialize request authenticator.
        
        Args:
            credential_manager: Credential manager instance
            enable_retry: Enable automatic retries on auth failures
            max_retries: Maximum number of retry attempts
            backoff_factor: Exponential backoff factor for retries
        """
        self.credential_manager = credential_manager or CredentialManager()
        self.enable_retry = enable_retry
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        
        # Cache for credentials to avoid repeated lookups
        self._credential_cache: Dict[UUID, ApiKeyCredentialModel] = {}
        self._cache_ttl = 300  # 5 minutes
        self._cache_timestamps: Dict[UUID, float] = {}
    
    def authenticate_request(
        self,
        request: httpx.Request,
        target: TargetModel
    ) -> httpx.Request:
        """Add authentication headers to request.
        
        Args:
            request: HTTP request to authenticate
            target: Target configuration
            
        Returns:
            Request with authentication headers added
        """
        try:
            # Get credential for target
            credential = self._get_credential_for_target(target)
            if not credential:
                logger.warning(f"No credential available for target {target.id}")
                return request
            
            # Build authentication headers
            auth_headers = self._build_authentication_headers(credential)
            
            # Add headers to request
            for header_name, header_value in auth_headers.items():
                request.headers[header_name] = header_value
            
            # Add query parameters if needed
            if credential.key_format == ApiKeyFormat.QUERY_PARAMETER:
                query_params = self._build_authentication_query_params(credential)
                if query_params:
                    # Merge with existing query parameters
                    current_params = dict(request.url.params)
                    current_params.update(query_params)
                    
                    # Rebuild URL with new parameters
                    url = request.url.copy_with(params=current_params)
                    request = request.copy_with(url=url)
            
            logger.debug(f"Added authentication to request for target {target.id}")
            return request
            
        except Exception as e:
            logger.error(f"Failed to authenticate request for target {target.id}: {e}")
            return request
    
    def _get_credential_for_target(self, target: TargetModel) -> Optional[ApiKeyCredentialModel]:
        """Get credential for target with caching."""
        try:
            # Check cache first
            if target.id in self._credential_cache:
                cache_time = self._cache_timestamps.get(target.id, 0)
                if time.time() - cache_time < self._cache_ttl:
                    return self._credential_cache[target.id]
            
            # Retrieve credential
            credential = self.credential_manager.retrieve_credential(target.id)
            
            if credential:
                # Update cache
                self._credential_cache[target.id] = credential
                self._cache_timestamps[target.id] = time.time()
            
            return credential
            
        except Exception as e:
            logger.error(f"Failed to retrieve credential for target {target.id}: {e}")
            return None
    
    def _build_authentication_headers(self, credential: ApiKeyCredentialModel) -> Dict[str, str]:
        """Build authentication headers based on credential format."""
        headers = {}
        
        if credential.key_format == ApiKeyFormat.BEARER_TOKEN:
            prefix = credential.token_prefix or "Bearer"
            headers["Authorization"] = f"{prefix} {credential.token}"
        
        elif credential.key_format == ApiKeyFormat.API_KEY_HEADER:
            headers["Authorization"] = f"ApiKey {credential.token}"
        
        elif credential.key_format == ApiKeyFormat.CUSTOM_HEADER:
            if credential.header_name:
                headers[credential.header_name] = credential.header_value or credential.token
        
        elif credential.key_format == ApiKeyFormat.OPENAI_FORMAT:
            headers["Authorization"] = f"Bearer {credential.token}"
        
        elif credential.key_format == ApiKeyFormat.ANTHROPIC_FORMAT:
            headers["x-api-key"] = credential.token
        
        elif credential.key_format == ApiKeyFormat.GOOGLE_FORMAT:
            headers["Authorization"] = f"Bearer {credential.token}"
        
        elif credential.key_format == ApiKeyFormat.AZURE_FORMAT:
            # Azure may use custom headers depending on service
            if credential.header_name:
                headers[credential.header_name] = credential.token
            else:
                headers["Authorization"] = f"Bearer {credential.token}"
        
        # Add any additional headers
        if credential.additional_headers:
            headers.update(credential.additional_headers)
        
        return headers
    
    def _build_authentication_query_params(self, credential: ApiKeyCredentialModel) -> Dict[str, str]:
        """Build authentication query parameters."""
        params = {}
        
        if credential.key_format == ApiKeyFormat.QUERY_PARAMETER:
            # Use header_name as the query parameter name, fallback to 'api_key'
            param_name = credential.header_name or 'api_key'
            params[param_name] = credential.token
        
        return params
    
    def handle_auth_response(self, response: httpx.Response) -> str:
        """Handle authentication response and determine status.
        
        Args:
            response: HTTP response to analyze
            
        Returns:
            Authentication status string
        """
        status_code = response.status_code
        
        if status_code == 200:
            return AuthenticationStatus.SUCCESS
        elif status_code == 401:
            logger.warning(f"Authentication failed: {response.status_code} - {response.text[:100]}")
            return AuthenticationStatus.INVALID_CREDENTIALS
        elif status_code == 403:
            logger.warning(f"Authentication forbidden: {response.status_code} - {response.text[:100]}")
            return AuthenticationStatus.INVALID_CREDENTIALS
        elif status_code == 429:
            logger.warning(f"Rate limited: {response.status_code} - {response.text[:100]}")
            return AuthenticationStatus.RATE_LIMITED
        elif status_code >= 500:
            logger.warning(f"Server error: {response.status_code} - {response.text[:100]}")
            return AuthenticationStatus.NETWORK_ERROR
        else:
            logger.warning(f"Unknown authentication response: {response.status_code}")
            return AuthenticationStatus.FAILED
    
    def create_auth_middleware(self) -> Callable:
        """Create authentication middleware function.
        
        Returns:
            Middleware function for HTTPX client
        """
        
        async def auth_middleware(request: httpx.Request, call_next):
            """HTTPX middleware function for authentication."""
            try:
                # Check if request needs authentication
                target_id = request.headers.get('X-Gibson-Target-ID')
                if not target_id:
                    # No target specified, pass through
                    return await call_next(request)
                
                # Get target information (this would need to be injected)
                # For now, we'll pass through as authentication is handled
                # at a higher level in the scan engine
                
                response = await call_next(request)
                
                # Handle authentication responses
                auth_status = self.handle_auth_response(response)
                
                if auth_status == AuthenticationStatus.RATE_LIMITED:
                    # Extract retry-after header if available
                    retry_after = response.headers.get('retry-after')
                    if retry_after:
                        try:
                            wait_time = int(retry_after)
                            logger.info(f"Rate limited, waiting {wait_time} seconds")
                            await asyncio.sleep(wait_time)
                            # Retry the request
                            return await call_next(request)
                        except (ValueError, asyncio.CancelledError):
                            pass
                
                return response
                
            except Exception as e:
                logger.error(f"Authentication middleware error: {e}")
                # Pass through on middleware errors
                return await call_next(request)
        
        return auth_middleware
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10)
    )
    async def authenticated_request(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        target: TargetModel,
        **kwargs
    ) -> httpx.Response:
        """Make authenticated HTTP request with automatic retries.
        
        Args:
            client: HTTP client to use
            method: HTTP method
            url: Request URL
            target: Target configuration
            **kwargs: Additional request parameters
            
        Returns:
            HTTP response
        """
        try:
            # Create request
            request = client.build_request(method, url, **kwargs)
            
            # Add authentication
            authenticated_request = self.authenticate_request(request, target)
            
            # Send request
            response = await client.send(authenticated_request)
            
            # Handle authentication errors
            auth_status = self.handle_auth_response(response)
            
            if auth_status == AuthenticationStatus.RATE_LIMITED:
                # Handle rate limiting with backoff
                retry_after = self._extract_retry_after(response)
                if retry_after:
                    logger.info(f"Rate limited, backing off for {retry_after} seconds")
                    await asyncio.sleep(retry_after)
                    # This will trigger a retry due to the @retry decorator
                    raise httpx.HTTPStatusError(
                        f"Rate limited: {response.status_code}",
                        request=authenticated_request,
                        response=response
                    )
            
            elif auth_status == AuthenticationStatus.INVALID_CREDENTIALS:
                # Clear credential cache to force refresh
                if target.id in self._credential_cache:
                    del self._credential_cache[target.id]
                    del self._cache_timestamps[target.id]
                
                # Don't retry invalid credentials
                logger.error(f"Invalid credentials for target {target.id}")
            
            return response
            
        except httpx.HTTPStatusError:
            # Re-raise HTTP errors for retry handling
            raise
        except Exception as e:
            logger.error(f"Authenticated request failed for target {target.id}: {e}")
            raise
    
    def _extract_retry_after(self, response: httpx.Response) -> Optional[int]:
        """Extract retry-after value from response headers."""
        retry_after_header = response.headers.get('retry-after')
        if retry_after_header:
            try:
                return int(retry_after_header)
            except ValueError:
                pass
        
        # Try X-RateLimit-Reset header
        reset_header = response.headers.get('x-ratelimit-reset')
        if reset_header:
            try:
                reset_time = int(reset_header)
                current_time = int(time.time())
                return max(0, reset_time - current_time)
            except ValueError:
                pass
        
        # Default backoff
        return 5
    
    def clear_credential_cache(self, target_id: Optional[UUID] = None) -> None:
        """Clear credential cache.
        
        Args:
            target_id: Specific target to clear, or None for all targets
        """
        if target_id:
            # Clear specific target
            if target_id in self._credential_cache:
                del self._credential_cache[target_id]
            if target_id in self._cache_timestamps:
                del self._cache_timestamps[target_id]
        else:
            # Clear all cached credentials
            self._credential_cache.clear()
            self._cache_timestamps.clear()
        
        logger.debug(f"Cleared credential cache for target {target_id or 'all targets'}")
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get credential cache statistics.
        
        Returns:
            Dictionary with cache statistics
        """
        current_time = time.time()
        
        active_entries = 0
        expired_entries = 0
        
        for target_id, cache_time in self._cache_timestamps.items():
            if current_time - cache_time < self._cache_ttl:
                active_entries += 1
            else:
                expired_entries += 1
        
        return {
            'total_entries': len(self._credential_cache),
            'active_entries': active_entries,
            'expired_entries': expired_entries,
            'cache_ttl_seconds': self._cache_ttl,
            'hit_ratio': 0.0  # Would need request tracking to calculate
        }
    
    def cleanup_expired_cache(self) -> int:
        """Clean up expired cache entries.
        
        Returns:
            Number of entries removed
        """
        current_time = time.time()
        expired_targets = []
        
        for target_id, cache_time in self._cache_timestamps.items():
            if current_time - cache_time >= self._cache_ttl:
                expired_targets.append(target_id)
        
        for target_id in expired_targets:
            if target_id in self._credential_cache:
                del self._credential_cache[target_id]
            del self._cache_timestamps[target_id]
        
        if expired_targets:
            logger.debug(f"Cleaned up {len(expired_targets)} expired cache entries")
        
        return len(expired_targets)
