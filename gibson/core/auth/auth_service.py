"""Authentication validation service for API keys.

Provides validation, testing, and error handling for API key authentication
across different service providers and authentication methods.
"""
import asyncio
import time
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from uuid import UUID
import httpx
from loguru import logger
from tenacity import retry, stop_after_attempt, wait_exponential
from gibson.models.auth import (
    ApiKeyCredentialModel,
    AuthenticationValidationResult,
    ValidationStatus,
    AuthErrorType,
    RateLimitInfo,
    ApiKeyFormat,
)
from gibson.models.target import TargetModel, AuthenticationType
from gibson.core.auth.credential_manager import CredentialManager


class AuthenticationServiceError(Exception):
    """Base exception for authentication service errors."""

    pass


class ValidationTimeoutError(AuthenticationServiceError):
    """Raised when validation times out."""

    pass


class AuthenticationService:
    """Service for validating and testing API key authentication."""

    def __init__(
        self,
        credential_manager: Optional[CredentialManager] = None,
        timeout: int = 30,
        max_retries: int = 3,
    ):
        """Initialize authentication service.

        Args:
            credential_manager: Credential manager instance
            timeout: Request timeout in seconds
            max_retries: Maximum retry attempts for validation
        """
        self.credential_manager = credential_manager or CredentialManager()
        self.timeout = timeout
        self.max_retries = max_retries
        self.http_client = httpx.AsyncClient(
            timeout=timeout,
            verify=True,
            headers={"User-Agent": "Gibson-Security-Framework/1.0"},
            limits=httpx.Limits(max_keepalive_connections=10, max_connections=20),
        )

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.http_client.aclose()

    async def validate_credential(
        self, target: TargetModel, credential: Optional[ApiKeyCredentialModel] = None
    ) -> AuthenticationValidationResult:
        """Validate API key credential for a target.

        Args:
            target: Target to validate against
            credential: Credential to validate (retrieved if None)

        Returns:
            Validation result with detailed information
        """
        start_time = time.time()
        try:
            if credential is None:
                try:
                    credential = self.credential_manager.retrieve_credential(target.id)
                    if not credential:
                        return self._create_validation_result(
                            False,
                            ValidationStatus.INVALID,
                            AuthErrorType.AUTHENTICATION_FAILED,
                            "No credential found for target",
                            response_time_ms=(time.time() - start_time) * 1000,
                        )
                except Exception as e:
                    return self._create_validation_result(
                        False,
                        ValidationStatus.NETWORK_ERROR,
                        AuthErrorType.STORAGE_ERROR,
                        f"Failed to retrieve credential: {e}",
                        response_time_ms=(time.time() - start_time) * 1000,
                    )
            if not credential.token:
                return self._create_validation_result(
                    False,
                    ValidationStatus.INVALID,
                    AuthErrorType.INVALID_KEY_FORMAT,
                    "API key token is empty",
                    response_time_ms=(time.time() - start_time) * 1000,
                )
            validation_url = self._get_validation_endpoint(target, credential)
            if not validation_url:
                return self._create_validation_result(
                    False,
                    ValidationStatus.INVALID,
                    AuthErrorType.INVALID_ENDPOINT,
                    "No validation endpoint available",
                    response_time_ms=(time.time() - start_time) * 1000,
                )
            result = await self._perform_validation_request(validation_url, credential, target)
            if result.is_valid:
                await self._update_credential_after_validation(target.id, result)
            return result
        except Exception as e:
            logger.error(f"Validation failed for target {target.id}: {e}")
            return self._create_validation_result(
                False,
                ValidationStatus.UNKNOWN_ERROR,
                AuthErrorType.CONFIGURATION_ERROR,
                f"Validation error: {e}",
                response_time_ms=(time.time() - start_time) * 1000,
            )

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=10))
    async def _perform_validation_request(
        self, url: str, credential: ApiKeyCredentialModel, target: TargetModel
    ) -> AuthenticationValidationResult:
        """Perform HTTP validation request with retries."""
        start_time = time.time()
        try:
            headers = self._build_auth_headers(credential)
            response = await self.http_client.get(url, headers=headers, timeout=self.timeout)
            response_time_ms = (time.time() - start_time) * 1000
            return self._parse_validation_response(response, credential, response_time_ms, url)
        except httpx.TimeoutException as e:
            return self._create_validation_result(
                False,
                ValidationStatus.NETWORK_ERROR,
                AuthErrorType.NETWORK_TIMEOUT,
                f"Validation request timed out: {e}",
                response_time_ms=(time.time() - start_time) * 1000,
                validation_endpoint=url,
            )
        except httpx.NetworkError as e:
            return self._create_validation_result(
                False,
                ValidationStatus.NETWORK_ERROR,
                AuthErrorType.NETWORK_TIMEOUT,
                f"Network error during validation: {e}",
                response_time_ms=(time.time() - start_time) * 1000,
                validation_endpoint=url,
            )
        except Exception as e:
            return self._create_validation_result(
                False,
                ValidationStatus.UNKNOWN_ERROR,
                AuthErrorType.CONFIGURATION_ERROR,
                f"Unexpected validation error: {e}",
                response_time_ms=(time.time() - start_time) * 1000,
                validation_endpoint=url,
            )

    def _build_auth_headers(self, credential: ApiKeyCredentialModel) -> Dict[str, str]:
        """Build authentication headers for validation request."""
        headers = {}
        if credential.key_format == ApiKeyFormat.BEARER_TOKEN:
            headers["Authorization"] = f"Bearer {credential.token}"
        elif credential.key_format == ApiKeyFormat.API_KEY_HEADER:
            headers["Authorization"] = f"ApiKey {credential.token}"
        elif credential.key_format == ApiKeyFormat.CUSTOM_HEADER and credential.header_name:
            headers[credential.header_name] = credential.header_value or credential.token
        elif credential.key_format == ApiKeyFormat.OPENAI_FORMAT:
            headers["Authorization"] = f"Bearer {credential.token}"
        elif credential.key_format == ApiKeyFormat.ANTHROPIC_FORMAT:
            headers["x-api-key"] = credential.token
        elif credential.key_format == ApiKeyFormat.GOOGLE_FORMAT:
            headers["Authorization"] = f"Bearer {credential.token}"
        if credential.additional_headers:
            headers.update(credential.additional_headers)
        return headers

    def _get_validation_endpoint(
        self, target: TargetModel, credential: ApiKeyCredentialModel
    ) -> Optional[str]:
        """Get validation endpoint URL for credential testing."""
        if credential.validation_endpoint:
            return credential.validation_endpoint
        base_url = target.base_url.rstrip("/")
        if "openai" in base_url.lower() or credential.key_format == ApiKeyFormat.OPENAI_FORMAT:
            return f"{base_url}/v1/models"
        elif (
            "anthropic" in base_url.lower()
            or credential.key_format == ApiKeyFormat.ANTHROPIC_FORMAT
        ):
            return f"{base_url}/v1/messages"
        elif (
            "googleapis.com" in base_url.lower()
            or credential.key_format == ApiKeyFormat.GOOGLE_FORMAT
        ):
            return f"{base_url}/v1/models"
        common_paths = [
            "/health",
            "/status",
            "/api/health",
            "/api/status",
            "/v1/health",
            "/v1/status",
            "/",
        ]
        return f"{base_url}{common_paths[0]}"

    def _parse_validation_response(
        self,
        response: httpx.Response,
        credential: ApiKeyCredentialModel,
        response_time_ms: float,
        validation_endpoint: str,
    ) -> AuthenticationValidationResult:
        """Parse HTTP response to determine validation result."""
        rate_limit_info = self._extract_rate_limit_info(response)
        if response.status_code == 200:
            return self._create_validation_result(
                True,
                ValidationStatus.VALID,
                None,
                "Credential validation successful",
                status_code=response.status_code,
                response_time_ms=response_time_ms,
                rate_limit_info=rate_limit_info,
                validation_endpoint=validation_endpoint,
            )
        elif response.status_code == 401:
            error_message = self._extract_error_message(response)
            return self._create_validation_result(
                False,
                ValidationStatus.INVALID,
                AuthErrorType.AUTHENTICATION_FAILED,
                error_message or "Invalid API key",
                status_code=response.status_code,
                response_time_ms=response_time_ms,
                validation_endpoint=validation_endpoint,
            )
        elif response.status_code == 403:
            error_message = self._extract_error_message(response)
            return self._create_validation_result(
                False,
                ValidationStatus.INSUFFICIENT_PERMISSIONS,
                AuthErrorType.INSUFFICIENT_PERMISSIONS,
                error_message or "Insufficient permissions",
                status_code=response.status_code,
                response_time_ms=response_time_ms,
                validation_endpoint=validation_endpoint,
            )
        elif response.status_code == 429:
            error_message = self._extract_error_message(response)
            return self._create_validation_result(
                False,
                ValidationStatus.RATE_LIMITED,
                AuthErrorType.RATE_LIMIT_EXCEEDED,
                error_message or "Rate limit exceeded",
                status_code=response.status_code,
                response_time_ms=response_time_ms,
                rate_limit_info=rate_limit_info,
                validation_endpoint=validation_endpoint,
            )
        elif response.status_code >= 500:
            error_message = self._extract_error_message(response)
            return self._create_validation_result(
                False,
                ValidationStatus.NETWORK_ERROR,
                AuthErrorType.SERVICE_UNAVAILABLE,
                error_message or f"Server error: {response.status_code}",
                status_code=response.status_code,
                response_time_ms=response_time_ms,
                validation_endpoint=validation_endpoint,
            )
        else:
            error_message = self._extract_error_message(response)
            return self._create_validation_result(
                False,
                ValidationStatus.UNKNOWN_ERROR,
                AuthErrorType.CONFIGURATION_ERROR,
                error_message or f"Unexpected status code: {response.status_code}",
                status_code=response.status_code,
                response_time_ms=response_time_ms,
                validation_endpoint=validation_endpoint,
            )

    def _extract_rate_limit_info(self, response: httpx.Response) -> Optional[RateLimitInfo]:
        """Extract rate limit information from response headers."""
        try:
            headers = response.headers
            requests_remaining = None
            reset_timestamp = None
            retry_after = None
            if "x-ratelimit-remaining" in headers:
                requests_remaining = int(headers["x-ratelimit-remaining"])
            if "x-ratelimit-reset" in headers:
                reset_timestamp = datetime.fromtimestamp(int(headers["x-ratelimit-reset"]))
            if "retry-after" in headers:
                retry_after = int(headers["retry-after"])
            if "ratelimit-remaining" in headers:
                requests_remaining = int(headers["ratelimit-remaining"])
            if "ratelimit-reset" in headers:
                reset_timestamp = datetime.fromtimestamp(int(headers["ratelimit-reset"]))
            if any([requests_remaining, reset_timestamp, retry_after]):
                return RateLimitInfo(
                    requests_remaining=requests_remaining,
                    reset_timestamp=reset_timestamp,
                    retry_after=retry_after,
                )
        except (ValueError, KeyError) as e:
            logger.debug(f"Failed to parse rate limit info: {e}")
        return None

    def _extract_error_message(self, response: httpx.Response) -> Optional[str]:
        """Extract error message from response body."""
        try:
            if response.headers.get("content-type", "").startswith("application/json"):
                error_data = response.model_dump_json()
                for key in ["error", "message", "detail", "error_description"]:
                    if key in error_data:
                        if isinstance(error_data[key], dict) and "message" in error_data[key]:
                            return error_data[key]["message"]
                        elif isinstance(error_data[key], str):
                            return error_data[key]
            text = response.text[:200]
            if text:
                return text
        except Exception as e:
            logger.debug(f"Failed to extract error message: {e}")
        return None

    def _create_validation_result(
        self,
        is_valid: bool,
        status: ValidationStatus,
        error_type: Optional[AuthErrorType] = None,
        error_message: Optional[str] = None,
        status_code: Optional[int] = None,
        response_time_ms: Optional[float] = None,
        rate_limit_info: Optional[RateLimitInfo] = None,
        validation_endpoint: Optional[str] = None,
    ) -> AuthenticationValidationResult:
        """Create validation result object."""
        result = AuthenticationValidationResult(
            is_valid=is_valid,
            validation_status=status,
            status_code=status_code,
            response_time_ms=response_time_ms,
            error_type=error_type,
            error_message=error_message,
            rate_limit_info=rate_limit_info,
            validation_endpoint=validation_endpoint,
        )
        if error_type == AuthErrorType.AUTHENTICATION_FAILED:
            result.add_recommendation("Verify API key is correct and active")
            result.add_recommendation("Check if API key has been revoked or expired")
        elif error_type == AuthErrorType.INSUFFICIENT_PERMISSIONS:
            result.add_recommendation("Verify API key has required permissions/scopes")
            result.add_recommendation("Check API documentation for required permissions")
        elif error_type == AuthErrorType.RATE_LIMIT_EXCEEDED:
            result.add_recommendation("Reduce request frequency or upgrade API plan")
            if rate_limit_info and rate_limit_info.retry_after:
                result.add_recommendation(
                    f"Wait {rate_limit_info.retry_after} seconds before retrying"
                )
        return result

    async def _update_credential_after_validation(
        self, target_id: UUID, result: AuthenticationValidationResult
    ) -> None:
        """Update credential metadata after successful validation."""
        try:
            self.credential_manager.update_credential_metadata(
                target_id,
                validation_status=result.validation_status,
                last_validated=result.validation_timestamp,
            )
        except Exception as e:
            logger.warning(f"Failed to update credential metadata for {target_id}: {e}")

    async def test_authentication(self, target: TargetModel) -> Dict[str, Any]:
        """Test authentication for a target with comprehensive checks.

        Args:
            target: Target to test authentication for

        Returns:
            Dictionary with test results
        """
        test_results = {
            "target_id": str(target.id),
            "target_name": target.name,
            "timestamp": datetime.utcnow().isoformat(),
            "overall_success": False,
            "tests": [],
        }
        try:
            credential_test = await self._test_credential_retrieval(target)
            test_results["tests"].append(credential_test)
            if not credential_test["success"]:
                return test_results
            credential = credential_test["credential"]
            validation_test = await self._test_credential_validation(target, credential)
            test_results["tests"].append(validation_test)
            if validation_test["success"]:
                rate_limit_test = await self._test_rate_limits(target, credential)
                test_results["tests"].append(rate_limit_test)
            test_results["overall_success"] = all(test["success"] for test in test_results["tests"])
        except Exception as e:
            test_results["tests"].append(
                {
                    "test_name": "authentication_test_error",
                    "success": False,
                    "error": str(e),
                    "timestamp": datetime.utcnow().isoformat(),
                }
            )
        return test_results

    async def _test_credential_retrieval(self, target: TargetModel) -> Dict[str, Any]:
        """Test credential retrieval for target."""
        test_result = {
            "test_name": "credential_retrieval",
            "success": False,
            "timestamp": datetime.utcnow().isoformat(),
        }
        try:
            credential = self.credential_manager.retrieve_credential(target.id)
            if credential and credential.token:
                test_result["success"] = True
                test_result["credential"] = credential
                test_result["key_format"] = credential.key_format.value
                test_result[
                    "masked_key"
                ] = f"{'*' * (len(credential.token) - 4)}{credential.token[-4:]}"
            else:
                test_result["error"] = "No valid credential found"
        except Exception as e:
            test_result["error"] = str(e)
        return test_result

    async def _test_credential_validation(
        self, target: TargetModel, credential: ApiKeyCredentialModel
    ) -> Dict[str, Any]:
        """Test credential validation."""
        test_result = {
            "test_name": "credential_validation",
            "success": False,
            "timestamp": datetime.utcnow().isoformat(),
        }
        try:
            validation_result = await self.validate_credential(target, credential)
            test_result["success"] = validation_result.is_valid
            test_result["validation_status"] = validation_result.validation_status.value
            test_result["response_time_ms"] = validation_result.response_time_ms
            test_result["status_code"] = validation_result.status_code
            if not validation_result.is_valid:
                test_result["error"] = validation_result.error_message
                test_result["error_type"] = (
                    validation_result.error_type.value if validation_result.error_type else None
                )
                test_result["recommendations"] = validation_result.recommendations
        except Exception as e:
            test_result["error"] = str(e)
        return test_result

    async def _test_rate_limits(
        self, target: TargetModel, credential: ApiKeyCredentialModel
    ) -> Dict[str, Any]:
        """Test rate limit detection."""
        test_result = {
            "test_name": "rate_limit_detection",
            "success": True,
            "timestamp": datetime.utcnow().isoformat(),
        }
        try:
            validation_url = self._get_validation_endpoint(target, credential)
            if not validation_url:
                test_result["success"] = False
                test_result["error"] = "No validation endpoint available"
                return test_result
            headers = self._build_auth_headers(credential)
            response = await self.http_client.get(
                validation_url, headers=headers, timeout=self.timeout
            )
            rate_limit_info = self._extract_rate_limit_info(response)
            if rate_limit_info:
                test_result["rate_limit_detected"] = True
                test_result["requests_remaining"] = rate_limit_info.requests_remaining
                test_result["reset_timestamp"] = (
                    rate_limit_info.reset_timestamp.isoformat()
                    if rate_limit_info.reset_timestamp
                    else None
                )
            else:
                test_result["rate_limit_detected"] = False
                test_result["note"] = "No rate limit headers detected"
        except Exception as e:
            test_result["error"] = str(e)
            test_result["success"] = False
        return test_result
