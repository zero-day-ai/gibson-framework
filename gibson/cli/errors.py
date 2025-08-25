"""
Error handling utilities for Gibson Framework CLI.

Provides consistent error formatting, user-friendly messages,
and recovery suggestions with context-aware handling.
"""

import sys
import traceback
from typing import Any, Dict, List, Optional, Type, Union

from pydantic import ValidationError
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.tree import Tree

from gibson.cli.models.base import ErrorResponse
from gibson.cli.models.enums import LogLevel


class CLIErrorHandler:
    """
    Central error handler for CLI operations.
    
    Provides consistent error formatting and user guidance.
    """
    
    def __init__(self, console: Optional[Console] = None, debug: bool = False):
        self.console = console or Console(stderr=True)
        self.debug = debug
        self.error_codes = {
            ValidationError: "VALIDATION_ERROR",
            FileNotFoundError: "FILE_NOT_FOUND",
            PermissionError: "PERMISSION_DENIED",
            ConnectionError: "CONNECTION_ERROR",
            TimeoutError: "TIMEOUT",
            KeyboardInterrupt: "USER_CANCELLED",
        }
    
    def handle_exception(
        self,
        exception: Exception,
        command: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> ErrorResponse:
        """Handle any exception and return formatted error response."""
        error_code = self.error_codes.get(type(exception), "UNKNOWN_ERROR")
        
        # Create base error response
        error_response = ErrorResponse.from_exception(
            exception,
            command=command,
            include_traceback=self.debug
        )
        error_response.error_code = error_code
        
        # Add context if provided
        if context:
            error_response.error_details = context
        
        # Add specific handling for common error types
        if isinstance(exception, ValidationError):
            error_response.suggestions = self._get_validation_suggestions(exception)
            error_response.error_details = self._format_validation_errors(exception)
        
        elif isinstance(exception, FileNotFoundError):
            error_response.suggestions = [
                "Check that the file path is correct",
                "Ensure the file exists and is accessible",
                "Use absolute paths to avoid confusion"
            ]
        
        elif isinstance(exception, PermissionError):
            error_response.suggestions = [
                "Check file/directory permissions",
                "Try running with elevated privileges if appropriate",
                "Ensure you have write access to the target location"
            ]
        
        elif isinstance(exception, (ConnectionError, TimeoutError)):
            error_response.suggestions = [
                "Check your internet connection",
                "Verify the target URL is accessible",
                "Try increasing timeout values",
                "Check firewall settings"
            ]
        
        elif isinstance(exception, KeyboardInterrupt):
            error_response.message = "Operation cancelled by user"
            error_response.suggestions = [
                "Use --force flag to skip confirmations",
                "Run in batch mode to avoid interruptions"
            ]
        
        # Display error to user
        self.display_error(error_response)
        
        return error_response
    
    def display_error(self, error: ErrorResponse) -> None:
        """Display formatted error to the user."""
        # Create error panel
        error_text = Text()
        error_text.append("❌ ", style="red bold")
        error_text.append("Error: ", style="red bold")
        error_text.append(error.message or "Unknown error occurred")
        
        if error.error_code:
            error_text.append(f" [{error.error_code}]", style="red dim")
        
        # Create panel with error details
        panel_content = [error_text]
        
        # Add error details if available
        if error.error_details:
            panel_content.append("")
            panel_content.append(Text("Details:", style="yellow bold"))
            for key, value in error.error_details.items():
                panel_content.append(Text(f"  {key}: {value}", style="yellow"))
        
        # Add suggestions if available
        if error.suggestions:
            panel_content.append("")
            panel_content.append(Text("Suggestions:", style="blue bold"))
            for i, suggestion in enumerate(error.suggestions, 1):
                panel_content.append(Text(f"  {i}. {suggestion}", style="blue"))
        
        # Add traceback in debug mode
        if self.debug and error.traceback:
            panel_content.append("")
            panel_content.append(Text("Traceback:", style="red dim"))
            panel_content.append(Text(error.traceback, style="red dim"))
        
        # Display the panel
        self.console.print(Panel(
            "\n".join(str(item) if isinstance(item, str) else "" 
                     for item in panel_content if item),
            title="[red bold]Error[/red bold]",
            border_style="red"
        ))
    
    def _get_validation_suggestions(self, error: ValidationError) -> List[str]:
        """Generate suggestions for validation errors."""
        suggestions = []
        
        for err in error.errors():
            field = ".".join(str(loc) for loc in err.get("loc", []))
            error_type = err.get("type", "")
            
            if error_type == "missing":
                suggestions.append(f"Provide required field: {field}")
            elif error_type == "value_error":
                suggestions.append(f"Check the value format for: {field}")
            elif "type" in error_type:
                suggestions.append(f"Check data type for: {field}")
            elif "range" in error_type or "greater" in error_type:
                suggestions.append(f"Check value range for: {field}")
        
        if not suggestions:
            suggestions = [
                "Review input parameters for correct format",
                "Use --help to see expected parameter formats",
                "Check the documentation for examples"
            ]
        
        return suggestions
    
    def _format_validation_errors(self, error: ValidationError) -> Dict[str, Any]:
        """Format validation errors for display."""
        formatted_errors = {}
        
        for err in error.errors():
            field = ".".join(str(loc) for loc in err.get("loc", []))
            message = err.get("msg", "Validation failed")
            error_type = err.get("type", "unknown")
            
            formatted_errors[field] = {
                "message": message,
                "type": error_type,
                "input": err.get("input")
            }
        
        return formatted_errors


class ValidationErrorFormatter:
    """
    Specialized formatter for Pydantic validation errors.
    
    Creates user-friendly error messages from validation failures.
    """
    
    @staticmethod
    def format_error(error: ValidationError, model_name: str = "Input") -> str:
        """Format validation error as user-friendly message."""
        if len(error.errors()) == 1:
            return ValidationErrorFormatter._format_single_error(
                error.errors()[0], model_name
            )
        
        return ValidationErrorFormatter._format_multiple_errors(
            error.errors(), model_name
        )
    
    @staticmethod
    def _format_single_error(error_dict: Dict[str, Any], model_name: str) -> str:
        """Format a single validation error."""
        loc = error_dict.get("loc", [])
        msg = error_dict.get("msg", "Validation failed")
        error_type = error_dict.get("type", "")
        
        field_path = ".".join(str(loc_part) for loc_part in loc)
        
        if error_type == "missing":
            return f"Missing required field: {field_path}"
        elif error_type == "value_error":
            return f"Invalid value for {field_path}: {msg}"
        elif "type" in error_type:
            return f"Wrong data type for {field_path}: {msg}"
        else:
            return f"Validation error in {field_path}: {msg}"
    
    @staticmethod
    def _format_multiple_errors(
        errors: List[Dict[str, Any]], 
        model_name: str
    ) -> str:
        """Format multiple validation errors."""
        error_count = len(errors)
        formatted_errors = []
        
        for error_dict in errors:
            loc = error_dict.get("loc", [])
            msg = error_dict.get("msg", "Validation failed")
            field_path = ".".join(str(loc_part) for loc_part in loc)
            formatted_errors.append(f"  - {field_path}: {msg}")
        
        return (f"{model_name} validation failed with {error_count} errors:\n" +
                "\n".join(formatted_errors))


class ContextualErrorHandler:
    """
    Context-aware error handler that provides specific guidance.
    
    Analyzes the current operation context to provide targeted help.
    """
    
    def __init__(self):
        self.context_handlers = {
            "scan": self._handle_scan_errors,
            "module": self._handle_module_errors,
            "target": self._handle_target_errors,
            "config": self._handle_config_errors,
        }
    
    def handle_contextual_error(
        self,
        error: Exception,
        command_context: str,
        operation_data: Optional[Dict[str, Any]] = None
    ) -> List[str]:
        """Handle error with context-specific suggestions."""
        handler = self.context_handlers.get(command_context.lower())
        if handler:
            return handler(error, operation_data or {})
        
        return self._handle_generic_error(error)
    
    def _handle_scan_errors(
        self, 
        error: Exception, 
        data: Dict[str, Any]
    ) -> List[str]:
        """Handle scan-specific errors."""
        suggestions = []
        
        if isinstance(error, ValidationError):
            # Check for common scan validation issues
            error_str = str(error)
            if "target" in error_str.lower():
                suggestions.extend([
                    "Ensure target URL includes protocol (http:// or https://)",
                    "Check that target URL is valid and accessible",
                    "Try using IP address instead of domain name"
                ])
            
            if "domain" in error_str.lower():
                suggestions.extend([
                    "Use valid attack domains: prompts, data, model, system, output",
                    "Check domain names for typos",
                    "Use --help scan to see available domains"
                ])
        
        elif isinstance(error, ConnectionError):
            target = data.get("target", "unknown")
            suggestions.extend([
                f"Target {target} is not reachable",
                "Check target URL and network connectivity",
                "Verify firewall settings allow outbound connections",
                "Try with --verify-ssl=false if SSL issues"
            ])
        
        return suggestions
    
    def _handle_module_errors(
        self, 
        error: Exception, 
        data: Dict[str, Any]
    ) -> List[str]:
        """Handle module-specific errors."""
        suggestions = []
        module_name = data.get("module", "unknown")
        
        if isinstance(error, FileNotFoundError):
            suggestions.extend([
                f"Module '{module_name}' not found",
                "Use 'gibson module list' to see available modules",
                "Check module name spelling",
                "Try updating the module index with 'gibson module update'"
            ])
        
        elif isinstance(error, ImportError):
            suggestions.extend([
                f"Module '{module_name}' has missing dependencies",
                "Try 'gibson module install --dependencies {module_name}'",
                "Check if all required Python packages are installed"
            ])
        
        return suggestions
    
    def _handle_target_errors(
        self, 
        error: Exception, 
        data: Dict[str, Any]
    ) -> List[str]:
        """Handle target-specific errors."""
        suggestions = []
        
        if isinstance(error, ValidationError):
            error_str = str(error).lower()
            
            if "url" in error_str:
                suggestions.extend([
                    "Ensure URL includes protocol (http:// or https://)",
                    "Check URL format and remove any trailing slashes",
                    "Verify the URL is accessible from your network"
                ])
            
            if "auth" in error_str:
                suggestions.extend([
                    "Check authentication method and credentials",
                    "Verify API key format and permissions",
                    "Test authentication separately before adding target"
                ])
        
        return suggestions
    
    def _handle_config_errors(
        self, 
        error: Exception, 
        data: Dict[str, Any]
    ) -> List[str]:
        """Handle config-specific errors."""
        suggestions = []
        
        if isinstance(error, (PermissionError, FileNotFoundError)):
            config_file = data.get("config_file", "config file")
            suggestions.extend([
                f"Cannot access {config_file}",
                "Check file permissions and ownership",
                "Ensure config directory exists and is writable",
                "Try running with appropriate permissions"
            ])
        
        elif isinstance(error, ValidationError):
            suggestions.extend([
                "Configuration contains invalid values",
                "Use 'gibson config validate' to check configuration",
                "Check the documentation for valid configuration options",
                "Try 'gibson config reset' to restore defaults"
            ])
        
        return suggestions
    
    def _handle_generic_error(self, error: Exception) -> List[str]:
        """Handle generic errors with general suggestions."""
        return [
            "Check command syntax and parameters",
            "Use --help for command usage information",
            "Enable debug mode with --debug for more details",
            "Check the logs for additional error information"
        ]


def format_error_for_cli(
    error: Exception,
    command: Optional[str] = None,
    context: Optional[Dict[str, Any]] = None,
    debug: bool = False
) -> str:
    """Format any error for CLI display."""
    handler = CLIErrorHandler(debug=debug)
    error_response = handler.handle_exception(error, command, context)
    
    # Format as simple string for non-interactive display
    output_parts = [f"Error: {error_response.message}"]
    
    if error_response.error_code:
        output_parts.append(f"Code: {error_response.error_code}")
    
    if error_response.suggestions:
        output_parts.append("\nSuggestions:")
        for i, suggestion in enumerate(error_response.suggestions, 1):
            output_parts.append(f"  {i}. {suggestion}")
    
    if debug and error_response.traceback:
        output_parts.append("\nTraceback:")
        output_parts.append(error_response.traceback)
    
    return "\n".join(output_parts)


def create_error_response(
    error: Exception,
    command: Optional[str] = None,
    include_traceback: bool = False
) -> ErrorResponse:
    """Create standardized error response from exception."""
    return ErrorResponse.from_exception(
        error,
        command=command,
        include_traceback=include_traceback
    )
