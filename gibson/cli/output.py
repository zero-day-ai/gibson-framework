"""
Output formatting utilities for Gibson Framework CLI.

Provides model-to-output format conversion including tables,
JSON, YAML, SARIF, and CSV with rich formatting support.
"""

import csv
import json
import sys
from datetime import datetime
from io import StringIO
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import yaml
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from gibson.models.base import GibsonBaseModel
from gibson.cli.models.base import CommandResponse, PaginatedResponse
from gibson.cli.models.enums import OutputFormat, Severity


class OutputFormatter:
    """
    Central output formatter for CLI responses.

    Converts Pydantic models to various output formats with rich styling.
    """

    def __init__(self, console: Optional[Console] = None, color_enabled: bool = True):
        self.console = console or Console()
        self.color_enabled = color_enabled

        # Color schemes for different severities
        self.severity_colors = {
            Severity.CRITICAL: "red bold",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "blue",
            Severity.INFO: "green",
        }

    def format_output(
        self,
        data: Union[GibsonBaseModel, Dict[str, Any], List[Any]],
        format: OutputFormat,
        **kwargs,
    ) -> str:
        """Format data according to specified output format."""
        if format == OutputFormat.JSON:
            return self.to_json(data, **kwargs)
        elif format == OutputFormat.YAML:
            return self.to_yaml(data, **kwargs)
        elif format == OutputFormat.TABLE:
            return self.to_table(data, **kwargs)
        elif format == OutputFormat.CSV:
            return self.to_csv(data, **kwargs)
        elif format == OutputFormat.SARIF:
            return self.to_sarif(data, **kwargs)
        elif format == OutputFormat.MARKDOWN:
            return self.to_markdown(data, **kwargs)
        elif format == OutputFormat.HTML:
            return self.to_html(data, **kwargs)
        else:
            return str(data)

    def to_json(
        self, data: Union[GibsonBaseModel, Dict[str, Any], List[Any]], indent: int = 2, **kwargs
    ) -> str:
        """Convert data to JSON format."""
        if isinstance(data, GibsonBaseModel):
            return data.model_dump_json(indent=indent)
        elif hasattr(data, "model_dump"):
            return json.dumps(data.model_dump(), indent=indent, default=str)
        else:
            return json.dumps(data, indent=indent, default=str)

    def to_yaml(self, data: Union[GibsonBaseModel, Dict[str, Any], List[Any]], **kwargs) -> str:
        """Convert data to YAML format."""
        if isinstance(data, GibsonBaseModel):
            data_dict = data.model_dump()
        elif hasattr(data, "model_dump"):
            data_dict = data.model_dump()
        else:
            data_dict = data

        return yaml.dump(data_dict, default_flow_style=False, sort_keys=False, allow_unicode=True)

    def to_table(
        self,
        data: Union[GibsonBaseModel, Dict[str, Any], List[Any]],
        title: Optional[str] = None,
        max_width: Optional[int] = None,
        **kwargs,
    ) -> str:
        """Convert data to rich table format."""
        if isinstance(data, list):
            return self._list_to_table(data, title, max_width)
        elif isinstance(data, dict) or hasattr(data, "model_dump"):
            return self._dict_to_table(data, title, max_width)
        else:
            # Single value
            table = Table(title=title, show_header=False)
            table.add_column("Value")
            table.add_row(str(data))

            with StringIO() as string_io:
                console = Console(file=string_io, force_terminal=True, width=max_width)
                console.print(table)
                return string_io.getvalue()

    def _list_to_table(
        self, data: List[Any], title: Optional[str] = None, max_width: Optional[int] = None
    ) -> str:
        """Convert list to table format."""
        if not data:
            return "No data available"

        # Extract common fields from all items
        if isinstance(data[0], dict) or hasattr(data[0], "model_dump"):
            first_item = data[0].model_dump() if hasattr(data[0], "model_dump") else data[0]
            columns = list(first_item.keys())

            table = Table(title=title)
            for col in columns:
                table.add_column(col.replace("_", " ").title())

            for item in data:
                item_dict = item.model_dump() if hasattr(item, "model_dump") else item
                row_values = []

                for col in columns:
                    value = item_dict.get(col, "")

                    # Apply color coding for severity
                    if col == "severity" and value in self.severity_colors:
                        styled_value = Text(str(value).upper(), style=self.severity_colors[value])
                        row_values.append(styled_value)
                    else:
                        # Truncate long values
                        str_value = str(value)
                        if len(str_value) > 50:
                            str_value = str_value[:47] + "..."
                        row_values.append(str_value)

                table.add_row(*row_values)
        else:
            # Simple list of values
            table = Table(title=title, show_header=False)
            table.add_column("Items")
            for item in data:
                table.add_row(str(item))

        with StringIO() as string_io:
            console = Console(file=string_io, force_terminal=True, width=max_width)
            console.print(table)
            return string_io.getvalue()

    def _dict_to_table(
        self,
        data: Union[Dict[str, Any], GibsonBaseModel],
        title: Optional[str] = None,
        max_width: Optional[int] = None,
    ) -> str:
        """Convert dict/model to table format."""
        data_dict = data.model_dump() if hasattr(data, "model_dump") else data

        table = Table(title=title)
        table.add_column("Field", style="bold")
        table.add_column("Value")

        for key, value in data_dict.items():
            field_name = key.replace("_", " ").title()

            # Handle complex values
            if isinstance(value, (dict, list)):
                if isinstance(value, dict) and len(value) <= 3:
                    # Small dict - show inline
                    value_str = ", ".join(f"{k}: {v}" for k, v in value.items())
                elif isinstance(value, list) and len(value) <= 5:
                    # Small list - show inline
                    value_str = ", ".join(str(v) for v in value)
                else:
                    # Large structure - show count
                    value_str = f"{type(value).__name__} ({len(value)} items)"
            else:
                value_str = str(value)

                # Truncate very long values
                if len(value_str) > 100:
                    value_str = value_str[:97] + "..."

            # Apply styling for certain fields
            if key == "severity" and value in self.severity_colors:
                styled_value = Text(value_str.upper(), style=self.severity_colors[value])
                table.add_row(field_name, styled_value)
            else:
                table.add_row(field_name, value_str)

        with StringIO() as string_io:
            console = Console(file=string_io, force_terminal=True, width=max_width)
            console.print(table)
            return string_io.getvalue()

    def to_csv(
        self,
        data: Union[GibsonBaseModel, Dict[str, Any], List[Any]],
        delimiter: str = ",",
        **kwargs,
    ) -> str:
        """Convert data to CSV format."""
        output = StringIO()

        if isinstance(data, list) and data:
            # List of items - create CSV with headers
            first_item = data[0]
            if hasattr(first_item, "model_dump"):
                headers = list(first_item.model_dump().keys())
                writer = csv.DictWriter(output, fieldnames=headers, delimiter=delimiter)
                writer.writeheader()

                for item in data:
                    item_dict = item.model_dump() if hasattr(item, "model_dump") else item
                    # Flatten complex values
                    flattened = {}
                    for k, v in item_dict.items():
                        if isinstance(v, (dict, list)):
                            flattened[k] = json.dumps(v)
                        else:
                            flattened[k] = str(v)
                    writer.writerow(flattened)
            else:
                # Simple list
                writer = csv.writer(output, delimiter=delimiter)
                writer.writerow(["Value"])
                for item in data:
                    writer.writerow([str(item)])

        elif isinstance(data, dict) or hasattr(data, "model_dump"):
            # Single dict/model
            data_dict = data.model_dump() if hasattr(data, "model_dump") else data
            writer = csv.writer(output, delimiter=delimiter)

            for key, value in data_dict.items():
                if isinstance(value, (dict, list)):
                    value = json.dumps(value)
                writer.writerow([key, str(value)])

        return output.getvalue()

    def to_sarif(self, data: Union[GibsonBaseModel, Dict[str, Any], List[Any]], **kwargs) -> str:
        """Convert scan results to SARIF format."""
        # SARIF 2.1.0 format
        sarif_report = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Gibson Framework",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/your-org/gibson",
                        }
                    },
                    "results": [],
                }
            ],
        }

        results = []

        if isinstance(data, list):
            for item in data:
                if hasattr(item, "model_dump"):
                    item_dict = item.model_dump()
                else:
                    item_dict = item

                # Convert to SARIF result format
                sarif_result = self._to_sarif_result(item_dict)
                if sarif_result:
                    results.append(sarif_result)

        elif hasattr(data, "findings") or (isinstance(data, dict) and "findings" in data):
            # Handle scan results with findings
            data_dict = data.model_dump() if hasattr(data, "model_dump") else data
            findings = data_dict.get("findings", [])

            for finding in findings:
                sarif_result = self._to_sarif_result(finding)
                if sarif_result:
                    results.append(sarif_result)

        sarif_report["runs"][0]["results"] = results
        return json.dumps(sarif_report, indent=2)

    def _to_sarif_result(self, item_dict: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Convert a single item to SARIF result format."""
        # Map severity levels
        severity_map = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "info": "note",
        }

        severity = item_dict.get("severity", "info")
        sarif_level = severity_map.get(severity.lower(), "note")

        return {
            "ruleId": item_dict.get("vulnerability_type", "generic"),
            "message": {
                "text": item_dict.get("description", item_dict.get("title", "Security finding"))
            },
            "level": sarif_level,
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": item_dict.get("target", "unknown")}
                    }
                }
            ],
            "properties": {
                "confidence": item_dict.get("confidence", 0),
                "domain": item_dict.get("domain", "unknown"),
                "module": item_dict.get("module", "unknown"),
            },
        }

    def to_markdown(self, data: Union[GibsonBaseModel, Dict[str, Any], List[Any]], **kwargs) -> str:
        """Convert data to Markdown format."""
        output = []

        if isinstance(data, list) and data:
            # Create markdown table
            first_item = data[0]
            if hasattr(first_item, "model_dump"):
                headers = list(first_item.model_dump().keys())

                # Table header
                output.append(
                    "| " + " | ".join(h.replace("_", " ").title() for h in headers) + " |"
                )
                output.append("|" + "---|" * len(headers))

                # Table rows
                for item in data:
                    item_dict = item.model_dump() if hasattr(item, "model_dump") else item
                    row_values = []
                    for header in headers:
                        value = item_dict.get(header, "")
                        if isinstance(value, (dict, list)):
                            value = f"{len(value)} items"
                        row_values.append(str(value))
                    output.append("| " + " | ".join(row_values) + " |")
            else:
                # Simple list
                for item in data:
                    output.append(f"- {item}")

        elif isinstance(data, dict) or hasattr(data, "model_dump"):
            # Convert dict to markdown
            data_dict = data.model_dump() if hasattr(data, "model_dump") else data

            for key, value in data_dict.items():
                field_name = key.replace("_", " ").title()

                if isinstance(value, (dict, list)):
                    output.append(f"**{field_name}:** {len(value)} items")
                else:
                    output.append(f"**{field_name}:** {value}")

        return "\n".join(output)

    def to_html(self, data: Union[GibsonBaseModel, Dict[str, Any], List[Any]], **kwargs) -> str:
        """Convert data to HTML format."""
        html_parts = [
            "<!DOCTYPE html>",
            "<html><head>",
            "<title>Gibson Framework Output</title>",
            "<style>",
            "body { font-family: Arial, sans-serif; margin: 20px; }",
            "table { border-collapse: collapse; width: 100%; }",
            "th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }",
            "th { background-color: #f2f2f2; }",
            ".critical { color: #d32f2f; font-weight: bold; }",
            ".high { color: #f57c00; }",
            ".medium { color: #fbc02d; }",
            ".low { color: #388e3c; }",
            "</style>",
            "</head><body>",
        ]

        if isinstance(data, list) and data:
            # Create HTML table
            first_item = data[0]
            if hasattr(first_item, "model_dump"):
                headers = list(first_item.model_dump().keys())

                html_parts.append("<table>")
                html_parts.append("<tr>")
                for header in headers:
                    html_parts.append(f"<th>{header.replace('_', ' ').title()}</th>")
                html_parts.append("</tr>")

                for item in data:
                    item_dict = item.model_dump() if hasattr(item, "model_dump") else item
                    html_parts.append("<tr>")

                    for header in headers:
                        value = item_dict.get(header, "")

                        if header == "severity":
                            css_class = str(value).lower()
                            html_parts.append(f'<td class="{css_class}">{value}</td>')
                        elif isinstance(value, (dict, list)):
                            html_parts.append(f"<td>{len(value)} items</td>")
                        else:
                            html_parts.append(f"<td>{value}</td>")

                    html_parts.append("</tr>")

                html_parts.append("</table>")

        elif isinstance(data, dict) or hasattr(data, "model_dump"):
            # Convert dict to HTML table
            data_dict = data.model_dump() if hasattr(data, "model_dump") else data

            html_parts.append("<table>")
            for key, value in data_dict.items():
                field_name = key.replace("_", " ").title()

                if isinstance(value, (dict, list)):
                    value_str = f"{len(value)} items"
                else:
                    value_str = str(value)

                html_parts.append(f"<tr><th>{field_name}</th><td>{value_str}</td></tr>")
            html_parts.append("</table>")

        html_parts.extend(["</body></html>"])
        return "\n".join(html_parts)


class PaginatedOutputFormatter(OutputFormatter):
    """
    Specialized formatter for paginated responses.

    Adds pagination information and navigation hints.
    """

    def format_paginated(self, response: PaginatedResponse, format: OutputFormat, **kwargs) -> str:
        """Format paginated response with pagination info."""
        # Format the main data
        main_output = self.format_output(response.items, format, **kwargs)

        # Add pagination information
        if format in [OutputFormat.TABLE, OutputFormat.MARKDOWN]:
            pagination_info = self._create_pagination_info(response)
            return f"{main_output}\n\n{pagination_info}"
        elif format == OutputFormat.JSON:
            # Include pagination in JSON
            full_data = response.model_dump()
            return json.dumps(full_data, indent=2, default=str)
        else:
            return main_output

    def _create_pagination_info(self, response: PaginatedResponse) -> str:
        """Create pagination information display."""
        info_parts = [
            f"Page {response.page} of {response.pages}",
            f"Showing {len(response.items)} of {response.total} items",
        ]

        if response.has_prev:
            info_parts.append("Previous: --page " + str(response.page - 1))

        if response.has_next:
            info_parts.append("Next: --page " + str(response.page + 1))

        return " | ".join(info_parts)


def create_progress_display(description: str) -> Progress:
    """Create a progress display for long-running operations."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=Console(stderr=True),
        transient=True,
    )


def save_output_to_file(content: str, file_path: Path, format: OutputFormat) -> None:
    """Save formatted output to file."""
    # Ensure directory exists
    file_path.parent.mkdir(parents=True, exist_ok=True)

    # Determine encoding
    encoding = "utf-8"

    with open(file_path, "w", encoding=encoding) as f:
        f.write(content)


def format_command_response(
    response: CommandResponse, format: OutputFormat = OutputFormat.TABLE
) -> str:
    """Format a command response for CLI output."""
    formatter = OutputFormatter()

    if isinstance(response, PaginatedResponse):
        paginated_formatter = PaginatedOutputFormatter()
        return paginated_formatter.format_paginated(response, format)
    else:
        return formatter.format_output(response, format)


# Console rendering utilities
console = Console()


def render_error(message: str, exit_code: int = 1) -> None:
    """Render error message and exit."""
    console.print(f"[red]Error:[/red] {message}")
    sys.exit(exit_code)


def render_success(message: str) -> None:
    """Render success message."""
    console.print(f"[green]Success:[/green] {message}")


def render_warning(message: str) -> None:
    """Render warning message."""
    console.print(f"[yellow]Warning:[/yellow] {message}")


def render_info(message: str) -> None:
    """Render info message."""
    console.print(f"[blue]Info:[/blue] {message}")
