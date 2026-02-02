"""HTTP request/response capture for reporting."""

from dataclasses import dataclass, field
from typing import Optional
import xml.dom.minidom

from pytest import StashKey

# Shared stash key for HTTP captures - import this in conftest.py files
http_captures_key = StashKey[list]()


@dataclass
class HTTPCapture:
    """Captured HTTP request and response details."""

    # Request details
    method: str
    url: str
    request_headers: dict = field(default_factory=dict)
    request_body: bytes = b""

    # Response details
    status_code: int = 0
    response_headers: dict = field(default_factory=dict)
    response_body: str = ""

    # Metadata
    endpoint_name: str = ""  # "aws" or "custom"

    def request_to_markdown(self, max_body_len: int = 2000) -> str:
        """Render request as markdown HTTP code block."""
        lines = [f"{self.method} {self.url} HTTP/1.1"]

        for key, value in self.request_headers.items():
            # Skip internal headers
            if key.lower() in ("authorization", "x-amz-security-token"):
                lines.append(f"{key}: [REDACTED]")
            else:
                lines.append(f"{key}: {value}")

        if self.request_body:
            lines.append("")
            body_str = self._decode_body(self.request_body)
            body_str = self._format_xml(body_str)
            if len(body_str) > max_body_len:
                body_str = body_str[:max_body_len] + "\n... [truncated]"
            lines.append(body_str)

        return "```http\n" + "\n".join(lines) + "\n```"

    def response_to_markdown(self, max_body_len: int = 2000) -> str:
        """Render response as markdown HTTP code block."""
        lines = [f"HTTP/1.1 {self.status_code}"]

        # Filter out noisy headers
        skip_headers = {"date", "server", "x-amz-request-id", "x-amz-id-2", "connection"}
        for key, value in self.response_headers.items():
            if key.lower() not in skip_headers:
                lines.append(f"{key}: {value}")

        if self.response_body:
            lines.append("")
            body_str = self._format_xml(self.response_body)
            if len(body_str) > max_body_len:
                body_str = body_str[:max_body_len] + "\n... [truncated]"
            lines.append(body_str)

        return "```http\n" + "\n".join(lines) + "\n```"

    def _decode_body(self, body: bytes) -> str:
        """Decode bytes to string."""
        if isinstance(body, str):
            return body
        try:
            return body.decode("utf-8")
        except UnicodeDecodeError:
            return body.decode("latin-1")

    def _format_xml(self, text: str) -> str:
        """Pretty-print XML if possible."""
        if not text or not text.strip().startswith("<?xml") and "<" not in text[:100]:
            return text
        try:
            dom = xml.dom.minidom.parseString(text.encode("utf-8"))
            return dom.toprettyxml(indent="  ").split("\n", 1)[1]  # Skip xml declaration
        except Exception:
            return text


@dataclass
class TestHTTPData:
    """HTTP data collected during a single test."""

    test_name: str
    test_nodeid: str
    handler: Optional[str] = None
    markers: list = field(default_factory=list)
    outcome: str = ""  # passed, failed, skipped
    duration: float = 0.0

    # Captures (may have multiple requests per test)
    captures: list = field(default_factory=list)  # List[HTTPCapture]

    # Comparison data (if --endpoint=both)
    aws_capture: Optional[HTTPCapture] = None
    custom_capture: Optional[HTTPCapture] = None
    comparison_result: Optional[dict] = None  # ComparisonResult as dict

    def add_capture(self, capture: HTTPCapture):
        """Add a captured request/response."""
        self.captures.append(capture)

    def set_comparison(self, aws: HTTPCapture, custom: HTTPCapture, result):
        """Set comparison data."""
        self.aws_capture = aws
        self.custom_capture = custom
        if hasattr(result, "__dict__"):
            self.comparison_result = {
                "is_compliant": result.is_compliant,
                "status_match": result.status_match,
                "error_code_match": result.error_code_match,
                "aws_status": result.aws_status,
                "custom_status": result.custom_status,
                "aws_error_code": getattr(result, "aws_error_code", None),
                "custom_error_code": getattr(result, "custom_error_code", None),
                "body_differences": result.body_differences,
                "header_differences": result.header_differences,
            }
        else:
            self.comparison_result = result
