"""S3 API Compliance Testing Framework"""

from s3_compliance.client import S3ClientFactory, EndpointConfig
from s3_compliance.signing import sign_request, get_credentials
from s3_compliance.utils import (
    calculate_content_md5,
    calculate_content_sha256,
    format_request_info,
    format_response_info,
)
from s3_compliance.comparison import (
    compare_responses,
    ComparisonResult,
    ComparisonResponse,
    ComparisonSummary,
)
from s3_compliance.reporting import (
    generate_json_report,
    generate_html_report,
    print_summary,
)
from s3_compliance.http_capture import HTTPCapture, TestHTTPData, http_captures_key
from s3_compliance.markdown_report import (
    generate_markdown_report,
    generate_grouped_reports,
)

__all__ = [
    # Client
    "S3ClientFactory",
    "EndpointConfig",
    # Signing
    "sign_request",
    "get_credentials",
    # Utils
    "calculate_content_md5",
    "calculate_content_sha256",
    "format_request_info",
    "format_response_info",
    # Comparison
    "compare_responses",
    "ComparisonResult",
    "ComparisonResponse",
    "ComparisonSummary",
    # Reporting
    "generate_json_report",
    "generate_html_report",
    "print_summary",
    # HTTP Capture
    "HTTPCapture",
    "TestHTTPData",
    "http_captures_key",
    # Markdown Report
    "generate_markdown_report",
    "generate_grouped_reports",
]
