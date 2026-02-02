"""Response comparison utilities for S3 compliance testing.

Compares responses from AWS S3 and custom S3 implementations,
identifying differences while ignoring dynamic fields.
"""

from dataclasses import dataclass, field
from typing import Any, Optional, TYPE_CHECKING
import xml.etree.ElementTree as ET

from deepdiff import DeepDiff

if TYPE_CHECKING:
    import requests


@dataclass
class ComparisonResponse:
    """Response wrapper for dual-endpoint comparison mode.

    In comparison mode (--endpoint=both), this wraps responses from both
    AWS and custom endpoints along with their comparison result.

    Usage:
        if hasattr(response, 'comparison'):
            # Comparison mode - check both endpoints
            assert response.aws.status_code == 400
            assert response.comparison.is_compliant
        else:
            # Single endpoint mode
            assert response.status_code == 400
    """
    aws: "requests.Response"
    custom: "requests.Response"
    comparison: "ComparisonResult"

    @property
    def is_compliant(self) -> bool:
        """Shortcut to check if custom matches AWS behavior."""
        return self.comparison.is_compliant

    @property
    def diff_summary(self) -> str:
        """Human-readable summary of differences."""
        if self.is_compliant:
            return "Responses match"

        parts = []
        if not self.comparison.status_match:
            parts.append(
                f"Status: AWS={self.comparison.aws_status}, "
                f"Custom={self.comparison.custom_status}"
            )
        if not self.comparison.error_code_match:
            parts.append(
                f"Error code: AWS={self.comparison.aws_error_code}, "
                f"Custom={self.comparison.custom_error_code}"
            )
        if self.comparison.body_differences:
            parts.append(f"Body differs: {self.comparison.body_differences}")

        return "; ".join(parts) if parts else "Unknown difference"


# Headers that vary between requests and should be ignored
IGNORE_HEADERS = {
    "x-amz-request-id",
    "x-amz-id-2",
    "date",
    "server",
    "x-amz-version-id",
    "content-length",  # May vary due to formatting
    "connection",
    "keep-alive",
}

# XML elements that are dynamic and should be ignored in comparison
IGNORE_XML_ELEMENTS = {
    "RequestId",
    "HostId",
    "Resource",
}


@dataclass
class ComparisonResult:
    """Result of comparing S3 responses between endpoints."""

    test_name: str
    aws_status: int
    custom_status: int
    status_match: bool
    aws_error_code: Optional[str] = None
    custom_error_code: Optional[str] = None
    error_code_match: bool = True
    body_differences: dict[str, Any] = field(default_factory=dict)
    header_differences: dict[str, Any] = field(default_factory=dict)
    aws_response: dict = field(default_factory=dict)
    custom_response: dict = field(default_factory=dict)

    @property
    def is_compliant(self) -> bool:
        """Check if custom S3 behavior matches AWS."""
        return (
            self.status_match
            and self.error_code_match
            and not self.body_differences
        )

    @property
    def compliance_level(self) -> str:
        """Return compliance level as string."""
        if self.is_compliant:
            return "FULL"
        if self.status_match and self.error_code_match:
            return "PARTIAL"  # Same status/error but body differs
        if self.status_match:
            return "STATUS_ONLY"  # Same status but different error
        return "NON_COMPLIANT"

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "test_name": self.test_name,
            "aws_status": self.aws_status,
            "custom_status": self.custom_status,
            "status_match": self.status_match,
            "aws_error_code": self.aws_error_code,
            "custom_error_code": self.custom_error_code,
            "error_code_match": self.error_code_match,
            "body_differences": self.body_differences,
            "header_differences": self.header_differences,
            "is_compliant": self.is_compliant,
            "compliance_level": self.compliance_level,
        }


def extract_error_code(xml_body: str) -> Optional[str]:
    """Extract error code from S3 XML error response."""
    if not xml_body or "<Error>" not in xml_body:
        return None
    try:
        root = ET.fromstring(xml_body)
        # Try with namespace
        code_elem = root.find(".//{http://s3.amazonaws.com/doc/2006-03-01/}Code")
        if code_elem is None:
            # Try without namespace
            code_elem = root.find(".//Code")
        return code_elem.text if code_elem is not None else None
    except ET.ParseError:
        return None


def filter_headers(headers: dict) -> dict:
    """Filter out dynamic headers that should be ignored in comparison."""
    return {
        k: v for k, v in headers.items() if k.lower() not in IGNORE_HEADERS
    }


def xml_to_dict(element: ET.Element) -> dict:
    """Convert XML element to dictionary, removing namespaces."""
    result = {}

    # Remove namespace from tag
    tag = element.tag
    if "}" in tag:
        tag = tag.split("}")[1]

    # Skip ignored elements
    if tag in IGNORE_XML_ELEMENTS:
        return {}

    # Get text content
    if element.text and element.text.strip():
        result["_text"] = element.text.strip()

    # Get attributes
    if element.attrib:
        result["_attrs"] = dict(element.attrib)

    # Get children
    children = {}
    for child in element:
        child_tag = child.tag
        if "}" in child_tag:
            child_tag = child_tag.split("}")[1]

        if child_tag in IGNORE_XML_ELEMENTS:
            continue

        child_dict = xml_to_dict(child)
        if child_dict:
            if child_tag in children:
                # Multiple children with same tag -> list
                if not isinstance(children[child_tag], list):
                    children[child_tag] = [children[child_tag]]
                children[child_tag].append(child_dict)
            else:
                children[child_tag] = child_dict

    if children:
        result.update(children)

    return result


def normalize_xml(xml_body: str) -> dict:
    """Convert XML body to normalized dict for comparison."""
    if not xml_body:
        return {}
    try:
        root = ET.fromstring(xml_body)
        return xml_to_dict(root)
    except ET.ParseError:
        return {"_raw": xml_body}


def compare_responses(
    aws_response: dict,
    custom_response: dict,
    test_name: str,
) -> ComparisonResult:
    """Compare AWS and custom S3 responses.

    Args:
        aws_response: Dict with 'status_code', 'headers', 'body' from AWS
        custom_response: Dict with same structure from custom S3
        test_name: Name of the test for reporting

    Returns:
        ComparisonResult with detailed comparison
    """
    # Compare status codes
    aws_status = aws_response.get("status_code", 0)
    custom_status = custom_response.get("status_code", 0)
    status_match = aws_status == custom_status

    # Compare error codes (if errors)
    aws_error = extract_error_code(aws_response.get("body", ""))
    custom_error = extract_error_code(custom_response.get("body", ""))
    error_code_match = aws_error == custom_error

    # Compare headers (excluding dynamic ones)
    aws_headers = filter_headers(aws_response.get("headers", {}))
    custom_headers = filter_headers(custom_response.get("headers", {}))
    header_diff = DeepDiff(aws_headers, custom_headers, ignore_order=True)

    # Compare body (excluding dynamic elements)
    aws_body_normalized = normalize_xml(aws_response.get("body", ""))
    custom_body_normalized = normalize_xml(custom_response.get("body", ""))
    body_diff = DeepDiff(
        aws_body_normalized,
        custom_body_normalized,
        ignore_order=True,
    )

    return ComparisonResult(
        test_name=test_name,
        aws_status=aws_status,
        custom_status=custom_status,
        status_match=status_match,
        aws_error_code=aws_error,
        custom_error_code=custom_error,
        error_code_match=error_code_match,
        body_differences=dict(body_diff) if body_diff else {},
        header_differences=dict(header_diff) if header_diff else {},
        aws_response=aws_response,
        custom_response=custom_response,
    )


@dataclass
class ComparisonSummary:
    """Summary of multiple comparison results."""

    results: list[ComparisonResult] = field(default_factory=list)

    def add(self, result: ComparisonResult):
        """Add a comparison result."""
        self.results.append(result)

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def compliant_count(self) -> int:
        return sum(1 for r in self.results if r.is_compliant)

    @property
    def partial_count(self) -> int:
        return sum(1 for r in self.results if r.compliance_level == "PARTIAL")

    @property
    def non_compliant_count(self) -> int:
        return sum(1 for r in self.results if r.compliance_level == "NON_COMPLIANT")

    @property
    def compliance_rate(self) -> float:
        if self.total == 0:
            return 0.0
        return self.compliant_count / self.total * 100

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "summary": {
                "total": self.total,
                "compliant": self.compliant_count,
                "partial": self.partial_count,
                "non_compliant": self.non_compliant_count,
                "compliance_rate": f"{self.compliance_rate:.1f}%",
            },
            "results": [r.to_dict() for r in self.results],
        }

    def get_non_compliant(self) -> list[ComparisonResult]:
        """Get list of non-compliant results."""
        return [r for r in self.results if not r.is_compliant]
