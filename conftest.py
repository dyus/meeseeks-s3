"""Global pytest configuration and fixtures."""

import os
import sys
from datetime import datetime
from pathlib import Path

import pytest

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from s3_compliance.client import S3ClientFactory
from s3_compliance.http_capture import TestHTTPData, http_captures_key

# Global storage for test results (used by markdown report generator)
_test_results: list[TestHTTPData] = []


def pytest_addoption(parser):
    """Add custom command-line options."""
    parser.addoption(
        "--endpoint",
        action="store",
        default="aws",
        choices=["aws", "custom", "both"],
        help="S3 endpoint(s) to test against (default: aws)",
    )
    parser.addoption(
        "--comparison-report",
        action="store",
        default="reports/comparison.json",
        help="Path for comparison report output",
    )
    parser.addoption(
        "--show-comparison",
        action="store_true",
        default=False,
        help="Show detailed comparison of request/response headers and bodies",
    )
    parser.addoption(
        "--no-verify-ssl",
        action="store_true",
        default=False,
        help="Disable SSL certificate verification (INSECURE - use for testing only)",
    )
    parser.addoption(
        "--md-report",
        action="store_true",
        default=False,
        help="Generate markdown report with HTTP request/response details",
    )
    parser.addoption(
        "--md-report-prefix",
        action="store",
        default=None,
        help="Report filename prefix (default: current date YYYY-MM-DD)",
    )
    parser.addoption(
        "--md-report-dir",
        action="store",
        default="reports",
        help="Output directory for markdown reports (default: reports)",
    )


def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers", "s3_handler(name): mark test as testing specific S3 handler"
    )
    config.addinivalue_line(
        "markers", "edge_case: mark test as edge case or boundary condition"
    )
    config.addinivalue_line(
        "markers", "comparison: mark test as comparing AWS vs custom S3"
    )
    config.addinivalue_line("markers", "slow: mark test as slow running")
    config.addinivalue_line(
        "markers", "aws_only: mark test as only running against real AWS"
    )


@pytest.fixture(scope="session")
def s3_factory():
    """Session-scoped S3 client factory."""
    return S3ClientFactory()


@pytest.fixture(scope="session")
def aws_client(s3_factory):
    """Session-scoped AWS S3 client."""
    return s3_factory.create_client("aws")


@pytest.fixture(scope="session")
def custom_client(s3_factory):
    """Session-scoped custom S3 client."""
    endpoint = os.getenv("S3_ENDPOINT")
    if not endpoint:
        pytest.skip("S3_ENDPOINT not configured for custom client")
    return s3_factory.create_client("custom")


@pytest.fixture
def s3_client(request, s3_factory):
    """Parametrized S3 client based on --endpoint option."""
    endpoint = request.config.getoption("--endpoint")
    if endpoint == "both":
        # Return dict with both clients for comparison tests
        return {
            "aws": s3_factory.create_client("aws"),
            "custom": s3_factory.create_client("custom"),
        }
    return s3_factory.create_client(endpoint)


@pytest.fixture
def endpoint_name(request):
    """Get the endpoint name being tested."""
    return request.config.getoption("--endpoint")


@pytest.fixture(scope="session")
def test_bucket():
    """Test bucket name from environment."""
    return os.getenv("TEST_BUCKET_NAME", "anon-reverse-s3-test-bucket")


@pytest.fixture(scope="session")
def aws_region():
    """AWS region from environment."""
    return os.getenv("AWS_REGION", "us-east-1")


@pytest.fixture(scope="session")
def aws_profile():
    """AWS profile from environment."""
    return os.getenv("AWS_PROFILE", "aws")


@pytest.fixture
def endpoint_url(s3_factory, endpoint_name):
    """Get the endpoint URL for the current test."""
    if endpoint_name == "both":
        return {
            "aws": s3_factory.get_endpoint_url("aws"),
            "custom": s3_factory.get_endpoint_url("custom"),
        }
    return s3_factory.get_endpoint_url(endpoint_name)


@pytest.fixture
def credentials(s3_factory, endpoint_name):
    """Get credentials for the current endpoint."""
    if endpoint_name == "both":
        return {
            "aws": s3_factory.get_credentials("aws"),
            "custom": s3_factory.get_credentials("custom"),
        }
    return s3_factory.get_credentials(endpoint_name)


@pytest.fixture
def region(s3_factory, endpoint_name):
    """Get region for the current endpoint."""
    if endpoint_name == "both":
        return {
            "aws": s3_factory.get_region("aws"),
            "custom": s3_factory.get_region("custom"),
        }
    return s3_factory.get_region(endpoint_name)


@pytest.fixture
def verify_ssl(request, s3_factory, endpoint_name):
    """Get SSL verification setting for HTTP requests.

    SSL verification is enabled by default for security.
    Use --no-verify-ssl CLI option to disable (for testing with self-signed certs).
    """
    # CLI flag takes precedence
    if request.config.getoption("--no-verify-ssl"):
        return False

    # Otherwise use endpoint configuration from S3ClientFactory
    if endpoint_name == "both":
        # For comparison mode, use custom endpoint's setting (more likely to need disabled)
        return s3_factory.get_verify_ssl("custom")
    return s3_factory.get_verify_ssl(endpoint_name)


@pytest.fixture
def json_metadata(request):
    """Fixture to collect JSON metadata for reports."""
    metadata = {}
    yield metadata
    # Attach to test report
    if hasattr(request.node, "user_properties"):
        for key, value in metadata.items():
            request.node.user_properties.append((key, value))


def ensure_bucket_exists(s3_client, bucket_name, region="us-east-1"):
    """Ensure bucket exists, create if it doesn't."""
    try:
        s3_client.head_bucket(Bucket=bucket_name)
        return True
    except s3_client.exceptions.ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code == "404":
            try:
                if region == "us-east-1":
                    s3_client.create_bucket(Bucket=bucket_name)
                else:
                    s3_client.create_bucket(
                        Bucket=bucket_name,
                        CreateBucketConfiguration={"LocationConstraint": region},
                    )
            except s3_client.exceptions.BucketAlreadyExists:
                pass
            except s3_client.exceptions.BucketAlreadyOwnedByYou:
                pass
            return True
        raise


@pytest.fixture(scope="session")
def setup_test_bucket(aws_client, test_bucket, aws_region):
    """Ensure test bucket exists before running tests."""
    ensure_bucket_exists(aws_client, test_bucket, aws_region)
    return test_bucket


# ============================================================================
# Pytest Hooks for Markdown Report Generation
# ============================================================================


@pytest.hookimpl(wrapper=True, tryfirst=True)
def pytest_runtest_makereport(item, call):
    """Capture test results with HTTP data for markdown reporting."""
    rep = yield

    if rep.when == "call":
        # Extract handler from s3_handler marker
        handler = None
        for marker in item.iter_markers(name="s3_handler"):
            if marker.args:
                handler = marker.args[0]
                break

        # Get all markers
        markers = [m.name for m in item.iter_markers()]

        # Create test data object
        test_data = TestHTTPData(
            test_name=item.name,
            test_nodeid=item.nodeid,
            handler=handler,
            markers=markers,
            outcome=rep.outcome,
            duration=rep.duration,
        )

        # Get HTTP captures from stash if available
        if http_captures_key in item.stash:
            captures = item.stash[http_captures_key]
            for capture_data in captures:
                if "single" in capture_data:
                    # Single endpoint mode
                    test_data.captures.append(capture_data["single"])
                elif "aws" in capture_data and "custom" in capture_data:
                    # Comparison mode
                    test_data.set_comparison(
                        capture_data["aws"],
                        capture_data["custom"],
                        capture_data.get("comparison"),
                    )

        # Store for report generation
        _test_results.append(test_data)

    return rep


def pytest_sessionfinish(session, exitstatus):
    """Generate markdown reports at end of session."""
    if not session.config.getoption("--md-report"):
        return

    if not _test_results:
        return

    from s3_compliance.markdown_report import generate_grouped_reports

    output_dir = Path(session.config.getoption("--md-report-dir"))
    prefix = session.config.getoption("--md-report-prefix")

    if prefix is None:
        prefix = datetime.now().strftime("%Y-%m-%d")

    generated = generate_grouped_reports(_test_results, output_dir, prefix)

    print(f"\n{'=' * 60}")
    print("Markdown Reports Generated:")
    print("=" * 60)
    for path in generated:
        print(f"  {path}")
    print("=" * 60)
