"""Test-level fixtures and utilities."""

import os
import uuid
from typing import Union

import pytest
import requests

from s3_compliance.signing import sign_request
from s3_compliance.utils import calculate_content_md5, calculate_content_sha256
from s3_compliance.comparison import (
    compare_responses,
    ComparisonResult,
    ComparisonResponse,
    ComparisonSummary,
)
from s3_compliance.http_capture import HTTPCapture, TestHTTPData, http_captures_key


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
            except Exception:
                pass
            return True
        raise


@pytest.fixture(scope="session", autouse=True)
def ensure_test_bucket_exists(aws_client, test_bucket, aws_region, request):
    """Auto-ensure test bucket exists for all tests."""
    ensure_bucket_exists(aws_client, test_bucket, aws_region)

    # Also ensure bucket exists on custom endpoint when running in comparison mode
    endpoint_mode = request.config.getoption("--endpoint")
    if endpoint_mode in ("custom", "both"):
        custom_endpoint = os.getenv("S3_ENDPOINT")
        if custom_endpoint:
            from s3_compliance.client import S3ClientFactory

            factory = S3ClientFactory()
            custom_client = factory.create_client("custom")
            custom_region = os.getenv("CUSTOM_S3_REGION", "eu-west-1")
            ensure_bucket_exists(custom_client, test_bucket, custom_region)

    return test_bucket


@pytest.fixture
def unique_key():
    """Generate a unique key for each test."""
    return f"test-{uuid.uuid4().hex[:8]}"


@pytest.fixture
def test_content():
    """Default test content."""
    return b"test content for compliance testing"


@pytest.fixture
def create_test_object(s3_client, test_bucket):
    """Factory fixture to create test objects."""
    created_objects = []

    def _create(key: str, content: bytes = b"test content"):
        response = s3_client.put_object(Bucket=test_bucket, Key=key, Body=content)
        etag = response.get("ETag", "").strip('"')
        created_objects.append(key)
        return etag

    yield _create

    # Cleanup
    for key in created_objects:
        try:
            s3_client.delete_object(Bucket=test_bucket, Key=key)
        except Exception:
            pass


@pytest.fixture
def make_signed_request(endpoint_url, credentials, region, verify_ssl):
    """Factory fixture for making signed HTTP requests."""

    def _make_request(
        method: str,
        path: str,
        body: bytes = b"",
        headers: dict = None,
        query_params: str = "",
    ):
        """Make a signed request to S3.

        Args:
            method: HTTP method
            path: URL path (e.g., "/bucket/key")
            body: Request body
            headers: Additional headers
            query_params: Query string (e.g., "?delete")

        Returns:
            requests.Response
        """
        url = f"{endpoint_url}{path}{query_params}"
        headers = headers or {}

        # Add required headers if not present
        if "Content-Length" not in headers:
            headers["Content-Length"] = str(len(body))

        if "x-amz-content-sha256" not in headers:
            headers["x-amz-content-sha256"] = calculate_content_sha256(body)

        # Sign the request
        signed_headers = sign_request(
            method=method,
            url=url,
            headers=headers,
            body=body,
            credentials=credentials,
            region=region,
        )

        # Make the request
        request_method = getattr(requests, method.lower())
        return request_method(url, data=body, headers=signed_headers, verify=verify_ssl)

    return _make_request


@pytest.fixture
def delete_objects_request(make_signed_request, test_bucket):
    """Factory fixture for DeleteObjects requests."""

    def _delete(keys_with_etags: list[tuple[str, str]], use_md5: bool = True):
        """Make DeleteObjects request.

        Args:
            keys_with_etags: List of (key, etag) tuples
            use_md5: Whether to include Content-MD5 header

        Returns:
            requests.Response
        """
        objects_xml = "\n".join(
            f"        <Object>\n            <Key>{key}</Key>\n            <ETag>{etag}</ETag>\n        </Object>"
            for key, etag in keys_with_etags
        )

        xml_body = f'''<?xml version="1.0" encoding="UTF-8"?>
<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
{objects_xml}
</Delete>'''

        body = xml_body.encode("utf-8")
        headers = {"Content-Type": "application/xml"}

        if use_md5:
            headers["Content-MD5"] = calculate_content_md5(body)

        return make_signed_request(
            method="POST",
            path=f"/{test_bucket}",
            body=body,
            headers=headers,
            query_params="?delete",
        )

    return _delete


@pytest.fixture
def put_object_request(make_signed_request, test_bucket):
    """Factory fixture for PutObject requests."""

    def _put(
        key: str,
        body: bytes,
        content_md5: str = None,
        content_type: str = "application/octet-stream",
    ):
        """Make PutObject request.

        Args:
            key: Object key
            body: Object content
            content_md5: Content-MD5 header value (None to skip, "correct" to calculate)
            content_type: Content-Type header

        Returns:
            requests.Response
        """
        headers = {"Content-Type": content_type}

        if content_md5 == "correct":
            headers["Content-MD5"] = calculate_content_md5(body)
        elif content_md5 is not None:
            headers["Content-MD5"] = content_md5

        return make_signed_request(
            method="PUT",
            path=f"/{test_bucket}/{key}",
            body=body,
            headers=headers,
        )

    return _put


# ============================================================================
# Comparison Fixtures (Phase 3)
# ============================================================================


@pytest.fixture(scope="session")
def comparison_summary():
    """Session-scoped summary to collect comparison results."""
    return ComparisonSummary()


@pytest.fixture
def capture_response():
    """Capture HTTP response as dict for comparison."""

    def _capture(response: requests.Response) -> dict:
        """Convert requests.Response to comparison dict.

        Args:
            response: HTTP response object

        Returns:
            Dict with status_code, headers, body
        """
        return {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": response.text,
        }

    return _capture


@pytest.fixture
def compare_endpoints_fixture(
    aws_endpoint_url,
    custom_endpoint_url,
    aws_credentials,
    custom_credentials,
    aws_region,
    custom_region,
    comparison_summary,
    capture_response,
    verify_ssl,
):
    """Factory fixture for comparing responses from AWS and custom endpoints."""

    def _compare(
        test_name: str,
        method: str,
        path: str,
        body: bytes = b"",
        headers: dict = None,
        query_params: str = "",
    ) -> ComparisonResult:
        """Execute same request against both endpoints and compare.

        Args:
            test_name: Name for the comparison result
            method: HTTP method
            path: URL path
            body: Request body
            headers: Additional headers
            query_params: Query string

        Returns:
            ComparisonResult with comparison details
        """
        headers = headers or {}

        # Add required headers
        if "Content-Length" not in headers:
            headers["Content-Length"] = str(len(body))
        if "x-amz-content-sha256" not in headers:
            headers["x-amz-content-sha256"] = calculate_content_sha256(body)

        # Request to AWS
        aws_url = f"{aws_endpoint_url}{path}{query_params}"
        aws_signed = sign_request(
            method=method,
            url=aws_url,
            headers=headers.copy(),
            body=body,
            credentials=aws_credentials,
            region=aws_region,
        )
        aws_response = getattr(requests, method.lower())(
            aws_url, data=body, headers=aws_signed, verify=verify_ssl
        )

        # Request to custom endpoint
        custom_url = f"{custom_endpoint_url}{path}{query_params}"
        custom_signed = sign_request(
            method=method,
            url=custom_url,
            headers=headers.copy(),
            body=body,
            credentials=custom_credentials,
            region=custom_region,
        )
        custom_response = getattr(requests, method.lower())(
            custom_url, data=body, headers=custom_signed, verify=verify_ssl
        )

        # Compare responses
        result = compare_responses(
            aws_response=capture_response(aws_response),
            custom_response=capture_response(custom_response),
            test_name=test_name,
        )

        # Add to session summary
        comparison_summary.add(result)

        return result

    return _compare


@pytest.fixture(scope="session")
def aws_endpoint_url():
    """AWS S3 endpoint URL."""
    return os.getenv("AWS_S3_ENDPOINT", "https://s3.us-east-1.amazonaws.com")


@pytest.fixture(scope="session")
def custom_endpoint_url():
    """Custom S3 endpoint URL."""
    url = os.getenv("S3_ENDPOINT")
    if not url:
        pytest.skip("S3_ENDPOINT environment variable is required for custom endpoint tests")
    if not url:
        pytest.skip("S3_ENDPOINT not set for comparison tests")
    return url


@pytest.fixture(scope="session")
def aws_credentials():
    """AWS credentials for comparison."""
    import boto3

    session = boto3.Session(profile_name=os.getenv("AWS_PROFILE", "aws"))
    creds = session.get_credentials()
    return {
        "access_key": creds.access_key,
        "secret_key": creds.secret_key,
        "token": creds.token,
    }


@pytest.fixture(scope="session")
def custom_credentials():
    """Custom endpoint credentials."""
    import boto3

    profile = os.getenv("CUSTOM_S3_PROFILE", os.getenv("AWS_PROFILE", "aws"))
    session = boto3.Session(profile_name=profile)
    creds = session.get_credentials()
    return {
        "access_key": creds.access_key,
        "secret_key": creds.secret_key,
        "token": creds.token,
    }


@pytest.fixture(scope="session")
def custom_region():
    """Custom endpoint region."""
    return os.getenv("CUSTOM_S3_REGION", "eu-west-1")


# ============================================================================
# Universal make_request Fixture (Unified Test + Comparison Mode)
# ============================================================================


def _do_request(
    endpoint_url: str,
    credentials,
    region: str,
    method: str,
    path: str,
    body: bytes = b"",
    headers: dict = None,
    query_params: str = "",
    verify_ssl: bool = True,
) -> requests.Response:
    """Execute a signed HTTP request to S3.

    Args:
        endpoint_url: Base URL for the endpoint
        credentials: Dict with access_key, secret_key, token OR botocore Credentials
        region: AWS region
        method: HTTP method (GET, PUT, POST, etc.)
        path: URL path (e.g., "/bucket/key")
        body: Request body bytes
        headers: Additional headers
        query_params: Query string (e.g., "?delete")
        verify_ssl: Whether to verify SSL certificates (default: True for security)

    Returns:
        requests.Response object
    """
    from botocore.credentials import Credentials

    url = f"{endpoint_url}{path}{query_params}"
    headers = dict(headers) if headers else {}

    # Add required headers if not present
    if "Content-Length" not in headers:
        headers["Content-Length"] = str(len(body))
    if "x-amz-content-sha256" not in headers:
        headers["x-amz-content-sha256"] = calculate_content_sha256(body)

    # Convert dict credentials to Credentials object if needed
    if isinstance(credentials, dict):
        creds = Credentials(
            access_key=credentials["access_key"],
            secret_key=credentials["secret_key"],
            token=credentials.get("token"),
        )
    else:
        creds = credentials

    # Sign the request
    signed_headers = sign_request(
        method=method,
        url=url,
        headers=headers,
        body=body,
        credentials=creds,
        region=region,
    )

    # Execute the request
    request_func = getattr(requests, method.lower())
    return request_func(url, data=body, headers=signed_headers, verify=verify_ssl)


def _response_to_dict(response: requests.Response) -> dict:
    """Convert requests.Response to dict for comparison."""
    return {
        "status_code": response.status_code,
        "headers": dict(response.headers),
        "body": response.text,
    }


@pytest.fixture
def make_request(
    request,
    endpoint_url,
    credentials,
    region,
    verify_ssl,
    aws_endpoint_url,
    aws_credentials,
    aws_region,
    custom_endpoint_url,
    custom_credentials,
    custom_region,
    comparison_summary,
):
    """Universal request fixture that works in single/comparison mode.

    In single mode (--endpoint=aws or --endpoint=custom):
        Returns requests.Response directly.

    In comparison mode (--endpoint=both):
        Returns ComparisonResponse with both responses and comparison.

    Also captures HTTP details for markdown reporting via --md-report.

    Usage:
        def test_something(make_request, test_bucket):
            response = make_request("PUT", f"/{test_bucket}/key", body=b"content")

            if hasattr(response, 'comparison'):
                # Comparison mode
                assert response.aws.status_code == 400
                assert response.comparison.is_compliant, response.diff_summary
            else:
                # Single endpoint mode
                assert response.status_code == 400
    """
    endpoint_mode = request.config.getoption("--endpoint")
    test_name = request.node.name

    # Initialize captures list in stash
    request.node.stash[http_captures_key] = []

    def _capture_http(
        method: str,
        url: str,
        req_headers: dict,
        req_body: bytes,
        response: requests.Response,
        endpoint_name: str = "",
    ) -> HTTPCapture:
        """Create HTTPCapture from request/response."""
        return HTTPCapture(
            method=method,
            url=url,
            request_headers=dict(req_headers) if req_headers else {},
            request_body=req_body,
            status_code=response.status_code,
            response_headers=dict(response.headers),
            response_body=response.text,
            endpoint_name=endpoint_name,
        )

    def _make(
        method: str,
        path: str,
        body: bytes = b"",
        headers: dict = None,
        query_params: str = "",
    ) -> Union[requests.Response, ComparisonResponse]:
        """Make a signed request to S3.

        Args:
            method: HTTP method (GET, PUT, POST, DELETE, HEAD)
            path: URL path (e.g., "/bucket/key")
            body: Request body bytes
            headers: Additional headers dict
            query_params: Query string (e.g., "?delete")

        Returns:
            requests.Response in single mode, ComparisonResponse in both mode
        """
        req_headers = dict(headers) if headers else {}

        if endpoint_mode == "both":
            # Execute request against both endpoints
            aws_resp = _do_request(
                aws_endpoint_url,
                aws_credentials,
                aws_region,
                method,
                path,
                body,
                dict(headers) if headers else None,
                query_params,
                verify_ssl=verify_ssl,
            )
            custom_resp = _do_request(
                custom_endpoint_url,
                custom_credentials,
                custom_region,
                method,
                path,
                body,
                dict(headers) if headers else None,
                query_params,
                verify_ssl=verify_ssl,
            )

            # Capture HTTP details for reporting
            aws_url = f"{aws_endpoint_url}{path}{query_params}"
            custom_url = f"{custom_endpoint_url}{path}{query_params}"
            aws_capture = _capture_http(method, aws_url, req_headers, body, aws_resp, "aws")
            custom_capture = _capture_http(method, custom_url, req_headers, body, custom_resp, "custom")

            # Compare responses
            comparison = compare_responses(
                aws_response=_response_to_dict(aws_resp),
                custom_response=_response_to_dict(custom_resp),
                test_name=f"{test_name}: {method} {path}",
            )

            # Store captures and comparison in stash for markdown report
            request.node.stash[http_captures_key].append({
                "aws": aws_capture,
                "custom": custom_capture,
                "comparison": comparison,
            })

            # Add to session summary for reporting
            comparison_summary.add(comparison)

            # Show detailed comparison if requested
            show_comparison = request.config.getoption("--show-comparison")
            if show_comparison:
                print("\n" + "=" * 70)
                print(f"COMPARISON: {method} {path}{query_params}")
                print("=" * 70)
                print("\n--- AWS Request ---")
                print(f"URL: {aws_endpoint_url}{path}{query_params}")
                print(f"Headers sent: {headers}")
                print("\n--- AWS Response ---")
                print(f"Status: {aws_resp.status_code}")
                print(f"Headers: {dict(aws_resp.headers)}")
                print(f"Body: {aws_resp.text[:500]}{'...' if len(aws_resp.text) > 500 else ''}")
                print("\n--- Custom Request ---")
                print(f"URL: {custom_endpoint_url}{path}{query_params}")
                print(f"Headers sent: {headers}")
                print("\n--- Custom Response ---")
                print(f"Status: {custom_resp.status_code}")
                print(f"Headers: {dict(custom_resp.headers)}")
                print(f"Body: {custom_resp.text[:500]}{'...' if len(custom_resp.text) > 500 else ''}")
                print("\n--- Comparison Result ---")
                print(f"Status match: {comparison.status_match}")
                print(f"Error code match: {comparison.error_code_match}")
                print(f"Is compliant: {comparison.is_compliant}")
                if comparison.body_differences:
                    print(f"Body differences: {comparison.body_differences}")
                print("=" * 70 + "\n")

            return ComparisonResponse(
                aws=aws_resp,
                custom=custom_resp,
                comparison=comparison,
            )
        else:
            # Single endpoint mode - use current endpoint
            response = _do_request(
                endpoint_url,
                credentials,
                region,
                method,
                path,
                body,
                dict(headers) if headers else None,
                query_params,
                verify_ssl=verify_ssl,
            )

            # Capture HTTP details for reporting
            url = f"{endpoint_url}{path}{query_params}"
            capture = _capture_http(method, url, req_headers, body, response, endpoint_mode)
            request.node.stash[http_captures_key].append({"single": capture})

            return response

    return _make
