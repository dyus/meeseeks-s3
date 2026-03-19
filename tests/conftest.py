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
from s3_compliance.http_capture import (
    HTTPCapture, TestHTTPData, SetupStep,
    http_captures_key, setup_steps_key,
)
from s3_compliance.golden import (
    golden_file_path,
    GoldenRecorder,
    GoldenPlayer,
)


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
def setup_steps(request):
    """Fixture that provides a recorder for setup operations.

    Usage in fixtures:
        def my_fixture(self, ..., setup_steps):
            mpu = client.create_multipart_upload(Bucket=bucket, Key=key, **ssec)
            setup_steps("CreateMultipartUpload", mpu, endpoint="aws",
                        Bucket=bucket, Key=key, SSE_C="AES256")
    """
    steps = []
    request.node.stash[setup_steps_key] = steps

    def _record(operation, response, endpoint="", **key_params):
        """Record a boto3 setup operation.

        Args:
            operation: Operation name (e.g. "CreateMultipartUpload")
            response: boto3 response dict (has ResponseMetadata)
            endpoint: Endpoint name ("aws", "custom", or "")
            **key_params: Key parameters to show in report
        """
        status = response.get("ResponseMetadata", {}).get("HTTPStatusCode", 0)
        # Extract only key result fields for the report
        _useful_keys = {"UploadId", "ETag", "ChecksumCRC32", "ChecksumSHA256",
                        "ChecksumSHA1", "ChecksumCRC32C", "ChecksumCRC64NVME",
                        "SSECustomerAlgorithm", "ServerSideEncryption",
                        "Bucket", "Key", "ContentLength"}
        result = {k: v for k, v in response.items()
                  if k != "ResponseMetadata" and k in _useful_keys}
        steps.append(SetupStep(
            operation=operation,
            params=key_params,
            status=status,
            result=result,
            endpoint_name=endpoint,
        ))

    return _record


@pytest.fixture
def golden_mode(request):
    """Returns True if golden replay is active (not recording, golden files exist)."""
    record = request.config.getoption("--record-golden")
    no_golden = request.config.getoption("--no-golden")
    return not record and not no_golden


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
def custom_endpoint_url(request):
    """Custom S3 endpoint URL.

    Returns None in single-endpoint AWS mode, skips in comparison/custom mode.
    """
    url = os.getenv("S3_ENDPOINT")
    endpoint_mode = request.config.getoption("--endpoint", default="aws")

    if endpoint_mode in ("custom", "both") and not url:
        pytest.skip("S3_ENDPOINT environment variable is required for custom endpoint tests")

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

    # Execute the request (no retries — fail immediately on connection errors)
    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(max_retries=0)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    request_func = getattr(session, method.lower())
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

    Golden file modes:
        --record-golden: Live AWS call + save response to golden file
        (default): Replay from golden file if it exists, live call if not
        --no-golden: Force live AWS calls, ignore golden files

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
    record_golden = request.config.getoption("--record-golden")
    no_golden = request.config.getoption("--no-golden")

    # Golden file setup
    # - --record-golden: always record (overwrite existing golden files)
    # - --no-golden: never use golden files, always live
    # - default: replay if golden file exists, auto-record on miss
    golden_path = golden_file_path(request.node.nodeid)
    use_golden = endpoint_mode in ("aws", "both") and not no_golden
    golden_recorder = None
    golden_player = None
    if use_golden:
        if record_golden:
            golden_recorder = GoldenRecorder(golden_path)
        elif golden_path.exists():
            golden_player = GoldenPlayer(golden_path)
        else:
            # Auto-record: no golden file yet, create one from live call
            golden_recorder = GoldenRecorder(golden_path)

    # Initialize captures list in stash
    request.node.stash[http_captures_key] = []

    def _capture_http(
        method: str,
        url: str,
        req_body: bytes,
        response,
        endpoint_name: str = "",
    ) -> HTTPCapture:
        """Create HTTPCapture from request/response.

        Uses response.request.headers to capture the actual signed headers
        that were sent over the wire (including Content-Length,
        x-amz-content-sha256, Authorization, etc.).

        For GoldenResponse (no .request attribute), request_headers will be empty.
        """
        actual_headers = {}
        if hasattr(response, "request") and response.request is not None:
            actual_headers = dict(response.request.headers)
        return HTTPCapture(
            method=method,
            url=url,
            request_headers=actual_headers,
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
        custom_body: bytes = None,
        custom_query_params: str = None,
        scheme: str = None,
    ) -> Union[requests.Response, ComparisonResponse]:
        """Make a signed request to S3.

        Args:
            method: HTTP method (GET, PUT, POST, DELETE, HEAD)
            path: URL path (e.g., "/bucket/key")
            body: Request body bytes
            headers: Additional headers dict
            query_params: Query string (e.g., "?delete")
            custom_body: Separate body for custom endpoint in 'both' mode (falls back to body)
            custom_query_params: Separate query params for custom endpoint in 'both' mode (falls back to query_params)
            scheme: Override URL scheme (e.g., "http" to force plain HTTP)

        Returns:
            requests.Response in single mode, ComparisonResponse in both mode
        """
        req_headers = dict(headers) if headers else {}

        # Add X-Forwarded-Proto: https to custom endpoint requests by default
        # (custom endpoint runs over HTTP, but Go server checks scheme for SSE-C).
        # Use --custom-http to disable this behavior.
        # Skipped when scheme="http" is explicitly passed (test wants plain HTTP).
        forward_proto = not request.config.getoption("--custom-http")

        def _inject_forwarded_proto(hdrs):
            """Add X-Forwarded-Proto: https if enabled and scheme not overridden to http."""
            if not forward_proto or scheme == "http":
                return hdrs
            if hdrs is not None:
                hdrs.setdefault("X-Forwarded-Proto", "https")
            else:
                hdrs = {"X-Forwarded-Proto": "https"}
            return hdrs

        def _apply_scheme(url):
            """Override URL scheme if requested."""
            if scheme and url:
                import re
                return re.sub(r'^https?://', f'{scheme}://', url)
            return url

        if endpoint_mode == "both":
            # Resolve per-endpoint body and query params
            actual_custom_body = custom_body if custom_body is not None else body
            actual_custom_query_params = custom_query_params if custom_query_params is not None else query_params

            # --- AWS side: golden file or live ---
            if golden_player:
                # Replay from golden file
                aws_resp = golden_player.next()
            else:
                # Live AWS call
                aws_resp = _do_request(
                    _apply_scheme(aws_endpoint_url),
                    aws_credentials,
                    aws_region,
                    method,
                    path,
                    body,
                    dict(headers) if headers else None,
                    query_params,
                    verify_ssl=verify_ssl,
                )
                if golden_recorder:
                    request_info = {
                        "method": method,
                        "path": path,
                        "query_params": query_params or "",
                        "headers": dict(aws_resp.request.headers),
                        "body": body,
                    }
                    golden_recorder.record(_response_to_dict(aws_resp), request_info=request_info)

            # Custom always goes live
            custom_headers = _inject_forwarded_proto(dict(headers) if headers else None)
            custom_resp = _do_request(
                _apply_scheme(custom_endpoint_url),
                custom_credentials,
                custom_region,
                method,
                path,
                actual_custom_body,
                custom_headers,
                actual_custom_query_params,
                verify_ssl=verify_ssl,
            )

            # Capture HTTP details for reporting
            aws_url = f"{_apply_scheme(aws_endpoint_url)}{path}{query_params}"
            custom_url = f"{_apply_scheme(custom_endpoint_url)}{path}{actual_custom_query_params}"
            aws_capture = _capture_http(method, aws_url, body, aws_resp, "aws")
            custom_capture = _capture_http(method, custom_url, actual_custom_body, custom_resp, "custom")

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
                golden_label = " [GOLDEN]" if golden_player else ""
                print("\n" + "=" * 70)
                print(f"COMPARISON: {method} {path}{query_params}{golden_label}")
                print("=" * 70)
                print("\n--- AWS Request ---")
                print(f"URL: {aws_endpoint_url}{path}{query_params}")
                print(f"Headers:")
                for k, v in aws_capture.request_headers.items():
                    print(f"  {k}: {v}")
                print(f"\n--- AWS Response{golden_label} ---")
                print(f"Status: {aws_resp.status_code}")
                print(f"Headers: {dict(aws_resp.headers)}")
                print(f"Body: {aws_resp.text[:500]}{'...' if len(aws_resp.text) > 500 else ''}")
                print("\n--- Custom Request ---")
                print(f"URL: {custom_endpoint_url}{path}{actual_custom_query_params}")
                print(f"Headers:")
                for k, v in custom_capture.request_headers.items():
                    print(f"  {k}: {v}")
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

        elif endpoint_mode == "aws" and golden_player:
            # Single AWS mode with golden replay
            aws_resp = golden_player.next()

            url = f"{endpoint_url}{path}{query_params}"
            capture = _capture_http(method, url, body, aws_resp, "aws")
            request.node.stash[http_captures_key].append({"single": capture})

            show_http = request.config.getoption("--show-http")
            if show_http:
                print("\n" + "=" * 70)
                print(f"HTTP [GOLDEN]: {method} {path}{query_params}")
                print("=" * 70)
                # Show request info from golden file if available
                if aws_resp._request_data:
                    req = aws_resp._request_data
                    print(f"\n--- REQUEST (from golden file) ---")
                    print(f"URL: {req.get('path', '')}{req.get('query_params', '')}")
                    print(f"Headers:")
                    for k, v in req.get("headers", {}).items():
                        print(f"  {k}: {v}")
                    req_body = req.get("body", "")
                    if req_body:
                        print(f"\nBody ({len(req_body)} chars):")
                        print(req_body[:2000])
                    else:
                        print("\nBody: (empty)")
                print(f"\n--- RESPONSE (from golden file) ---")
                print(f"Status: {aws_resp.status_code}")
                print(f"Headers:")
                for k, v in aws_resp.headers.items():
                    print(f"  {k}: {v}")
                if aws_resp.text:
                    print(f"\nBody ({len(aws_resp.text)} chars):")
                    print(aws_resp.text[:2000])
                print("=" * 70 + "\n")

            return aws_resp

        else:
            # Single endpoint mode - use current endpoint (live call)
            single_headers = dict(headers) if headers else None
            if endpoint_mode == "custom":
                single_headers = _inject_forwarded_proto(single_headers)
            response = _do_request(
                _apply_scheme(endpoint_url),
                credentials,
                region,
                method,
                path,
                body,
                single_headers,
                query_params,
                verify_ssl=verify_ssl,
            )

            # Record if in aws mode and recording
            if endpoint_mode == "aws" and golden_recorder:
                request_info = {
                    "method": method,
                    "path": path,
                    "query_params": query_params or "",
                    "headers": dict(response.request.headers),
                    "body": body,
                }
                golden_recorder.record(_response_to_dict(response), request_info=request_info)

            # Capture HTTP details for reporting
            url = f"{_apply_scheme(endpoint_url)}{path}{query_params}"
            capture = _capture_http(method, url, body, response, endpoint_mode)
            request.node.stash[http_captures_key].append({"single": capture})

            # Show HTTP details if requested
            show_http = request.config.getoption("--show-http")
            if show_http:
                print("\n" + "=" * 70)
                print(f"HTTP: {method} {path}{query_params}")
                print("=" * 70)
                print(f"\n--- REQUEST ---")
                print(f"URL: {url}")
                print(f"Headers:")
                # Show signed headers from capture
                for key, value in capture.request_headers.items():
                    print(f"  {key}: {value}")
                if body:
                    body_str = body.decode("utf-8", errors="replace")
                    print(f"\nBody ({len(body)} bytes):")
                    if len(body_str) > 1000:
                        print(body_str[:1000] + "... (truncated)")
                    else:
                        print(body_str)
                else:
                    print("\nBody: (empty)")
                print(f"\n--- RESPONSE ---")
                print(f"Status: {response.status_code}")
                print(f"Headers:")
                for key, value in response.headers.items():
                    print(f"  {key}: {value}")
                if response.text:
                    print(f"\nBody ({len(response.text)} chars):")
                    if len(response.text) > 2000:
                        print(response.text[:2000] + "... (truncated)")
                    else:
                        print(response.text)
                else:
                    print("\nBody: (empty)")
                print("=" * 70 + "\n")

            return response

    def _finalize():
        """Save golden recordings on test teardown."""
        if golden_recorder:
            golden_recorder.finalize()

    request.addfinalizer(_finalize)

    return _make
