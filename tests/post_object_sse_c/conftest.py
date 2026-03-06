"""Shared fixtures for PostObject SSE-C tests."""

import io
import uuid

import pytest
import requests

from s3_compliance.http_capture import HTTPCapture, http_captures_key
from s3_compliance.sse_c import generate_sse_c_key


@pytest.fixture
def test_key():
    """Generate unique test key."""
    return f"test-post-ssec-{uuid.uuid4().hex[:8]}"


@pytest.fixture
def file_content():
    """Test file content."""
    return b"test content for PostObject SSE-C"


def make_presigned_post(s3_client, bucket, key, ssec_conditions=None, extra_conditions=None):
    """Generate presigned POST with optional SSE-C conditions.

    Args:
        s3_client: boto3 S3 client
        bucket: bucket name
        key: object key
        ssec_conditions: list of SSE-C condition tuples, e.g.:
            [["starts-with", "$x-amz-server-side-encryption-customer-algorithm", ""]]
        extra_conditions: additional policy conditions

    Returns:
        presigned POST dict with 'url' and 'fields'
    """
    conditions = []
    if ssec_conditions:
        conditions.extend(ssec_conditions)
    if extra_conditions:
        conditions.extend(extra_conditions)

    return s3_client.generate_presigned_post(
        Bucket=bucket,
        Key=key,
        Conditions=conditions or None,
        ExpiresIn=3600,
    )


ALL_SSEC_CONDITIONS = [
    ["starts-with", "$x-amz-server-side-encryption-customer-algorithm", ""],
    ["starts-with", "$x-amz-server-side-encryption-customer-key", ""],
    ["starts-with", "$x-amz-server-side-encryption-customer-key-MD5", ""],
]


def _do_post_with_ssec(url, fields, file_content, ssec_fields=None):
    """Execute POST request with SSE-C form fields.

    Returns:
        requests.Response
    """
    post_fields = fields.copy()
    if ssec_fields:
        post_fields.update(ssec_fields)

    files = {"file": ("test_file.txt", io.BytesIO(file_content), "application/octet-stream")}
    return requests.post(url, data=post_fields, files=files, verify=True)


@pytest.fixture
def post_with_ssec(request):
    """Fixture that executes POST with SSE-C fields and records HTTPCapture.

    Usage:
        response = post_with_ssec(url, fields, file_content, ssec_fields={...})
    """
    request.node.stash.setdefault(http_captures_key, [])

    def _post(url, fields, file_content, ssec_fields=None):
        response = _do_post_with_ssec(url, fields, file_content, ssec_fields)

        # Build all form fields for capture (presigned + SSE-C)
        all_fields = fields.copy()
        if ssec_fields:
            all_fields.update(ssec_fields)

        # Build request body representation
        body_lines = []
        for k, v in all_fields.items():
            body_lines.append(f"{k}: {v}")
        body_lines.append(f"file: ({len(file_content)} bytes)")
        body_str = "\n".join(body_lines).encode("utf-8")

        capture = HTTPCapture(
            method="POST",
            url=url,
            request_headers=dict(response.request.headers) if response.request else {},
            request_body=body_str,
            status_code=response.status_code,
            response_headers=dict(response.headers),
            response_body=response.text,
            endpoint_name="aws",
        )

        request.node.stash[http_captures_key].append({"single": capture})

        # Show HTTP if requested
        show_http = request.config.getoption("--show-http", default=False)
        if show_http:
            print(f"\n{'=' * 70}")
            print(f"HTTP: POST {url}")
            print(f"{'=' * 70}")
            print("\n--- REQUEST (form fields) ---")
            for k, v in all_fields.items():
                print(f"  {k}: {v}")
            print(f"  file: ({len(file_content)} bytes)")
            print(f"\n--- RESPONSE ---")
            print(f"Status: {response.status_code}")
            for k, v in response.headers.items():
                print(f"  {k}: {v}")
            if response.text:
                print(f"\n{response.text[:2000]}")
            print(f"{'=' * 70}\n")

        return response

    return _post
