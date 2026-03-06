"""Shared fixtures for UploadPartCopy tests.

UploadPartCopy (PUT /{Bucket}/{Key}?partNumber={N}&uploadId={Id})
copies data from an existing object into a part of a multipart upload.

Fixtures are session-scoped where possible to minimize AWS requests.
"""

import os
import uuid

import pytest

from s3_compliance.client import S3ClientFactory


SOURCE_BODY = b"upload-part-copy source content for compliance testing"  # 54 bytes
LARGE_SOURCE_BODY = b"x" * (5 * 1024 * 1024 + 1)  # 5 MB + 1 byte


@pytest.fixture(scope="session")
def upc_source_key():
    return f"test-upc-src-{uuid.uuid4().hex[:8]}"


@pytest.fixture(scope="session")
def upc_dest_key():
    return f"test-upc-dst-{uuid.uuid4().hex[:8]}"


@pytest.fixture(scope="session")
def upc_large_source_key():
    return f"test-upc-large-src-{uuid.uuid4().hex[:8]}"


@pytest.fixture(scope="session")
def source_object(request, aws_client, test_bucket, setup_test_bucket, upc_source_key):
    """Create a small source object for UploadPartCopy tests.

    Returns dict with key and etag.
    """
    endpoint_mode = request.config.getoption("--endpoint")

    custom_cl = None
    if os.getenv("S3_ENDPOINT") and endpoint_mode in ("custom", "both"):
        custom_cl = S3ClientFactory().create_client("custom")

    aws_etag = None
    if endpoint_mode in ("aws", "both"):
        resp = aws_client.put_object(
            Bucket=test_bucket, Key=upc_source_key, Body=SOURCE_BODY,
        )
        aws_etag = resp["ETag"]

    if custom_cl:
        custom_cl.put_object(
            Bucket=test_bucket, Key=upc_source_key, Body=SOURCE_BODY,
        )

    yield {"key": upc_source_key, "etag": aws_etag}

    if endpoint_mode in ("aws", "both"):
        try:
            aws_client.delete_object(Bucket=test_bucket, Key=upc_source_key)
        except Exception:
            pass
    if custom_cl:
        try:
            custom_cl.delete_object(Bucket=test_bucket, Key=upc_source_key)
        except Exception:
            pass


@pytest.fixture(scope="session")
def large_source_object(request, aws_client, test_bucket, setup_test_bucket, upc_large_source_key):
    """Create a >5MB source object for byte-range UploadPartCopy tests.

    Returns dict with key and etag.
    """
    endpoint_mode = request.config.getoption("--endpoint")

    custom_cl = None
    if os.getenv("S3_ENDPOINT") and endpoint_mode in ("custom", "both"):
        custom_cl = S3ClientFactory().create_client("custom")

    aws_etag = None
    if endpoint_mode in ("aws", "both"):
        resp = aws_client.put_object(
            Bucket=test_bucket, Key=upc_large_source_key, Body=LARGE_SOURCE_BODY,
        )
        aws_etag = resp["ETag"]

    if custom_cl:
        custom_cl.put_object(
            Bucket=test_bucket, Key=upc_large_source_key, Body=LARGE_SOURCE_BODY,
        )

    yield {"key": upc_large_source_key, "etag": aws_etag}

    if endpoint_mode in ("aws", "both"):
        try:
            aws_client.delete_object(Bucket=test_bucket, Key=upc_large_source_key)
        except Exception:
            pass
    if custom_cl:
        try:
            custom_cl.delete_object(Bucket=test_bucket, Key=upc_large_source_key)
        except Exception:
            pass


@pytest.fixture(scope="session")
def multipart_upload(request, aws_client, test_bucket, setup_test_bucket, upc_dest_key):
    """Create a multipart upload for UploadPartCopy tests.

    Session-scoped: shared across all UploadPartCopy tests.
    UploadPartCopy doesn't complete/abort the MPU, so sharing is safe.

    Returns upload_id string.
    """
    endpoint_mode = request.config.getoption("--endpoint")

    custom_cl = None
    if os.getenv("S3_ENDPOINT") and endpoint_mode in ("custom", "both"):
        custom_cl = S3ClientFactory().create_client("custom")

    aws_upload_id = None
    if endpoint_mode in ("aws", "both"):
        resp = aws_client.create_multipart_upload(
            Bucket=test_bucket, Key=upc_dest_key,
        )
        aws_upload_id = resp["UploadId"]

    custom_upload_id = None
    if custom_cl:
        resp = custom_cl.create_multipart_upload(
            Bucket=test_bucket, Key=upc_dest_key,
        )
        custom_upload_id = resp["UploadId"]

    if endpoint_mode == "both":
        yield {"aws": aws_upload_id, "custom": custom_upload_id}
    elif endpoint_mode == "custom":
        yield custom_upload_id
    else:
        yield aws_upload_id

    if endpoint_mode in ("aws", "both") and aws_upload_id:
        try:
            aws_client.abort_multipart_upload(
                Bucket=test_bucket, Key=upc_dest_key, UploadId=aws_upload_id,
            )
        except Exception:
            pass
    if custom_cl and custom_upload_id:
        try:
            custom_cl.abort_multipart_upload(
                Bucket=test_bucket, Key=upc_dest_key, UploadId=custom_upload_id,
            )
        except Exception:
            pass
