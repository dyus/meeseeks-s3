"""Shared fixtures for UploadPartCopy SSE-C tests.

UploadPartCopy (PUT /{Bucket}/{Key}?partNumber={N}&uploadId={Id})
copies data from an existing object into a part of a multipart upload.

SSE-C header groups (same as CopyObject):
- Destination: x-amz-server-side-encryption-customer-* (encrypt part in MPU)
- Source: x-amz-copy-source-server-side-encryption-customer-* (decrypt source)
"""

import hashlib
import os
import uuid

import pytest

from s3_compliance.client import S3ClientFactory
from s3_compliance.sse_c import DEFAULT_SSE_C_KEY_BYTES, generate_sse_c_key


UPC_BODY = b"upload-part-copy sse-c test content"

# Second key for "different key" tests
SECOND_KEY_BYTES = hashlib.sha256(b"reverse_s3_ssec_second_key").digest()


@pytest.fixture(scope="module")
def source_key():
    return f"test-upc-ssec-src-{uuid.uuid4().hex[:8]}"


@pytest.fixture(scope="module")
def ssec_source_key():
    return f"test-upc-ssec-enc-src-{uuid.uuid4().hex[:8]}"


@pytest.fixture(scope="module")
def dest_key_prefix():
    return f"test-upc-ssec-dst-{uuid.uuid4().hex[:8]}"


@pytest.fixture(scope="module")
def upc_dest_key():
    return f"test-upc-ssec-mpu-{uuid.uuid4().hex[:8]}"


@pytest.fixture(scope="module")
def plain_source(request, aws_client, test_bucket, setup_test_bucket, source_key):
    """Create a plain (unencrypted) source object on each endpoint."""
    endpoint_mode = request.config.getoption("--endpoint")

    custom_cl = None
    if os.getenv("S3_ENDPOINT") and endpoint_mode in ("custom", "both"):
        custom_cl = S3ClientFactory().create_client("custom")

    kwargs = dict(Bucket=test_bucket, Key=source_key, Body=UPC_BODY)

    if endpoint_mode in ("aws", "both"):
        aws_client.put_object(**kwargs)
    if custom_cl:
        custom_cl.put_object(**kwargs)

    yield source_key

    if endpoint_mode in ("aws", "both"):
        try:
            aws_client.delete_object(Bucket=test_bucket, Key=source_key)
        except Exception:
            pass
    if custom_cl:
        try:
            custom_cl.delete_object(Bucket=test_bucket, Key=source_key)
        except Exception:
            pass


@pytest.fixture(scope="module")
def ssec_source(request, aws_client, test_bucket, setup_test_bucket, ssec_source_key):
    """Create an SSE-C encrypted source object on each endpoint.

    Uses DEFAULT_SSE_C_KEY_BYTES (key A).
    """
    endpoint_mode = request.config.getoption("--endpoint")
    key_b64, key_md5 = generate_sse_c_key()

    sse_kwargs = dict(
        Bucket=test_bucket,
        Key=ssec_source_key,
        Body=UPC_BODY,
        SSECustomerAlgorithm="AES256",
        SSECustomerKey=key_b64,
        SSECustomerKeyMD5=key_md5,
    )

    custom_cl = None
    if os.getenv("S3_ENDPOINT") and endpoint_mode in ("custom", "both"):
        custom_cl = S3ClientFactory().create_client("custom")

    def _add_forwarded_proto(params, **kwargs):
        params["headers"]["X-Forwarded-Proto"] = "https"

    if endpoint_mode in ("aws", "both"):
        aws_client.put_object(**sse_kwargs)
    if custom_cl:
        custom_cl.meta.events.register("before-call.s3.PutObject", _add_forwarded_proto)
        custom_cl.put_object(**sse_kwargs)
        custom_cl.meta.events.unregister("before-call.s3.PutObject", _add_forwarded_proto)

    yield ssec_source_key

    if endpoint_mode in ("aws", "both"):
        try:
            aws_client.delete_object(Bucket=test_bucket, Key=ssec_source_key)
        except Exception:
            pass
    if custom_cl:
        try:
            custom_cl.delete_object(Bucket=test_bucket, Key=ssec_source_key)
        except Exception:
            pass


def _create_multipart_upload(request, aws_client, test_bucket, key, ssec_params=None):
    """Helper to create an MPU on each endpoint with optional SSE-C params.

    Returns (aws_upload_id, custom_upload_id, custom_cl).
    """
    endpoint_mode = request.config.getoption("--endpoint")

    custom_cl = None
    if os.getenv("S3_ENDPOINT") and endpoint_mode in ("custom", "both"):
        custom_cl = S3ClientFactory().create_client("custom")

    create_kwargs = {"Bucket": test_bucket, "Key": key}
    if ssec_params:
        create_kwargs.update(ssec_params)

    def _add_forwarded_proto(params, **kwargs):
        params["headers"]["X-Forwarded-Proto"] = "https"

    aws_upload_id = None
    if endpoint_mode in ("aws", "both"):
        resp = aws_client.create_multipart_upload(**create_kwargs)
        aws_upload_id = resp["UploadId"]

    custom_upload_id = None
    if custom_cl:
        if ssec_params:
            custom_cl.meta.events.register(
                "before-call.s3.CreateMultipartUpload", _add_forwarded_proto,
            )
        resp = custom_cl.create_multipart_upload(**create_kwargs)
        if ssec_params:
            custom_cl.meta.events.unregister(
                "before-call.s3.CreateMultipartUpload", _add_forwarded_proto,
            )
        custom_upload_id = resp["UploadId"]

    return aws_upload_id, custom_upload_id, custom_cl


def _yield_mpu(endpoint_mode, aws_upload_id, custom_upload_id, key):
    """Format MPU result based on endpoint mode."""
    if endpoint_mode == "both":
        return {"aws": aws_upload_id, "custom": custom_upload_id, "key": key}
    elif endpoint_mode == "custom":
        return {"upload_id": custom_upload_id, "key": key}
    else:
        return {"upload_id": aws_upload_id, "key": key}


def _cleanup_mpu(aws_client, test_bucket, key, aws_upload_id, custom_upload_id, custom_cl, endpoint_mode):
    """Abort MPU on all endpoints."""
    if endpoint_mode in ("aws", "both") and aws_upload_id:
        try:
            aws_client.abort_multipart_upload(
                Bucket=test_bucket, Key=key, UploadId=aws_upload_id,
            )
        except Exception:
            pass
    if custom_cl and custom_upload_id:
        try:
            custom_cl.abort_multipart_upload(
                Bucket=test_bucket, Key=key, UploadId=custom_upload_id,
            )
        except Exception:
            pass


@pytest.fixture(scope="module")
def plain_multipart_upload(request, aws_client, test_bucket, setup_test_bucket, upc_dest_key):
    """Create a plain (no SSE-C) MPU on each endpoint.

    Used for tests that only test source SSE-C headers (decrypting source).
    """
    endpoint_mode = request.config.getoption("--endpoint")
    key = f"{upc_dest_key}-plain"

    aws_upload_id, custom_upload_id, custom_cl = _create_multipart_upload(
        request, aws_client, test_bucket, key,
    )

    yield _yield_mpu(endpoint_mode, aws_upload_id, custom_upload_id, key)

    _cleanup_mpu(aws_client, test_bucket, key, aws_upload_id, custom_upload_id, custom_cl, endpoint_mode)


@pytest.fixture(scope="module")
def ssec_multipart_upload(request, aws_client, test_bucket, setup_test_bucket, upc_dest_key):
    """Create an SSE-C MPU with DEFAULT key (key A) on each endpoint.

    Used for tests that test destination SSE-C headers (encrypting into MPU).
    """
    endpoint_mode = request.config.getoption("--endpoint")
    key = f"{upc_dest_key}-ssec"
    key_b64, key_md5 = generate_sse_c_key()

    aws_upload_id, custom_upload_id, custom_cl = _create_multipart_upload(
        request, aws_client, test_bucket, key,
        ssec_params={
            "SSECustomerAlgorithm": "AES256",
            "SSECustomerKey": key_b64,
            "SSECustomerKeyMD5": key_md5,
        },
    )

    yield _yield_mpu(endpoint_mode, aws_upload_id, custom_upload_id, key)

    _cleanup_mpu(aws_client, test_bucket, key, aws_upload_id, custom_upload_id, custom_cl, endpoint_mode)


@pytest.fixture(scope="module")
def ssec_multipart_upload_alt(request, aws_client, test_bucket, setup_test_bucket, upc_dest_key):
    """Create an SSE-C MPU with SECOND key (key B) on each endpoint.

    Used for "different key" happy path: source encrypted with DEFAULT key (A),
    MPU created with SECOND key (B), both valid but different.
    """
    endpoint_mode = request.config.getoption("--endpoint")
    key = f"{upc_dest_key}-ssec-alt"
    key_b64, key_md5 = generate_sse_c_key(SECOND_KEY_BYTES)

    aws_upload_id, custom_upload_id, custom_cl = _create_multipart_upload(
        request, aws_client, test_bucket, key,
        ssec_params={
            "SSECustomerAlgorithm": "AES256",
            "SSECustomerKey": key_b64,
            "SSECustomerKeyMD5": key_md5,
        },
    )

    yield _yield_mpu(endpoint_mode, aws_upload_id, custom_upload_id, key)

    _cleanup_mpu(aws_client, test_bucket, key, aws_upload_id, custom_upload_id, custom_cl, endpoint_mode)
