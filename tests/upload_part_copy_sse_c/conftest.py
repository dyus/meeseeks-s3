"""Shared fixtures for UploadPartCopy SSE-C tests.

UploadPartCopy (PUT /{Bucket}/{Key}?partNumber={N}&uploadId={Id})
copies data from an existing object into a part of a multipart upload.

SSE-C header groups (same as CopyObject):
- Destination: x-amz-server-side-encryption-customer-* (encrypt part in MPU)
- Source: x-amz-copy-source-server-side-encryption-customer-* (decrypt source)
"""

import os
import uuid

import pytest

from s3_compliance.client import S3ClientFactory
from s3_compliance.sse_c import DEFAULT_SSE_C_KEY_BYTES, generate_sse_c_key


UPC_BODY = b"upload-part-copy sse-c test content"


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
    """Create an SSE-C encrypted source object on each endpoint."""
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


@pytest.fixture(scope="module")
def plain_multipart_upload(request, aws_client, test_bucket, setup_test_bucket, upc_dest_key):
    """Create a plain (no SSE-C) MPU on each endpoint.

    Used for tests that only test source SSE-C headers (decrypting source).
    """
    endpoint_mode = request.config.getoption("--endpoint")
    # Use a distinct key to avoid collision with ssec_multipart_upload
    key = f"{upc_dest_key}-plain"

    custom_cl = None
    if os.getenv("S3_ENDPOINT") and endpoint_mode in ("custom", "both"):
        custom_cl = S3ClientFactory().create_client("custom")

    aws_upload_id = None
    if endpoint_mode in ("aws", "both"):
        resp = aws_client.create_multipart_upload(Bucket=test_bucket, Key=key)
        aws_upload_id = resp["UploadId"]

    custom_upload_id = None
    if custom_cl:
        resp = custom_cl.create_multipart_upload(Bucket=test_bucket, Key=key)
        custom_upload_id = resp["UploadId"]

    if endpoint_mode == "both":
        yield {"aws": aws_upload_id, "custom": custom_upload_id, "key": key}
    elif endpoint_mode == "custom":
        yield {"upload_id": custom_upload_id, "key": key}
    else:
        yield {"upload_id": aws_upload_id, "key": key}

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
def ssec_multipart_upload(request, aws_client, test_bucket, setup_test_bucket, upc_dest_key):
    """Create an SSE-C MPU on each endpoint.

    Used for tests that test destination SSE-C headers (encrypting into MPU).
    """
    endpoint_mode = request.config.getoption("--endpoint")
    key = f"{upc_dest_key}-ssec"
    key_b64, key_md5 = generate_sse_c_key()

    ssec_params = {
        "SSECustomerAlgorithm": "AES256",
        "SSECustomerKey": key_b64,
        "SSECustomerKeyMD5": key_md5,
    }

    custom_cl = None
    if os.getenv("S3_ENDPOINT") and endpoint_mode in ("custom", "both"):
        custom_cl = S3ClientFactory().create_client("custom")

    def _add_forwarded_proto(params, **kwargs):
        params["headers"]["X-Forwarded-Proto"] = "https"

    aws_upload_id = None
    if endpoint_mode in ("aws", "both"):
        resp = aws_client.create_multipart_upload(
            Bucket=test_bucket, Key=key, **ssec_params,
        )
        aws_upload_id = resp["UploadId"]

    custom_upload_id = None
    if custom_cl:
        custom_cl.meta.events.register(
            "before-call.s3.CreateMultipartUpload", _add_forwarded_proto,
        )
        resp = custom_cl.create_multipart_upload(
            Bucket=test_bucket, Key=key, **ssec_params,
        )
        custom_cl.meta.events.unregister(
            "before-call.s3.CreateMultipartUpload", _add_forwarded_proto,
        )
        custom_upload_id = resp["UploadId"]

    if endpoint_mode == "both":
        yield {"aws": aws_upload_id, "custom": custom_upload_id, "key": key}
    elif endpoint_mode == "custom":
        yield {"upload_id": custom_upload_id, "key": key}
    else:
        yield {"upload_id": aws_upload_id, "key": key}

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
