"""Tests for CopyObject with SSE-C happy paths.

CopyObject has two groups of SSE-C headers:
- Destination (x-amz-server-side-encryption-customer-*): encrypt the new copy
- Source (x-amz-copy-source-server-side-encryption-customer-*): decrypt the source

Tests cover all 4 combinations:
1. Plain source -> SSE-C dest (dest headers only)
2. SSE-C source -> plain dest (source headers only)
3. SSE-C source -> SSE-C dest same key (both groups)
4. SSE-C source -> SSE-C dest new key (both groups, different keys)
"""

import base64
import hashlib
import os
import uuid

import pytest

from s3_compliance.client import S3ClientFactory
from s3_compliance.sse_c import DEFAULT_SSE_C_KEY_BYTES, generate_sse_c_key


COPY_BODY = b"copy-object sse-c happy path test content"

# Second key for "different key" test
SECOND_KEY_BYTES = hashlib.sha256(b"reverse_s3_ssec_second_key").digest()


@pytest.fixture(scope="module")
def source_key():
    return f"test-copy-src-{uuid.uuid4().hex[:8]}"


@pytest.fixture(scope="module")
def dest_key():
    return f"test-copy-dst-{uuid.uuid4().hex[:8]}"


@pytest.fixture(scope="module")
def plain_source(request, aws_client, test_bucket, setup_test_bucket, source_key):
    """Create a plain (unencrypted) source object on each endpoint."""
    endpoint_mode = request.config.getoption("--endpoint")

    custom_cl = None
    if os.getenv("S3_ENDPOINT") and endpoint_mode in ("custom", "both"):
        custom_cl = S3ClientFactory().create_client("custom")

    kwargs = dict(Bucket=test_bucket, Key=source_key, Body=COPY_BODY)

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
def ssec_source(request, aws_client, test_bucket, setup_test_bucket):
    """Create an SSE-C encrypted source object on each endpoint.

    Uses a unique key to avoid collision with plain_source.
    Returns the source key name.
    """
    endpoint_mode = request.config.getoption("--endpoint")
    key_name = f"test-copy-ssec-src-{uuid.uuid4().hex[:8]}"

    key_b64, key_md5 = generate_sse_c_key()

    sse_kwargs = dict(
        Bucket=test_bucket,
        Key=key_name,
        Body=COPY_BODY,
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

    yield key_name

    if endpoint_mode in ("aws", "both"):
        try:
            aws_client.delete_object(Bucket=test_bucket, Key=key_name)
        except Exception:
            pass
    if custom_cl:
        try:
            custom_cl.delete_object(Bucket=test_bucket, Key=key_name)
        except Exception:
            pass


@pytest.mark.s3_handler("CopyObject")
@pytest.mark.sse_c
class TestCopyObjectSSECHappyPath:
    """Test CopyObject with SSE-C for all source/dest encryption combinations."""

    def _cleanup_dest(self, aws_client, test_bucket, dest_key, endpoint_mode):
        """Clean up destination object after test."""
        if endpoint_mode in ("aws", "both"):
            try:
                aws_client.delete_object(Bucket=test_bucket, Key=dest_key)
            except Exception:
                pass
        if os.getenv("S3_ENDPOINT") and endpoint_mode in ("custom", "both"):
            try:
                custom_cl = S3ClientFactory().create_client("custom")
                custom_cl.delete_object(Bucket=test_bucket, Key=dest_key)
            except Exception:
                pass

    # =========================================================================
    # Test 1: Plain source -> SSE-C destination
    # =========================================================================

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_copy_plain_to_ssec(
        self,
        aws_client,
        test_bucket,
        plain_source,
        dest_key,
        make_request,
        json_metadata,
        request,
    ):
        """Copy unencrypted object to SSE-C encrypted destination."""
        key_b64, key_md5 = generate_sse_c_key()
        endpoint_mode = request.config.getoption("--endpoint")

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}/{dest_key}",
            headers=headers,
        )

        json_metadata["source_encryption"] = "none"
        json_metadata["dest_encryption"] = "SSE-C"

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 200, (
                f"AWS expected 200, got {response.aws.status_code}: {response.aws.text[:200]}"
            )
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            assert response.status_code == 200, (
                f"Expected 200, got {response.status_code}: {response.text[:200]}"
            )
            json_metadata["status"] = response.status_code

        self._cleanup_dest(aws_client, test_bucket, dest_key, endpoint_mode)

    # =========================================================================
    # Test 2: SSE-C source -> plain destination
    # =========================================================================

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_copy_ssec_to_plain(
        self,
        aws_client,
        test_bucket,
        ssec_source,
        dest_key,
        make_request,
        json_metadata,
        request,
    ):
        """Copy SSE-C encrypted object to unencrypted destination."""
        key_b64, key_md5 = generate_sse_c_key()
        endpoint_mode = request.config.getoption("--endpoint")

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-copy-source-server-side-encryption-customer-key": key_b64,
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}/{dest_key}",
            headers=headers,
        )

        json_metadata["source_encryption"] = "SSE-C"
        json_metadata["dest_encryption"] = "none"

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 200, (
                f"AWS expected 200, got {response.aws.status_code}: {response.aws.text[:200]}"
            )
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            assert response.status_code == 200, (
                f"Expected 200, got {response.status_code}: {response.text[:200]}"
            )
            json_metadata["status"] = response.status_code

        self._cleanup_dest(aws_client, test_bucket, dest_key, endpoint_mode)

    # =========================================================================
    # Test 3: SSE-C source -> SSE-C destination (same key)
    # =========================================================================

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_copy_ssec_to_ssec_same_key(
        self,
        aws_client,
        test_bucket,
        ssec_source,
        dest_key,
        make_request,
        json_metadata,
        request,
    ):
        """Copy SSE-C object to SSE-C destination using the same key."""
        key_b64, key_md5 = generate_sse_c_key()
        endpoint_mode = request.config.getoption("--endpoint")

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            # Source SSE-C headers (decrypt)
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-copy-source-server-side-encryption-customer-key": key_b64,
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": key_md5,
            # Dest SSE-C headers (encrypt) — same key
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}/{dest_key}",
            headers=headers,
        )

        json_metadata["source_encryption"] = "SSE-C"
        json_metadata["dest_encryption"] = "SSE-C"
        json_metadata["same_key"] = True

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 200, (
                f"AWS expected 200, got {response.aws.status_code}: {response.aws.text[:200]}"
            )
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            assert response.status_code == 200, (
                f"Expected 200, got {response.status_code}: {response.text[:200]}"
            )
            json_metadata["status"] = response.status_code

        self._cleanup_dest(aws_client, test_bucket, dest_key, endpoint_mode)

    # =========================================================================
    # Test 4: SSE-C source -> SSE-C destination (different key)
    # =========================================================================

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_copy_ssec_to_ssec_new_key(
        self,
        aws_client,
        test_bucket,
        ssec_source,
        dest_key,
        make_request,
        json_metadata,
        request,
    ):
        """Copy SSE-C object to SSE-C destination using a different key."""
        src_key_b64, src_key_md5 = generate_sse_c_key()
        dst_key_b64, dst_key_md5 = generate_sse_c_key(SECOND_KEY_BYTES)
        endpoint_mode = request.config.getoption("--endpoint")

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            # Source SSE-C headers (decrypt with original key)
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-copy-source-server-side-encryption-customer-key": src_key_b64,
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": src_key_md5,
            # Dest SSE-C headers (encrypt with new key)
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": dst_key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": dst_key_md5,
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}/{dest_key}",
            headers=headers,
        )

        json_metadata["source_encryption"] = "SSE-C"
        json_metadata["dest_encryption"] = "SSE-C"
        json_metadata["same_key"] = False

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 200, (
                f"AWS expected 200, got {response.aws.status_code}: {response.aws.text[:200]}"
            )
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            assert response.status_code == 200, (
                f"Expected 200, got {response.status_code}: {response.text[:200]}"
            )
            json_metadata["status"] = response.status_code

        self._cleanup_dest(aws_client, test_bucket, dest_key, endpoint_mode)
