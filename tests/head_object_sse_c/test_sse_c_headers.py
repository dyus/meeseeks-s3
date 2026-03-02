"""Tests for HeadObject with SSE-C (Server-Side Encryption with Customer-Provided Keys).

These tests verify S3 behavior when calling HeadObject on an SSE-C encrypted object
with various header combinations and validation errors.

A single SSE-C encrypted object is created once per module and reused
across all tests.

HeadObject for SSE-C requires three headers:
- x-amz-server-side-encryption-customer-algorithm: Must be "AES256"
- x-amz-server-side-encryption-customer-key: Base64-encoded 32-byte key
- x-amz-server-side-encryption-customer-key-MD5: Base64-encoded MD5 of the key

Note: HEAD responses have no body per HTTP spec, so error details
are only available via status code and headers.
"""

import base64
import hashlib
import uuid

import pytest

from s3_compliance.sse_c import DEFAULT_SSE_C_KEY_BYTES, generate_sse_c_key


@pytest.fixture(scope="module")
def ssec_object_key():
    """Unique key for the SSE-C encrypted object shared across the module."""
    return f"test-ssec-head-{uuid.uuid4().hex[:8]}"


@pytest.fixture(scope="module")
def ssec_object(request, aws_client, test_bucket, setup_test_bucket, ssec_object_key):
    """Create a single SSE-C encrypted object for the entire module.

    Creates the object on the endpoint(s) being tested:
    - aws: AWS only
    - custom: Custom only
    - both: AWS and Custom
    """
    import os
    from s3_compliance.client import S3ClientFactory

    sse_kwargs = dict(
        Bucket=test_bucket,
        Key=ssec_object_key,
        Body=b"head-object sse-c test content",
        SSECustomerAlgorithm="AES256",
        SSECustomerKey=base64.b64encode(DEFAULT_SSE_C_KEY_BYTES).decode("utf-8"),
        SSECustomerKeyMD5=base64.b64encode(
            hashlib.md5(DEFAULT_SSE_C_KEY_BYTES).digest()
        ).decode("utf-8"),
    )

    endpoint_mode = request.config.getoption("--endpoint")

    custom_cl = None
    if os.getenv("S3_ENDPOINT") and endpoint_mode in ("custom", "both"):
        custom_cl = S3ClientFactory().create_client("custom")

    # Create on the endpoint(s) under test
    if endpoint_mode in ("aws", "both"):
        aws_client.put_object(**sse_kwargs)
    if custom_cl:
        custom_cl.put_object(**sse_kwargs)

    yield ssec_object_key

    # Cleanup
    if endpoint_mode in ("aws", "both"):
        try:
            aws_client.delete_object(Bucket=test_bucket, Key=ssec_object_key)
        except Exception:
            pass
    if custom_cl:
        try:
            custom_cl.delete_object(Bucket=test_bucket, Key=ssec_object_key)
        except Exception:
            pass


@pytest.mark.s3_handler("HeadObject")
@pytest.mark.sse_c
class TestSSECHeadObjectHeaders:
    """Test HeadObject API with SSE-C header combinations."""

    # =========================================================================
    # Successful Request
    # =========================================================================

    def test_head_ssec_object_with_valid_headers(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Server should return metadata with all valid SSE-C headers."""
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "HEAD",
            f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 200, (
                f"AWS expected 200, got {response.aws.status_code}"
            )
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            assert response.status_code == 200, (
                f"Expected 200, got {response.status_code}"
            )
            json_metadata["status"] = response.status_code

    # =========================================================================
    # No SSE-C Headers (plain HEAD on encrypted object)
    # =========================================================================

    def test_head_ssec_object_without_headers_rejected(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Server should reject HEAD without any SSE-C headers on encrypted object."""
        response = make_request(
            "HEAD",
            f"/{test_bucket}/{ssec_object}",
        )

        json_metadata["provided_headers"] = []

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400, (
                f"AWS expected 400, got {response.aws.status_code}"
            )
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            assert response.status_code == 400, (
                f"Expected 400, got {response.status_code}"
            )
            json_metadata["status"] = response.status_code

    # =========================================================================
    # Missing Header Tests (partial SSE-C headers)
    # =========================================================================

    @pytest.mark.edge_case
    def test_head_ssec_object_only_algorithm_rejected(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Server should reject HEAD with only SSE-C algorithm header."""
        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
        }

        response = make_request(
            "HEAD",
            f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["provided_headers"] = ["algorithm"]
        json_metadata["missing_headers"] = ["key", "key_md5"]

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400, (
                f"AWS expected 400, got {response.aws.status_code}"
            )
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            assert response.status_code == 400, (
                f"Expected 400, got {response.status_code}"
            )
            json_metadata["status"] = response.status_code

    @pytest.mark.edge_case
    def test_head_ssec_object_only_key_rejected(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Server should reject HEAD with only SSE-C key header."""
        key_b64, _ = generate_sse_c_key()

        headers = {
            "x-amz-server-side-encryption-customer-key": key_b64,
        }

        response = make_request(
            "HEAD",
            f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["provided_headers"] = ["key"]
        json_metadata["missing_headers"] = ["algorithm", "key_md5"]

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400, (
                f"AWS expected 400, got {response.aws.status_code}"
            )
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            assert response.status_code == 400, (
                f"Expected 400, got {response.status_code}"
            )
            json_metadata["status"] = response.status_code

    @pytest.mark.edge_case
    def test_head_ssec_object_only_key_md5_rejected(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Server should reject HEAD with only SSE-C key MD5 header."""
        _, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "HEAD",
            f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["provided_headers"] = ["key_md5"]
        json_metadata["missing_headers"] = ["algorithm", "key"]

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400, (
                f"AWS expected 400, got {response.aws.status_code}"
            )
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            assert response.status_code == 400, (
                f"Expected 400, got {response.status_code}"
            )
            json_metadata["status"] = response.status_code

    @pytest.mark.edge_case
    def test_head_ssec_object_algorithm_and_key_without_md5_accepted(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Server accepts HEAD with algorithm and key but missing MD5.

        Like GetObject, HeadObject does NOT require the key MD5 header
        when algorithm and key are provided.
        """
        key_b64, _ = generate_sse_c_key()

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
        }

        response = make_request(
            "HEAD",
            f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["provided_headers"] = ["algorithm", "key"]
        json_metadata["missing_headers"] = ["key_md5"]

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 200, (
                f"AWS expected 200, got {response.aws.status_code}"
            )
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            assert response.status_code == 200, (
                f"Expected 200, got {response.status_code}"
            )
            json_metadata["status"] = response.status_code

    @pytest.mark.edge_case
    def test_head_ssec_object_algorithm_and_md5_missing_key_rejected(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Server should reject HEAD with algorithm and MD5 but missing key."""
        _, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "HEAD",
            f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["provided_headers"] = ["algorithm", "key_md5"]
        json_metadata["missing_headers"] = ["key"]

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400, (
                f"AWS expected 400, got {response.aws.status_code}"
            )
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            assert response.status_code == 400, (
                f"Expected 400, got {response.status_code}"
            )
            json_metadata["status"] = response.status_code

    @pytest.mark.edge_case
    def test_head_ssec_object_key_and_md5_missing_algorithm_rejected(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Server should reject HEAD with key and MD5 but missing algorithm."""
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "HEAD",
            f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["provided_headers"] = ["key", "key_md5"]
        json_metadata["missing_headers"] = ["algorithm"]

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400, (
                f"AWS expected 400, got {response.aws.status_code}"
            )
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            assert response.status_code == 400, (
                f"Expected 400, got {response.status_code}"
            )
            json_metadata["status"] = response.status_code

    # =========================================================================
    # Invalid Value Tests
    # =========================================================================

    @pytest.mark.edge_case
    def test_head_ssec_object_invalid_algorithm_rejected(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Server should reject HEAD with invalid SSE-C algorithm."""
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES128-INVALID",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "HEAD",
            f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["invalid_algorithm"] = "AES128-INVALID"

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400, (
                f"AWS expected 400, got {response.aws.status_code}"
            )
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            assert response.status_code == 400, (
                f"Expected 400, got {response.status_code}"
            )
            json_metadata["status"] = response.status_code

    @pytest.mark.edge_case
    def test_head_ssec_object_wrong_key_rejected(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Server should reject HEAD with a different (wrong) SSE-C key."""
        wrong_key_bytes = hashlib.sha256(b"this_is_a_totally_wrong_key").digest()
        key_b64, key_md5 = generate_sse_c_key(wrong_key_bytes)

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "HEAD",
            f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["wrong_key"] = True

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 403, (
                f"AWS expected 403, got {response.aws.status_code}"
            )
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            assert response.status_code == 403, (
                f"Expected 403, got {response.status_code}"
            )
            json_metadata["status"] = response.status_code

    @pytest.mark.edge_case
    def test_head_ssec_object_invalid_key_length_10_rejected(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Server should reject HEAD with invalid key length (10 bytes).

        AWS returns 403 Forbidden for invalid key length on HeadObject
        (same as GetObject, unlike PutObject which returns 400).
        """
        short_key = b"1234567890"
        key_b64, key_md5 = generate_sse_c_key(short_key)

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "HEAD",
            f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["key_length_bytes"] = 10

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 403, (
                f"AWS expected 403, got {response.aws.status_code}"
            )
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            assert response.status_code == 403, (
                f"Expected 403, got {response.status_code}"
            )
            json_metadata["status"] = response.status_code

    @pytest.mark.edge_case
    def test_head_ssec_object_mismatched_key_md5_rejected(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Server should reject HEAD when key MD5 doesn't match key."""
        key_b64, _ = generate_sse_c_key()
        wrong_md5 = base64.b64encode(
            hashlib.md5(b"wrong-key-for-md5-mismatch").digest()
        ).decode("utf-8")

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": wrong_md5,
        }

        response = make_request(
            "HEAD",
            f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["key_md5_matches_key"] = False

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400, (
                f"AWS expected 400, got {response.aws.status_code}"
            )
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            assert response.status_code == 400, (
                f"Expected 400, got {response.status_code}"
            )
            json_metadata["status"] = response.status_code

    @pytest.mark.edge_case
    def test_head_ssec_object_invalid_key_md5_not_base64_rejected(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Server should reject HEAD when key MD5 is not valid base64."""
        key_b64, _ = generate_sse_c_key()

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": "not-valid-base64!!!",
        }

        response = make_request(
            "HEAD",
            f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["invalid_base64_md5"] = "not-valid-base64!!!"

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400, (
                f"AWS expected 400, got {response.aws.status_code}"
            )
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            assert response.status_code == 400, (
                f"Expected 400, got {response.status_code}"
            )
            json_metadata["status"] = response.status_code

    # =========================================================================
    # Validation Order Tests
    # =========================================================================

    @pytest.mark.edge_case
    def test_head_ssec_object_all_invalid_validation_order(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Test which validation error is returned first when all headers are invalid."""
        short_key = b"short-key"
        key_b64 = base64.b64encode(short_key).decode("utf-8")
        wrong_md5 = base64.b64encode(hashlib.md5(b"wrong").digest()).decode("utf-8")

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256-INVALID",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": wrong_md5,
        }

        response = make_request(
            "HEAD",
            f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["invalid_algorithm"] = "AES256-INVALID"
        json_metadata["invalid_key_length"] = len(short_key)
        json_metadata["key_md5_matches_key"] = False

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400, (
                f"AWS expected 400, got {response.aws.status_code}"
            )
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            assert response.status_code == 400, (
                f"Expected 400, got {response.status_code}"
            )
            json_metadata["status"] = response.status_code
