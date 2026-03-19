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
    # SSE-C headers on non-encrypted object
    # =========================================================================

    @pytest.mark.edge_case
    def test_head_non_encrypted_object_with_ssec_headers(
        self,
        test_bucket,
        make_request,
        json_metadata,
        request,
        aws_client,
    ):
        """Server should reject HEAD with SSE-C headers on a non-encrypted object.

        AWS returns 400 InvalidRequest: "The encryption parameters are not
        applicable to this object."
        Note: HEAD responses have no body, so only status code is checked.
        """
        import os
        from s3_compliance.client import S3ClientFactory

        plain_key = f"test-plain-head-ssec-{uuid.uuid4().hex[:8]}"
        plain_body = b"plain object without encryption"

        endpoint_mode = request.config.getoption("--endpoint")

        custom_cl = None
        if os.getenv("S3_ENDPOINT") and endpoint_mode in ("custom", "both"):
            custom_cl = S3ClientFactory().create_client("custom")

        if endpoint_mode in ("aws", "both"):
            aws_client.put_object(Bucket=test_bucket, Key=plain_key, Body=plain_body)
        if custom_cl:
            custom_cl.put_object(Bucket=test_bucket, Key=plain_key, Body=plain_body)

        try:
            key_b64, key_md5 = generate_sse_c_key()

            headers = {
                "x-amz-server-side-encryption-customer-algorithm": "AES256",
                "x-amz-server-side-encryption-customer-key": key_b64,
                "x-amz-server-side-encryption-customer-key-MD5": key_md5,
            }

            response = make_request(
                "HEAD",
                f"/{test_bucket}/{plain_key}",
                headers=headers,
            )

            json_metadata["object_encrypted"] = False
            json_metadata["ssec_headers_sent"] = True

            if hasattr(response, "comparison"):
                json_metadata["aws_status"] = response.aws.status_code
                json_metadata["custom_status"] = response.custom.status_code
                assert response.aws.status_code == 400, (
                    f"AWS expected 400, got {response.aws.status_code}"
                )
            else:
                json_metadata["status"] = response.status_code
                assert response.status_code == 400, (
                    f"Expected 400, got {response.status_code}"
                )
        finally:
            if endpoint_mode in ("aws", "both"):
                try:
                    aws_client.delete_object(Bucket=test_bucket, Key=plain_key)
                except Exception:
                    pass
            if custom_cl:
                try:
                    custom_cl.delete_object(Bucket=test_bucket, Key=plain_key)
                except Exception:
                    pass

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

    @pytest.mark.edge_case
    def test_head_ssec_object_invalid_key_base64_with_invalid_algorithm(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Test validation order: invalid base64 customer key + invalid algorithm."""
        invalid_key = "not-valid-base64!!!"
        key_md5 = base64.b64encode(hashlib.md5(b"anything").digest()).decode("utf-8")

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "INVALID-ALGO",
            "x-amz-server-side-encryption-customer-key": invalid_key,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "HEAD",
            f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["invalid_algorithm"] = "INVALID-ALGO"
        json_metadata["invalid_key_base64"] = invalid_key

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
    def test_head_ssec_object_invalid_key_length_with_invalid_algorithm(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Test validation order: invalid algorithm vs invalid key length."""
        short_key = b"1234567890"  # 10 bytes
        key_b64, key_md5 = generate_sse_c_key(short_key)

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "INVALID-ALGO",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "HEAD",
            f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["invalid_algorithm"] = "INVALID-ALGO"
        json_metadata["key_length_bytes"] = 10
        json_metadata["key_md5_matches_key"] = True

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
    def test_head_ssec_object_invalid_key_length_with_mismatched_md5(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Test validation order: invalid key length vs mismatched MD5."""
        short_key = b"1234567890"  # 10 bytes
        key_b64 = base64.b64encode(short_key).decode("utf-8")
        wrong_md5 = base64.b64encode(hashlib.md5(b"wrong").digest()).decode("utf-8")

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

        json_metadata["key_length_bytes"] = 10
        json_metadata["key_md5_matches_key"] = False

        if hasattr(response, "comparison"):
            assert response.aws.status_code in (400, 403), (
                f"AWS expected 400 or 403, got {response.aws.status_code}"
            )
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            assert response.status_code in (400, 403), (
                f"Expected 400 or 403, got {response.status_code}"
            )
            json_metadata["status"] = response.status_code

    # =========================================================================
    # Base64 encoding edge cases for customer key
    # =========================================================================

    @pytest.mark.edge_case
    def test_head_ssec_object_key_base64_with_spaces(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Valid 32-byte key base64 with spaces inserted.

        AWS lenient base64 strips non-base64 chars including spaces.
        """
        key_b64, key_md5 = generate_sse_c_key()
        spaced_key = " ".join([key_b64[i:i+4] for i in range(0, len(key_b64), 4)])

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": spaced_key,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "HEAD",
            f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["key_value"] = spaced_key

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code

    @pytest.mark.edge_case
    def test_head_ssec_object_key_base64_with_tabs_and_newlines(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Valid 32-byte key base64 with tabs and newlines (PEM-style).

        AWS lenient base64 strips non-base64 chars including tabs/newlines.
        """
        key_b64, key_md5 = generate_sse_c_key()
        wrapped_key = "\t".join([key_b64[i:i+8] for i in range(0, len(key_b64), 8)])

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": wrapped_key,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "HEAD",
            f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["key_value"] = repr(wrapped_key)

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code

    @pytest.mark.edge_case
    def test_head_ssec_object_key_base64_without_padding(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Valid 32-byte key base64 with padding '=' removed.

        AWS may accept no-padding (lenient decoder) or reject.
        """
        key_b64, key_md5 = generate_sse_c_key()
        no_pad_key = key_b64.rstrip("=")

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": no_pad_key,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "HEAD",
            f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["key_value"] = no_pad_key
        json_metadata["original_key"] = key_b64

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code

    @pytest.mark.edge_case
    def test_head_ssec_object_key_base64_with_extra_padding(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Valid 32-byte key base64 with extra '===' appended.

        Extra padding may cause decode failure or be ignored by lenient decoder.
        """
        key_b64, key_md5 = generate_sse_c_key()
        extra_pad_key = key_b64 + "==="

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": extra_pad_key,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "HEAD",
            f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["key_value"] = extra_pad_key

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code

    @pytest.mark.edge_case
    def test_head_ssec_object_key_url_safe_base64(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Key encoded with URL-safe base64 (- and _ instead of + and /).

        Tests whether AWS uses StdEncoding (+/) or URLEncoding (-_).
        """
        url_safe_key = base64.urlsafe_b64encode(DEFAULT_SSE_C_KEY_BYTES).decode("utf-8")
        _, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": url_safe_key,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "HEAD",
            f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        std_key, _ = generate_sse_c_key()
        json_metadata["key_value"] = url_safe_key
        json_metadata["original_key"] = std_key
        json_metadata["has_plus_or_slash"] = "+" in std_key or "/" in std_key

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code

    @pytest.mark.edge_case
    def test_head_ssec_object_key_and_md5_both_url_safe_base64(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Both key and MD5 encoded with URL-safe base64 (- and _ instead of + and /).

        Definitive test: if AWS returns 200, it supports URLEncoding.
        If error, it strictly uses StdEncoding (+/).
        """
        url_safe_key = base64.urlsafe_b64encode(DEFAULT_SSE_C_KEY_BYTES).decode("utf-8")
        url_safe_md5 = base64.urlsafe_b64encode(
            hashlib.md5(DEFAULT_SSE_C_KEY_BYTES).digest()
        ).decode("utf-8")

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": url_safe_key,
            "x-amz-server-side-encryption-customer-key-MD5": url_safe_md5,
        }

        response = make_request(
            "HEAD",
            f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        std_key, std_md5 = generate_sse_c_key()
        json_metadata["key_value"] = url_safe_key
        json_metadata["md5_value"] = url_safe_md5
        json_metadata["original_key"] = std_key
        json_metadata["original_md5"] = std_md5
        json_metadata["conclusion"] = "200 = URLEncoding supported, error = StdEncoding only"

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code

    @pytest.mark.edge_case
    @pytest.mark.parametrize(
        "garbage_position",
        [
            pytest.param("suffix", id="garbage-at-end"),
            pytest.param("prefix", id="garbage-at-start"),
            pytest.param("middle", id="garbage-in-middle"),
            pytest.param("scattered", id="garbage-scattered"),
        ],
    )
    def test_head_ssec_object_key_with_garbage_chars_in_base64(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
        garbage_position,
    ):
        """Test HEAD with valid 32-byte key base64 + garbage chars at various positions.

        AWS uses lenient base64 decoder -- strips non-base64 chars, decodes rest.
        MD5 is from the original 32-byte key.
        """
        key_b64, key_md5 = generate_sse_c_key()
        garbage = "!!!!#"

        if garbage_position == "suffix":
            dirty_key = key_b64 + garbage
        elif garbage_position == "prefix":
            dirty_key = garbage + key_b64
        elif garbage_position == "middle":
            mid = len(key_b64) // 2
            dirty_key = key_b64[:mid] + garbage + key_b64[mid:]
        else:  # scattered
            dirty_key = "!" + key_b64[:8] + "#" + key_b64[8:20] + "!!" + key_b64[20:] + "#"

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": dirty_key,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "HEAD",
            f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["key_value"] = dirty_key
        json_metadata["garbage_position"] = garbage_position

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code

    @pytest.mark.edge_case
    def test_head_ssec_object_valid_key_md5_without_padding(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Valid padded key, but MD5 has base64 padding '=' stripped.

        AWS may accept no-padding (lenient decoder) or reject.
        """
        key_b64, key_md5 = generate_sse_c_key()
        no_pad_md5 = key_md5.rstrip("=")

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": no_pad_md5,
        }

        response = make_request(
            "HEAD",
            f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["md5_value"] = no_pad_md5
        json_metadata["original_md5"] = key_md5

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code

    # =========================================================================
    # Key length boundary cases
    # =========================================================================

    @pytest.mark.edge_case
    def test_head_ssec_object_key_decodes_to_short_value(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Key '####' decodes to 0 bytes via lenient base64.

        AWS returns error for too-short key.
        """
        _, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": "####",
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "HEAD",
            f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["key_value"] = "####"

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code

    @pytest.mark.edge_case
    def test_head_ssec_object_key_zz(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Test HEAD with customer key 'ZZ' that decodes to 1 byte (0x65) via base64."""
        _, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": "ZZ",
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "HEAD",
            f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["key_value"] = "ZZ"

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code

    @pytest.mark.edge_case
    def test_head_ssec_object_key_single_char_a(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Test HEAD with customer key 'a' -- invalid base64 (1 char, needs min 2 for a byte)."""
        _, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": "a",
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "HEAD",
            f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["key_value"] = "a"

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code

    @pytest.mark.edge_case
    def test_head_ssec_object_key_latin1_chars(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Test HEAD with customer key as latin-1 non-ASCII chars.

        These are valid latin-1 (0xE9, 0xF1, 0xFC, 0xDF) so they can be sent
        in HTTP headers, but they are not valid base64 characters.
        """
        _, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": "\u00e9\u00f1\u00fc\u00df",
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "HEAD",
            f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["key_value"] = "\u00e9\u00f1\u00fc\u00df"

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code

    @pytest.mark.edge_case
    def test_head_ssec_object_empty_key(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Test HEAD when customer key is empty string.

        AWS returns error for too-short key.
        """
        _, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": "",
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "HEAD",
            f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["key_value"] = ""

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code

    @pytest.mark.edge_case
    def test_head_ssec_object_key_decodes_to_1_byte(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Test HEAD with customer key that decodes to 1 byte (AQ==)."""
        short_key = b"\x01"
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

        json_metadata["key_b64"] = key_b64
        json_metadata["key_decoded_length"] = 1

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code

    @pytest.mark.edge_case
    def test_head_ssec_object_short_key_zz_with_matching_md5(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Key 'ZZ' (decodes to 1 byte) with correct MD5 for that 1 byte.

        Tests validation order after MD5 passes: does AWS return
        error for too-short or invalid-for-algorithm?
        """
        decoded_key = base64.b64decode("ZZ==")  # 1 byte: 0x65
        key_md5 = base64.b64encode(
            hashlib.md5(decoded_key).digest()
        ).decode("utf-8")

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": "ZZ",
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "HEAD", f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["key_value"] = "ZZ"
        json_metadata["key_decoded_length"] = len(decoded_key)
        json_metadata["md5_matches_key"] = True

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code

    @pytest.mark.edge_case
    def test_head_ssec_object_long_key_33_bytes_with_matching_md5(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Key that decodes to 33 bytes with correct MD5.

        Tests validation after MD5 passes: should return error for invalid key length.
        """
        long_key = b"\x01" * 33
        key_b64, key_md5 = generate_sse_c_key(long_key)

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "HEAD", f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["key_decoded_length"] = 33
        json_metadata["md5_matches_key"] = True

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code

    @pytest.mark.edge_case
    def test_head_ssec_object_key_31_bytes(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Key that decodes to 31 bytes (one byte short of AES-256)."""
        short_key = b"\x01" * 31
        key_b64, key_md5 = generate_sse_c_key(short_key)

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "HEAD", f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["key_decoded_length"] = 31

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code

    @pytest.mark.edge_case
    def test_head_ssec_object_key_33_bytes(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Key that decodes to 33 bytes (one byte over AES-256)."""
        long_key = b"\x01" * 33
        key_b64, key_md5 = generate_sse_c_key(long_key)

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "HEAD", f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["key_decoded_length"] = 33

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code

    # =========================================================================
    # MD5 base64 edge cases
    # =========================================================================

    @pytest.mark.edge_case
    def test_head_ssec_object_md5_with_garbage_chars(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Valid key + MD5 base64 with garbage chars inserted.

        AWS lenient base64 may strip garbage and still match, or reject.
        """
        key_b64, key_md5 = generate_sse_c_key()
        garbage_md5 = "!!" + key_md5[:8] + "##" + key_md5[8:]

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": garbage_md5,
        }

        response = make_request(
            "HEAD", f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["md5_value"] = garbage_md5
        json_metadata["original_md5"] = key_md5

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code

    @pytest.mark.edge_case
    def test_head_ssec_object_md5_decodes_to_wrong_length(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Valid key + MD5 that decodes to 8 bytes instead of 16.

        MD5 length mismatch should cause rejection.
        """
        key_b64, _ = generate_sse_c_key()
        short_md5 = base64.b64encode(b"\x01" * 8).decode("utf-8")

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": short_md5,
        }

        response = make_request(
            "HEAD", f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["md5_value"] = short_md5
        json_metadata["md5_decoded_length"] = 8

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code

    @pytest.mark.edge_case
    def test_head_ssec_object_md5_without_padding(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Valid padded key, but MD5 has base64 padding '=' stripped.

        Same test as valid_key_md5_without_padding, checking MD5 no-pad behavior.
        """
        key_b64, key_md5 = generate_sse_c_key()
        no_pad_md5 = key_md5.rstrip("=")

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": no_pad_md5,
        }

        response = make_request(
            "HEAD", f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["md5_value"] = no_pad_md5
        json_metadata["original_md5"] = key_md5

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code

    # =========================================================================
    # HTTP (non-TLS) with invalid SSE-C headers
    # =========================================================================

    @pytest.mark.edge_case
    def test_head_ssec_object_all_invalid_headers_over_http(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Test all three SSE-C headers invalid + request sent over HTTP (not HTTPS).

        AWS requires HTTPS for SSE-C. Over HTTP, the error may differ.
        """
        invalid_key = "not-valid-base64!!!"
        wrong_md5 = base64.b64encode(hashlib.md5(b"wrong").digest()).decode("utf-8")

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256-INVALID",
            "x-amz-server-side-encryption-customer-key": invalid_key,
            "x-amz-server-side-encryption-customer-key-MD5": wrong_md5,
        }

        response = make_request(
            "HEAD",
            f"/{test_bucket}/{ssec_object}",
            headers=headers,
            scheme="http",
        )

        json_metadata["transport"] = "http"
        json_metadata["invalid_algorithm"] = "AES256-INVALID"
        json_metadata["invalid_key_base64"] = invalid_key
        json_metadata["key_md5_matches_key"] = False

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code
