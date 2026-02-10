"""Tests for GetObject with SSE-C (Server-Side Encryption with Customer-Provided Keys).

These tests verify S3 behavior when retrieving an SSE-C encrypted object
with various header combinations and validation errors.

A single SSE-C encrypted object is created once per module and reused
across all tests.

GetObject for SSE-C requires three headers:
- x-amz-server-side-encryption-customer-algorithm: Must be "AES256"
- x-amz-server-side-encryption-customer-key: Base64-encoded 32-byte key
- x-amz-server-side-encryption-customer-key-MD5: Base64-encoded MD5 of the key
"""

import base64
import hashlib
import re
import uuid

import pytest


# Default test key (deterministic, same as put_object_sse_c tests)
DEFAULT_SSE_C_KEY_BYTES = hashlib.sha256(b"reverse_s3_ssec_default_key").digest()
SSE_C_BODY = b"get-object sse-c test content"


def generate_sse_c_key(key_bytes: bytes = None) -> tuple[str, str]:
    """Generate SSE-C key and MD5 in base64 format."""
    if key_bytes is None:
        key_bytes = DEFAULT_SSE_C_KEY_BYTES
    key_b64 = base64.b64encode(key_bytes).decode("utf-8")
    key_md5 = base64.b64encode(hashlib.md5(key_bytes).digest()).decode("utf-8")
    return key_b64, key_md5


def extract_error_info(response_text: str) -> tuple[str | None, str | None]:
    """Extract error code and message from S3 XML error response."""
    code_match = re.search(r"<Code>([^<]+)</Code>", response_text)
    msg_match = re.search(r"<Message>([^<]+)</Message>", response_text)
    return (
        code_match.group(1) if code_match else None,
        msg_match.group(1) if msg_match else None,
    )


@pytest.fixture(scope="module")
def ssec_object_key():
    """Unique key for the SSE-C encrypted object shared across the module."""
    return f"test-ssec-get-{uuid.uuid4().hex[:8]}"


@pytest.fixture(scope="module")
def ssec_object(request, aws_client, test_bucket, setup_test_bucket, ssec_object_key):
    """Create a single SSE-C encrypted object for the entire module.

    Uploads the object with SSE-C encryption on AWS (and Custom in both mode),
    yields the key name, and cleans up after all tests in the module finish.
    """
    sse_kwargs = dict(
        Bucket=test_bucket,
        Key=ssec_object_key,
        Body=SSE_C_BODY,
        SSECustomerAlgorithm="AES256",
        SSECustomerKey=base64.b64encode(DEFAULT_SSE_C_KEY_BYTES).decode("utf-8"),
        SSECustomerKeyMD5=base64.b64encode(
            hashlib.md5(DEFAULT_SSE_C_KEY_BYTES).digest()
        ).decode("utf-8"),
    )

    aws_client.put_object(**sse_kwargs)

    # Also create on custom endpoint in comparison mode
    custom_cl = None
    endpoint_mode = request.config.getoption("--endpoint")
    if endpoint_mode == "both":
        import os
        if os.getenv("S3_ENDPOINT"):
            from s3_compliance.client import S3ClientFactory
            custom_cl = S3ClientFactory().create_client("custom")
            custom_cl.put_object(**sse_kwargs)

    yield ssec_object_key

    # Cleanup on both endpoints
    try:
        aws_client.delete_object(Bucket=test_bucket, Key=ssec_object_key)
    except Exception:
        pass
    if custom_cl:
        try:
            custom_cl.delete_object(Bucket=test_bucket, Key=ssec_object_key)
        except Exception:
            pass


@pytest.mark.s3_handler("GetObject")
@pytest.mark.sse_c
class TestSSECGetObjectHeaders:
    """Test GetObject API with SSE-C header combinations."""

    # =========================================================================
    # Successful Request
    # =========================================================================

    def test_get_ssec_object_with_valid_headers(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Server should return decrypted object with all valid SSE-C headers."""
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "GET",
            f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 200, (
                f"AWS expected 200, got {response.aws.status_code}"
            )
            assert response.aws.content == SSE_C_BODY
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            assert response.status_code == 200, (
                f"Expected 200, got {response.status_code}: {response.text[:200]}"
            )
            assert response.content == SSE_C_BODY
            json_metadata["status"] = response.status_code

    # =========================================================================
    # No SSE-C Headers (plain GET on encrypted object)
    # =========================================================================

    def test_get_ssec_object_without_headers_rejected(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Server should reject GET without any SSE-C headers on encrypted object."""
        response = make_request(
            "GET",
            f"/{test_bucket}/{ssec_object}",
        )

        json_metadata["provided_headers"] = []

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400, (
                f"AWS expected 400, got {response.aws.status_code}"
            )
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
        else:
            assert response.status_code == 400, (
                f"Expected 400, got {response.status_code}"
            )
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

    # =========================================================================
    # Missing Header Tests (partial SSE-C headers)
    # =========================================================================

    @pytest.mark.edge_case
    def test_get_ssec_object_only_algorithm_rejected(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Server should reject GET with only SSE-C algorithm header."""
        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
        }

        response = make_request(
            "GET",
            f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["provided_headers"] = ["algorithm"]
        json_metadata["missing_headers"] = ["key", "key_md5"]

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400, (
                f"AWS expected 400, got {response.aws.status_code}"
            )
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
        else:
            assert response.status_code == 400, (
                f"Expected 400, got {response.status_code}"
            )
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

    @pytest.mark.edge_case
    def test_get_ssec_object_only_key_rejected(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Server should reject GET with only SSE-C key header."""
        key_b64, _ = generate_sse_c_key()

        headers = {
            "x-amz-server-side-encryption-customer-key": key_b64,
        }

        response = make_request(
            "GET",
            f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["provided_headers"] = ["key"]
        json_metadata["missing_headers"] = ["algorithm", "key_md5"]

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400, (
                f"AWS expected 400, got {response.aws.status_code}"
            )
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
        else:
            assert response.status_code == 400, (
                f"Expected 400, got {response.status_code}"
            )
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

    @pytest.mark.edge_case
    def test_get_ssec_object_only_key_md5_rejected(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Server should reject GET with only SSE-C key MD5 header."""
        _, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "GET",
            f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["provided_headers"] = ["key_md5"]
        json_metadata["missing_headers"] = ["algorithm", "key"]

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400, (
                f"AWS expected 400, got {response.aws.status_code}"
            )
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
        else:
            assert response.status_code == 400, (
                f"Expected 400, got {response.status_code}"
            )
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

    @pytest.mark.edge_case
    def test_get_ssec_object_algorithm_and_key_without_md5_accepted(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Server accepts GET with algorithm and key but missing MD5.

        Unlike PutObject, GetObject does NOT require the key MD5 header
        when algorithm and key are provided. AWS returns 200 OK.
        """
        key_b64, _ = generate_sse_c_key()

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
        }

        response = make_request(
            "GET",
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
    def test_get_ssec_object_algorithm_and_md5_missing_key_rejected(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Server should reject GET with algorithm and MD5 but missing key."""
        _, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "GET",
            f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["provided_headers"] = ["algorithm", "key_md5"]
        json_metadata["missing_headers"] = ["key"]

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400, (
                f"AWS expected 400, got {response.aws.status_code}"
            )
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
        else:
            assert response.status_code == 400, (
                f"Expected 400, got {response.status_code}"
            )
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

    @pytest.mark.edge_case
    def test_get_ssec_object_key_and_md5_missing_algorithm_rejected(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Server should reject GET with key and MD5 but missing algorithm."""
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "GET",
            f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["provided_headers"] = ["key", "key_md5"]
        json_metadata["missing_headers"] = ["algorithm"]

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400, (
                f"AWS expected 400, got {response.aws.status_code}"
            )
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
        else:
            assert response.status_code == 400, (
                f"Expected 400, got {response.status_code}"
            )
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

    # =========================================================================
    # Invalid Value Tests
    # =========================================================================

    @pytest.mark.edge_case
    def test_get_ssec_object_invalid_algorithm_rejected(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Server should reject GET with invalid SSE-C algorithm."""
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES128-INVALID",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "GET",
            f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["invalid_algorithm"] = "AES128-INVALID"

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400, (
                f"AWS expected 400, got {response.aws.status_code}"
            )
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
        else:
            assert response.status_code == 400, (
                f"Expected 400, got {response.status_code}"
            )
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

    @pytest.mark.edge_case
    def test_get_ssec_object_wrong_key_rejected(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Server should reject GET with a different (wrong) SSE-C key."""
        wrong_key_bytes = hashlib.sha256(b"this_is_a_totally_wrong_key").digest()
        key_b64, key_md5 = generate_sse_c_key(wrong_key_bytes)

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "GET",
            f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["wrong_key"] = True

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 403, (
                f"AWS expected 403, got {response.aws.status_code}"
            )
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
        else:
            assert response.status_code == 403, (
                f"Expected 403, got {response.status_code}"
            )
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

    @pytest.mark.edge_case
    def test_get_ssec_object_invalid_key_length_10_rejected(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Server should reject GET with invalid key length (10 bytes).

        AWS returns 403 Forbidden for invalid key length on GetObject
        (unlike PutObject which returns 400).
        """
        short_key = b"1234567890"
        key_b64, key_md5 = generate_sse_c_key(short_key)

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "GET",
            f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["key_length_bytes"] = 10

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 403, (
                f"AWS expected 403, got {response.aws.status_code}"
            )
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
        else:
            assert response.status_code == 403, (
                f"Expected 403, got {response.status_code}"
            )
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

    @pytest.mark.edge_case
    def test_get_ssec_object_mismatched_key_md5_rejected(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Server should reject GET when key MD5 doesn't match key."""
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
            "GET",
            f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["key_md5_matches_key"] = False

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400, (
                f"AWS expected 400, got {response.aws.status_code}"
            )
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
        else:
            assert response.status_code == 400, (
                f"Expected 400, got {response.status_code}"
            )
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

    @pytest.mark.edge_case
    def test_get_ssec_object_invalid_key_md5_not_base64_rejected(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Server should reject GET when key MD5 is not valid base64."""
        key_b64, _ = generate_sse_c_key()

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": "not-valid-base64!!!",
        }

        response = make_request(
            "GET",
            f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["invalid_base64_md5"] = "not-valid-base64!!!"

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400, (
                f"AWS expected 400, got {response.aws.status_code}"
            )
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
        else:
            assert response.status_code == 400, (
                f"Expected 400, got {response.status_code}"
            )
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

    # =========================================================================
    # Validation Order Tests
    # =========================================================================

    @pytest.mark.edge_case
    def test_get_ssec_object_all_invalid_validation_order(
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
            "GET",
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
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            json_metadata["first_validation_error"] = error_code
        else:
            assert response.status_code == 400, (
                f"Expected 400, got {response.status_code}"
            )
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg
            json_metadata["first_validation_error"] = error_code
