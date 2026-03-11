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
import uuid

import pytest

from s3_compliance.sse_c import DEFAULT_SSE_C_KEY_BYTES, generate_sse_c_key
from s3_compliance.xml_utils import extract_error_info

SSE_C_BODY = b"get-object sse-c test content"


@pytest.fixture(scope="module")
def ssec_object_key():
    """Unique key for the SSE-C encrypted object shared across the module."""
    return f"test-ssec-get-{uuid.uuid4().hex[:8]}"


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
        Body=SSE_C_BODY,
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

    @pytest.mark.edge_case
    def test_get_ssec_object_invalid_key_not_base64_rejected(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Server should reject GET when customer key is not valid base64.

        AWS decodes 'not-valid-base64!!!' into some bytes (lenient decoder),
        then compares MD5 — returns MD5 mismatch.
        """
        _, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": "not-valid-base64!!!",
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "GET",
            f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["invalid_base64_key"] = "not-valid-base64!!!"

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
    def test_get_ssec_object_key_decodes_to_short_rejected(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Server should reject GET when customer key decodes to too few bytes.

        '####' decodes to 0 bytes via lenient base64. AWS returns
        'The secret key was invalid - too short.' with ArgumentValue echoed.
        """
        _, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": "####",
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "GET",
            f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["key_value"] = "####"

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
    def test_get_ssec_object_empty_key_rejected(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Server should reject GET when customer key is empty string.

        AWS returns 'The secret key was invalid - too short.'
        """
        _, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": "",
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "GET",
            f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["key_value"] = ""

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
    # SSE-C headers on non-encrypted object
    # =========================================================================

    @pytest.mark.edge_case
    def test_get_non_encrypted_object_with_ssec_headers(
        self,
        test_bucket,
        make_request,
        json_metadata,
        request,
        aws_client,
    ):
        """Server should reject GET with SSE-C headers on a non-encrypted object.

        AWS returns 400 InvalidRequest: "The encryption parameters are not
        applicable to this object."
        """
        import os
        from s3_compliance.client import S3ClientFactory

        plain_key = f"test-plain-get-ssec-{uuid.uuid4().hex[:8]}"
        plain_body = b"plain object without encryption"

        endpoint_mode = request.config.getoption("--endpoint")

        # Create plain (non-encrypted) object on endpoint(s)
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
                "GET",
                f"/{test_bucket}/{plain_key}",
                headers=headers,
            )

            json_metadata["object_encrypted"] = False
            json_metadata["ssec_headers_sent"] = True

            if hasattr(response, "comparison"):
                assert response.aws.status_code == 400, (
                    f"AWS expected 400, got {response.aws.status_code}: {response.aws.text[:200]}"
                )
                error_code, error_msg = extract_error_info(response.aws.text)
                json_metadata["aws_status"] = response.aws.status_code
                json_metadata["aws_error_code"] = error_code
                json_metadata["aws_error_message"] = error_msg
                json_metadata["custom_status"] = response.custom.status_code
            else:
                assert response.status_code == 400, (
                    f"Expected 400, got {response.status_code}: {response.text[:200]}"
                )
                error_code, error_msg = extract_error_info(response.text)
                json_metadata["status"] = response.status_code
                json_metadata["error_code"] = error_code
                json_metadata["error_message"] = error_msg
        finally:
            # Cleanup
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

    @pytest.mark.edge_case
    def test_get_ssec_object_key_md5_decodes_to_1_byte(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Test GET when customerKeyMD5 decodes to exactly 1 byte.

        Normal MD5 is 16 bytes. Here we send a base64 value that decodes
        to just 1 byte to see how AWS handles it.
        """
        key_b64, _ = generate_sse_c_key()
        # 1 byte -> base64 = "AQ=="
        short_md5 = base64.b64encode(b"\x01").decode("utf-8")

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": short_md5,
        }

        response = make_request(
            "GET",
            f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["key_md5_value"] = short_md5
        json_metadata["key_md5_decoded_length"] = 1

        if hasattr(response, "comparison"):
            # Don't assert status — probe first
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            json_metadata["custom_status"] = response.custom.status_code
        else:
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

    @pytest.mark.edge_case
    def test_get_ssec_object_key_md5_100_bytes(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Test GET when customerKeyMD5 decodes to 100 bytes (random).

        Checks whether AWS validates MD5 length or just compares bytes.
        """
        key_b64, _ = generate_sse_c_key()
        import os
        random_100 = os.urandom(100)
        long_md5 = base64.b64encode(random_100).decode("utf-8")

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": long_md5,
        }

        response = make_request(
            "GET",
            f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["key_md5_decoded_length"] = 100

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            if response.aws.status_code != 200:
                error_code, error_msg = extract_error_info(response.aws.text)
                json_metadata["aws_error_code"] = error_code
                json_metadata["aws_error_message"] = error_msg
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code
            if response.status_code != 200:
                error_code, error_msg = extract_error_info(response.text)
                json_metadata["error_code"] = error_code
                json_metadata["error_message"] = error_msg

    @pytest.mark.edge_case
    def test_get_ssec_object_key_md5_100_bytes_correct_prefix(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Test GET when customerKeyMD5 is 100 bytes starting with correct 16-byte MD5.

        Checks whether AWS compares only first 16 bytes or full value.
        """
        key_b64, _ = generate_sse_c_key()
        correct_md5 = hashlib.md5(DEFAULT_SSE_C_KEY_BYTES).digest()
        padded = correct_md5 + b"\x00" * 84  # 100 bytes, starts with correct MD5
        long_md5 = base64.b64encode(padded).decode("utf-8")

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": long_md5,
        }

        response = make_request(
            "GET",
            f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["key_md5_decoded_length"] = 100
        json_metadata["correct_prefix"] = True

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            if response.aws.status_code != 200:
                error_code, error_msg = extract_error_info(response.aws.text)
                json_metadata["aws_error_code"] = error_code
                json_metadata["aws_error_message"] = error_msg
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code
            if response.status_code != 200:
                error_code, error_msg = extract_error_info(response.text)
                json_metadata["error_code"] = error_code
                json_metadata["error_message"] = error_msg

    @pytest.mark.edge_case
    def test_get_ssec_object_empty_key_md5(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Test GET when customerKeyMD5 is empty string (0 bytes)."""
        key_b64, _ = generate_sse_c_key()

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": "",
        }

        response = make_request(
            "GET",
            f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["key_md5_value"] = ""
        json_metadata["key_md5_decoded_length"] = 0

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            if response.aws.status_code != 200:
                error_code, error_msg = extract_error_info(response.aws.text)
                json_metadata["aws_error_code"] = error_code
                json_metadata["aws_error_message"] = error_msg
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code
            if response.status_code != 200:
                error_code, error_msg = extract_error_info(response.text)
                json_metadata["error_code"] = error_code
                json_metadata["error_message"] = error_msg

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
    def test_get_ssec_object_key_with_garbage_chars_in_base64(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
        garbage_position,
    ):
        """Test GET with valid 32-byte key base64 + garbage chars at various positions.

        AWS uses lenient base64 decoder — strips non-base64 chars, decodes rest.
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
            "GET",
            f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["key_value"] = dirty_key
        json_metadata["garbage_position"] = garbage_position

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            if response.aws.status_code != 200:
                error_code, error_msg = extract_error_info(response.aws.text)
                json_metadata["aws_error_code"] = error_code
                json_metadata["aws_error_message"] = error_msg
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code
            if response.status_code != 200:
                error_code, error_msg = extract_error_info(response.text)
                json_metadata["error_code"] = error_code
                json_metadata["error_message"] = error_msg

    # =========================================================================
    # Validation Order Tests
    # =========================================================================

    @pytest.mark.edge_case
    def test_get_ssec_object_invalid_algorithm_and_short_key(
        self,
        test_bucket,
        ssec_object,
        make_request,
        json_metadata,
    ):
        """Test which error wins: invalid algorithm or short key.

        Both algorithm and key length are invalid, but MD5 matches the short key.
        Shows AWS validation priority between these two checks.
        """
        short_key = b"short-key"
        key_b64, key_md5 = generate_sse_c_key(short_key)

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256-INVALID",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "GET",
            f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["invalid_algorithm"] = "AES256-INVALID"
        json_metadata["key_length_bytes"] = len(short_key)
        json_metadata["key_md5_matches_key"] = True

        if hasattr(response, "comparison"):
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            json_metadata["custom_status"] = response.custom.status_code
        else:
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

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
