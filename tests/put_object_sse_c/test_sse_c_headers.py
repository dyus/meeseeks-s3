"""Tests for PutObject with SSE-C (Server-Side Encryption with Customer-Provided Keys).

These tests verify S3 behavior when SSE-C headers are provided in various
combinations and with various validation errors.

SSE-C requires three headers:
- x-amz-server-side-encryption-customer-algorithm: Must be "AES256"
- x-amz-server-side-encryption-customer-key: Base64-encoded 32-byte key
- x-amz-server-side-encryption-customer-key-MD5: Base64-encoded MD5 of the key

Supports both single endpoint mode (--endpoint=aws or --endpoint=custom)
and comparison mode (--endpoint=both).
"""

import base64
import hashlib
import re
import uuid

import pytest


# Default test key (deterministic for reproducibility)
DEFAULT_SSE_C_KEY_BYTES = hashlib.sha256(b"reverse_s3_ssec_default_key").digest()


def generate_sse_c_key(key_bytes: bytes = None) -> tuple[str, str]:
    """Generate SSE-C key and MD5 in base64 format.

    Args:
        key_bytes: Raw key bytes (default: DEFAULT_SSE_C_KEY_BYTES)

    Returns:
        Tuple of (key_base64, key_md5_base64)
    """
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


@pytest.mark.put_object
@pytest.mark.s3_handler("PutObject")
@pytest.mark.sse_c
class TestSSECPutObjectHeaders:
    """Test PutObject API with SSE-C header combinations."""

    @pytest.fixture
    def test_key(self):
        """Generate unique test key."""
        return f"test-ssec-{uuid.uuid4().hex[:8]}"

    @pytest.fixture
    def test_body(self):
        """Test content."""
        return b"test content for SSE-C encryption test"

    # =========================================================================
    # Successful Request Tests
    # =========================================================================

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_all_valid_headers_accepted(
        self,
        s3_client,
        test_bucket,
        test_key,
        test_body,
        make_request,
        json_metadata,
    ):
        """Server should accept PutObject with all valid SSE-C headers."""
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "Content-Type": "text/plain",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}/{test_key}",
            body=test_body,
            headers=headers,
        )

        json_metadata["sse_c_algorithm"] = "AES256"
        json_metadata["sse_c_key_length"] = 32

        if hasattr(response, "comparison"):
            assert response.aws.status_code in [200, 204], (
                f"AWS expected 200/204, got {response.aws.status_code}: {response.aws.text[:200]}"
            )
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
            assert response.comparison.is_compliant, (
                f"Custom S3 doesn't match AWS: {response.diff_summary}"
            )
        else:
            assert response.status_code in [200, 204], (
                f"Expected 200/204, got {response.status_code}: {response.text[:200]}"
            )
            json_metadata["status"] = response.status_code

        # Cleanup
        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    # =========================================================================
    # Missing Header Tests (partial SSE-C headers)
    # =========================================================================

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_only_algorithm_rejected(
        self,
        s3_client,
        test_bucket,
        test_key,
        test_body,
        make_request,
        json_metadata,
    ):
        """Server should reject request with only SSE-C algorithm header."""
        headers = {
            "Content-Type": "text/plain",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}/{test_key}",
            body=test_body,
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
            assert response.comparison.is_compliant, (
                f"Custom S3 doesn't match AWS: {response.diff_summary}"
            )
        else:
            assert response.status_code == 400, (
                f"Expected 400, got {response.status_code}"
            )
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        # Cleanup
        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_only_key_rejected(
        self,
        s3_client,
        test_bucket,
        test_key,
        test_body,
        make_request,
        json_metadata,
    ):
        """Server should reject request with only SSE-C key header."""
        key_b64, _ = generate_sse_c_key()

        headers = {
            "Content-Type": "text/plain",
            "x-amz-server-side-encryption-customer-key": key_b64,
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}/{test_key}",
            body=test_body,
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
            assert response.comparison.is_compliant, (
                f"Custom S3 doesn't match AWS: {response.diff_summary}"
            )
        else:
            assert response.status_code == 400, (
                f"Expected 400, got {response.status_code}"
            )
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        # Cleanup
        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_only_key_md5_rejected(
        self,
        s3_client,
        test_bucket,
        test_key,
        test_body,
        make_request,
        json_metadata,
    ):
        """Server should reject request with only SSE-C key MD5 header."""
        _, key_md5 = generate_sse_c_key()

        headers = {
            "Content-Type": "text/plain",
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}/{test_key}",
            body=test_body,
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
            assert response.comparison.is_compliant, (
                f"Custom S3 doesn't match AWS: {response.diff_summary}"
            )
        else:
            assert response.status_code == 400, (
                f"Expected 400, got {response.status_code}"
            )
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        # Cleanup
        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_algorithm_and_key_missing_md5_rejected(
        self,
        s3_client,
        test_bucket,
        test_key,
        test_body,
        make_request,
        json_metadata,
    ):
        """Server should reject request with algorithm and key but missing MD5."""
        key_b64, _ = generate_sse_c_key()

        headers = {
            "Content-Type": "text/plain",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}/{test_key}",
            body=test_body,
            headers=headers,
        )

        json_metadata["provided_headers"] = ["algorithm", "key"]
        json_metadata["missing_headers"] = ["key_md5"]

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400, (
                f"AWS expected 400, got {response.aws.status_code}"
            )
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, (
                f"Custom S3 doesn't match AWS: {response.diff_summary}"
            )
        else:
            assert response.status_code == 400, (
                f"Expected 400, got {response.status_code}"
            )
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        # Cleanup
        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_algorithm_and_md5_missing_key_rejected(
        self,
        s3_client,
        test_bucket,
        test_key,
        test_body,
        make_request,
        json_metadata,
    ):
        """Server should reject request with algorithm and MD5 but missing key."""
        _, key_md5 = generate_sse_c_key()

        headers = {
            "Content-Type": "text/plain",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}/{test_key}",
            body=test_body,
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
            assert response.comparison.is_compliant, (
                f"Custom S3 doesn't match AWS: {response.diff_summary}"
            )
        else:
            assert response.status_code == 400, (
                f"Expected 400, got {response.status_code}"
            )
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        # Cleanup
        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_key_and_md5_missing_algorithm_rejected(
        self,
        s3_client,
        test_bucket,
        test_key,
        test_body,
        make_request,
        json_metadata,
    ):
        """Server should reject request with key and MD5 but missing algorithm."""
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "Content-Type": "text/plain",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}/{test_key}",
            body=test_body,
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
            assert response.comparison.is_compliant, (
                f"Custom S3 doesn't match AWS: {response.diff_summary}"
            )
        else:
            assert response.status_code == 400, (
                f"Expected 400, got {response.status_code}"
            )
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        # Cleanup
        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    # =========================================================================
    # Invalid Value Tests
    # =========================================================================

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_invalid_algorithm_rejected(
        self,
        s3_client,
        test_bucket,
        test_key,
        test_body,
        make_request,
        json_metadata,
    ):
        """Server should reject request with invalid SSE-C algorithm."""
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "Content-Type": "text/plain",
            "x-amz-server-side-encryption-customer-algorithm": "AES128-INVALID",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}/{test_key}",
            body=test_body,
            headers=headers,
        )

        json_metadata["invalid_algorithm"] = "AES128-INVALID"
        json_metadata["expected_algorithm"] = "AES256"

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400, (
                f"AWS expected 400, got {response.aws.status_code}"
            )
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, (
                f"Custom S3 doesn't match AWS: {response.diff_summary}"
            )
        else:
            assert response.status_code == 400, (
                f"Expected 400, got {response.status_code}"
            )
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        # Cleanup
        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_invalid_key_length_10_rejected(
        self,
        s3_client,
        test_bucket,
        test_key,
        test_body,
        make_request,
        json_metadata,
    ):
        """Server should reject request with invalid key length (10 bytes instead of 32)."""
        short_key = b"1234567890"  # 10 bytes
        key_b64, key_md5 = generate_sse_c_key(short_key)

        headers = {
            "Content-Type": "text/plain",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}/{test_key}",
            body=test_body,
            headers=headers,
        )

        json_metadata["key_length_bytes"] = 10
        json_metadata["expected_key_length"] = 32

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400, (
                f"AWS expected 400, got {response.aws.status_code}"
            )
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, (
                f"Custom S3 doesn't match AWS: {response.diff_summary}"
            )
        else:
            assert response.status_code == 400, (
                f"Expected 400, got {response.status_code}"
            )
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        # Cleanup
        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_mismatched_key_md5_rejected(
        self,
        s3_client,
        test_bucket,
        test_key,
        test_body,
        make_request,
        json_metadata,
    ):
        """Server should reject request when key MD5 doesn't match key."""
        key_b64, _ = generate_sse_c_key()
        # Use MD5 of a different key
        wrong_key_md5 = base64.b64encode(
            hashlib.md5(b"wrong-key-for-md5-mismatch").digest()
        ).decode("utf-8")

        headers = {
            "Content-Type": "text/plain",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": wrong_key_md5,
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}/{test_key}",
            body=test_body,
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
            assert response.comparison.is_compliant, (
                f"Custom S3 doesn't match AWS: {response.diff_summary}"
            )
        else:
            assert response.status_code == 400, (
                f"Expected 400, got {response.status_code}"
            )
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        # Cleanup
        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_invalid_key_md5_not_base64_rejected(
        self,
        s3_client,
        test_bucket,
        test_key,
        test_body,
        make_request,
        json_metadata,
    ):
        """Server should reject request when key MD5 is not valid base64."""
        key_b64, _ = generate_sse_c_key()

        headers = {
            "Content-Type": "text/plain",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": "not-valid-base64!!!",
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}/{test_key}",
            body=test_body,
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
            assert response.comparison.is_compliant, (
                f"Custom S3 doesn't match AWS: {response.diff_summary}"
            )
        else:
            assert response.status_code == 400, (
                f"Expected 400, got {response.status_code}"
            )
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        # Cleanup
        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    # =========================================================================
    # Validation Order Tests
    # =========================================================================

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_all_invalid_validation_order(
        self,
        s3_client,
        test_bucket,
        test_key,
        test_body,
        make_request,
        json_metadata,
    ):
        """Test which validation error is returned first when all headers are invalid.

        This test helps understand the server's validation order:
        - Invalid algorithm (AES256-INVALID)
        - Invalid key (too short)
        - Invalid MD5 (doesn't match key)
        """
        short_key = b"short-key"  # Invalid length
        key_b64 = base64.b64encode(short_key).decode("utf-8")
        wrong_md5 = base64.b64encode(hashlib.md5(b"wrong").digest()).decode("utf-8")

        headers = {
            "Content-Type": "text/plain",
            "x-amz-server-side-encryption-customer-algorithm": "AES256-INVALID",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": wrong_md5,
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}/{test_key}",
            body=test_body,
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
            assert response.comparison.is_compliant, (
                f"Custom S3 doesn't match AWS: {response.diff_summary}"
            )
        else:
            assert response.status_code == 400, (
                f"Expected 400, got {response.status_code}"
            )
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg
            json_metadata["first_validation_error"] = error_code

        # Cleanup
        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_invalid_key_length_with_invalid_algorithm(
        self,
        s3_client,
        test_bucket,
        test_key,
        test_body,
        make_request,
        json_metadata,
    ):
        """Test validation order: invalid algorithm vs invalid key length."""
        short_key = b"1234567890"  # 10 bytes
        key_b64, key_md5 = generate_sse_c_key(short_key)

        headers = {
            "Content-Type": "text/plain",
            "x-amz-server-side-encryption-customer-algorithm": "INVALID-ALGO",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}/{test_key}",
            body=test_body,
            headers=headers,
        )

        json_metadata["invalid_algorithm"] = "INVALID-ALGO"
        json_metadata["key_length_bytes"] = 10
        json_metadata["key_md5_matches_key"] = True  # MD5 is valid

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400, (
                f"AWS expected 400, got {response.aws.status_code}"
            )
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            json_metadata["first_validation_error"] = error_code
            assert response.comparison.is_compliant, (
                f"Custom S3 doesn't match AWS: {response.diff_summary}"
            )
        else:
            assert response.status_code == 400, (
                f"Expected 400, got {response.status_code}"
            )
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg
            json_metadata["first_validation_error"] = error_code

        # Cleanup
        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_invalid_key_length_with_mismatched_md5(
        self,
        s3_client,
        test_bucket,
        test_key,
        test_body,
        make_request,
        json_metadata,
    ):
        """Test validation order: invalid key length vs mismatched MD5."""
        short_key = b"1234567890"  # 10 bytes
        key_b64 = base64.b64encode(short_key).decode("utf-8")
        # Use wrong MD5
        wrong_md5 = base64.b64encode(hashlib.md5(b"wrong").digest()).decode("utf-8")

        headers = {
            "Content-Type": "text/plain",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": wrong_md5,
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}/{test_key}",
            body=test_body,
            headers=headers,
        )

        json_metadata["key_length_bytes"] = 10
        json_metadata["key_md5_matches_key"] = False

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400, (
                f"AWS expected 400, got {response.aws.status_code}"
            )
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            json_metadata["first_validation_error"] = error_code
            assert response.comparison.is_compliant, (
                f"Custom S3 doesn't match AWS: {response.diff_summary}"
            )
        else:
            assert response.status_code == 400, (
                f"Expected 400, got {response.status_code}"
            )
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg
            json_metadata["first_validation_error"] = error_code

        # Cleanup
        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass
