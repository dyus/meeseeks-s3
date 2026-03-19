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
import uuid

import pytest

from s3_compliance.sse_c import DEFAULT_SSE_C_KEY_BYTES, generate_sse_c_key
from s3_compliance.xml_utils import extract_error_info


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
    # TODO wrong error on custom due to invalid md5 check should be last one
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
        - Invalid key (not valid base64)
        - Invalid MD5 (doesn't match key)
        """
        invalid_key = "not-valid-base64!!!"
        wrong_md5 = base64.b64encode(hashlib.md5(b"wrong").digest()).decode("utf-8")

        headers = {
            "Content-Type": "text/plain",
            "x-amz-server-side-encryption-customer-algorithm": "AES256-INVALID",
            "x-amz-server-side-encryption-customer-key": invalid_key,
            "x-amz-server-side-encryption-customer-key-MD5": wrong_md5,
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}/{test_key}",
            body=test_body,
            headers=headers,
        )

        json_metadata["invalid_algorithm"] = "AES256-INVALID"
        json_metadata["invalid_key_base64"] = invalid_key
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
    def test_sse_c_invalid_key_base64_with_invalid_algorithm(
        self,
        s3_client,
        test_bucket,
        test_key,
        test_body,
        make_request,
        json_metadata,
    ):
        """Test validation order: invalid base64 customer key + invalid algorithm."""
        invalid_key = "not-valid-base64!!!"
        key_md5 = base64.b64encode(hashlib.md5(b"anything").digest()).decode("utf-8")

        headers = {
            "Content-Type": "text/plain",
            "x-amz-server-side-encryption-customer-algorithm": "INVALID-ALGO",
            "x-amz-server-side-encryption-customer-key": invalid_key,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}/{test_key}",
            body=test_body,
            headers=headers,
        )

        json_metadata["invalid_algorithm"] = "INVALID-ALGO"
        json_metadata["invalid_key_base64"] = invalid_key

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

    # =========================================================================
    # HTTP (non-TLS) with invalid SSE-C headers
    # =========================================================================

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_all_invalid_headers_over_http(
        self,
        s3_client,
        test_bucket,
        test_key,
        test_body,
        make_request,
        json_metadata,
    ):
        """Test all three SSE-C headers invalid + request sent over HTTP (not HTTPS).

        SSE-C requires HTTPS. This tests which error takes priority:
        the HTTP transport violation or the invalid header values.
        """
        invalid_key = "not-valid-base64!!!"
        wrong_md5 = base64.b64encode(hashlib.md5(b"wrong").digest()).decode("utf-8")

        headers = {
            "Content-Type": "text/plain",
            "x-amz-server-side-encryption-customer-algorithm": "AES256-INVALID",
            "x-amz-server-side-encryption-customer-key": invalid_key,
            "x-amz-server-side-encryption-customer-key-MD5": wrong_md5,
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}/{test_key}",
            body=test_body,
            headers=headers,
            scheme="http",
        )

        json_metadata["transport"] = "http"
        json_metadata["invalid_algorithm"] = "AES256-INVALID"
        json_metadata["invalid_key_base64"] = invalid_key
        json_metadata["key_md5_matches_key"] = False

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400, (
                f"AWS expected 400, got {response.aws.status_code}"
            )
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            # HTTPS check runs before header value validation
            assert error_code == "InvalidArgument"
            assert "secure connection" in error_msg
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
            # HTTPS check runs before header value validation
            assert error_code == "InvalidArgument"
            assert "secure connection" in error_msg

        # Cleanup
        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    # =========================================================================
    # SSE-C + SSE-S3 conflict
    # =========================================================================

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_valid_with_sse_s3_header_conflict(
        self,
        s3_client,
        test_bucket,
        test_key,
        test_body,
        make_request,
        json_metadata,
    ):
        """Valid SSE-C headers + x-amz-server-side-encryption: AES256.

        SSE-C and SSE-S3 are mutually exclusive.
        """
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "Content-Type": "text/plain",
            "x-amz-server-side-encryption": "AES256",
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

        json_metadata["sse_s3_value"] = "AES256"
        json_metadata["sse_c_algorithm"] = "AES256"

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

        # Cleanup
        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    # =========================================================================
    # Invalid customer key values
    # =========================================================================

    @pytest.mark.edge_case
    def test_sse_c_customer_key_decodes_to_short_value(
        self,
        s3_client,
        test_bucket,
        test_key,
        test_body,
        make_request,
        json_metadata,
    ):
        """Test PUT with customer key '####' that decodes to 0 bytes via lenient base64."""
        _, key_md5 = generate_sse_c_key()

        headers = {
            "Content-Type": "text/plain",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": "####",
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}/{test_key}",
            body=test_body,
            headers=headers,
        )

        json_metadata["key_value"] = "####"

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

        # Cleanup
        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    @pytest.mark.edge_case
    def test_sse_c_customer_key_zz(
        self,
        s3_client,
        test_bucket,
        test_key,
        test_body,
        make_request,
        json_metadata,
    ):
        """Test PUT with customer key 'ZZ' that decodes to 1 byte (0x65) via base64."""
        _, key_md5 = generate_sse_c_key()

        headers = {
            "Content-Type": "text/plain",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": "ZZ",
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}/{test_key}",
            body=test_body,
            headers=headers,
        )

        json_metadata["key_value"] = "ZZ"

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

        # Cleanup
        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    @pytest.mark.edge_case
    def test_sse_c_customer_key_single_char_a(
        self,
        s3_client,
        test_bucket,
        test_key,
        test_body,
        make_request,
        json_metadata,
    ):
        """Test PUT with customer key 'a' — invalid base64 (1 char, needs min 2 for a byte)."""
        _, key_md5 = generate_sse_c_key()

        headers = {
            "Content-Type": "text/plain",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": "a",
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}/{test_key}",
            body=test_body,
            headers=headers,
        )

        json_metadata["key_value"] = "a"

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

        # Cleanup
        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    @pytest.mark.edge_case
    def test_sse_c_customer_key_latin1_chars(
        self,
        s3_client,
        test_bucket,
        test_key,
        test_body,
        make_request,
        json_metadata,
    ):
        """Test PUT with customer key as latin-1 non-ASCII chars 'éñüß'.

        These are valid latin-1 (0xE9, 0xF1, 0xFC, 0xDF) so they can be sent
        in HTTP headers, but they are not valid base64 characters.
        """
        _, key_md5 = generate_sse_c_key()

        headers = {
            "Content-Type": "text/plain",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": "\u00e9\u00f1\u00fc\u00df",
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}/{test_key}",
            body=test_body,
            headers=headers,
        )

        json_metadata["key_value"] = "\u00e9\u00f1\u00fc\u00df"

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

        # Cleanup
        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    @pytest.mark.edge_case
    def test_sse_c_empty_customer_key(
        self,
        s3_client,
        test_bucket,
        test_key,
        test_body,
        make_request,
        json_metadata,
    ):
        """Test PUT with empty string as customer key."""
        _, key_md5 = generate_sse_c_key()

        headers = {
            "Content-Type": "text/plain",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": "",
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}/{test_key}",
            body=test_body,
            headers=headers,
        )

        json_metadata["key_value"] = ""

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

        # Cleanup
        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

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
    def test_sse_c_customer_key_with_garbage_chars_in_base64(
        self,
        s3_client,
        test_bucket,
        test_key,
        test_body,
        make_request,
        json_metadata,
        garbage_position,
    ):
        """Test PUT with valid 32-byte key base64 + garbage chars at various positions.

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
            "Content-Type": "text/plain",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": dirty_key,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}/{test_key}",
            body=test_body,
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

        # Cleanup
        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    @pytest.mark.edge_case
    def test_sse_c_customer_key_decodes_to_1_byte(
        self,
        s3_client,
        test_bucket,
        test_key,
        test_body,
        make_request,
        json_metadata,
    ):
        """Test PUT with customer key that decodes to 1 byte (AQ==)."""
        short_key = b"\x01"
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

        json_metadata["key_b64"] = key_b64
        json_metadata["key_decoded_length"] = 1

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

        # Cleanup
        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    # =========================================================================
    # Key length validation with correct MD5
    # =========================================================================

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_short_key_zz_with_matching_md5(
        self, s3_client, test_bucket, test_key, test_body, make_request, json_metadata,
    ):
        """Key 'ZZ' (decodes to 1 byte) with correct MD5 for that 1 byte.

        Tests validation order after MD5 passes: does AWS return
        "too short" or "invalid for the specified algorithm"?

        Go flow: decode → len==0? no (1 byte) → MD5 match → algo ok → len!=32 → "invalid for algorithm".
        """
        decoded_key = base64.b64decode("ZZ==")  # 1 byte: 0x65
        key_md5 = base64.b64encode(
            hashlib.md5(decoded_key).digest()
        ).decode("utf-8")

        headers = {
            "Content-Type": "text/plain",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": "ZZ",
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "PUT", f"/{test_bucket}/{test_key}", body=test_body, headers=headers,
        )

        json_metadata["key_value"] = "ZZ"
        json_metadata["key_decoded_length"] = len(decoded_key)
        json_metadata["md5_matches_key"] = True

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
        else:
            json_metadata["status"] = response.status_code
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_long_key_33_bytes_with_matching_md5(
        self, s3_client, test_bucket, test_key, test_body, make_request, json_metadata,
    ):
        """Key that decodes to 33 bytes with correct MD5.

        Tests validation after MD5 passes: should return "invalid for the specified algorithm".

        Go flow: decode → len==0? no (33) → MD5 match → algo ok → len!=32 → "invalid for algorithm".
        """
        long_key = b"\x01" * 33
        key_b64, key_md5 = generate_sse_c_key(long_key)

        headers = {
            "Content-Type": "text/plain",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "PUT", f"/{test_bucket}/{test_key}", body=test_body, headers=headers,
        )

        json_metadata["key_decoded_length"] = 33
        json_metadata["md5_matches_key"] = True

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
        else:
            json_metadata["status"] = response.status_code
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    # =========================================================================
    # Base64 encoding edge cases
    # =========================================================================

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_key_base64_with_spaces(
        self, s3_client, test_bucket, test_key, test_body, make_request, json_metadata,
    ):
        """Valid 32-byte key base64 with spaces inserted.

        AWS lenient base64 strips non-base64 chars including spaces.
        Go: spaces stripped → 32 bytes → MD5 match → 200.
        """
        key_b64, key_md5 = generate_sse_c_key()
        spaced_key = " ".join([key_b64[i:i+4] for i in range(0, len(key_b64), 4)])

        headers = {
            "Content-Type": "text/plain",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": spaced_key,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "PUT", f"/{test_bucket}/{test_key}", body=test_body, headers=headers,
        )

        json_metadata["key_value"] = spaced_key
        json_metadata["go_prediction"] = "200 (spaces stripped, 32 bytes, MD5 match)"

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            if response.aws.status_code != 200:
                error_code, error_msg = extract_error_info(response.aws.text)
                json_metadata["aws_error_code"] = error_code
                json_metadata["aws_error_message"] = error_msg
        else:
            json_metadata["status"] = response.status_code
            if response.status_code != 200:
                error_code, error_msg = extract_error_info(response.text)
                json_metadata["error_code"] = error_code
                json_metadata["error_message"] = error_msg

        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_key_base64_with_tabs_and_newlines(
        self, s3_client, test_bucket, test_key, test_body, make_request, json_metadata,
    ):
        """Valid 32-byte key base64 with tabs and newlines (PEM-style).

        Go: tabs/newlines stripped → 32 bytes → MD5 match → 200.
        """
        key_b64, key_md5 = generate_sse_c_key()
        wrapped_key = "\t".join([key_b64[i:i+8] for i in range(0, len(key_b64), 8)])

        headers = {
            "Content-Type": "text/plain",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": wrapped_key,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "PUT", f"/{test_bucket}/{test_key}", body=test_body, headers=headers,
        )

        json_metadata["key_value"] = repr(wrapped_key)
        json_metadata["go_prediction"] = "200 (tabs stripped, 32 bytes, MD5 match)"

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            if response.aws.status_code != 200:
                error_code, error_msg = extract_error_info(response.aws.text)
                json_metadata["aws_error_code"] = error_code
                json_metadata["aws_error_message"] = error_msg
        else:
            json_metadata["status"] = response.status_code
            if response.status_code != 200:
                error_code, error_msg = extract_error_info(response.text)
                json_metadata["error_code"] = error_code
                json_metadata["error_message"] = error_msg

        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_key_base64_without_padding(
        self, s3_client, test_bucket, test_key, test_body, make_request, json_metadata,
    ):
        """Valid 32-byte key base64 with padding '=' removed.

        Go: base64.StdEncoding requires padding → decode fails → 0 bytes → "too short".
        AWS may accept no-padding (lenient decoder).
        """
        key_b64, key_md5 = generate_sse_c_key()
        no_pad_key = key_b64.rstrip("=")

        headers = {
            "Content-Type": "text/plain",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": no_pad_key,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "PUT", f"/{test_bucket}/{test_key}", body=test_body, headers=headers,
        )

        json_metadata["key_value"] = no_pad_key
        json_metadata["original_key"] = key_b64
        json_metadata["go_prediction"] = "400 too short (StdEncoding fails without padding)"

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            if response.aws.text:
                error_code, error_msg = extract_error_info(response.aws.text)
                json_metadata["aws_error_code"] = error_code
                json_metadata["aws_error_message"] = error_msg
        else:
            json_metadata["status"] = response.status_code
            if response.text:
                error_code, error_msg = extract_error_info(response.text)
                json_metadata["error_code"] = error_code
                json_metadata["error_message"] = error_msg

        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_key_base64_with_extra_padding(
        self, s3_client, test_bucket, test_key, test_body, make_request, json_metadata,
    ):
        """Valid 32-byte key base64 with extra '===' appended.

        Go: extra '=' kept (valid base64 char) → StdEncoding may fail → 0 bytes → "too short".
        """
        key_b64, key_md5 = generate_sse_c_key()
        extra_pad_key = key_b64 + "==="

        headers = {
            "Content-Type": "text/plain",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": extra_pad_key,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "PUT", f"/{test_bucket}/{test_key}", body=test_body, headers=headers,
        )

        json_metadata["key_value"] = extra_pad_key
        json_metadata["go_prediction"] = "400 too short (StdEncoding fails with extra padding)"

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            if response.aws.text:
                error_code, error_msg = extract_error_info(response.aws.text)
                json_metadata["aws_error_code"] = error_code
                json_metadata["aws_error_message"] = error_msg
        else:
            json_metadata["status"] = response.status_code
            if response.text:
                error_code, error_msg = extract_error_info(response.text)
                json_metadata["error_code"] = error_code
                json_metadata["error_message"] = error_msg

        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_key_url_safe_base64(
        self, s3_client, test_bucket, test_key, test_body, make_request, json_metadata,
    ):
        """Key encoded with URL-safe base64 (- and _ instead of + and /).

        Go: '-' and '_' stripped → different decoded bytes → MD5 mismatch or wrong length.
        """
        import base64
        key_bytes = DEFAULT_SSE_C_KEY_BYTES
        url_safe_key = base64.urlsafe_b64encode(key_bytes).decode("utf-8")
        _, key_md5 = generate_sse_c_key()

        headers = {
            "Content-Type": "text/plain",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": url_safe_key,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "PUT", f"/{test_bucket}/{test_key}", body=test_body, headers=headers,
        )

        std_key, _ = generate_sse_c_key()
        json_metadata["key_value"] = url_safe_key
        json_metadata["original_key"] = std_key
        json_metadata["has_plus_or_slash"] = "+" in std_key or "/" in std_key
        json_metadata["go_prediction"] = "400 MD5 mismatch or too short (- and _ stripped)"

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            if response.aws.text:
                error_code, error_msg = extract_error_info(response.aws.text)
                json_metadata["aws_error_code"] = error_code
                json_metadata["aws_error_message"] = error_msg
        else:
            json_metadata["status"] = response.status_code
            if response.text:
                error_code, error_msg = extract_error_info(response.text)
                json_metadata["error_code"] = error_code
                json_metadata["error_message"] = error_msg

        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_key_and_md5_both_url_safe_base64(
        self, s3_client, test_bucket, test_key, test_body, make_request, json_metadata,
    ):
        """Both key and MD5 encoded with URL-safe base64 (- and _ instead of + and /).

        Definitive test: if AWS returns 200, it supports URLEncoding.
        If 400, it strictly uses StdEncoding (+/).
        """
        import base64, hashlib
        key_bytes = DEFAULT_SSE_C_KEY_BYTES
        url_safe_key = base64.urlsafe_b64encode(key_bytes).decode("utf-8")
        url_safe_md5 = base64.urlsafe_b64encode(hashlib.md5(key_bytes).digest()).decode("utf-8")

        headers = {
            "Content-Type": "text/plain",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": url_safe_key,
            "x-amz-server-side-encryption-customer-key-MD5": url_safe_md5,
        }

        response = make_request(
            "PUT", f"/{test_bucket}/{test_key}", body=test_body, headers=headers,
        )

        std_key, std_md5 = generate_sse_c_key()
        json_metadata["key_value"] = url_safe_key
        json_metadata["md5_value"] = url_safe_md5
        json_metadata["original_key"] = std_key
        json_metadata["original_md5"] = std_md5
        json_metadata["conclusion"] = "200 = URLEncoding supported, 400 = StdEncoding only"

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            if response.aws.text:
                error_code, error_msg = extract_error_info(response.aws.text)
                json_metadata["aws_error_code"] = error_code
                json_metadata["aws_error_message"] = error_msg
        else:
            json_metadata["status"] = response.status_code
            if response.text:
                error_code, error_msg = extract_error_info(response.text)
                json_metadata["error_code"] = error_code
                json_metadata["error_message"] = error_msg

        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_key_31_bytes(
        self, s3_client, test_bucket, test_key, test_body, make_request, json_metadata,
    ):
        """Key that decodes to 31 bytes (one byte short of AES-256).

        Go: decode ok → MD5 match → algo ok → len!=32 → "invalid for algorithm".
        """
        short_key = b"\x01" * 31
        key_b64, key_md5 = generate_sse_c_key(short_key)

        headers = {
            "Content-Type": "text/plain",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "PUT", f"/{test_bucket}/{test_key}", body=test_body, headers=headers,
        )

        json_metadata["key_decoded_length"] = 31
        json_metadata["go_prediction"] = "400 invalid for algorithm (len 31 != 32)"

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
        else:
            json_metadata["status"] = response.status_code
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_key_33_bytes(
        self, s3_client, test_bucket, test_key, test_body, make_request, json_metadata,
    ):
        """Key that decodes to 33 bytes (one byte over AES-256).

        Go: decode ok → MD5 match → algo ok → len!=32 → "invalid for algorithm".
        """
        long_key = b"\x01" * 33
        key_b64, key_md5 = generate_sse_c_key(long_key)

        headers = {
            "Content-Type": "text/plain",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "PUT", f"/{test_bucket}/{test_key}", body=test_body, headers=headers,
        )

        json_metadata["key_decoded_length"] = 33
        json_metadata["go_prediction"] = "400 invalid for algorithm (len 33 != 32)"

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
        else:
            json_metadata["status"] = response.status_code
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_md5_with_garbage_chars(
        self, s3_client, test_bucket, test_key, test_body, make_request, json_metadata,
    ):
        """Valid key + MD5 base64 with garbage chars inserted.

        Go: MD5 decoded with lenient base64 (garbage stripped) → if decoded MD5
        still matches key MD5 → success. Otherwise MD5 mismatch.
        """
        key_b64, key_md5 = generate_sse_c_key()
        garbage_md5 = "!!" + key_md5[:8] + "##" + key_md5[8:]

        headers = {
            "Content-Type": "text/plain",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": garbage_md5,
        }

        response = make_request(
            "PUT", f"/{test_bucket}/{test_key}", body=test_body, headers=headers,
        )

        json_metadata["md5_value"] = garbage_md5
        json_metadata["original_md5"] = key_md5
        json_metadata["go_prediction"] = "200 (garbage stripped, MD5 matches)"

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            if response.aws.status_code != 200:
                error_code, error_msg = extract_error_info(response.aws.text)
                json_metadata["aws_error_code"] = error_code
                json_metadata["aws_error_message"] = error_msg
        else:
            json_metadata["status"] = response.status_code
            if response.status_code != 200:
                error_code, error_msg = extract_error_info(response.text)
                json_metadata["error_code"] = error_code
                json_metadata["error_message"] = error_msg

        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_md5_decodes_to_wrong_length(
        self, s3_client, test_bucket, test_key, test_body, make_request, json_metadata,
    ):
        """Valid key + MD5 that decodes to 8 bytes instead of 16.

        Go: MD5 decoded to 8 bytes → ConstantTimeCompare with 16-byte actual MD5
        → lengths differ → mismatch → "MD5 hash did not match".
        """
        key_b64, _ = generate_sse_c_key()
        # 8 bytes encoded as base64 (instead of 16-byte MD5)
        short_md5 = base64.b64encode(b"\x01" * 8).decode("utf-8")

        headers = {
            "Content-Type": "text/plain",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": short_md5,
        }

        response = make_request(
            "PUT", f"/{test_bucket}/{test_key}", body=test_body, headers=headers,
        )

        json_metadata["md5_value"] = short_md5
        json_metadata["md5_decoded_length"] = 8
        json_metadata["go_prediction"] = "400 MD5 hash did not match"

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
        else:
            json_metadata["status"] = response.status_code
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_valid_key_md5_without_padding(
        self, s3_client, test_bucket, test_key, test_body, make_request, json_metadata,
    ):
        """Valid padded key, but MD5 has base64 padding '=' stripped.

        Go: base64.StdEncoding requires padding → decode fails → rejected.
        AWS may accept no-padding (lenient decoder).
        """
        key_b64, key_md5 = generate_sse_c_key()
        no_pad_md5 = key_md5.rstrip("=")

        headers = {
            "Content-Type": "text/plain",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": no_pad_md5,
        }

        response = make_request(
            "PUT", f"/{test_bucket}/{test_key}", body=test_body, headers=headers,
        )

        json_metadata["md5_value"] = no_pad_md5
        json_metadata["original_md5"] = key_md5
        json_metadata["key_value"] = key_b64
        json_metadata["go_prediction"] = "400 (StdEncoding fails without padding on MD5)"

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            if response.aws.text:
                error_code, error_msg = extract_error_info(response.aws.text)
                json_metadata["aws_error_code"] = error_code
                json_metadata["aws_error_message"] = error_msg
        else:
            json_metadata["status"] = response.status_code
            if response.text:
                error_code, error_msg = extract_error_info(response.text)
                json_metadata["error_code"] = error_code
                json_metadata["error_message"] = error_msg

        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass
