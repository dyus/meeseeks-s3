"""Tests for CreateMultipartUpload with SSE-C (Server-Side Encryption with Customer-Provided Keys).

These tests verify S3 behavior when initiating a multipart upload with SSE-C headers
in various combinations and with various validation errors.

CreateMultipartUpload (POST /{bucket}/{key}?uploads) for SSE-C requires three headers:
- x-amz-server-side-encryption-customer-algorithm: Must be "AES256"
- x-amz-server-side-encryption-customer-key: Base64-encoded 32-byte key
- x-amz-server-side-encryption-customer-key-MD5: Base64-encoded MD5 of the key

On success, returns 200 with XML body containing UploadId.
This is a write-path operation, so SSE-C validation behavior should match PutObject.
"""

import base64
import hashlib
import uuid

import pytest

from s3_compliance.sse_c import generate_sse_c_key
from s3_compliance.xml_utils import extract_error_info, extract_upload_id


@pytest.mark.s3_handler("CreateMultipartUpload")
@pytest.mark.sse_c
class TestSSECCreateMultipartUploadHeaders:
    """Test CreateMultipartUpload API with SSE-C header combinations."""

    @pytest.fixture
    def test_key(self):
        """Generate unique test key."""
        return f"test-ssec-mpu-{uuid.uuid4().hex[:8]}"

    def _abort_upload(self, s3_client, bucket, key, response):
        """Abort multipart upload if it was successfully created."""
        if hasattr(response, "comparison"):
            # Both mode — abort on both endpoints
            for resp, client_key in [(response.aws, "aws"), (response.custom, "custom")]:
                if resp.status_code == 200:
                    upload_id = extract_upload_id(resp.text)
                    if upload_id:
                        try:
                            client = s3_client[client_key] if isinstance(s3_client, dict) else s3_client
                            client.abort_multipart_upload(
                                Bucket=bucket, Key=key, UploadId=upload_id,
                            )
                        except Exception:
                            pass
        else:
            if response.status_code == 200:
                upload_id = extract_upload_id(response.text)
                if upload_id:
                    try:
                        s3_client.abort_multipart_upload(
                            Bucket=bucket, Key=key, UploadId=upload_id,
                        )
                    except Exception:
                        pass

    # =========================================================================
    # Successful Request
    # =========================================================================

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_all_valid_headers_accepted(
        self,
        s3_client,
        test_bucket,
        test_key,
        make_request,
        json_metadata,
    ):
        """Server should accept CreateMultipartUpload with all valid SSE-C headers."""
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "Content-Type": "application/octet-stream",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "POST",
            f"/{test_bucket}/{test_key}",
            headers=headers,
            query_params="?uploads",
        )

        json_metadata["sse_c_algorithm"] = "AES256"
        json_metadata["sse_c_key_length"] = 32

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 200, (
                f"AWS expected 200, got {response.aws.status_code}: {response.aws.text[:200]}"
            )
            upload_id = extract_upload_id(response.aws.text)
            assert upload_id, "AWS response missing UploadId"
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
            assert response.comparison.is_compliant, (
                f"Custom S3 doesn't match AWS: {response.diff_summary}"
            )
        else:
            assert response.status_code == 200, (
                f"Expected 200, got {response.status_code}: {response.text[:200]}"
            )
            upload_id = extract_upload_id(response.text)
            assert upload_id, "Response missing UploadId"
            json_metadata["status"] = response.status_code

        self._abort_upload(s3_client, test_bucket, test_key, response)

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
        make_request,
        json_metadata,
    ):
        """Server should reject request with only SSE-C algorithm header."""
        headers = {
            "Content-Type": "application/octet-stream",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
        }

        response = make_request(
            "POST",
            f"/{test_bucket}/{test_key}",
            headers=headers,
            query_params="?uploads",
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

        self._abort_upload(s3_client, test_bucket, test_key, response)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_only_key_rejected(
        self,
        s3_client,
        test_bucket,
        test_key,
        make_request,
        json_metadata,
    ):
        """Server should reject request with only SSE-C key header."""
        key_b64, _ = generate_sse_c_key()

        headers = {
            "Content-Type": "application/octet-stream",
            "x-amz-server-side-encryption-customer-key": key_b64,
        }

        response = make_request(
            "POST",
            f"/{test_bucket}/{test_key}",
            headers=headers,
            query_params="?uploads",
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

        self._abort_upload(s3_client, test_bucket, test_key, response)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_only_key_md5_rejected(
        self,
        s3_client,
        test_bucket,
        test_key,
        make_request,
        json_metadata,
    ):
        """Server should reject request with only SSE-C key MD5 header."""
        _, key_md5 = generate_sse_c_key()

        headers = {
            "Content-Type": "application/octet-stream",
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "POST",
            f"/{test_bucket}/{test_key}",
            headers=headers,
            query_params="?uploads",
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

        self._abort_upload(s3_client, test_bucket, test_key, response)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_algorithm_and_key_missing_md5_rejected(
        self,
        s3_client,
        test_bucket,
        test_key,
        make_request,
        json_metadata,
    ):
        """Server should reject request with algorithm and key but missing MD5.

        CreateMultipartUpload is a write-path operation like PutObject,
        so it should require all three SSE-C headers.
        """
        key_b64, _ = generate_sse_c_key()

        headers = {
            "Content-Type": "application/octet-stream",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
        }

        response = make_request(
            "POST",
            f"/{test_bucket}/{test_key}",
            headers=headers,
            query_params="?uploads",
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

        self._abort_upload(s3_client, test_bucket, test_key, response)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_algorithm_and_md5_missing_key_rejected(
        self,
        s3_client,
        test_bucket,
        test_key,
        make_request,
        json_metadata,
    ):
        """Server should reject request with algorithm and MD5 but missing key."""
        _, key_md5 = generate_sse_c_key()

        headers = {
            "Content-Type": "application/octet-stream",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "POST",
            f"/{test_bucket}/{test_key}",
            headers=headers,
            query_params="?uploads",
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

        self._abort_upload(s3_client, test_bucket, test_key, response)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_key_and_md5_missing_algorithm_rejected(
        self,
        s3_client,
        test_bucket,
        test_key,
        make_request,
        json_metadata,
    ):
        """Server should reject request with key and MD5 but missing algorithm."""
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "Content-Type": "application/octet-stream",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "POST",
            f"/{test_bucket}/{test_key}",
            headers=headers,
            query_params="?uploads",
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

        self._abort_upload(s3_client, test_bucket, test_key, response)

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
        make_request,
        json_metadata,
    ):
        """Server should reject request with invalid SSE-C algorithm."""
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "Content-Type": "application/octet-stream",
            "x-amz-server-side-encryption-customer-algorithm": "AES128-INVALID",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "POST",
            f"/{test_bucket}/{test_key}",
            headers=headers,
            query_params="?uploads",
        )

        json_metadata["invalid_algorithm"] = "AES128-INVALID"

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

        self._abort_upload(s3_client, test_bucket, test_key, response)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_invalid_key_length_10_rejected(
        self,
        s3_client,
        test_bucket,
        test_key,
        make_request,
        json_metadata,
    ):
        """Server should reject request with invalid key length (10 bytes instead of 32).

        CreateMultipartUpload is a write-path operation like PutObject,
        so AWS returns 400 InvalidArgument for invalid key length.
        """
        short_key = b"1234567890"  # 10 bytes
        key_b64, key_md5 = generate_sse_c_key(short_key)

        headers = {
            "Content-Type": "application/octet-stream",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "POST",
            f"/{test_bucket}/{test_key}",
            headers=headers,
            query_params="?uploads",
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

        self._abort_upload(s3_client, test_bucket, test_key, response)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_mismatched_key_md5_rejected(
        self,
        s3_client,
        test_bucket,
        test_key,
        make_request,
        json_metadata,
    ):
        """Server should reject request when key MD5 doesn't match key."""
        key_b64, _ = generate_sse_c_key()
        wrong_key_md5 = base64.b64encode(
            hashlib.md5(b"wrong-key-for-md5-mismatch").digest()
        ).decode("utf-8")

        headers = {
            "Content-Type": "application/octet-stream",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": wrong_key_md5,
        }

        response = make_request(
            "POST",
            f"/{test_bucket}/{test_key}",
            headers=headers,
            query_params="?uploads",
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

        self._abort_upload(s3_client, test_bucket, test_key, response)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_invalid_key_md5_not_base64_rejected(
        self,
        s3_client,
        test_bucket,
        test_key,
        make_request,
        json_metadata,
    ):
        """Server should reject request when key MD5 is not valid base64."""
        key_b64, _ = generate_sse_c_key()

        headers = {
            "Content-Type": "application/octet-stream",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": "not-valid-base64!!!",
        }

        response = make_request(
            "POST",
            f"/{test_bucket}/{test_key}",
            headers=headers,
            query_params="?uploads",
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

        self._abort_upload(s3_client, test_bucket, test_key, response)

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
        make_request,
        json_metadata,
    ):
        """Test which validation error is returned first when all headers are invalid.

        Invalid algorithm (AES256-INVALID), invalid key (too short),
        invalid MD5 (doesn't match key).
        """
        short_key = b"short-key"
        key_b64 = base64.b64encode(short_key).decode("utf-8")
        wrong_md5 = base64.b64encode(hashlib.md5(b"wrong").digest()).decode("utf-8")

        headers = {
            "Content-Type": "application/octet-stream",
            "x-amz-server-side-encryption-customer-algorithm": "AES256-INVALID",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": wrong_md5,
        }

        response = make_request(
            "POST",
            f"/{test_bucket}/{test_key}",
            headers=headers,
            query_params="?uploads",
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

        self._abort_upload(s3_client, test_bucket, test_key, response)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_invalid_key_length_with_invalid_algorithm(
        self,
        s3_client,
        test_bucket,
        test_key,
        make_request,
        json_metadata,
    ):
        """Test validation order: invalid algorithm vs invalid key length."""
        short_key = b"1234567890"  # 10 bytes
        key_b64, key_md5 = generate_sse_c_key(short_key)

        headers = {
            "Content-Type": "application/octet-stream",
            "x-amz-server-side-encryption-customer-algorithm": "INVALID-ALGO",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "POST",
            f"/{test_bucket}/{test_key}",
            headers=headers,
            query_params="?uploads",
        )

        json_metadata["invalid_algorithm"] = "INVALID-ALGO"
        json_metadata["key_length_bytes"] = 10
        json_metadata["key_md5_matches_key"] = True

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

        self._abort_upload(s3_client, test_bucket, test_key, response)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_invalid_key_length_with_mismatched_md5(
        self,
        s3_client,
        test_bucket,
        test_key,
        make_request,
        json_metadata,
    ):
        """Test validation order: invalid key length vs mismatched MD5."""
        short_key = b"1234567890"  # 10 bytes
        key_b64 = base64.b64encode(short_key).decode("utf-8")
        wrong_md5 = base64.b64encode(hashlib.md5(b"wrong").digest()).decode("utf-8")

        headers = {
            "Content-Type": "application/octet-stream",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": wrong_md5,
        }

        response = make_request(
            "POST",
            f"/{test_bucket}/{test_key}",
            headers=headers,
            query_params="?uploads",
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

        self._abort_upload(s3_client, test_bucket, test_key, response)
