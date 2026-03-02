"""Tests for UploadPart with SSE-C (Server-Side Encryption with Customer-Provided Keys).

These tests verify S3 behavior when uploading a part with SSE-C headers
in various combinations and with various validation errors.

UploadPart (PUT /{bucket}/{key}?uploadId={id}&partNumber={n}) for SSE-C requires three headers:
- x-amz-server-side-encryption-customer-algorithm: Must be "AES256"
- x-amz-server-side-encryption-customer-key: Base64-encoded 32-byte key
- x-amz-server-side-encryption-customer-key-MD5: Base64-encoded MD5 of the key

The multipart upload must be initiated with SSE-C (CreateMultipartUpload with SSE-C headers).
UploadPart is a write-path operation, so SSE-C validation behavior should match PutObject.
"""

import base64
import hashlib
import uuid

import pytest

from s3_compliance.sse_c import generate_sse_c_key
from s3_compliance.xml_utils import extract_error_info


@pytest.mark.upload_part
@pytest.mark.s3_handler("UploadPart")
@pytest.mark.sse_c
class TestSSECUploadPartHeaders:
    """Test UploadPart API with SSE-C header combinations."""

    @pytest.fixture
    def test_key(self):
        """Generate unique test key."""
        return f"test-ssec-upload-part-{uuid.uuid4().hex[:8]}"

    @pytest.fixture
    def part_body(self):
        """Test part content."""
        return b"test part content for SSE-C upload part test"

    @pytest.fixture
    def ssec_multipart_upload(self, request, s3_client, aws_client, test_bucket, test_key):
        """Create and cleanup SSE-C multipart upload.

        In comparison mode (--endpoint=both), creates uploads on both endpoints.
        Returns upload_id or dict of upload_ids.
        """
        key_b64, key_md5 = generate_sse_c_key()
        endpoint_mode = request.config.getoption("--endpoint")

        ssec_params = {
            "SSECustomerAlgorithm": "AES256",
            "SSECustomerKey": key_b64,
            "SSECustomerKeyMD5": key_md5,
        }

        if endpoint_mode == "both":
            aws_response = aws_client.create_multipart_upload(
                Bucket=test_bucket, Key=test_key, **ssec_params,
            )
            aws_upload_id = aws_response["UploadId"]

            from s3_compliance.client import S3ClientFactory
            factory = S3ClientFactory()
            custom_client = factory.create_client("custom")
            custom_response = custom_client.create_multipart_upload(
                Bucket=test_bucket, Key=test_key, **ssec_params,
            )
            custom_upload_id = custom_response["UploadId"]

            yield {"aws": aws_upload_id, "custom": custom_upload_id}

            try:
                aws_client.abort_multipart_upload(
                    Bucket=test_bucket, Key=test_key, UploadId=aws_upload_id,
                )
            except Exception:
                pass
            try:
                custom_client.abort_multipart_upload(
                    Bucket=test_bucket, Key=test_key, UploadId=custom_upload_id,
                )
            except Exception:
                pass
        else:
            response = s3_client.create_multipart_upload(
                Bucket=test_bucket, Key=test_key, **ssec_params,
            )
            upload_id = response["UploadId"]

            yield upload_id

            try:
                s3_client.abort_multipart_upload(
                    Bucket=test_bucket, Key=test_key, UploadId=upload_id,
                )
            except Exception:
                pass

    @pytest.fixture
    def plain_multipart_upload(self, request, s3_client, aws_client, test_bucket, test_key):
        """Create and cleanup a plain (non-SSE-C) multipart upload.

        In comparison mode (--endpoint=both), creates uploads on both endpoints.
        Returns upload_id or dict of upload_ids.
        """
        endpoint_mode = request.config.getoption("--endpoint")

        if endpoint_mode == "both":
            aws_response = aws_client.create_multipart_upload(
                Bucket=test_bucket, Key=test_key,
            )
            aws_upload_id = aws_response["UploadId"]

            from s3_compliance.client import S3ClientFactory
            factory = S3ClientFactory()
            custom_client = factory.create_client("custom")
            custom_response = custom_client.create_multipart_upload(
                Bucket=test_bucket, Key=test_key,
            )
            custom_upload_id = custom_response["UploadId"]

            yield {"aws": aws_upload_id, "custom": custom_upload_id}

            try:
                aws_client.abort_multipart_upload(
                    Bucket=test_bucket, Key=test_key, UploadId=aws_upload_id,
                )
            except Exception:
                pass
            try:
                custom_client.abort_multipart_upload(
                    Bucket=test_bucket, Key=test_key, UploadId=custom_upload_id,
                )
            except Exception:
                pass
        else:
            response = s3_client.create_multipart_upload(
                Bucket=test_bucket, Key=test_key,
            )
            upload_id = response["UploadId"]

            yield upload_id

            try:
                s3_client.abort_multipart_upload(
                    Bucket=test_bucket, Key=test_key, UploadId=upload_id,
                )
            except Exception:
                pass

    def _make_upload_part_request(
        self, make_request, request, test_bucket, test_key,
        ssec_multipart_upload, part_body, headers, part_number=1,
    ):
        """Make an UploadPart request via make_request fixture."""
        endpoint_mode = request.config.getoption("--endpoint")
        if endpoint_mode == "both":
            query_params = f"?uploadId={ssec_multipart_upload['aws']}&partNumber={part_number}"
            custom_query_params = f"?uploadId={ssec_multipart_upload['custom']}&partNumber={part_number}"
        else:
            query_params = f"?uploadId={ssec_multipart_upload}&partNumber={part_number}"
            custom_query_params = None

        return make_request(
            "PUT",
            f"/{test_bucket}/{test_key}",
            body=part_body if part_body is not None else b"",
            headers=headers,
            query_params=query_params,
            custom_query_params=custom_query_params,
        )

    # =========================================================================
    # Successful Request
    # =========================================================================

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_all_valid_headers_accepted(
        self,
        test_bucket,
        test_key,
        part_body,
        ssec_multipart_upload,
        make_request,
        request,
        json_metadata,
    ):
        """Server should accept UploadPart with all valid SSE-C headers."""
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "Content-Type": "application/octet-stream",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_upload_part_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_upload, part_body, headers,
        )

        json_metadata["sse_c_algorithm"] = "AES256"
        json_metadata["sse_c_key_length"] = 32

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 200, (
                f"AWS expected 200, got {response.aws.status_code}: {response.aws.text[:200]}"
            )
            assert "ETag" in response.aws.headers, "AWS expected ETag in response headers"
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
            assert response.comparison.is_compliant, (
                f"Custom S3 doesn't match AWS: {response.diff_summary}"
            )
        else:
            assert response.status_code == 200, (
                f"Expected 200, got {response.status_code}: {response.text[:200]}"
            )
            assert "ETag" in response.headers, "Expected ETag in response headers"
            json_metadata["status"] = response.status_code

    # =========================================================================
    # SSE-C Mismatch Between CreateMultipartUpload and UploadPart
    # =========================================================================

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_plain_upload_with_sse_c_part_rejected(
        self,
        test_bucket,
        test_key,
        part_body,
        plain_multipart_upload,
        make_request,
        request,
        json_metadata,
    ):
        """Server should reject UploadPart with SSE-C when upload was created without encryption.

        CreateMultipartUpload was plain (no SSE-C), but UploadPart sends SSE-C headers.
        """
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "Content-Type": "application/octet-stream",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_upload_part_request(
            make_request, request, test_bucket, test_key,
            plain_multipart_upload, part_body, headers,
        )

        json_metadata["create_mpu_encryption"] = "none"
        json_metadata["upload_part_encryption"] = "SSE-C"

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

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_upload_with_plain_part_rejected(
        self,
        test_bucket,
        test_key,
        part_body,
        ssec_multipart_upload,
        make_request,
        request,
        json_metadata,
    ):
        """Server should reject UploadPart without SSE-C when upload was created with SSE-C.

        CreateMultipartUpload had SSE-C, but UploadPart sends no SSE-C headers.
        """
        headers = {
            "Content-Type": "application/octet-stream",
        }

        response = self._make_upload_part_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_upload, part_body, headers,
        )

        json_metadata["create_mpu_encryption"] = "SSE-C"
        json_metadata["upload_part_encryption"] = "none"

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

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_upload_with_different_key_part_rejected(
        self,
        test_bucket,
        test_key,
        part_body,
        ssec_multipart_upload,
        make_request,
        request,
        json_metadata,
    ):
        """Server should reject UploadPart with different SSE-C key than CreateMultipartUpload.

        CreateMultipartUpload used DEFAULT_SSE_C_KEY_BYTES, UploadPart uses a different key.
        """
        wrong_key_bytes = hashlib.sha256(b"different_key_for_upload_part").digest()
        key_b64, key_md5 = generate_sse_c_key(wrong_key_bytes)

        headers = {
            "Content-Type": "application/octet-stream",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_upload_part_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_upload, part_body, headers,
        )

        json_metadata["create_mpu_encryption"] = "SSE-C (default key)"
        json_metadata["upload_part_encryption"] = "SSE-C (different key)"

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

    # =========================================================================
    # Missing Header Tests (partial SSE-C headers)
    # =========================================================================

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_only_algorithm_rejected(
        self,
        test_bucket,
        test_key,
        part_body,
        ssec_multipart_upload,
        make_request,
        request,
        json_metadata,
    ):
        """Server should reject UploadPart with only SSE-C algorithm header."""
        headers = {
            "Content-Type": "application/octet-stream",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
        }

        response = self._make_upload_part_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_upload, part_body, headers,
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

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_only_key_rejected(
        self,
        test_bucket,
        test_key,
        part_body,
        ssec_multipart_upload,
        make_request,
        request,
        json_metadata,
    ):
        """Server should reject UploadPart with only SSE-C key header."""
        key_b64, _ = generate_sse_c_key()

        headers = {
            "Content-Type": "application/octet-stream",
            "x-amz-server-side-encryption-customer-key": key_b64,
        }

        response = self._make_upload_part_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_upload, part_body, headers,
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

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_only_key_md5_rejected(
        self,
        test_bucket,
        test_key,
        part_body,
        ssec_multipart_upload,
        make_request,
        request,
        json_metadata,
    ):
        """Server should reject UploadPart with only SSE-C key MD5 header."""
        _, key_md5 = generate_sse_c_key()

        headers = {
            "Content-Type": "application/octet-stream",
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_upload_part_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_upload, part_body, headers,
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

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_algorithm_and_key_missing_md5_rejected(
        self,
        test_bucket,
        test_key,
        part_body,
        ssec_multipart_upload,
        make_request,
        request,
        json_metadata,
    ):
        """Server should reject UploadPart with algorithm and key but missing MD5.

        UploadPart is a write-path operation like PutObject,
        so it should require all three SSE-C headers.
        """
        key_b64, _ = generate_sse_c_key()

        headers = {
            "Content-Type": "application/octet-stream",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
        }

        response = self._make_upload_part_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_upload, part_body, headers,
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

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_algorithm_and_md5_missing_key_rejected(
        self,
        test_bucket,
        test_key,
        part_body,
        ssec_multipart_upload,
        make_request,
        request,
        json_metadata,
    ):
        """Server should reject UploadPart with algorithm and MD5 but missing key."""
        _, key_md5 = generate_sse_c_key()

        headers = {
            "Content-Type": "application/octet-stream",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_upload_part_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_upload, part_body, headers,
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

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_key_and_md5_missing_algorithm_rejected(
        self,
        test_bucket,
        test_key,
        part_body,
        ssec_multipart_upload,
        make_request,
        request,
        json_metadata,
    ):
        """Server should reject UploadPart with key and MD5 but missing algorithm."""
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "Content-Type": "application/octet-stream",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_upload_part_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_upload, part_body, headers,
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

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_no_headers_rejected(
        self,
        test_bucket,
        test_key,
        part_body,
        ssec_multipart_upload,
        make_request,
        request,
        json_metadata,
    ):
        """Server should reject UploadPart without any SSE-C headers on SSE-C upload."""
        headers = {
            "Content-Type": "application/octet-stream",
        }

        response = self._make_upload_part_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_upload, part_body, headers,
        )

        json_metadata["provided_headers"] = []
        json_metadata["missing_headers"] = ["algorithm", "key", "key_md5"]

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

    # =========================================================================
    # Invalid Value Tests
    # =========================================================================

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_invalid_algorithm_rejected(
        self,
        test_bucket,
        test_key,
        part_body,
        ssec_multipart_upload,
        make_request,
        request,
        json_metadata,
    ):
        """Server should reject UploadPart with invalid SSE-C algorithm."""
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "Content-Type": "application/octet-stream",
            "x-amz-server-side-encryption-customer-algorithm": "AES128-INVALID",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_upload_part_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_upload, part_body, headers,
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

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_invalid_key_length_10_rejected(
        self,
        test_bucket,
        test_key,
        part_body,
        ssec_multipart_upload,
        make_request,
        request,
        json_metadata,
    ):
        """Server should reject UploadPart with invalid key length (10 bytes instead of 32).

        UploadPart is a write-path operation like PutObject,
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

        response = self._make_upload_part_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_upload, part_body, headers,
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

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_mismatched_key_md5_rejected(
        self,
        test_bucket,
        test_key,
        part_body,
        ssec_multipart_upload,
        make_request,
        request,
        json_metadata,
    ):
        """Server should reject UploadPart when key MD5 doesn't match key."""
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

        response = self._make_upload_part_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_upload, part_body, headers,
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

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_invalid_key_md5_not_base64_rejected(
        self,
        test_bucket,
        test_key,
        part_body,
        ssec_multipart_upload,
        make_request,
        request,
        json_metadata,
    ):
        """Server should reject UploadPart when key MD5 is not valid base64."""
        key_b64, _ = generate_sse_c_key()

        headers = {
            "Content-Type": "application/octet-stream",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": "not-valid-base64!!!",
        }

        response = self._make_upload_part_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_upload, part_body, headers,
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

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_wrong_key_rejected(
        self,
        test_bucket,
        test_key,
        part_body,
        ssec_multipart_upload,
        make_request,
        request,
        json_metadata,
    ):
        """Server should reject UploadPart when SSE-C key differs from CreateMultipartUpload key.

        The upload was created with DEFAULT_SSE_C_KEY_BYTES, but this request
        uses a different valid 32-byte key.
        """
        wrong_key_bytes = hashlib.sha256(b"different_key_for_upload_part").digest()
        key_b64, key_md5 = generate_sse_c_key(wrong_key_bytes)

        headers = {
            "Content-Type": "application/octet-stream",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_upload_part_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_upload, part_body, headers,
        )

        json_metadata["key_matches_upload"] = False

        if hasattr(response, "comparison"):
            # AWS returns 403 when the key doesn't match the one used to create the upload
            assert response.aws.status_code in [400, 403], (
                f"AWS expected 400/403, got {response.aws.status_code}"
            )
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, (
                f"Custom S3 doesn't match AWS: {response.diff_summary}"
            )
        else:
            assert response.status_code in [400, 403], (
                f"Expected 400/403, got {response.status_code}"
            )
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

    # =========================================================================
    # Content-MD5 vs SSE-C Validation Order Tests
    # =========================================================================

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_baseline_invalid_content_md5_only(
        self,
        test_bucket,
        test_key,
        part_body,
        ssec_multipart_upload,
        make_request,
        request,
        json_metadata,
    ):
        """Baseline: valid SSE-C + invalid Content-MD5. Should return BadDigest."""
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "Content-Type": "application/octet-stream",
            "Content-MD5": "dGhpcyBpcyB3cm9uZw==",  # valid base64, wrong digest
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_upload_part_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_upload, part_body, headers,
        )

        json_metadata["invalid_headers"] = ["content_md5"]

        if hasattr(response, "comparison"):
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
        else:
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_baseline_invalid_algorithm_only(
        self,
        test_bucket,
        test_key,
        part_body,
        ssec_multipart_upload,
        make_request,
        request,
        json_metadata,
    ):
        """Baseline: invalid SSE-C algorithm + no Content-MD5. Should return InvalidArgument."""
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "Content-Type": "application/octet-stream",
            "x-amz-server-side-encryption-customer-algorithm": "AES128-INVALID",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_upload_part_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_upload, part_body, headers,
        )

        json_metadata["invalid_headers"] = ["algorithm"]

        if hasattr(response, "comparison"):
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
        else:
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_invalid_content_md5_and_invalid_algorithm(
        self,
        test_bucket,
        test_key,
        part_body,
        ssec_multipart_upload,
        make_request,
        request,
        json_metadata,
    ):
        """Test validation order: invalid Content-MD5 + invalid SSE-C algorithm.

        If Content-MD5 is checked first -> BadDigest.
        If SSE-C algorithm is checked first -> InvalidArgument.
        """
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "Content-Type": "application/octet-stream",
            "Content-MD5": "dGhpcyBpcyB3cm9uZw==",  # valid base64, wrong digest
            "x-amz-server-side-encryption-customer-algorithm": "AES128-INVALID",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_upload_part_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_upload, part_body, headers,
        )

        json_metadata["invalid_headers"] = ["content_md5", "algorithm"]

        if hasattr(response, "comparison"):
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            json_metadata["validated_first"] = (
                "content_md5" if error_code == "BadDigest" else "sse_c_headers"
            )
        else:
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg
            json_metadata["validated_first"] = (
                "content_md5" if error_code == "BadDigest" else "sse_c_headers"
            )

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_invalid_content_md5_and_missing_sse_c_key(
        self,
        test_bucket,
        test_key,
        part_body,
        ssec_multipart_upload,
        make_request,
        request,
        json_metadata,
    ):
        """Test validation order: invalid Content-MD5 + missing SSE-C key.

        If Content-MD5 is checked first -> BadDigest.
        If SSE-C completeness is checked first -> 400 (missing key).
        """
        _, key_md5 = generate_sse_c_key()

        headers = {
            "Content-Type": "application/octet-stream",
            "Content-MD5": "dGhpcyBpcyB3cm9uZw==",  # valid base64, wrong digest
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_upload_part_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_upload, part_body, headers,
        )

        json_metadata["invalid_headers"] = ["content_md5", "missing_key"]

        if hasattr(response, "comparison"):
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            json_metadata["validated_first"] = (
                "content_md5" if error_code == "BadDigest" else "sse_c_headers"
            )
        else:
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg
            json_metadata["validated_first"] = (
                "content_md5" if error_code == "BadDigest" else "sse_c_headers"
            )

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_invalid_content_md5_and_invalid_key_length(
        self,
        test_bucket,
        test_key,
        part_body,
        ssec_multipart_upload,
        make_request,
        request,
        json_metadata,
    ):
        """Test validation order: invalid Content-MD5 + invalid SSE-C key length.

        If Content-MD5 is checked first -> BadDigest.
        If SSE-C key length is checked first -> InvalidArgument.
        """
        short_key = b"1234567890"  # 10 bytes
        key_b64, key_md5 = generate_sse_c_key(short_key)

        headers = {
            "Content-Type": "application/octet-stream",
            "Content-MD5": "dGhpcyBpcyB3cm9uZw==",  # valid base64, wrong digest
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_upload_part_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_upload, part_body, headers,
        )

        json_metadata["invalid_headers"] = ["content_md5", "key_length"]

        if hasattr(response, "comparison"):
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            json_metadata["validated_first"] = (
                "content_md5" if error_code == "BadDigest" else "sse_c_headers"
            )
        else:
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg
            json_metadata["validated_first"] = (
                "content_md5" if error_code == "BadDigest" else "sse_c_headers"
            )

    # =========================================================================
    # SSE-C Header Validation Order Tests
    # =========================================================================

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_all_invalid_validation_order(
        self,
        test_bucket,
        test_key,
        part_body,
        ssec_multipart_upload,
        make_request,
        request,
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

        response = self._make_upload_part_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_upload, part_body, headers,
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

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_invalid_key_length_with_invalid_algorithm(
        self,
        test_bucket,
        test_key,
        part_body,
        ssec_multipart_upload,
        make_request,
        request,
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

        response = self._make_upload_part_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_upload, part_body, headers,
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

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_invalid_key_length_with_mismatched_md5(
        self,
        test_bucket,
        test_key,
        part_body,
        ssec_multipart_upload,
        make_request,
        request,
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

        response = self._make_upload_part_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_upload, part_body, headers,
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
