"""Tests for CompleteMultipartUpload with SSE-C (Server-Side Encryption with Customer-Provided Keys).

These tests verify S3 behavior when completing a multipart upload with SSE-C headers
in various combinations. According to AWS docs, x-amz-server-side-encryption-customer-algorithm
is "required only when the object was created using a checksum algorithm or if your bucket
policy requires the use of SSE-C".

CompleteMultipartUpload (POST /{bucket}/{key}?uploadId={id}) accepts a request body:
<CompleteMultipartUpload>
  <Part>
    <PartNumber>{n}</PartNumber>
    <ETag>{etag}</ETag>
  </Part>
</CompleteMultipartUpload>

Tests also check validation order: SSE-C headers vs request body errors
(e.g. negative part number, invalid ETag).
"""

import base64
import hashlib
import uuid

import pytest

from s3_compliance.sse_c import generate_sse_c_key
from s3_compliance.xml_utils import extract_error_info

# Minimum part size for UploadPart (5 MB) — use smaller for tests, AWS allows small last part
PART_BODY = b"A" * 1024  # 1 KB — fine for single-part multipart upload


def build_complete_xml(parts: list[tuple[int, str]]) -> str:
    """Build CompleteMultipartUpload XML body.

    Args:
        parts: list of (part_number, etag) tuples.
    """
    parts_xml = "\n".join(
        f"    <Part>\n"
        f"        <PartNumber>{num}</PartNumber>\n"
        f"        <ETag>{etag}</ETag>\n"
        f"    </Part>"
        for num, etag in parts
    )
    return (
        "<CompleteMultipartUpload>\n"
        f"{parts_xml}\n"
        "</CompleteMultipartUpload>"
    )


@pytest.mark.s3_handler("CompleteMultipartUpload")
@pytest.mark.sse_c
class TestSSECCompleteMultipartUploadHeaders:
    """Test CompleteMultipartUpload API with SSE-C header combinations."""

    @pytest.fixture
    def test_key(self):
        """Generate unique test key."""
        return f"test-ssec-complete-mpu-{uuid.uuid4().hex[:8]}"

    @pytest.fixture
    def ssec_multipart_with_part(self, request, s3_client, aws_client, test_bucket, test_key):
        """Create SSE-C multipart upload with one uploaded part.

        Returns dict with upload_id and etag (or dicts of them in both mode).
        Cleanup aborts the upload if not completed, or deletes the object if completed.
        """
        key_b64, key_md5 = generate_sse_c_key()
        endpoint_mode = request.config.getoption("--endpoint")

        ssec_params = {
            "SSECustomerAlgorithm": "AES256",
            "SSECustomerKey": key_b64,
            "SSECustomerKeyMD5": key_md5,
        }

        if endpoint_mode == "both":
            from s3_compliance.client import S3ClientFactory

            # AWS
            aws_mpu = aws_client.create_multipart_upload(
                Bucket=test_bucket, Key=test_key, **ssec_params,
            )
            aws_upload_id = aws_mpu["UploadId"]
            aws_part = aws_client.upload_part(
                Bucket=test_bucket, Key=test_key,
                UploadId=aws_upload_id, PartNumber=1,
                Body=PART_BODY, **ssec_params,
            )
            aws_etag = aws_part["ETag"]

            # Custom
            factory = S3ClientFactory()
            custom_client = factory.create_client("custom")
            custom_mpu = custom_client.create_multipart_upload(
                Bucket=test_bucket, Key=test_key, **ssec_params,
            )
            custom_upload_id = custom_mpu["UploadId"]
            custom_part = custom_client.upload_part(
                Bucket=test_bucket, Key=test_key,
                UploadId=custom_upload_id, PartNumber=1,
                Body=PART_BODY, **ssec_params,
            )
            custom_etag = custom_part["ETag"]

            yield {
                "aws": {"upload_id": aws_upload_id, "etag": aws_etag},
                "custom": {"upload_id": custom_upload_id, "etag": custom_etag},
            }

            for client, uid in [(aws_client, aws_upload_id), (custom_client, custom_upload_id)]:
                try:
                    client.abort_multipart_upload(
                        Bucket=test_bucket, Key=test_key, UploadId=uid,
                    )
                except Exception:
                    pass
                try:
                    client.delete_object(Bucket=test_bucket, Key=test_key)
                except Exception:
                    pass
        else:
            mpu = s3_client.create_multipart_upload(
                Bucket=test_bucket, Key=test_key, **ssec_params,
            )
            upload_id = mpu["UploadId"]
            part = s3_client.upload_part(
                Bucket=test_bucket, Key=test_key,
                UploadId=upload_id, PartNumber=1,
                Body=PART_BODY, **ssec_params,
            )
            etag = part["ETag"]

            yield {"upload_id": upload_id, "etag": etag}

            try:
                s3_client.abort_multipart_upload(
                    Bucket=test_bucket, Key=test_key, UploadId=upload_id,
                )
            except Exception:
                pass
            try:
                s3_client.delete_object(Bucket=test_bucket, Key=test_key)
            except Exception:
                pass

    @pytest.fixture
    def plain_multipart_with_part(self, request, s3_client, aws_client, test_bucket, test_key):
        """Create plain (non-SSE-C) multipart upload with one uploaded part.

        Returns dict with upload_id and etag (or dicts of them in both mode).
        """
        endpoint_mode = request.config.getoption("--endpoint")

        if endpoint_mode == "both":
            from s3_compliance.client import S3ClientFactory

            aws_mpu = aws_client.create_multipart_upload(
                Bucket=test_bucket, Key=test_key,
            )
            aws_upload_id = aws_mpu["UploadId"]
            aws_part = aws_client.upload_part(
                Bucket=test_bucket, Key=test_key,
                UploadId=aws_upload_id, PartNumber=1,
                Body=PART_BODY,
            )
            aws_etag = aws_part["ETag"]

            factory = S3ClientFactory()
            custom_client = factory.create_client("custom")
            custom_mpu = custom_client.create_multipart_upload(
                Bucket=test_bucket, Key=test_key,
            )
            custom_upload_id = custom_mpu["UploadId"]
            custom_part = custom_client.upload_part(
                Bucket=test_bucket, Key=test_key,
                UploadId=custom_upload_id, PartNumber=1,
                Body=PART_BODY,
            )
            custom_etag = custom_part["ETag"]

            yield {
                "aws": {"upload_id": aws_upload_id, "etag": aws_etag},
                "custom": {"upload_id": custom_upload_id, "etag": custom_etag},
            }

            for client, uid in [(aws_client, aws_upload_id), (custom_client, custom_upload_id)]:
                try:
                    client.abort_multipart_upload(
                        Bucket=test_bucket, Key=test_key, UploadId=uid,
                    )
                except Exception:
                    pass
                try:
                    client.delete_object(Bucket=test_bucket, Key=test_key)
                except Exception:
                    pass
        else:
            mpu = s3_client.create_multipart_upload(
                Bucket=test_bucket, Key=test_key,
            )
            upload_id = mpu["UploadId"]
            part = s3_client.upload_part(
                Bucket=test_bucket, Key=test_key,
                UploadId=upload_id, PartNumber=1,
                Body=PART_BODY,
            )
            etag = part["ETag"]

            yield {"upload_id": upload_id, "etag": etag}

            try:
                s3_client.abort_multipart_upload(
                    Bucket=test_bucket, Key=test_key, UploadId=upload_id,
                )
            except Exception:
                pass
            try:
                s3_client.delete_object(Bucket=test_bucket, Key=test_key)
            except Exception:
                pass

    def _make_complete_request(
        self, make_request, request, test_bucket, test_key,
        multipart_data, xml_body, headers, custom_xml_body=None,
    ):
        """Make a CompleteMultipartUpload request via make_request fixture.

        Args:
            custom_xml_body: Optional separate XML body for custom endpoint in 'both' mode.
                           When provided, aws gets xml_body and custom gets custom_xml_body.
        """
        endpoint_mode = request.config.getoption("--endpoint")

        body = xml_body.encode("utf-8") if isinstance(xml_body, str) else xml_body
        custom_body = None
        custom_query_params = None

        if endpoint_mode == "both":
            query_params = f"?uploadId={multipart_data['aws']['upload_id']}"
            custom_query_params = f"?uploadId={multipart_data['custom']['upload_id']}"
            if custom_xml_body is not None:
                custom_body = custom_xml_body.encode("utf-8") if isinstance(custom_xml_body, str) else custom_xml_body
        else:
            query_params = f"?uploadId={multipart_data['upload_id']}"

        return make_request(
            "POST",
            f"/{test_bucket}/{test_key}",
            body=body,
            headers=headers,
            query_params=query_params,
            custom_body=custom_body,
            custom_query_params=custom_query_params,
        )

    # =========================================================================
    # Successful Requests
    # =========================================================================

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_complete_ssec_upload_with_valid_sse_c_headers(
        self,
        test_bucket,
        test_key,
        ssec_multipart_with_part,
        make_request,
        request,
        json_metadata,
    ):
        """Server should accept CompleteMultipartUpload with valid SSE-C headers on SSE-C upload."""
        key_b64, key_md5 = generate_sse_c_key()

        endpoint_mode = request.config.getoption("--endpoint")
        if endpoint_mode == "both":
            xml_body = build_complete_xml([(1, ssec_multipart_with_part["aws"]["etag"])])
            custom_xml_body = build_complete_xml([(1, ssec_multipart_with_part["custom"]["etag"])])
        else:
            xml_body = build_complete_xml([(1, ssec_multipart_with_part["etag"])])
            custom_xml_body = None

        headers = {
            "Content-Type": "application/xml",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_complete_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_with_part, xml_body, headers, custom_xml_body,
        )

        json_metadata["sse_c_algorithm"] = "AES256"
        json_metadata["sse_c_key_length"] = 32

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 200, (
                f"AWS expected 200, got {response.aws.status_code}: {response.aws.text[:200]}"
            )
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
            assert response.comparison.is_compliant, (
                f"Custom S3 doesn't match AWS: {response.diff_summary}"
            )
        else:
            assert response.status_code == 200, (
                f"Expected 200, got {response.status_code}: {response.text[:200]}"
            )
            json_metadata["status"] = response.status_code

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_complete_ssec_upload_without_sse_c_headers(
        self,
        test_bucket,
        test_key,
        ssec_multipart_with_part,
        make_request,
        request,
        json_metadata,
    ):
        """Test CompleteMultipartUpload without SSE-C headers on SSE-C upload.

        According to AWS docs, SSE-C algorithm is "required only when the object was
        created using a checksum algorithm or if your bucket policy requires the use
        of SSE-C". This test checks what actually happens.
        """
        endpoint_mode = request.config.getoption("--endpoint")
        if endpoint_mode == "both":
            xml_body = build_complete_xml([(1, ssec_multipart_with_part["aws"]["etag"])])
            custom_xml_body = build_complete_xml([(1, ssec_multipart_with_part["custom"]["etag"])])
        else:
            xml_body = build_complete_xml([(1, ssec_multipart_with_part["etag"])])
            custom_xml_body = None

        headers = {
            "Content-Type": "application/xml",
        }

        response = self._make_complete_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_with_part, xml_body, headers, custom_xml_body,
        )

        json_metadata["create_mpu_encryption"] = "SSE-C"
        json_metadata["complete_encryption"] = "none"

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 200, (
                f"AWS expected 200, got {response.aws.status_code}: {response.aws.text[:200]}"
            )
            json_metadata["aws_status"] = response.aws.status_code
        else:
            assert response.status_code == 200, (
                f"Expected 200, got {response.status_code}: {response.text[:200]}"
            )
            json_metadata["status"] = response.status_code

    # =========================================================================
    # SSE-C Mismatch Between CreateMultipartUpload and Complete
    # =========================================================================

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_complete_plain_upload_with_sse_c_headers(
        self,
        test_bucket,
        test_key,
        plain_multipart_with_part,
        make_request,
        request,
        json_metadata,
    ):
        """Server behavior when completing a plain upload with SSE-C headers.

        CreateMultipartUpload was plain (no SSE-C), but CompleteMultipartUpload sends SSE-C headers.
        """
        key_b64, key_md5 = generate_sse_c_key()

        endpoint_mode = request.config.getoption("--endpoint")
        if endpoint_mode == "both":
            xml_body = build_complete_xml([(1, plain_multipart_with_part["aws"]["etag"])])
            custom_xml_body = build_complete_xml([(1, plain_multipart_with_part["custom"]["etag"])])
        else:
            xml_body = build_complete_xml([(1, plain_multipart_with_part["etag"])])
            custom_xml_body = None

        headers = {
            "Content-Type": "application/xml",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_complete_request(
            make_request, request, test_bucket, test_key,
            plain_multipart_with_part, xml_body, headers, custom_xml_body,
        )

        json_metadata["create_mpu_encryption"] = "none"
        json_metadata["complete_encryption"] = "SSE-C"

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400, (
                f"AWS expected 400, got {response.aws.status_code}: {response.aws.text[:200]}"
            )
            error_code, error_msg = extract_error_info(response.aws.text)
            assert error_code == "InvalidRequest", f"Expected InvalidRequest, got {error_code}"
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
        else:
            assert response.status_code == 400, (
                f"Expected 400, got {response.status_code}: {response.text[:200]}"
            )
            error_code, error_msg = extract_error_info(response.text)
            assert error_code == "InvalidRequest", f"Expected InvalidRequest, got {error_code}"
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_complete_ssec_upload_with_wrong_key(
        self,
        test_bucket,
        test_key,
        ssec_multipart_with_part,
        make_request,
        request,
        json_metadata,
    ):
        """Server behavior when completing SSE-C upload with a different customer key."""
        wrong_key_bytes = hashlib.sha256(b"different_key_for_complete").digest()
        key_b64, key_md5 = generate_sse_c_key(wrong_key_bytes)

        endpoint_mode = request.config.getoption("--endpoint")
        if endpoint_mode == "both":
            xml_body = build_complete_xml([(1, ssec_multipart_with_part["aws"]["etag"])])
            custom_xml_body = build_complete_xml([(1, ssec_multipart_with_part["custom"]["etag"])])
        else:
            xml_body = build_complete_xml([(1, ssec_multipart_with_part["etag"])])
            custom_xml_body = None

        headers = {
            "Content-Type": "application/xml",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_complete_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_with_part, xml_body, headers, custom_xml_body,
        )

        json_metadata["create_mpu_encryption"] = "SSE-C (default key)"
        json_metadata["complete_encryption"] = "SSE-C (different key)"

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400, (
                f"AWS expected 400, got {response.aws.status_code}: {response.aws.text[:200]}"
            )
            error_code, error_msg = extract_error_info(response.aws.text)
            assert error_code == "InvalidRequest", f"Expected InvalidRequest, got {error_code}"
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
        else:
            assert response.status_code == 400, (
                f"Expected 400, got {response.status_code}: {response.text[:200]}"
            )
            error_code, error_msg = extract_error_info(response.text)
            assert error_code == "InvalidRequest", f"Expected InvalidRequest, got {error_code}"
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_complete_ssec_upload_with_invalid_algorithm(
        self,
        test_bucket,
        test_key,
        ssec_multipart_with_part,
        make_request,
        request,
        json_metadata,
    ):
        """Server should reject CompleteMultipartUpload with invalid SSE-C algorithm."""
        key_b64, key_md5 = generate_sse_c_key()

        endpoint_mode = request.config.getoption("--endpoint")
        if endpoint_mode == "both":
            xml_body = build_complete_xml([(1, ssec_multipart_with_part["aws"]["etag"])])
            custom_xml_body = build_complete_xml([(1, ssec_multipart_with_part["custom"]["etag"])])
        else:
            xml_body = build_complete_xml([(1, ssec_multipart_with_part["etag"])])
            custom_xml_body = None

        headers = {
            "Content-Type": "application/xml",
            "x-amz-server-side-encryption-customer-algorithm": "AES128-INVALID",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_complete_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_with_part, xml_body, headers, custom_xml_body,
        )

        json_metadata["invalid_algorithm"] = "AES128-INVALID"

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400, (
                f"AWS expected 400, got {response.aws.status_code}"
            )
            error_code, error_msg = extract_error_info(response.aws.text)
            assert error_code == "InvalidEncryptionAlgorithmError", (
                f"Expected InvalidEncryptionAlgorithmError, got {error_code}"
            )
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
        else:
            assert response.status_code == 400, (
                f"Expected 400, got {response.status_code}"
            )
            error_code, error_msg = extract_error_info(response.text)
            assert error_code == "InvalidEncryptionAlgorithmError", (
                f"Expected InvalidEncryptionAlgorithmError, got {error_code}"
            )
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

    # =========================================================================
    # Invalid SSE-C Headers
    # =========================================================================

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_only_algorithm(
        self,
        test_bucket,
        test_key,
        ssec_multipart_with_part,
        make_request,
        request,
        json_metadata,
    ):
        """Server behavior with only SSE-C algorithm header (missing key and MD5)."""
        endpoint_mode = request.config.getoption("--endpoint")
        if endpoint_mode == "both":
            xml_body = build_complete_xml([(1, ssec_multipart_with_part["aws"]["etag"])])
            custom_xml_body = build_complete_xml([(1, ssec_multipart_with_part["custom"]["etag"])])
        else:
            xml_body = build_complete_xml([(1, ssec_multipart_with_part["etag"])])
            custom_xml_body = None

        headers = {
            "Content-Type": "application/xml",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
        }

        response = self._make_complete_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_with_part, xml_body, headers, custom_xml_body,
        )

        json_metadata["provided_headers"] = ["algorithm"]
        json_metadata["missing_headers"] = ["key", "key_md5"]

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 200, (
                f"AWS expected 200, got {response.aws.status_code}: {response.aws.text[:200]}"
            )
            json_metadata["aws_status"] = response.aws.status_code
        else:
            assert response.status_code == 200, (
                f"Expected 200, got {response.status_code}: {response.text[:200]}"
            )
            json_metadata["status"] = response.status_code

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_only_invalid_algorithm(
        self,
        test_bucket,
        test_key,
        ssec_multipart_with_part,
        make_request,
        request,
        json_metadata,
    ):
        """Server behavior with only invalid SSE-C algorithm header (missing key and MD5).

        Contrast with test_sse_c_only_algorithm (valid AES256 → 200) and
        test_complete_ssec_upload_with_invalid_algorithm (invalid algo + valid key+md5 → 400).
        Does AWS validate the algorithm when it's the only SSE-C header?
        """
        endpoint_mode = request.config.getoption("--endpoint")
        if endpoint_mode == "both":
            xml_body = build_complete_xml([(1, ssec_multipart_with_part["aws"]["etag"])])
            custom_xml_body = build_complete_xml([(1, ssec_multipart_with_part["custom"]["etag"])])
        else:
            xml_body = build_complete_xml([(1, ssec_multipart_with_part["etag"])])
            custom_xml_body = None

        headers = {
            "Content-Type": "application/xml",
            "x-amz-server-side-encryption-customer-algorithm": "AES128-INVALID",
        }

        response = self._make_complete_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_with_part, xml_body, headers, custom_xml_body,
        )

        json_metadata["provided_headers"] = ["algorithm"]
        json_metadata["algorithm_value"] = "AES128-INVALID"
        json_metadata["missing_headers"] = ["key", "key_md5"]

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 200, (
                f"AWS expected 200, got {response.aws.status_code}: {response.aws.text[:200]}"
            )
            json_metadata["aws_status"] = response.aws.status_code
        else:
            assert response.status_code == 200, (
                f"Expected 200, got {response.status_code}: {response.text[:200]}"
            )
            json_metadata["status"] = response.status_code

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_only_key(
        self,
        test_bucket,
        test_key,
        ssec_multipart_with_part,
        make_request,
        request,
        json_metadata,
    ):
        """Server behavior with only SSE-C key header (missing algorithm and MD5)."""
        key_b64, _ = generate_sse_c_key()

        endpoint_mode = request.config.getoption("--endpoint")
        if endpoint_mode == "both":
            xml_body = build_complete_xml([(1, ssec_multipart_with_part["aws"]["etag"])])
            custom_xml_body = build_complete_xml([(1, ssec_multipart_with_part["custom"]["etag"])])
        else:
            xml_body = build_complete_xml([(1, ssec_multipart_with_part["etag"])])
            custom_xml_body = None

        headers = {
            "Content-Type": "application/xml",
            "x-amz-server-side-encryption-customer-key": key_b64,
        }

        response = self._make_complete_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_with_part, xml_body, headers, custom_xml_body,
        )

        json_metadata["provided_headers"] = ["key"]
        json_metadata["missing_headers"] = ["algorithm", "key_md5"]

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 200, (
                f"AWS expected 200, got {response.aws.status_code}: {response.aws.text[:200]}"
            )
            json_metadata["aws_status"] = response.aws.status_code
        else:
            assert response.status_code == 200, (
                f"Expected 200, got {response.status_code}: {response.text[:200]}"
            )
            json_metadata["status"] = response.status_code

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_only_key_md5(
        self,
        test_bucket,
        test_key,
        ssec_multipart_with_part,
        make_request,
        request,
        json_metadata,
    ):
        """Server behavior with only SSE-C key MD5 header (missing algorithm and key)."""
        _, key_md5 = generate_sse_c_key()

        endpoint_mode = request.config.getoption("--endpoint")
        if endpoint_mode == "both":
            xml_body = build_complete_xml([(1, ssec_multipart_with_part["aws"]["etag"])])
            custom_xml_body = build_complete_xml([(1, ssec_multipart_with_part["custom"]["etag"])])
        else:
            xml_body = build_complete_xml([(1, ssec_multipart_with_part["etag"])])
            custom_xml_body = None

        headers = {
            "Content-Type": "application/xml",
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_complete_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_with_part, xml_body, headers, custom_xml_body,
        )

        json_metadata["provided_headers"] = ["key_md5"]
        json_metadata["missing_headers"] = ["algorithm", "key"]

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 200, (
                f"AWS expected 200, got {response.aws.status_code}: {response.aws.text[:200]}"
            )
            json_metadata["aws_status"] = response.aws.status_code
        else:
            assert response.status_code == 200, (
                f"Expected 200, got {response.status_code}: {response.text[:200]}"
            )
            json_metadata["status"] = response.status_code

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_algorithm_and_key(
        self,
        test_bucket,
        test_key,
        ssec_multipart_with_part,
        make_request,
        request,
        json_metadata,
    ):
        """Server behavior with algorithm + key but missing MD5."""
        key_b64, _ = generate_sse_c_key()

        endpoint_mode = request.config.getoption("--endpoint")
        if endpoint_mode == "both":
            xml_body = build_complete_xml([(1, ssec_multipart_with_part["aws"]["etag"])])
            custom_xml_body = build_complete_xml([(1, ssec_multipart_with_part["custom"]["etag"])])
        else:
            xml_body = build_complete_xml([(1, ssec_multipart_with_part["etag"])])
            custom_xml_body = None

        headers = {
            "Content-Type": "application/xml",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
        }

        response = self._make_complete_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_with_part, xml_body, headers, custom_xml_body,
        )

        json_metadata["provided_headers"] = ["algorithm", "key"]
        json_metadata["missing_headers"] = ["key_md5"]

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 200, (
                f"AWS expected 200, got {response.aws.status_code}: {response.aws.text[:200]}"
            )
            json_metadata["aws_status"] = response.aws.status_code
        else:
            assert response.status_code == 200, (
                f"Expected 200, got {response.status_code}: {response.text[:200]}"
            )
            json_metadata["status"] = response.status_code

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_algorithm_and_key_md5(
        self,
        test_bucket,
        test_key,
        ssec_multipart_with_part,
        make_request,
        request,
        json_metadata,
    ):
        """Server behavior with algorithm + key MD5 but missing key."""
        _, key_md5 = generate_sse_c_key()

        endpoint_mode = request.config.getoption("--endpoint")
        if endpoint_mode == "both":
            xml_body = build_complete_xml([(1, ssec_multipart_with_part["aws"]["etag"])])
            custom_xml_body = build_complete_xml([(1, ssec_multipart_with_part["custom"]["etag"])])
        else:
            xml_body = build_complete_xml([(1, ssec_multipart_with_part["etag"])])
            custom_xml_body = None

        headers = {
            "Content-Type": "application/xml",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_complete_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_with_part, xml_body, headers, custom_xml_body,
        )

        json_metadata["provided_headers"] = ["algorithm", "key_md5"]
        json_metadata["missing_headers"] = ["key"]

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 200, (
                f"AWS expected 200, got {response.aws.status_code}: {response.aws.text[:200]}"
            )
            json_metadata["aws_status"] = response.aws.status_code
        else:
            assert response.status_code == 200, (
                f"Expected 200, got {response.status_code}: {response.text[:200]}"
            )
            json_metadata["status"] = response.status_code

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_key_and_key_md5(
        self,
        test_bucket,
        test_key,
        ssec_multipart_with_part,
        make_request,
        request,
        json_metadata,
    ):
        """Server behavior with key + key MD5 but missing algorithm."""
        key_b64, key_md5 = generate_sse_c_key()

        endpoint_mode = request.config.getoption("--endpoint")
        if endpoint_mode == "both":
            xml_body = build_complete_xml([(1, ssec_multipart_with_part["aws"]["etag"])])
            custom_xml_body = build_complete_xml([(1, ssec_multipart_with_part["custom"]["etag"])])
        else:
            xml_body = build_complete_xml([(1, ssec_multipart_with_part["etag"])])
            custom_xml_body = None

        headers = {
            "Content-Type": "application/xml",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_complete_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_with_part, xml_body, headers, custom_xml_body,
        )

        json_metadata["provided_headers"] = ["key", "key_md5"]
        json_metadata["missing_headers"] = ["algorithm"]

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 200, (
                f"AWS expected 200, got {response.aws.status_code}: {response.aws.text[:200]}"
            )
            json_metadata["aws_status"] = response.aws.status_code
        else:
            assert response.status_code == 200, (
                f"Expected 200, got {response.status_code}: {response.text[:200]}"
            )
            json_metadata["status"] = response.status_code

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_invalid_key_length(
        self,
        test_bucket,
        test_key,
        ssec_multipart_with_part,
        make_request,
        request,
        json_metadata,
    ):
        """Server should reject CompleteMultipartUpload with invalid key length (10 bytes)."""
        short_key = b"1234567890"  # 10 bytes
        key_b64, key_md5 = generate_sse_c_key(short_key)

        endpoint_mode = request.config.getoption("--endpoint")
        if endpoint_mode == "both":
            xml_body = build_complete_xml([(1, ssec_multipart_with_part["aws"]["etag"])])
            custom_xml_body = build_complete_xml([(1, ssec_multipart_with_part["custom"]["etag"])])
        else:
            xml_body = build_complete_xml([(1, ssec_multipart_with_part["etag"])])
            custom_xml_body = None

        headers = {
            "Content-Type": "application/xml",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_complete_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_with_part, xml_body, headers, custom_xml_body,
        )

        json_metadata["key_length_bytes"] = 10
        json_metadata["expected_key_length"] = 32

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400, (
                f"AWS expected 400, got {response.aws.status_code}: {response.aws.text[:200]}"
            )
            error_code, error_msg = extract_error_info(response.aws.text)
            assert error_code == "InvalidRequest", f"Expected InvalidRequest, got {error_code}"
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
        else:
            assert response.status_code == 400, (
                f"Expected 400, got {response.status_code}: {response.text[:200]}"
            )
            error_code, error_msg = extract_error_info(response.text)
            assert error_code == "InvalidRequest", f"Expected InvalidRequest, got {error_code}"
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_mismatched_key_md5(
        self,
        test_bucket,
        test_key,
        ssec_multipart_with_part,
        make_request,
        request,
        json_metadata,
    ):
        """Server should reject CompleteMultipartUpload when key MD5 doesn't match key."""
        key_b64, _ = generate_sse_c_key()
        wrong_key_md5 = base64.b64encode(
            hashlib.md5(b"wrong-key-for-md5-mismatch").digest()
        ).decode("utf-8")

        endpoint_mode = request.config.getoption("--endpoint")
        if endpoint_mode == "both":
            xml_body = build_complete_xml([(1, ssec_multipart_with_part["aws"]["etag"])])
            custom_xml_body = build_complete_xml([(1, ssec_multipart_with_part["custom"]["etag"])])
        else:
            xml_body = build_complete_xml([(1, ssec_multipart_with_part["etag"])])
            custom_xml_body = None

        headers = {
            "Content-Type": "application/xml",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": wrong_key_md5,
        }

        response = self._make_complete_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_with_part, xml_body, headers, custom_xml_body,
        )

        json_metadata["key_md5_matches_key"] = False

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400, (
                f"AWS expected 400, got {response.aws.status_code}: {response.aws.text[:200]}"
            )
            error_code, error_msg = extract_error_info(response.aws.text)
            assert error_code == "InvalidArgument", f"Expected InvalidArgument, got {error_code}"
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
        else:
            assert response.status_code == 400, (
                f"Expected 400, got {response.status_code}: {response.text[:200]}"
            )
            error_code, error_msg = extract_error_info(response.text)
            assert error_code == "InvalidArgument", f"Expected InvalidArgument, got {error_code}"
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

    # =========================================================================
    # Validation Order: SSE-C Headers vs Request Body
    # =========================================================================

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_invalid_algorithm_and_negative_part_number(
        self,
        test_bucket,
        test_key,
        ssec_multipart_with_part,
        make_request,
        request,
        json_metadata,
    ):
        """Test validation order: invalid SSE-C algorithm vs negative part number.

        If SSE-C is checked first -> InvalidEncryptionAlgorithmError.
        If body is checked first -> InvalidPart / MalformedXML.
        """
        key_b64, key_md5 = generate_sse_c_key()

        xml_body = build_complete_xml([(-1, '"fake-etag"')])

        headers = {
            "Content-Type": "application/xml",
            "x-amz-server-side-encryption-customer-algorithm": "AES128-INVALID",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_complete_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_with_part, xml_body, headers,
        )

        json_metadata["invalid_algorithm"] = "AES128-INVALID"
        json_metadata["part_number"] = -1
        json_metadata["validated_first"] = "request_body"

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400, (
                f"AWS expected 400, got {response.aws.status_code}: {response.aws.text[:200]}"
            )
            error_code, error_msg = extract_error_info(response.aws.text)
            assert error_code == "InvalidArgument", f"Expected InvalidArgument, got {error_code}"
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
        else:
            assert response.status_code == 400, (
                f"Expected 400, got {response.status_code}: {response.text[:200]}"
            )
            error_code, error_msg = extract_error_info(response.text)
            assert error_code == "InvalidArgument", f"Expected InvalidArgument, got {error_code}"
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_invalid_algorithm_and_zero_part_number(
        self,
        test_bucket,
        test_key,
        ssec_multipart_with_part,
        make_request,
        request,
        json_metadata,
    ):
        """Test validation order: invalid SSE-C algorithm vs zero part number."""
        key_b64, key_md5 = generate_sse_c_key()

        xml_body = build_complete_xml([(0, '"fake-etag"')])

        headers = {
            "Content-Type": "application/xml",
            "x-amz-server-side-encryption-customer-algorithm": "AES128-INVALID",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_complete_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_with_part, xml_body, headers,
        )

        json_metadata["invalid_algorithm"] = "AES128-INVALID"
        json_metadata["part_number"] = 0
        json_metadata["validated_first"] = "request_body"

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400, (
                f"AWS expected 400, got {response.aws.status_code}: {response.aws.text[:200]}"
            )
            error_code, error_msg = extract_error_info(response.aws.text)
            assert error_code == "InvalidArgument", f"Expected InvalidArgument, got {error_code}"
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
        else:
            assert response.status_code == 400, (
                f"Expected 400, got {response.status_code}: {response.text[:200]}"
            )
            error_code, error_msg = extract_error_info(response.text)
            assert error_code == "InvalidArgument", f"Expected InvalidArgument, got {error_code}"
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_invalid_key_length_and_negative_part_number(
        self,
        test_bucket,
        test_key,
        ssec_multipart_with_part,
        make_request,
        request,
        json_metadata,
    ):
        """Test validation order: invalid SSE-C key length vs negative part number."""
        short_key = b"1234567890"  # 10 bytes
        key_b64, key_md5 = generate_sse_c_key(short_key)

        xml_body = build_complete_xml([(-1, '"fake-etag"')])

        headers = {
            "Content-Type": "application/xml",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_complete_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_with_part, xml_body, headers,
        )

        json_metadata["key_length_bytes"] = 10
        json_metadata["part_number"] = -1
        json_metadata["validated_first"] = "request_body"

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400, (
                f"AWS expected 400, got {response.aws.status_code}: {response.aws.text[:200]}"
            )
            error_code, error_msg = extract_error_info(response.aws.text)
            assert error_code == "InvalidArgument", f"Expected InvalidArgument, got {error_code}"
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
        else:
            assert response.status_code == 400, (
                f"Expected 400, got {response.status_code}: {response.text[:200]}"
            )
            error_code, error_msg = extract_error_info(response.text)
            assert error_code == "InvalidArgument", f"Expected InvalidArgument, got {error_code}"
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_missing_sse_c_key_and_negative_part_number(
        self,
        test_bucket,
        test_key,
        ssec_multipart_with_part,
        make_request,
        request,
        json_metadata,
    ):
        """Test validation order: partial SSE-C (only algorithm) vs negative part number."""
        xml_body = build_complete_xml([(-1, '"fake-etag"')])

        headers = {
            "Content-Type": "application/xml",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
        }

        response = self._make_complete_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_with_part, xml_body, headers,
        )

        json_metadata["provided_headers"] = ["algorithm"]
        json_metadata["part_number"] = -1
        json_metadata["validated_first"] = "request_body"

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400, (
                f"AWS expected 400, got {response.aws.status_code}: {response.aws.text[:200]}"
            )
            error_code, error_msg = extract_error_info(response.aws.text)
            assert error_code == "InvalidArgument", f"Expected InvalidArgument, got {error_code}"
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
        else:
            assert response.status_code == 400, (
                f"Expected 400, got {response.status_code}: {response.text[:200]}"
            )
            error_code, error_msg = extract_error_info(response.text)
            assert error_code == "InvalidArgument", f"Expected InvalidArgument, got {error_code}"
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_invalid_algorithm_and_invalid_etag(
        self,
        test_bucket,
        test_key,
        ssec_multipart_with_part,
        make_request,
        request,
        json_metadata,
    ):
        """Test validation order: invalid SSE-C algorithm vs invalid ETag.

        Uses valid part number (1) but with a fabricated ETag.
        """
        key_b64, key_md5 = generate_sse_c_key()

        xml_body = build_complete_xml([(1, '"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"')])

        headers = {
            "Content-Type": "application/xml",
            "x-amz-server-side-encryption-customer-algorithm": "AES128-INVALID",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_complete_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_with_part, xml_body, headers,
        )

        json_metadata["invalid_algorithm"] = "AES128-INVALID"
        json_metadata["invalid_etag"] = True
        json_metadata["validated_first"] = "sse_c_headers"

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400, (
                f"AWS expected 400, got {response.aws.status_code}: {response.aws.text[:200]}"
            )
            error_code, error_msg = extract_error_info(response.aws.text)
            assert error_code == "InvalidEncryptionAlgorithmError", (
                f"Expected InvalidEncryptionAlgorithmError, got {error_code}"
            )
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
        else:
            assert response.status_code == 400, (
                f"Expected 400, got {response.status_code}: {response.text[:200]}"
            )
            error_code, error_msg = extract_error_info(response.text)
            assert error_code == "InvalidEncryptionAlgorithmError", (
                f"Expected InvalidEncryptionAlgorithmError, got {error_code}"
            )
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg
