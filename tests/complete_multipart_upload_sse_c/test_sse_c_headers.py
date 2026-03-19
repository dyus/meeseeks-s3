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

            def _add_forwarded_proto(params, **kwargs):
                params["headers"]["X-Forwarded-Proto"] = "https"

            custom_client.meta.events.register("before-call.s3.CreateMultipartUpload", _add_forwarded_proto)
            custom_mpu = custom_client.create_multipart_upload(
                Bucket=test_bucket, Key=test_key, **ssec_params,
            )
            custom_client.meta.events.unregister("before-call.s3.CreateMultipartUpload", _add_forwarded_proto)
            custom_upload_id = custom_mpu["UploadId"]
            custom_client.meta.events.register("before-call.s3.UploadPart", _add_forwarded_proto)
            custom_part = custom_client.upload_part(
                Bucket=test_bucket, Key=test_key,
                UploadId=custom_upload_id, PartNumber=1,
                Body=PART_BODY, **ssec_params,
            )
            custom_client.meta.events.unregister("before-call.s3.UploadPart", _add_forwarded_proto)
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
            endpoint_is_custom = endpoint_mode == "custom"
            if endpoint_is_custom:
                def _add_forwarded_proto(params, **kwargs):
                    params["headers"]["X-Forwarded-Proto"] = "https"

                s3_client.meta.events.register("before-call.s3.CreateMultipartUpload", _add_forwarded_proto)

            mpu = s3_client.create_multipart_upload(
                Bucket=test_bucket, Key=test_key, **ssec_params,
            )
            upload_id = mpu["UploadId"]

            if endpoint_is_custom:
                s3_client.meta.events.unregister("before-call.s3.CreateMultipartUpload", _add_forwarded_proto)
                s3_client.meta.events.register("before-call.s3.UploadPart", _add_forwarded_proto)

            part = s3_client.upload_part(
                Bucket=test_bucket, Key=test_key,
                UploadId=upload_id, PartNumber=1,
                Body=PART_BODY, **ssec_params,
            )
            etag = part["ETag"]

            if endpoint_is_custom:
                s3_client.meta.events.unregister("before-call.s3.UploadPart", _add_forwarded_proto)

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

    # =========================================================================
    # E. Base64 Encoding Edge Cases
    # =========================================================================

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_key_base64_with_spaces(
        self,
        test_bucket,
        test_key,
        ssec_multipart_with_part,
        make_request,
        request,
        json_metadata,
    ):
        """Valid 32-byte key base64 with spaces inserted.

        AWS lenient base64 strips non-base64 chars including spaces.
        """
        key_b64, key_md5 = generate_sse_c_key()
        spaced_key = " ".join([key_b64[i:i+4] for i in range(0, len(key_b64), 4)])

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
            "x-amz-server-side-encryption-customer-key": spaced_key,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_complete_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_with_part, xml_body, headers, custom_xml_body,
        )

        json_metadata["key_value"] = spaced_key

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

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_key_base64_with_tabs_and_newlines(
        self,
        test_bucket,
        test_key,
        ssec_multipart_with_part,
        make_request,
        request,
        json_metadata,
    ):
        """Valid 32-byte key base64 with tabs and newlines (PEM-style)."""
        key_b64, key_md5 = generate_sse_c_key()
        wrapped_key = "\t".join([key_b64[i:i+8] for i in range(0, len(key_b64), 8)])

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
            "x-amz-server-side-encryption-customer-key": wrapped_key,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_complete_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_with_part, xml_body, headers, custom_xml_body,
        )

        json_metadata["key_value"] = repr(wrapped_key)

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

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_key_base64_without_padding(
        self,
        test_bucket,
        test_key,
        ssec_multipart_with_part,
        make_request,
        request,
        json_metadata,
    ):
        """Valid 32-byte key base64 with padding '=' removed."""
        key_b64, key_md5 = generate_sse_c_key()
        no_pad_key = key_b64.rstrip("=")

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
            "x-amz-server-side-encryption-customer-key": no_pad_key,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_complete_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_with_part, xml_body, headers, custom_xml_body,
        )

        json_metadata["key_value"] = no_pad_key
        json_metadata["original_key"] = key_b64

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

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_key_base64_with_extra_padding(
        self,
        test_bucket,
        test_key,
        ssec_multipart_with_part,
        make_request,
        request,
        json_metadata,
    ):
        """Valid 32-byte key base64 with extra '===' appended."""
        key_b64, key_md5 = generate_sse_c_key()
        extra_pad_key = key_b64 + "==="

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
            "x-amz-server-side-encryption-customer-key": extra_pad_key,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_complete_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_with_part, xml_body, headers, custom_xml_body,
        )

        json_metadata["key_value"] = extra_pad_key

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

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_key_url_safe_base64(
        self,
        test_bucket,
        test_key,
        ssec_multipart_with_part,
        make_request,
        request,
        json_metadata,
    ):
        """Key encoded with URL-safe base64 (- and _ instead of + and /)."""
        from s3_compliance.sse_c import DEFAULT_SSE_C_KEY_BYTES
        url_safe_key = base64.urlsafe_b64encode(DEFAULT_SSE_C_KEY_BYTES).decode("utf-8")
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
            "x-amz-server-side-encryption-customer-key": url_safe_key,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_complete_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_with_part, xml_body, headers, custom_xml_body,
        )

        std_key, _ = generate_sse_c_key()
        json_metadata["key_value"] = url_safe_key
        json_metadata["original_key"] = std_key
        json_metadata["has_plus_or_slash"] = "+" in std_key or "/" in std_key

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

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_key_and_md5_both_url_safe_base64(
        self,
        test_bucket,
        test_key,
        ssec_multipart_with_part,
        make_request,
        request,
        json_metadata,
    ):
        """Both key and MD5 encoded with URL-safe base64 (- and _ instead of + and /).

        Definitive test: if AWS returns 200, it supports URLEncoding.
        If 400, it strictly uses StdEncoding (+/).
        """
        from s3_compliance.sse_c import DEFAULT_SSE_C_KEY_BYTES
        url_safe_key = base64.urlsafe_b64encode(DEFAULT_SSE_C_KEY_BYTES).decode("utf-8")
        url_safe_md5 = base64.urlsafe_b64encode(hashlib.md5(DEFAULT_SSE_C_KEY_BYTES).digest()).decode("utf-8")

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
            "x-amz-server-side-encryption-customer-key": url_safe_key,
            "x-amz-server-side-encryption-customer-key-MD5": url_safe_md5,
        }

        response = self._make_complete_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_with_part, xml_body, headers, custom_xml_body,
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

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
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
        test_bucket,
        test_key,
        ssec_multipart_with_part,
        make_request,
        request,
        json_metadata,
        garbage_position,
    ):
        """Test CompleteMultipartUpload with valid 32-byte key base64 + garbage chars at various positions.

        AWS uses lenient base64 decoder -- strips non-base64 chars, decodes rest.
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
            "x-amz-server-side-encryption-customer-key": dirty_key,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_complete_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_with_part, xml_body, headers, custom_xml_body,
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
    # F. Key Length Boundary Cases
    # =========================================================================

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_customer_key_decodes_to_short_value(
        self,
        test_bucket,
        test_key,
        ssec_multipart_with_part,
        make_request,
        request,
        json_metadata,
    ):
        """Test CompleteMultipartUpload with customer key '####' that decodes to 0 bytes via lenient base64."""
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
            "x-amz-server-side-encryption-customer-key": "####",
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_complete_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_with_part, xml_body, headers, custom_xml_body,
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

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_customer_key_zz(
        self,
        test_bucket,
        test_key,
        ssec_multipart_with_part,
        make_request,
        request,
        json_metadata,
    ):
        """Test CompleteMultipartUpload with customer key 'ZZ' that decodes to 1 byte (0x65) via base64."""
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
            "x-amz-server-side-encryption-customer-key": "ZZ",
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_complete_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_with_part, xml_body, headers, custom_xml_body,
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

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_customer_key_single_char_a(
        self,
        test_bucket,
        test_key,
        ssec_multipart_with_part,
        make_request,
        request,
        json_metadata,
    ):
        """Test CompleteMultipartUpload with customer key 'a' -- invalid base64 (1 char)."""
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
            "x-amz-server-side-encryption-customer-key": "a",
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_complete_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_with_part, xml_body, headers, custom_xml_body,
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

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_customer_key_latin1_chars(
        self,
        test_bucket,
        test_key,
        ssec_multipart_with_part,
        make_request,
        request,
        json_metadata,
    ):
        """Test CompleteMultipartUpload with customer key as latin-1 non-ASCII chars.

        These are valid latin-1 (0xE9, 0xF1, 0xFC, 0xDF) so they can be sent
        in HTTP headers, but they are not valid base64 characters.
        """
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
            "x-amz-server-side-encryption-customer-key": "\u00e9\u00f1\u00fc\u00df",
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_complete_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_with_part, xml_body, headers, custom_xml_body,
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

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_empty_customer_key(
        self,
        test_bucket,
        test_key,
        ssec_multipart_with_part,
        make_request,
        request,
        json_metadata,
    ):
        """Test CompleteMultipartUpload with empty string as customer key."""
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
            "x-amz-server-side-encryption-customer-key": "",
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_complete_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_with_part, xml_body, headers, custom_xml_body,
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

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_customer_key_decodes_to_1_byte(
        self,
        test_bucket,
        test_key,
        ssec_multipart_with_part,
        make_request,
        request,
        json_metadata,
    ):
        """Test CompleteMultipartUpload with customer key that decodes to 1 byte (AQ==)."""
        short_key = b"\x01"
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

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_short_key_zz_with_matching_md5(
        self,
        test_bucket,
        test_key,
        ssec_multipart_with_part,
        make_request,
        request,
        json_metadata,
    ):
        """Key 'ZZ' (decodes to 1 byte) with correct MD5 for that 1 byte.

        Tests validation order after MD5 passes: does AWS return
        "too short" or "invalid for the specified algorithm"?
        """
        decoded_key = base64.b64decode("ZZ==")  # 1 byte: 0x65
        key_md5 = base64.b64encode(
            hashlib.md5(decoded_key).digest()
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
            "x-amz-server-side-encryption-customer-key": "ZZ",
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_complete_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_with_part, xml_body, headers, custom_xml_body,
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

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_key_31_bytes(
        self,
        test_bucket,
        test_key,
        ssec_multipart_with_part,
        make_request,
        request,
        json_metadata,
    ):
        """Key that decodes to 31 bytes (one byte short of AES-256)."""
        short_key = b"\x01" * 31
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

        json_metadata["key_decoded_length"] = 31

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
    def test_sse_c_key_33_bytes(
        self,
        test_bucket,
        test_key,
        ssec_multipart_with_part,
        make_request,
        request,
        json_metadata,
    ):
        """Key that decodes to 33 bytes (one byte over AES-256)."""
        long_key = b"\x01" * 33
        key_b64, key_md5 = generate_sse_c_key(long_key)

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

        json_metadata["key_decoded_length"] = 33

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
    def test_sse_c_long_key_33_bytes_with_matching_md5(
        self,
        test_bucket,
        test_key,
        ssec_multipart_with_part,
        make_request,
        request,
        json_metadata,
    ):
        """Key that decodes to 33 bytes with correct MD5.

        Tests validation after MD5 passes: should return "invalid for the specified algorithm".
        """
        long_key = b"\x01" * 33
        key_b64, key_md5 = generate_sse_c_key(long_key)

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

    # =========================================================================
    # G. MD5 Edge Cases
    # =========================================================================

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_md5_with_garbage_chars(
        self,
        test_bucket,
        test_key,
        ssec_multipart_with_part,
        make_request,
        request,
        json_metadata,
    ):
        """Valid key + MD5 base64 with garbage chars inserted.

        Go: MD5 decoded with lenient base64 (garbage stripped) -- if decoded MD5
        still matches key MD5 then success. Otherwise MD5 mismatch.
        """
        key_b64, key_md5 = generate_sse_c_key()
        garbage_md5 = "!!" + key_md5[:8] + "##" + key_md5[8:]

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
            "x-amz-server-side-encryption-customer-key-MD5": garbage_md5,
        }

        response = self._make_complete_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_with_part, xml_body, headers, custom_xml_body,
        )

        json_metadata["md5_value"] = garbage_md5
        json_metadata["original_md5"] = key_md5

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

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_md5_decodes_to_wrong_length(
        self,
        test_bucket,
        test_key,
        ssec_multipart_with_part,
        make_request,
        request,
        json_metadata,
    ):
        """Valid key + MD5 that decodes to 8 bytes instead of 16.

        Go: MD5 decoded to 8 bytes then ConstantTimeCompare with 16-byte actual MD5
        -- lengths differ -- mismatch.
        """
        key_b64, _ = generate_sse_c_key()
        short_md5 = base64.b64encode(b"\x01" * 8).decode("utf-8")

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
            "x-amz-server-side-encryption-customer-key-MD5": short_md5,
        }

        response = self._make_complete_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_with_part, xml_body, headers, custom_xml_body,
        )

        json_metadata["md5_value"] = short_md5
        json_metadata["md5_decoded_length"] = 8

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
    def test_sse_c_valid_key_md5_without_padding(
        self,
        test_bucket,
        test_key,
        ssec_multipart_with_part,
        make_request,
        request,
        json_metadata,
    ):
        """Valid padded key, but MD5 has base64 padding '=' stripped."""
        key_b64, key_md5 = generate_sse_c_key()
        no_pad_md5 = key_md5.rstrip("=")

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
            "x-amz-server-side-encryption-customer-key-MD5": no_pad_md5,
        }

        response = self._make_complete_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_with_part, xml_body, headers, custom_xml_body,
        )

        json_metadata["md5_value"] = no_pad_md5
        json_metadata["original_md5"] = key_md5
        json_metadata["key_value"] = key_b64

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

    # =========================================================================
    # H. HTTP (non-TLS) with invalid SSE-C headers
    # =========================================================================

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_all_invalid_headers_over_http(
        self,
        test_bucket,
        test_key,
        ssec_multipart_with_part,
        make_request,
        request,
        json_metadata,
    ):
        """Test all three SSE-C headers invalid + request sent over HTTP (not HTTPS).

        SSE-C requires HTTPS. This tests which error takes priority:
        the HTTP transport violation or the invalid header values.
        """
        invalid_key = "not-valid-base64!!!"
        wrong_md5 = base64.b64encode(hashlib.md5(b"wrong").digest()).decode("utf-8")

        endpoint_mode = request.config.getoption("--endpoint")
        if endpoint_mode == "both":
            xml_body = build_complete_xml([(1, ssec_multipart_with_part["aws"]["etag"])])
            custom_xml_body = build_complete_xml([(1, ssec_multipart_with_part["custom"]["etag"])])
        else:
            xml_body = build_complete_xml([(1, ssec_multipart_with_part["etag"])])
            custom_xml_body = None

        headers = {
            "Content-Type": "application/xml",
            "x-amz-server-side-encryption-customer-algorithm": "AES256-INVALID",
            "x-amz-server-side-encryption-customer-key": invalid_key,
            "x-amz-server-side-encryption-customer-key-MD5": wrong_md5,
        }

        body = xml_body.encode("utf-8") if isinstance(xml_body, str) else xml_body
        custom_body = None
        custom_query_params = None

        if endpoint_mode == "both":
            query_params = f"?uploadId={ssec_multipart_with_part['aws']['upload_id']}"
            custom_query_params = f"?uploadId={ssec_multipart_with_part['custom']['upload_id']}"
            if custom_xml_body is not None:
                custom_body = custom_xml_body.encode("utf-8") if isinstance(custom_xml_body, str) else custom_xml_body
        else:
            query_params = f"?uploadId={ssec_multipart_with_part['upload_id']}"

        response = make_request(
            "POST",
            f"/{test_bucket}/{test_key}",
            body=body,
            headers=headers,
            query_params=query_params,
            custom_body=custom_body,
            custom_query_params=custom_query_params,
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
        else:
            assert response.status_code == 400, (
                f"Expected 400, got {response.status_code}"
            )
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg
