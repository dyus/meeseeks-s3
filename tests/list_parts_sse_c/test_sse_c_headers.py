"""Tests for ListParts with SSE-C header combinations.

These tests verify S3 behavior when calling ListParts on an SSE-C multipart upload
with various SSE-C header combinations.

ListParts (GET /{bucket}/{key}?uploadId={id}) returns part metadata.
Unlike GetObject/HeadObject, ListParts may not require SSE-C headers since
it doesn't access encrypted content — only part metadata.

These tests probe AWS behavior for edge cases:
- Partial SSE-C headers
- Invalid SSE-C values
- Wrong key
- SSE-C headers on plain (non-SSE-C) multipart upload
"""

import base64
import hashlib
import uuid

import pytest

from s3_compliance.sse_c import DEFAULT_SSE_C_KEY_BYTES, generate_sse_c_key
from s3_compliance.xml_utils import extract_error_info


PART_BODY = b"A" * (5 * 1024 * 1024)  # 5 MB part


@pytest.mark.s3_handler("ListParts")
@pytest.mark.sse_c
class TestSSECListPartsHeaders:
    """Test ListParts API with SSE-C header combinations."""

    @pytest.fixture
    def test_key(self):
        """Generate unique test key."""
        return f"test-ssec-list-parts-hdr-{uuid.uuid4().hex[:8]}"

    @pytest.fixture
    def ssec_mpu_with_part(self, request, s3_client, aws_client, test_bucket, test_key, setup_steps):
        """Create SSE-C multipart upload and upload 1 part.

        Returns upload_id(s) for ListParts testing.
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

            aws_mpu = aws_client.create_multipart_upload(
                Bucket=test_bucket, Key=test_key, **ssec_params,
            )
            aws_upload_id = aws_mpu["UploadId"]
            setup_steps("CreateMultipartUpload", aws_mpu, "aws", SSE_C="AES256")
            part1_aws = aws_client.upload_part(
                Bucket=test_bucket, Key=test_key,
                UploadId=aws_upload_id, PartNumber=1,
                Body=PART_BODY, **ssec_params,
            )
            setup_steps("UploadPart", part1_aws, "aws", PartNumber=1, Size="5 MB", SSE_C="AES256")

            factory = S3ClientFactory()
            custom_client = factory.create_client("custom")
            custom_mpu = custom_client.create_multipart_upload(
                Bucket=test_bucket, Key=test_key, **ssec_params,
            )
            custom_upload_id = custom_mpu["UploadId"]
            setup_steps("CreateMultipartUpload", custom_mpu, "custom", SSE_C="AES256")
            part1_custom = custom_client.upload_part(
                Bucket=test_bucket, Key=test_key,
                UploadId=custom_upload_id, PartNumber=1,
                Body=PART_BODY, **ssec_params,
            )
            setup_steps("UploadPart", part1_custom, "custom", PartNumber=1, Size="5 MB", SSE_C="AES256")

            yield {"aws": aws_upload_id, "custom": custom_upload_id}

            for client, uid in [(aws_client, aws_upload_id), (custom_client, custom_upload_id)]:
                try:
                    client.abort_multipart_upload(
                        Bucket=test_bucket, Key=test_key, UploadId=uid,
                    )
                except Exception:
                    pass
        else:
            mpu = s3_client.create_multipart_upload(
                Bucket=test_bucket, Key=test_key, **ssec_params,
            )
            upload_id = mpu["UploadId"]
            setup_steps("CreateMultipartUpload", mpu, SSE_C="AES256")
            part1 = s3_client.upload_part(
                Bucket=test_bucket, Key=test_key,
                UploadId=upload_id, PartNumber=1,
                Body=PART_BODY, **ssec_params,
            )
            setup_steps("UploadPart", part1, PartNumber=1, Size="5 MB", SSE_C="AES256")

            yield upload_id

            try:
                s3_client.abort_multipart_upload(
                    Bucket=test_bucket, Key=test_key, UploadId=upload_id,
                )
            except Exception:
                pass

    @pytest.fixture
    def plain_mpu_with_part(self, request, s3_client, aws_client, test_bucket, test_key, setup_steps):
        """Create plain (non-SSE-C) multipart upload and upload 1 part.

        Returns upload_id(s) for ListParts testing.
        """
        endpoint_mode = request.config.getoption("--endpoint")

        if endpoint_mode == "both":
            from s3_compliance.client import S3ClientFactory

            aws_mpu = aws_client.create_multipart_upload(
                Bucket=test_bucket, Key=test_key,
            )
            aws_upload_id = aws_mpu["UploadId"]
            setup_steps("CreateMultipartUpload", aws_mpu, "aws")
            part1_aws = aws_client.upload_part(
                Bucket=test_bucket, Key=test_key,
                UploadId=aws_upload_id, PartNumber=1,
                Body=PART_BODY,
            )
            setup_steps("UploadPart", part1_aws, "aws", PartNumber=1, Size="5 MB")

            factory = S3ClientFactory()
            custom_client = factory.create_client("custom")
            custom_mpu = custom_client.create_multipart_upload(
                Bucket=test_bucket, Key=test_key,
            )
            custom_upload_id = custom_mpu["UploadId"]
            setup_steps("CreateMultipartUpload", custom_mpu, "custom")
            part1_custom = custom_client.upload_part(
                Bucket=test_bucket, Key=test_key,
                UploadId=custom_upload_id, PartNumber=1,
                Body=PART_BODY,
            )
            setup_steps("UploadPart", part1_custom, "custom", PartNumber=1, Size="5 MB")

            yield {"aws": aws_upload_id, "custom": custom_upload_id}

            for client, uid in [(aws_client, aws_upload_id), (custom_client, custom_upload_id)]:
                try:
                    client.abort_multipart_upload(
                        Bucket=test_bucket, Key=test_key, UploadId=uid,
                    )
                except Exception:
                    pass
        else:
            mpu = s3_client.create_multipart_upload(
                Bucket=test_bucket, Key=test_key,
            )
            upload_id = mpu["UploadId"]
            setup_steps("CreateMultipartUpload", mpu)
            part1 = s3_client.upload_part(
                Bucket=test_bucket, Key=test_key,
                UploadId=upload_id, PartNumber=1,
                Body=PART_BODY,
            )
            setup_steps("UploadPart", part1, PartNumber=1, Size="5 MB")

            yield upload_id

            try:
                s3_client.abort_multipart_upload(
                    Bucket=test_bucket, Key=test_key, UploadId=upload_id,
                )
            except Exception:
                pass

    def _make_list_parts_request(
        self, make_request, request, test_bucket, test_key,
        upload_ids, headers=None,
    ):
        """Make a ListParts request via make_request fixture."""
        endpoint_mode = request.config.getoption("--endpoint")
        if endpoint_mode == "both":
            query_params = f"?uploadId={upload_ids['aws']}"
            custom_query_params = f"?uploadId={upload_ids['custom']}"
        else:
            query_params = f"?uploadId={upload_ids}"
            custom_query_params = None

        return make_request(
            "GET",
            f"/{test_bucket}/{test_key}",
            headers=headers or {},
            query_params=query_params,
            custom_query_params=custom_query_params,
        )

    # =========================================================================
    # Missing Header Tests (partial SSE-C headers on SSE-C upload)
    # =========================================================================

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_list_parts_only_algorithm(
        self,
        test_bucket,
        test_key,
        ssec_mpu_with_part,
        make_request,
        request,
        json_metadata,
    ):
        """ListParts with only SSE-C algorithm header on SSE-C upload."""
        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
        }

        response = self._make_list_parts_request(
            make_request, request, test_bucket, test_key,
            ssec_mpu_with_part, headers=headers,
        )

        json_metadata["provided_headers"] = ["algorithm"]
        json_metadata["missing_headers"] = ["key", "key_md5"]

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_list_parts_only_key(
        self,
        test_bucket,
        test_key,
        ssec_mpu_with_part,
        make_request,
        request,
        json_metadata,
    ):
        """ListParts with only SSE-C key header on SSE-C upload."""
        key_b64, _ = generate_sse_c_key()

        headers = {
            "x-amz-server-side-encryption-customer-key": key_b64,
        }

        response = self._make_list_parts_request(
            make_request, request, test_bucket, test_key,
            ssec_mpu_with_part, headers=headers,
        )

        json_metadata["provided_headers"] = ["key"]
        json_metadata["missing_headers"] = ["algorithm", "key_md5"]

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_list_parts_only_key_md5(
        self,
        test_bucket,
        test_key,
        ssec_mpu_with_part,
        make_request,
        request,
        json_metadata,
    ):
        """ListParts with only SSE-C key MD5 header on SSE-C upload."""
        _, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_list_parts_request(
            make_request, request, test_bucket, test_key,
            ssec_mpu_with_part, headers=headers,
        )

        json_metadata["provided_headers"] = ["key_md5"]
        json_metadata["missing_headers"] = ["algorithm", "key"]

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_list_parts_algorithm_and_key_missing_md5(
        self,
        test_bucket,
        test_key,
        ssec_mpu_with_part,
        make_request,
        request,
        json_metadata,
    ):
        """ListParts with algorithm and key but missing MD5 on SSE-C upload."""
        key_b64, _ = generate_sse_c_key()

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
        }

        response = self._make_list_parts_request(
            make_request, request, test_bucket, test_key,
            ssec_mpu_with_part, headers=headers,
        )

        json_metadata["provided_headers"] = ["algorithm", "key"]
        json_metadata["missing_headers"] = ["key_md5"]

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_list_parts_algorithm_and_md5_missing_key(
        self,
        test_bucket,
        test_key,
        ssec_mpu_with_part,
        make_request,
        request,
        json_metadata,
    ):
        """ListParts with algorithm and MD5 but missing key on SSE-C upload."""
        _, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_list_parts_request(
            make_request, request, test_bucket, test_key,
            ssec_mpu_with_part, headers=headers,
        )

        json_metadata["provided_headers"] = ["algorithm", "key_md5"]
        json_metadata["missing_headers"] = ["key"]

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_list_parts_key_and_md5_missing_algorithm(
        self,
        test_bucket,
        test_key,
        ssec_mpu_with_part,
        make_request,
        request,
        json_metadata,
    ):
        """ListParts with key and MD5 but missing algorithm on SSE-C upload."""
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_list_parts_request(
            make_request, request, test_bucket, test_key,
            ssec_mpu_with_part, headers=headers,
        )

        json_metadata["provided_headers"] = ["key", "key_md5"]
        json_metadata["missing_headers"] = ["algorithm"]

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

    # =========================================================================
    # Invalid Value Tests
    # =========================================================================

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_list_parts_invalid_algorithm(
        self,
        test_bucket,
        test_key,
        ssec_mpu_with_part,
        make_request,
        request,
        json_metadata,
    ):
        """ListParts with invalid SSE-C algorithm on SSE-C upload."""
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES128-INVALID",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_list_parts_request(
            make_request, request, test_bucket, test_key,
            ssec_mpu_with_part, headers=headers,
        )

        json_metadata["invalid_algorithm"] = "AES128-INVALID"

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_list_parts_wrong_key(
        self,
        test_bucket,
        test_key,
        ssec_mpu_with_part,
        make_request,
        request,
        json_metadata,
    ):
        """ListParts with wrong SSE-C key (different from CreateMultipartUpload key)."""
        wrong_key_bytes = hashlib.sha256(b"wrong_key_for_list_parts").digest()
        key_b64, key_md5 = generate_sse_c_key(wrong_key_bytes)

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_list_parts_request(
            make_request, request, test_bucket, test_key,
            ssec_mpu_with_part, headers=headers,
        )

        json_metadata["wrong_key"] = True

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_list_parts_invalid_key_length(
        self,
        test_bucket,
        test_key,
        ssec_mpu_with_part,
        make_request,
        request,
        json_metadata,
    ):
        """ListParts with invalid key length (10 bytes instead of 32)."""
        short_key = b"1234567890"
        key_b64, key_md5 = generate_sse_c_key(short_key)

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_list_parts_request(
            make_request, request, test_bucket, test_key,
            ssec_mpu_with_part, headers=headers,
        )

        json_metadata["key_length_bytes"] = 10

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_list_parts_mismatched_key_md5(
        self,
        test_bucket,
        test_key,
        ssec_mpu_with_part,
        make_request,
        request,
        json_metadata,
    ):
        """ListParts when key MD5 doesn't match key."""
        key_b64, _ = generate_sse_c_key()
        wrong_md5 = base64.b64encode(
            hashlib.md5(b"wrong-key-for-md5-mismatch").digest()
        ).decode("utf-8")

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": wrong_md5,
        }

        response = self._make_list_parts_request(
            make_request, request, test_bucket, test_key,
            ssec_mpu_with_part, headers=headers,
        )

        json_metadata["key_md5_matches_key"] = False

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

    # =========================================================================
    # SSE-C Mismatch: SSE-C headers on plain upload
    # =========================================================================

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_list_parts_sse_c_headers_on_plain_upload(
        self,
        test_bucket,
        test_key,
        plain_mpu_with_part,
        make_request,
        request,
        json_metadata,
    ):
        """ListParts with SSE-C headers on a plain (non-SSE-C) multipart upload."""
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_list_parts_request(
            make_request, request, test_bucket, test_key,
            plain_mpu_with_part, headers=headers,
        )

        json_metadata["create_mpu_encryption"] = "none"
        json_metadata["list_parts_encryption"] = "SSE-C"

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg
