"""Probe: ListParts with checksum algorithm on SSE-C multipart upload.

Tests whether SSE-C headers affect ListParts response when the multipart
upload was created with a checksum algorithm (e.g., CRC32).

AWS docs say x-amz-server-side-encryption-customer-algorithm is
"needed only when the object was created using a checksum algorithm".
This test verifies that claim.
"""

import uuid
import zlib
import base64

import pytest

from s3_compliance.sse_c import generate_sse_c_key


PART_BODY = b"A" * (5 * 1024 * 1024)  # 5 MB


def _crc32_b64(data: bytes) -> str:
    """Compute CRC32 and return base64-encoded big-endian 4-byte value."""
    crc = zlib.crc32(data) & 0xFFFFFFFF
    return base64.b64encode(crc.to_bytes(4, "big")).decode()


@pytest.mark.s3_handler("ListParts")
@pytest.mark.sse_c
@pytest.mark.edge_case
class TestSSECListPartsChecksum:
    """Probe: does ListParts need SSE-C headers when checksum algorithm is used?"""

    @pytest.fixture
    def test_key(self):
        return f"test-ssec-list-parts-crc-{uuid.uuid4().hex[:8]}"

    @pytest.fixture
    def ssec_crc32_mpu_with_part(self, request, s3_client, aws_client, test_bucket, test_key, setup_steps):
        """Create SSE-C + CRC32 multipart upload, upload 1 part."""
        key_b64, key_md5 = generate_sse_c_key()
        endpoint_mode = request.config.getoption("--endpoint")

        ssec_params = {
            "SSECustomerAlgorithm": "AES256",
            "SSECustomerKey": key_b64,
            "SSECustomerKeyMD5": key_md5,
        }

        crc32_value = _crc32_b64(PART_BODY)

        if endpoint_mode == "both":
            from s3_compliance.client import S3ClientFactory

            aws_mpu = aws_client.create_multipart_upload(
                Bucket=test_bucket, Key=test_key,
                ChecksumAlgorithm="CRC32",
                **ssec_params,
            )
            aws_upload_id = aws_mpu["UploadId"]
            setup_steps("CreateMultipartUpload", aws_mpu, "aws", SSE_C="AES256", Checksum="CRC32")
            part1_aws = aws_client.upload_part(
                Bucket=test_bucket, Key=test_key,
                UploadId=aws_upload_id, PartNumber=1,
                Body=PART_BODY,
                ChecksumCRC32=crc32_value,
                **ssec_params,
            )
            setup_steps("UploadPart", part1_aws, "aws", PartNumber=1, Size="5 MB", SSE_C="AES256", CRC32=crc32_value)

            factory = S3ClientFactory()
            custom_client = factory.create_client("custom")
            custom_mpu = custom_client.create_multipart_upload(
                Bucket=test_bucket, Key=test_key,
                ChecksumAlgorithm="CRC32",
                **ssec_params,
            )
            custom_upload_id = custom_mpu["UploadId"]
            setup_steps("CreateMultipartUpload", custom_mpu, "custom", SSE_C="AES256", Checksum="CRC32")
            part1_custom = custom_client.upload_part(
                Bucket=test_bucket, Key=test_key,
                UploadId=custom_upload_id, PartNumber=1,
                Body=PART_BODY,
                ChecksumCRC32=crc32_value,
                **ssec_params,
            )
            setup_steps("UploadPart", part1_custom, "custom", PartNumber=1, Size="5 MB", SSE_C="AES256", CRC32=crc32_value)

            yield {
                "aws": aws_upload_id,
                "custom": custom_upload_id,
                "key_b64": key_b64,
                "key_md5": key_md5,
            }

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
                ChecksumAlgorithm="CRC32",
                **ssec_params,
            )
            upload_id = mpu["UploadId"]
            setup_steps("CreateMultipartUpload", mpu, SSE_C="AES256", Checksum="CRC32")
            part1 = s3_client.upload_part(
                Bucket=test_bucket, Key=test_key,
                UploadId=upload_id, PartNumber=1,
                Body=PART_BODY,
                ChecksumCRC32=crc32_value,
                **ssec_params,
            )
            setup_steps("UploadPart", part1, PartNumber=1, Size="5 MB", SSE_C="AES256", CRC32=crc32_value)

            yield {
                "upload_id": upload_id,
                "key_b64": key_b64,
                "key_md5": key_md5,
            }

            try:
                s3_client.abort_multipart_upload(
                    Bucket=test_bucket, Key=test_key, UploadId=upload_id,
                )
            except Exception:
                pass

    def _make_list_parts_request(
        self, make_request, request, test_bucket, test_key,
        mpu_data, headers=None,
    ):
        """Make a ListParts request."""
        endpoint_mode = request.config.getoption("--endpoint")
        if endpoint_mode == "both":
            query_params = f"?uploadId={mpu_data['aws']}"
            custom_query_params = f"?uploadId={mpu_data['custom']}"
        else:
            query_params = f"?uploadId={mpu_data['upload_id']}"
            custom_query_params = None

        return make_request(
            "GET",
            f"/{test_bucket}/{test_key}",
            headers=headers or {},
            query_params=query_params,
            custom_query_params=custom_query_params,
        )

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_list_parts_crc32_without_sse_c(
        self,
        test_bucket,
        test_key,
        ssec_crc32_mpu_with_part,
        make_request,
        request,
        json_metadata,
    ):
        """ListParts on SSE-C + CRC32 upload WITHOUT SSE-C headers.

        Does AWS still return ChecksumCRC32 in the response?
        """
        response = self._make_list_parts_request(
            make_request, request, test_bucket, test_key,
            ssec_crc32_mpu_with_part,
        )

        json_metadata["checksum_algorithm"] = "CRC32"
        json_metadata["sse_c_headers_sent"] = False

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["aws_has_checksum"] = "ChecksumCRC32" in response.aws.text
            json_metadata["aws_body"] = response.aws.text[:500]
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code
            json_metadata["has_checksum"] = "ChecksumCRC32" in response.text
            json_metadata["body"] = response.text[:500]

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_list_parts_crc32_with_sse_c(
        self,
        test_bucket,
        test_key,
        ssec_crc32_mpu_with_part,
        make_request,
        request,
        json_metadata,
    ):
        """ListParts on SSE-C + CRC32 upload WITH SSE-C headers.

        Does the response differ — e.g., include ChecksumCRC32 only when SSE-C is provided?
        """
        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": ssec_crc32_mpu_with_part["key_b64"],
            "x-amz-server-side-encryption-customer-key-MD5": ssec_crc32_mpu_with_part["key_md5"],
        }

        response = self._make_list_parts_request(
            make_request, request, test_bucket, test_key,
            ssec_crc32_mpu_with_part, headers=headers,
        )

        json_metadata["checksum_algorithm"] = "CRC32"
        json_metadata["sse_c_headers_sent"] = True

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["aws_has_checksum"] = "ChecksumCRC32" in response.aws.text
            json_metadata["aws_body"] = response.aws.text[:500]
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code
            json_metadata["has_checksum"] = "ChecksumCRC32" in response.text
            json_metadata["body"] = response.text[:500]
