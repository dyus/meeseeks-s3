"""Happy path test for HeadObject after SSE-C multipart upload.

End-to-end test that verifies HeadObject on an SSE-C multipart upload:
1. CreateMultipartUpload with SSE-C headers
2. UploadPart x2 with SSE-C headers (5 MB + 1 KB)
3. CompleteMultipartUpload
4. HeadObject with SSE-C headers — verify metadata (status, content-length)

Uses two parts to exercise the real multipart path (first part >= 5 MB).
"""

import uuid

import pytest

from s3_compliance.sse_c import generate_sse_c_key


PART1_SIZE = 5 * 1024 * 1024  # 5 MB — minimum for non-last part
PART2_SIZE = 1024  # 1 KB — last part, no minimum
TOTAL_SIZE = PART1_SIZE + PART2_SIZE

PART1_BODY = b"A" * PART1_SIZE
PART2_BODY = b"B" * PART2_SIZE


def _upload_two_parts(client, bucket, key, upload_id, ssec_params):
    """Upload two parts and return list of {PartNumber, ETag} dicts."""
    part1 = client.upload_part(
        Bucket=bucket, Key=key,
        UploadId=upload_id, PartNumber=1,
        Body=PART1_BODY, **ssec_params,
    )
    part2 = client.upload_part(
        Bucket=bucket, Key=key,
        UploadId=upload_id, PartNumber=2,
        Body=PART2_BODY, **ssec_params,
    )
    return [
        {"PartNumber": 1, "ETag": part1["ETag"]},
        {"PartNumber": 2, "ETag": part2["ETag"]},
    ]


@pytest.mark.s3_handler("HeadObject")
@pytest.mark.sse_c
class TestSSECMultipartHeadObjectHappyPath:
    """End-to-end happy path: SSE-C multipart upload (2 parts) then HeadObject."""

    @pytest.fixture
    def test_key(self):
        """Generate unique test key."""
        return f"test-ssec-mpu-head-{uuid.uuid4().hex[:8]}"

    @pytest.fixture
    def completed_ssec_multipart(self, request, s3_client, aws_client, test_bucket, test_key):
        """Create, upload 2 parts, complete an SSE-C multipart upload.

        Returns the SSE-C key params used, so HeadObject can reuse them.
        In 'both' mode, creates on both endpoints independently.
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
            aws_parts = _upload_two_parts(
                aws_client, test_bucket, test_key, aws_upload_id, ssec_params,
            )
            aws_client.complete_multipart_upload(
                Bucket=test_bucket, Key=test_key,
                UploadId=aws_upload_id,
                MultipartUpload={"Parts": aws_parts},
            )

            # Custom
            factory = S3ClientFactory()
            custom_client = factory.create_client("custom")
            custom_mpu = custom_client.create_multipart_upload(
                Bucket=test_bucket, Key=test_key, **ssec_params,
            )
            custom_upload_id = custom_mpu["UploadId"]
            custom_parts = _upload_two_parts(
                custom_client, test_bucket, test_key, custom_upload_id, ssec_params,
            )
            custom_client.complete_multipart_upload(
                Bucket=test_bucket, Key=test_key,
                UploadId=custom_upload_id,
                MultipartUpload={"Parts": custom_parts},
            )

            yield {"key_b64": key_b64, "key_md5": key_md5}

            for client in [aws_client, custom_client]:
                try:
                    client.delete_object(Bucket=test_bucket, Key=test_key)
                except Exception:
                    pass
        else:
            mpu = s3_client.create_multipart_upload(
                Bucket=test_bucket, Key=test_key, **ssec_params,
            )
            upload_id = mpu["UploadId"]
            parts = _upload_two_parts(
                s3_client, test_bucket, test_key, upload_id, ssec_params,
            )
            s3_client.complete_multipart_upload(
                Bucket=test_bucket, Key=test_key,
                UploadId=upload_id,
                MultipartUpload={"Parts": parts},
            )

            yield {"key_b64": key_b64, "key_md5": key_md5}

            try:
                s3_client.delete_object(Bucket=test_bucket, Key=test_key)
            except Exception:
                pass

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_head_object_after_ssec_multipart_upload(
        self,
        test_bucket,
        test_key,
        completed_ssec_multipart,
        make_request,
        json_metadata,
    ):
        """HeadObject with correct SSE-C key should return metadata for multipart object."""
        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": completed_ssec_multipart["key_b64"],
            "x-amz-server-side-encryption-customer-key-MD5": completed_ssec_multipart["key_md5"],
        }

        response = make_request(
            "HEAD",
            f"/{test_bucket}/{test_key}",
            headers=headers,
        )

        json_metadata["flow"] = "CreateMPU -> UploadPart x2 -> Complete -> HeadObject"
        json_metadata["encryption"] = "SSE-C"
        json_metadata["part1_size"] = PART1_SIZE
        json_metadata["part2_size"] = PART2_SIZE
        json_metadata["total_size"] = TOTAL_SIZE

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 200, (
                f"AWS expected 200, got {response.aws.status_code}"
            )
            aws_content_length = int(response.aws.headers.get("Content-Length", 0))
            assert aws_content_length == TOTAL_SIZE, (
                f"AWS Content-Length mismatch: expected {TOTAL_SIZE}, got {aws_content_length}"
            )
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
            assert response.comparison.is_compliant, (
                f"Custom S3 doesn't match AWS: {response.diff_summary}"
            )
        else:
            assert response.status_code == 200, (
                f"Expected 200, got {response.status_code}"
            )
            content_length = int(response.headers.get("Content-Length", 0))
            assert content_length == TOTAL_SIZE, (
                f"Content-Length mismatch: expected {TOTAL_SIZE}, got {content_length}"
            )
            json_metadata["status"] = response.status_code
