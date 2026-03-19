"""Happy path test for full SSE-C multipart upload flow.

End-to-end test that verifies the complete SSE-C multipart upload lifecycle:
1. CreateMultipartUpload with SSE-C headers
2. UploadPart x2 with SSE-C headers (5 MB + 1 KB)
3. CompleteMultipartUpload
4. GetObject with SSE-C headers — verify decrypted content matches

Uses two parts to exercise the real multipart path (first part >= 5 MB).
"""

import uuid

import pytest

from s3_compliance.sse_c import generate_sse_c_key


PART1_BODY = b"A" * (5 * 1024 * 1024)  # 5 MB — minimum for non-last part
PART2_BODY = b"B" * 1024  # 1 KB — last part, no minimum
FULL_BODY = PART1_BODY + PART2_BODY


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


@pytest.mark.s3_handler("GetObject")
@pytest.mark.sse_c
class TestSSECMultipartUploadHappyPath:
    """End-to-end happy path: SSE-C multipart upload (2 parts) then GetObject."""

    @pytest.fixture
    def test_key(self):
        """Generate unique test key."""
        return f"test-ssec-mpu-e2e-{uuid.uuid4().hex[:8]}"

    @pytest.fixture
    def completed_ssec_multipart(self, request, s3_client, aws_client, test_bucket, test_key):
        """Create, upload 2 parts, complete an SSE-C multipart upload.

        Returns the SSE-C key params used, so GetObject can reuse them.
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

            def _add_forwarded_proto(params, **kwargs):
                params["headers"]["X-Forwarded-Proto"] = "https"

            custom_client.meta.events.register("before-call.s3.CreateMultipartUpload", _add_forwarded_proto)
            custom_mpu = custom_client.create_multipart_upload(
                Bucket=test_bucket, Key=test_key, **ssec_params,
            )
            custom_client.meta.events.unregister("before-call.s3.CreateMultipartUpload", _add_forwarded_proto)
            custom_upload_id = custom_mpu["UploadId"]
            custom_client.meta.events.register("before-call.s3.UploadPart", _add_forwarded_proto)
            custom_parts = _upload_two_parts(
                custom_client, test_bucket, test_key, custom_upload_id, ssec_params,
            )
            custom_client.meta.events.unregister("before-call.s3.UploadPart", _add_forwarded_proto)
            custom_client.meta.events.register("before-call.s3.CompleteMultipartUpload", _add_forwarded_proto)
            custom_client.complete_multipart_upload(
                Bucket=test_bucket, Key=test_key,
                UploadId=custom_upload_id,
                MultipartUpload={"Parts": custom_parts},
            )
            custom_client.meta.events.unregister("before-call.s3.CompleteMultipartUpload", _add_forwarded_proto)

            yield {"key_b64": key_b64, "key_md5": key_md5}

            for client in [aws_client, custom_client]:
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

            parts = _upload_two_parts(
                s3_client, test_bucket, test_key, upload_id, ssec_params,
            )

            if endpoint_is_custom:
                s3_client.meta.events.unregister("before-call.s3.UploadPart", _add_forwarded_proto)
                s3_client.meta.events.register("before-call.s3.CompleteMultipartUpload", _add_forwarded_proto)

            s3_client.complete_multipart_upload(
                Bucket=test_bucket, Key=test_key,
                UploadId=upload_id,
                MultipartUpload={"Parts": parts},
            )

            if endpoint_is_custom:
                s3_client.meta.events.unregister("before-call.s3.CompleteMultipartUpload", _add_forwarded_proto)

            yield {"key_b64": key_b64, "key_md5": key_md5}

            try:
                s3_client.delete_object(Bucket=test_bucket, Key=test_key)
            except Exception:
                pass

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_get_object_after_ssec_multipart_upload(
        self,
        test_bucket,
        test_key,
        completed_ssec_multipart,
        make_request,
        json_metadata,
    ):
        """GetObject with correct SSE-C key should return decrypted multipart content."""
        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": completed_ssec_multipart["key_b64"],
            "x-amz-server-side-encryption-customer-key-MD5": completed_ssec_multipart["key_md5"],
        }

        response = make_request(
            "GET",
            f"/{test_bucket}/{test_key}",
            headers=headers,
        )

        json_metadata["flow"] = "CreateMPU -> UploadPart x2 -> Complete -> GetObject"
        json_metadata["encryption"] = "SSE-C"
        json_metadata["part1_size"] = len(PART1_BODY)
        json_metadata["part2_size"] = len(PART2_BODY)
        json_metadata["total_size"] = len(FULL_BODY)

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 200, (
                f"AWS expected 200, got {response.aws.status_code}: {response.aws.text[:200]}"
            )
            assert response.aws.content == FULL_BODY, (
                f"AWS content mismatch: expected {len(FULL_BODY)} bytes, "
                f"got {len(response.aws.content)} bytes"
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
            assert response.content == FULL_BODY, (
                f"Content mismatch: expected {len(FULL_BODY)} bytes, "
                f"got {len(response.content)} bytes"
            )
            json_metadata["status"] = response.status_code
