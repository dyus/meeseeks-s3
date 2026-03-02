"""Happy path test for ListParts on SSE-C multipart upload.

End-to-end test that verifies ListParts on an SSE-C multipart upload:
1. CreateMultipartUpload with SSE-C headers
2. UploadPart x2 with SSE-C headers (5 MB + 1 KB)
3. ListParts — verify parts are listed correctly

ListParts (GET /{bucket}/{key}?uploadId={id}) should work without SSE-C headers,
since it only returns part metadata (not encrypted content).
"""

import uuid

import pytest

from s3_compliance.sse_c import generate_sse_c_key
from s3_compliance.xml_utils import extract_error_info


PART1_SIZE = 5 * 1024 * 1024  # 5 MB — minimum for non-last part
PART2_SIZE = 1024  # 1 KB — last part, no minimum

PART1_BODY = b"A" * PART1_SIZE
PART2_BODY = b"B" * PART2_SIZE


def _upload_two_parts(client, bucket, key, upload_id, ssec_params, record=None, endpoint=""):
    """Upload two parts and return list of {PartNumber, ETag} dicts."""
    part1 = client.upload_part(
        Bucket=bucket, Key=key,
        UploadId=upload_id, PartNumber=1,
        Body=PART1_BODY, **ssec_params,
    )
    if record:
        record("UploadPart", part1, endpoint, PartNumber=1, Size="5 MB", SSE_C="AES256")
    part2 = client.upload_part(
        Bucket=bucket, Key=key,
        UploadId=upload_id, PartNumber=2,
        Body=PART2_BODY, **ssec_params,
    )
    if record:
        record("UploadPart", part2, endpoint, PartNumber=2, Size="1 KB", SSE_C="AES256")
    return [
        {"PartNumber": 1, "ETag": part1["ETag"]},
        {"PartNumber": 2, "ETag": part2["ETag"]},
    ]


@pytest.mark.s3_handler("ListParts")
@pytest.mark.sse_c
class TestSSECListPartsHappyPath:
    """Happy path: ListParts on SSE-C multipart upload with uploaded parts."""

    @pytest.fixture
    def test_key(self):
        """Generate unique test key."""
        return f"test-ssec-list-parts-{uuid.uuid4().hex[:8]}"

    @pytest.fixture
    def ssec_mpu_with_parts(self, request, s3_client, aws_client, test_bucket, test_key, setup_steps):
        """Create SSE-C multipart upload and upload 2 parts.

        Returns upload_id(s) for ListParts.
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
            setup_steps("CreateMultipartUpload", aws_mpu, "aws", SSE_C="AES256")
            _upload_two_parts(
                aws_client, test_bucket, test_key, aws_upload_id, ssec_params,
                record=setup_steps, endpoint="aws",
            )

            # Custom
            factory = S3ClientFactory()
            custom_client = factory.create_client("custom")
            custom_mpu = custom_client.create_multipart_upload(
                Bucket=test_bucket, Key=test_key, **ssec_params,
            )
            custom_upload_id = custom_mpu["UploadId"]
            setup_steps("CreateMultipartUpload", custom_mpu, "custom", SSE_C="AES256")
            _upload_two_parts(
                custom_client, test_bucket, test_key, custom_upload_id, ssec_params,
                record=setup_steps, endpoint="custom",
            )

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
            _upload_two_parts(
                s3_client, test_bucket, test_key, upload_id, ssec_params,
                record=setup_steps,
            )

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

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_list_parts_without_sse_c_headers(
        self,
        test_bucket,
        test_key,
        ssec_mpu_with_parts,
        make_request,
        request,
        json_metadata,
    ):
        """ListParts without SSE-C headers should succeed on SSE-C multipart upload.

        ListParts returns part metadata only, not encrypted content.
        """
        response = self._make_list_parts_request(
            make_request, request, test_bucket, test_key,
            ssec_mpu_with_parts,
        )

        json_metadata["flow"] = "CreateMPU(SSE-C) -> UploadPart x2 -> ListParts (no SSE-C)"
        json_metadata["encryption"] = "SSE-C"
        json_metadata["sse_c_headers_sent"] = False

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 200, (
                f"AWS expected 200, got {response.aws.status_code}: {response.aws.text[:200]}"
            )
            assert "<Part>" in response.aws.text, "AWS response should contain <Part> elements"
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
            assert response.comparison.is_compliant, (
                f"Custom S3 doesn't match AWS: {response.diff_summary}"
            )
        else:
            assert response.status_code == 200, (
                f"Expected 200, got {response.status_code}: {response.text[:200]}"
            )
            assert "<Part>" in response.text, "Response should contain <Part> elements"
            json_metadata["status"] = response.status_code

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_list_parts_with_sse_c_headers(
        self,
        test_bucket,
        test_key,
        ssec_mpu_with_parts,
        make_request,
        request,
        json_metadata,
    ):
        """ListParts with SSE-C headers should also succeed.

        Even though SSE-C headers are not required for ListParts,
        sending them should not cause an error.
        """
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_list_parts_request(
            make_request, request, test_bucket, test_key,
            ssec_mpu_with_parts, headers=headers,
        )

        json_metadata["flow"] = "CreateMPU(SSE-C) -> UploadPart x2 -> ListParts (with SSE-C)"
        json_metadata["encryption"] = "SSE-C"
        json_metadata["sse_c_headers_sent"] = True

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 200, (
                f"AWS expected 200, got {response.aws.status_code}: {response.aws.text[:200]}"
            )
            assert "<Part>" in response.aws.text, "AWS response should contain <Part> elements"
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
            assert response.comparison.is_compliant, (
                f"Custom S3 doesn't match AWS: {response.diff_summary}"
            )
        else:
            assert response.status_code == 200, (
                f"Expected 200, got {response.status_code}: {response.text[:200]}"
            )
            assert "<Part>" in response.text, "Response should contain <Part> elements"
            json_metadata["status"] = response.status_code
