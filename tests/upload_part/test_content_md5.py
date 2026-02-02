"""Tests for UploadPart Content-MD5 validation.

These tests verify S3 correctly rejects UploadPart requests when
Content-MD5 header doesn't match the actual body content.

Supports both single endpoint mode (--endpoint=aws or --endpoint=custom)
and comparison mode (--endpoint=both).

Note: In comparison mode, multipart uploads are created on both endpoints
before the test runs.
"""

import uuid

import pytest

from s3_compliance.utils import calculate_content_md5


@pytest.mark.upload_part
@pytest.mark.s3_handler("UploadPart")
class TestUploadPartContentMD5:
    """Test UploadPart API with Content-MD5 validation."""

    @pytest.fixture
    def test_key(self):
        """Generate unique test key."""
        return f"test-upload-part-invalid-md5-{uuid.uuid4().hex[:8]}"

    @pytest.fixture
    def part_content(self):
        """Test part content."""
        return b"test part content for invalid MD5 test"

    @pytest.fixture
    def wrong_md5(self):
        """Calculate MD5 of different content."""
        wrong_content = b"different content that will produce different MD5"
        return calculate_content_md5(wrong_content)

    @pytest.fixture
    def multipart_upload(self, request, s3_client, aws_client, test_bucket, test_key):
        """Create and cleanup multipart upload.

        In comparison mode (--endpoint=both), creates uploads on both endpoints.
        Returns upload_id or dict of upload_ids.
        """
        endpoint_mode = request.config.getoption("--endpoint")

        if endpoint_mode == "both":
            # Create multipart uploads on both endpoints
            aws_response = aws_client.create_multipart_upload(Bucket=test_bucket, Key=test_key)
            aws_upload_id = aws_response["UploadId"]

            # For custom client, get it from factory
            from s3_compliance.client import S3ClientFactory
            factory = S3ClientFactory()
            custom_client = factory.create_client("custom")
            custom_response = custom_client.create_multipart_upload(Bucket=test_bucket, Key=test_key)
            custom_upload_id = custom_response["UploadId"]

            yield {"aws": aws_upload_id, "custom": custom_upload_id}

            # Cleanup both
            try:
                aws_client.abort_multipart_upload(
                    Bucket=test_bucket, Key=test_key, UploadId=aws_upload_id
                )
            except Exception:
                pass
            try:
                custom_client.abort_multipart_upload(
                    Bucket=test_bucket, Key=test_key, UploadId=custom_upload_id
                )
            except Exception:
                pass
        else:
            # Single endpoint mode
            response = s3_client.create_multipart_upload(Bucket=test_bucket, Key=test_key)
            upload_id = response["UploadId"]

            yield upload_id

            # Cleanup
            try:
                s3_client.abort_multipart_upload(
                    Bucket=test_bucket, Key=test_key, UploadId=upload_id
                )
            except Exception:
                pass

    @pytest.mark.edge_case
    def test_invalid_content_md5_rejected(
        self,
        s3_client,
        test_bucket,
        test_key,
        part_content,
        wrong_md5,
        multipart_upload,
        make_request,
        request,
    ):
        """Server should reject UploadPart with invalid Content-MD5."""
        endpoint_mode = request.config.getoption("--endpoint")

        headers = {
            "Content-Type": "application/octet-stream",
            "Content-MD5": wrong_md5,  # INVALID MD5
        }

        if endpoint_mode == "both":
            # Comparison mode - make requests to both endpoints with their respective upload IDs
            # This is more complex as we need different query params for each endpoint
            from botocore.credentials import Credentials
            from s3_compliance.signing import sign_request
            from s3_compliance.utils import calculate_content_sha256
            from s3_compliance.comparison import compare_responses, ComparisonResponse
            import requests as http_requests
            import os

            aws_upload_id = multipart_upload["aws"]
            custom_upload_id = multipart_upload["custom"]

            # Get AWS config
            aws_endpoint = os.getenv("AWS_S3_ENDPOINT", "https://s3.us-east-1.amazonaws.com")
            aws_region = os.getenv("AWS_REGION", "us-east-1")
            import boto3
            aws_session = boto3.Session(profile_name=os.getenv("AWS_PROFILE", "aws"))
            aws_creds = aws_session.get_credentials()
            aws_creds_obj = Credentials(aws_creds.access_key, aws_creds.secret_key, aws_creds.token)

            # Get custom config
            custom_endpoint = os.getenv("S3_ENDPOINT")
            custom_region = os.getenv("CUSTOM_S3_REGION", "eu-west-1")
            custom_profile = os.getenv("CUSTOM_S3_PROFILE", os.getenv("AWS_PROFILE", "aws"))
            custom_session = boto3.Session(profile_name=custom_profile)
            custom_creds = custom_session.get_credentials()
            custom_creds_obj = Credentials(custom_creds.access_key, custom_creds.secret_key, custom_creds.token)

            # Make AWS request
            aws_url = f"{aws_endpoint}/{test_bucket}/{test_key}?uploadId={aws_upload_id}&partNumber=1"
            aws_headers = dict(headers)
            aws_headers["Content-Length"] = str(len(part_content))
            aws_headers["x-amz-content-sha256"] = calculate_content_sha256(part_content)
            aws_signed = sign_request("PUT", aws_url, aws_headers, part_content, aws_creds_obj, aws_region)
            aws_response = http_requests.put(aws_url, data=part_content, headers=aws_signed, verify=False)

            # Make custom request
            custom_url = f"{custom_endpoint}/{test_bucket}/{test_key}?uploadId={custom_upload_id}&partNumber=1"
            custom_headers = dict(headers)
            custom_headers["Content-Length"] = str(len(part_content))
            custom_headers["x-amz-content-sha256"] = calculate_content_sha256(part_content)
            custom_signed = sign_request("PUT", custom_url, custom_headers, part_content, custom_creds_obj, custom_region)
            custom_response = http_requests.put(custom_url, data=part_content, headers=custom_signed, verify=False)

            # Compare
            comparison = compare_responses(
                {"status_code": aws_response.status_code, "headers": dict(aws_response.headers), "body": aws_response.text},
                {"status_code": custom_response.status_code, "headers": dict(custom_response.headers), "body": custom_response.text},
                "test_invalid_content_md5_rejected",
            )

            response = ComparisonResponse(aws=aws_response, custom=custom_response, comparison=comparison)

            assert response.aws.status_code == 400, (
                f"AWS expected 400 Bad Request, got {response.aws.status_code}"
            )
            assert "BadDigest" in response.aws.text or "bad digest" in response.aws.text.lower(), (
                f"AWS expected BadDigest error, got: {response.aws.text[:200]}"
            )
            assert response.comparison.is_compliant, (
                f"Custom S3 doesn't match AWS: {response.diff_summary}"
            )
        else:
            # Single endpoint mode
            upload_id = multipart_upload
            response = make_request(
                "PUT",
                f"/{test_bucket}/{test_key}",
                body=part_content,
                headers=headers,
                query_params=f"?uploadId={upload_id}&partNumber=1",
            )

            assert response.status_code == 400, (
                f"Expected 400 Bad Request, got {response.status_code}"
            )
            assert "BadDigest" in response.text or "bad digest" in response.text.lower(), (
                f"Expected BadDigest error, got: {response.text[:200]}"
            )

    @pytest.mark.edge_case
    def test_correct_content_md5_accepted(
        self,
        s3_client,
        test_bucket,
        test_key,
        part_content,
        multipart_upload,
        make_request,
        request,
    ):
        """Server should accept UploadPart with correct Content-MD5."""
        endpoint_mode = request.config.getoption("--endpoint")
        correct_md5 = calculate_content_md5(part_content)

        headers = {
            "Content-Type": "application/octet-stream",
            "Content-MD5": correct_md5,  # CORRECT MD5
        }

        if endpoint_mode == "both":
            # Comparison mode - similar handling as above
            from botocore.credentials import Credentials
            from s3_compliance.signing import sign_request
            from s3_compliance.utils import calculate_content_sha256
            from s3_compliance.comparison import compare_responses, ComparisonResponse
            import requests as http_requests
            import os

            aws_upload_id = multipart_upload["aws"]
            custom_upload_id = multipart_upload["custom"]

            # Get AWS config
            aws_endpoint = os.getenv("AWS_S3_ENDPOINT", "https://s3.us-east-1.amazonaws.com")
            aws_region = os.getenv("AWS_REGION", "us-east-1")
            import boto3
            aws_session = boto3.Session(profile_name=os.getenv("AWS_PROFILE", "aws"))
            aws_creds = aws_session.get_credentials()
            aws_creds_obj = Credentials(aws_creds.access_key, aws_creds.secret_key, aws_creds.token)

            # Get custom config
            custom_endpoint = os.getenv("S3_ENDPOINT")
            custom_region = os.getenv("CUSTOM_S3_REGION", "eu-west-1")
            custom_profile = os.getenv("CUSTOM_S3_PROFILE", os.getenv("AWS_PROFILE", "aws"))
            custom_session = boto3.Session(profile_name=custom_profile)
            custom_creds = custom_session.get_credentials()
            custom_creds_obj = Credentials(custom_creds.access_key, custom_creds.secret_key, custom_creds.token)

            # Make AWS request
            aws_url = f"{aws_endpoint}/{test_bucket}/{test_key}?uploadId={aws_upload_id}&partNumber=1"
            aws_headers = dict(headers)
            aws_headers["Content-Length"] = str(len(part_content))
            aws_headers["x-amz-content-sha256"] = calculate_content_sha256(part_content)
            aws_signed = sign_request("PUT", aws_url, aws_headers, part_content, aws_creds_obj, aws_region)
            aws_response = http_requests.put(aws_url, data=part_content, headers=aws_signed, verify=False)

            # Make custom request
            custom_url = f"{custom_endpoint}/{test_bucket}/{test_key}?uploadId={custom_upload_id}&partNumber=1"
            custom_headers = dict(headers)
            custom_headers["Content-Length"] = str(len(part_content))
            custom_headers["x-amz-content-sha256"] = calculate_content_sha256(part_content)
            custom_signed = sign_request("PUT", custom_url, custom_headers, part_content, custom_creds_obj, custom_region)
            custom_response = http_requests.put(custom_url, data=part_content, headers=custom_signed, verify=False)

            # Compare
            comparison = compare_responses(
                {"status_code": aws_response.status_code, "headers": dict(aws_response.headers), "body": aws_response.text},
                {"status_code": custom_response.status_code, "headers": dict(custom_response.headers), "body": custom_response.text},
                "test_correct_content_md5_accepted",
            )

            response = ComparisonResponse(aws=aws_response, custom=custom_response, comparison=comparison)

            assert response.aws.status_code == 200, (
                f"AWS expected 200, got {response.aws.status_code}: {response.aws.text[:200]}"
            )
            assert "ETag" in response.aws.headers, "AWS expected ETag in response headers"
            assert response.comparison.is_compliant, (
                f"Custom S3 doesn't match AWS: {response.diff_summary}"
            )
        else:
            # Single endpoint mode
            upload_id = multipart_upload
            response = make_request(
                "PUT",
                f"/{test_bucket}/{test_key}",
                body=part_content,
                headers=headers,
                query_params=f"?uploadId={upload_id}&partNumber=1",
            )

            assert response.status_code == 200, (
                f"Expected 200, got {response.status_code}: {response.text[:200]}"
            )
            assert "ETag" in response.headers, "Expected ETag in response headers"
