"""Tests for PostObject Content-MD5 validation.

These tests verify S3 correctly rejects POST Object (form upload) requests when
Content-MD5 field doesn't match the actual file content.
"""

import io
import uuid

import pytest
import requests

from s3_compliance.utils import calculate_content_md5


@pytest.mark.post_object
@pytest.mark.s3_handler("PostObject")
class TestPostObjectContentMD5:
    """Test POST Object (form upload) API with Content-MD5 validation."""

    @pytest.fixture
    def test_key(self):
        """Generate unique test key."""
        return f"test-post-invalid-md5-{uuid.uuid4().hex[:8]}"

    @pytest.fixture
    def file_content(self):
        """Test file content."""
        return b"test file content for invalid MD5 test"

    @pytest.fixture
    def wrong_md5(self):
        """Calculate MD5 of different content."""
        wrong_content = b"different content that will produce different MD5"
        return calculate_content_md5(wrong_content)

    @pytest.fixture
    def presigned_post(self, s3_client, test_bucket, test_key):
        """Generate presigned POST with Content-MD5 allowed in policy."""
        presigned = s3_client.generate_presigned_post(
            Bucket=test_bucket,
            Key=test_key,
            Fields=None,
            Conditions=[
                ["starts-with", "$Content-MD5", ""],  # Allow any Content-MD5 value
            ],
            ExpiresIn=3600,
        )
        return presigned

    @pytest.mark.edge_case
    def test_invalid_content_md5_rejected(
        self,
        s3_client,
        test_bucket,
        test_key,
        file_content,
        wrong_md5,
        presigned_post,
    ):
        """Server should reject POST Object with invalid Content-MD5."""
        url = presigned_post["url"]
        post_fields = presigned_post["fields"].copy()

        # Add invalid Content-MD5
        post_fields["Content-MD5"] = wrong_md5

        files = {"file": ("test_file.txt", io.BytesIO(file_content), "text/plain")}

        response = requests.post(url, data=post_fields, files=files, verify=False)

        # Should be rejected with 400 BadDigest
        assert response.status_code == 400, (
            f"Expected 400 Bad Request, got {response.status_code}"
        )
        assert "BadDigest" in response.text or "bad digest" in response.text.lower(), (
            f"Expected BadDigest error, got: {response.text[:200]}"
        )

        # Cleanup
        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    @pytest.mark.edge_case
    def test_correct_content_md5_accepted(
        self,
        s3_client,
        test_bucket,
        test_key,
        file_content,
        presigned_post,
    ):
        """Server should accept POST Object with correct Content-MD5."""
        url = presigned_post["url"]
        post_fields = presigned_post["fields"].copy()

        # Add correct Content-MD5
        correct_md5 = calculate_content_md5(file_content)
        post_fields["Content-MD5"] = correct_md5

        files = {"file": ("test_file.txt", io.BytesIO(file_content), "text/plain")}

        response = requests.post(url, data=post_fields, files=files, verify=False)

        # Should succeed
        assert response.status_code in [200, 201, 204], (
            f"Expected success, got {response.status_code}: {response.text[:200]}"
        )

        # Cleanup
        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    @pytest.mark.edge_case
    def test_no_content_md5_accepted(
        self,
        s3_client,
        test_bucket,
        test_key,
        file_content,
    ):
        """Server should accept POST Object without Content-MD5 field."""
        # Generate presigned POST without Content-MD5 condition
        presigned = s3_client.generate_presigned_post(
            Bucket=test_bucket,
            Key=test_key,
            Fields=None,
            Conditions=None,
            ExpiresIn=3600,
        )

        url = presigned["url"]
        post_fields = presigned["fields"].copy()

        files = {"file": ("test_file.txt", io.BytesIO(file_content), "text/plain")}

        response = requests.post(url, data=post_fields, files=files, verify=False)

        # Should succeed (Content-MD5 is optional)
        assert response.status_code in [200, 201, 204], (
            f"Expected success, got {response.status_code}: {response.text[:200]}"
        )

        # Cleanup
        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass
