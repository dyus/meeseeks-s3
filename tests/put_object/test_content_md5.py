"""Tests for PutObject Content-MD5 validation.

These tests verify S3 correctly rejects PutObject requests when
Content-MD5 header doesn't match the actual body content.

Supports both single endpoint mode (--endpoint=aws or --endpoint=custom)
and comparison mode (--endpoint=both).
"""

import re
import uuid

import pytest

from s3_compliance.utils import calculate_content_md5


@pytest.mark.put_object
@pytest.mark.s3_handler("PutObject")
class TestPutObjectContentMD5:
    """Test PutObject API with Content-MD5 validation."""

    @pytest.fixture
    def test_key(self):
        """Generate unique test key."""
        return f"test-invalid-md5-{uuid.uuid4().hex[:8]}"

    @pytest.fixture
    def test_body(self):
        """Test content."""
        return b"test content for invalid MD5 test"

    @pytest.fixture
    def wrong_md5(self):
        """Calculate MD5 of different content (will be wrong for test_body)."""
        wrong_content = b"different content that will produce different MD5"
        return calculate_content_md5(wrong_content)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_invalid_content_md5_rejected(
        self,
        s3_client,
        test_bucket,
        test_key,
        test_body,
        wrong_md5,
        make_request,
    ):
        """Server should reject PutObject with invalid Content-MD5."""
        headers = {
            "Content-Type": "text/plain",
            "Content-MD5": wrong_md5,  # INVALID MD5
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}/{test_key}",
            body=test_body,
            headers=headers,
        )

        if hasattr(response, "comparison"):
            # Comparison mode: verify AWS behavior first, then check compliance
            assert response.aws.status_code == 400, (
                f"AWS expected 400 Bad Request, got {response.aws.status_code}"
            )
            assert "BadDigest" in response.aws.text or "bad digest" in response.aws.text.lower(), (
                f"AWS expected BadDigest error, got: {response.aws.text[:200]}"
            )
            # Check custom matches AWS
            assert response.comparison.is_compliant, (
                f"Custom S3 doesn't match AWS: {response.diff_summary}"
            )
        else:
            # Single endpoint mode
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
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_correct_content_md5_accepted(
        self,
        s3_client,
        test_bucket,
        test_key,
        test_body,
        make_request,
    ):
        """Server should accept PutObject with correct Content-MD5."""
        correct_md5 = calculate_content_md5(test_body)

        headers = {
            "Content-Type": "text/plain",
            "Content-MD5": correct_md5,  # CORRECT MD5
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}/{test_key}",
            body=test_body,
            headers=headers,
        )

        if hasattr(response, "comparison"):
            # Comparison mode
            assert response.aws.status_code in [200, 204], (
                f"AWS expected 200/204, got {response.aws.status_code}: {response.aws.text[:200]}"
            )
            assert response.comparison.is_compliant, (
                f"Custom S3 doesn't match AWS: {response.diff_summary}"
            )
        else:
            # Single endpoint mode
            assert response.status_code in [200, 204], (
                f"Expected 200/204, got {response.status_code}: {response.text[:200]}"
            )

        # Cleanup
        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_no_content_md5_accepted(
        self,
        s3_client,
        test_bucket,
        test_key,
        test_body,
        make_request,
    ):
        """Server should accept PutObject without Content-MD5 header."""
        headers = {
            "Content-Type": "text/plain",
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}/{test_key}",
            body=test_body,
            headers=headers,
        )

        if hasattr(response, "comparison"):
            # Comparison mode
            assert response.aws.status_code in [200, 204], (
                f"AWS expected 200/204, got {response.aws.status_code}: {response.aws.text[:200]}"
            )
            assert response.comparison.is_compliant, (
                f"Custom S3 doesn't match AWS: {response.diff_summary}"
            )
        else:
            # Single endpoint mode
            assert response.status_code in [200, 204], (
                f"Expected 200/204, got {response.status_code}: {response.text[:200]}"
            )

        # Cleanup
        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_bad_digest_error_format(
        self,
        s3_client,
        test_bucket,
        test_key,
        test_body,
        wrong_md5,
        make_request,
        json_metadata,
    ):
        """Verify BadDigest error response format."""
        headers = {
            "Content-Type": "text/plain",
            "Content-MD5": wrong_md5,
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}/{test_key}",
            body=test_body,
            headers=headers,
        )

        # Get the response text (works for both modes)
        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            response_text = response.aws.text
            # In comparison mode, also verify compliance
            assert response.comparison.is_compliant, (
                f"Custom S3 doesn't match AWS: {response.diff_summary}"
            )
        else:
            assert response.status_code == 400
            response_text = response.text

        # Check for ExpectedDigest element
        expected_match = re.search(r"<ExpectedDigest>(.*?)</ExpectedDigest>", response_text)
        calculated_match = re.search(r"<CalculatedDigest>(.*?)</CalculatedDigest>", response_text)

        json_metadata["has_expected_digest"] = expected_match is not None
        json_metadata["has_calculated_digest"] = calculated_match is not None

        if expected_match:
            expected_digest = expected_match.group(1)
            json_metadata["expected_digest"] = expected_digest
            # Check format (hex vs base64)
            if len(expected_digest) == 32 and all(
                c in "0123456789abcdef" for c in expected_digest.lower()
            ):
                json_metadata["expected_digest_format"] = "hex"
            else:
                json_metadata["expected_digest_format"] = "base64"

        if calculated_match:
            calculated_digest = calculated_match.group(1)
            json_metadata["calculated_digest"] = calculated_digest

        # Cleanup
        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass
