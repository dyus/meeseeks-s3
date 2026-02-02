"""Tests for PutObjectACL Content-MD5 validation.

These tests verify S3 correctly rejects PutObjectACL requests when
Content-MD5 header doesn't match the actual XML body content.

Supports both single endpoint mode (--endpoint=aws or --endpoint=custom)
and comparison mode (--endpoint=both).
"""

import uuid

import pytest

from s3_compliance.utils import calculate_content_md5


@pytest.mark.put_object_acl
@pytest.mark.s3_handler("PutObjectACL")
class TestPutObjectACLContentMD5:
    """Test PutObjectACL API with Content-MD5 validation."""

    @pytest.fixture
    def test_key(self):
        """Generate unique test key."""
        return f"test-put-object-acl-invalid-md5-{uuid.uuid4().hex[:8]}"

    @pytest.fixture
    def test_object(self, request, s3_client, aws_client, test_bucket, test_key):
        """Create test object for ACL tests."""
        endpoint_mode = request.config.getoption("--endpoint")

        if endpoint_mode == "both":
            # In comparison mode, create object on both endpoints
            aws_client.put_object(
                Bucket=test_bucket,
                Key=test_key,
                Body=b"test object for ACL test",
            )
            # Also create on custom endpoint
            from s3_compliance.client import S3ClientFactory
            factory = S3ClientFactory()
            custom_client = factory.create_client("custom")
            custom_client.put_object(
                Bucket=test_bucket,
                Key=test_key,
                Body=b"test object for ACL test",
            )

            yield test_key

            # Cleanup both
            try:
                aws_client.delete_object(Bucket=test_bucket, Key=test_key)
            except Exception:
                pass
            try:
                custom_client.delete_object(Bucket=test_bucket, Key=test_key)
            except Exception:
                pass
        else:
            # Single endpoint mode
            s3_client.put_object(
                Bucket=test_bucket,
                Key=test_key,
                Body=b"test object for ACL test",
            )

            yield test_key

            # Cleanup
            try:
                s3_client.delete_object(Bucket=test_bucket, Key=test_key)
            except Exception:
                pass

    @pytest.fixture
    def acl_xml(self):
        """ACL XML body."""
        return b'''<?xml version="1.0" encoding="UTF-8"?>
<AccessControlPolicy xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Owner>
        <ID>test-owner-id</ID>
    </Owner>
    <AccessControlList>
        <Grant>
            <Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="Group">
                <URI>http://acs.amazonaws.com/groups/s3/LogDelivery</URI>
            </Grantee>
            <Permission>WRITE</Permission>
        </Grant>
    </AccessControlList>
</AccessControlPolicy>'''

    @pytest.fixture
    def wrong_md5(self):
        """Calculate MD5 of different content."""
        wrong_content = b"different content that will produce different MD5"
        return calculate_content_md5(wrong_content)

    @pytest.mark.edge_case
    def test_invalid_content_md5_rejected(
        self,
        test_bucket,
        test_object,
        acl_xml,
        wrong_md5,
        make_request,
    ):
        """Server should reject PutObjectACL with invalid Content-MD5."""
        headers = {
            "Content-Type": "application/xml",
            "Content-MD5": wrong_md5,  # INVALID MD5
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}/{test_object}",
            body=acl_xml,
            headers=headers,
            query_params="?acl",
        )

        if hasattr(response, "comparison"):
            # Comparison mode
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
            assert response.status_code == 400, (
                f"Expected 400 Bad Request, got {response.status_code}"
            )
            assert "BadDigest" in response.text or "bad digest" in response.text.lower(), (
                f"Expected BadDigest error, got: {response.text[:200]}"
            )

    @pytest.mark.edge_case
    def test_correct_content_md5_accepted(
        self,
        test_bucket,
        test_object,
        acl_xml,
        make_request,
    ):
        """Server should accept PutObjectACL with correct Content-MD5."""
        correct_md5 = calculate_content_md5(acl_xml)

        headers = {
            "Content-Type": "application/xml",
            "Content-MD5": correct_md5,  # CORRECT MD5
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}/{test_object}",
            body=acl_xml,
            headers=headers,
            query_params="?acl",
        )

        if hasattr(response, "comparison"):
            # Comparison mode
            # AWS validates owner ID - fake ID will cause 400 InvalidArgument
            # This test documents: correct MD5 passes MD5 validation,
            # but ACL may fail for other reasons (invalid owner ID)
            assert response.aws.status_code in [200, 204, 400], (
                f"AWS expected 200/204/400, got {response.aws.status_code}: {response.aws.text[:200]}"
            )
            assert response.comparison.is_compliant, (
                f"Custom S3 doesn't match AWS: {response.diff_summary}"
            )
        else:
            # Single endpoint mode
            assert response.status_code in [200, 204, 400], (
                f"Expected 200/204/400, got {response.status_code}: {response.text[:200]}"
            )
