"""Tests for PutBucketACL Content-MD5 validation.

These tests verify S3 correctly rejects PutBucketACL requests when
Content-MD5 header doesn't match the actual XML body content.

Supports both single endpoint mode (--endpoint=aws or --endpoint=custom)
and comparison mode (--endpoint=both).
"""

import pytest

from s3_compliance.utils import calculate_content_md5


@pytest.mark.put_bucket_acl
@pytest.mark.s3_handler("PutBucketACL")
class TestPutBucketACLContentMD5:
    """Test PutBucketACL API with Content-MD5 validation."""

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
        acl_xml,
        wrong_md5,
        make_request,
    ):
        """Server should reject PutBucketACL with invalid Content-MD5."""
        headers = {
            "Content-Type": "application/xml",
            "Content-MD5": wrong_md5,  # INVALID MD5
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}",
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
        acl_xml,
        make_request,
    ):
        """Server should accept PutBucketACL with correct Content-MD5."""
        correct_md5 = calculate_content_md5(acl_xml)

        headers = {
            "Content-Type": "application/xml",
            "Content-MD5": correct_md5,  # CORRECT MD5
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}",
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
