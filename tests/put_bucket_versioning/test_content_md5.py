"""Tests for PutBucketVersioning Content-MD5 header validation.

Verifies S3 behavior with wrong and missing Content-MD5 headers.

Supports --endpoint=aws, --endpoint=custom, and --endpoint=both.
"""

import pytest

from s3_compliance.utils import calculate_content_md5
from s3_compliance.xml_utils import extract_error_info
from tests.put_bucket_versioning.conftest import build_versioning_xml


@pytest.mark.put_bucket_versioning
@pytest.mark.s3_handler("PutBucketVersioning")
class TestPutBucketVersioningContentMD5:
    """Test PutBucketVersioning Content-MD5 header validation."""

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_wrong_content_md5_rejected(
        self, test_bucket, make_request, json_metadata
    ):
        """Wrong Content-MD5 should return 400 BadDigest."""
        body = build_versioning_xml("Enabled")
        wrong_md5 = calculate_content_md5(b"wrong content that produces different MD5")
        headers = {
            "Content-Type": "application/xml",
            "Content-MD5": wrong_md5,
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}",
            body=body,
            headers=headers,
            query_params="?versioning",
        )

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400, (
                f"AWS expected 400, got {response.aws.status_code}: {response.aws.text[:200]}"
            )
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400, (
                f"Expected 400, got {response.status_code}: {response.text[:200]}"
            )
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_no_content_md5_header(
        self, test_bucket, make_request, json_metadata
    ):
        """Missing Content-MD5 — probe whether AWS requires it or accepts without."""
        body = build_versioning_xml("Enabled")
        headers = {"Content-Type": "application/xml"}

        response = make_request(
            "PUT",
            f"/{test_bucket}",
            body=body,
            headers=headers,
            query_params="?versioning",
        )

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
            if response.aws.status_code >= 400:
                error_code, error_msg = extract_error_info(response.aws.text)
                json_metadata["aws_error_code"] = error_code
                json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            json_metadata["status"] = response.status_code
            if response.status_code >= 400:
                error_code, error_msg = extract_error_info(response.text)
                json_metadata["error_code"] = error_code
                json_metadata["error_message"] = error_msg
