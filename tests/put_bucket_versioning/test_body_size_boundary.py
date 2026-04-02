"""Tests for PutBucketVersioning with body sizes at 1024/1025 byte boundary.

Verifies S3 behavior at the 1KB boundary for valid XML padded with comments.

Supports --endpoint=aws, --endpoint=custom, and --endpoint=both.
"""

import pytest

from s3_compliance.xml_utils import extract_error_info
from tests.put_bucket_versioning.conftest import build_versioning_xml_padded


@pytest.mark.put_bucket_versioning
@pytest.mark.s3_handler("PutBucketVersioning")
class TestPutBucketVersioningBodySizeBoundary:
    """Test PutBucketVersioning with body sizes at 1024/1025 byte boundary."""

    @pytest.mark.edge_case
    @pytest.mark.parametrize(
        "target_bytes",
        [
            pytest.param(1024, id="1024_bytes"),
            pytest.param(1025, id="1025_bytes"),
        ],
    )
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_body_size_boundary(
        self, target_bytes, test_bucket, make_request, json_metadata
    ):
        """Valid XML padded to exactly 1024 / 1025 bytes."""
        body = build_versioning_xml_padded("Enabled", target_bytes=target_bytes)
        headers = {"Content-Type": "application/xml"}

        json_metadata["payload_size_bytes"] = len(body)
        json_metadata["target_bytes"] = target_bytes

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
