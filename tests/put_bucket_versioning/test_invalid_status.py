"""Tests for PutBucketVersioning with invalid Status values.

Verifies that S3 rejects Status values other than Enabled/Suspended
with IllegalVersioningConfigurationException (400).

Supports --endpoint=aws, --endpoint=custom, and --endpoint=both.
"""

import pytest

from s3_compliance.xml_utils import extract_error_info
from tests.put_bucket_versioning.conftest import build_versioning_xml


INVALID_STATUSES = [
    pytest.param("Disabled", id="disabled"),
    pytest.param("enabled", id="lowercase"),
    pytest.param("ENABLED", id="uppercase"),
    pytest.param("Foo", id="arbitrary_string"),
]


@pytest.mark.put_bucket_versioning
@pytest.mark.s3_handler("PutBucketVersioning")
class TestPutBucketVersioningInvalidStatus:
    """Test PutBucketVersioning with invalid Status values."""

    @pytest.mark.edge_case
    @pytest.mark.parametrize("invalid_status", INVALID_STATUSES)
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_invalid_status_rejected(
        self, invalid_status, test_bucket, make_request, json_metadata
    ):
        """Invalid Status values should return 400."""
        body = build_versioning_xml(invalid_status)
        headers = {"Content-Type": "application/xml"}

        response = make_request(
            "PUT",
            f"/{test_bucket}",
            body=body,
            headers=headers,
            query_params="?versioning",
        )

        json_metadata["invalid_status"] = invalid_status

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
