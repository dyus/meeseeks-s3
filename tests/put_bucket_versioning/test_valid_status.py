"""Tests for PutBucketVersioning happy path — valid Status values.

Verifies that S3 accepts Enabled and Suspended status values,
and that re-applying the same status is idempotent (200).

Supports --endpoint=aws, --endpoint=custom, and --endpoint=both.
"""

import pytest

from tests.put_bucket_versioning.conftest import build_versioning_xml


@pytest.mark.put_bucket_versioning
@pytest.mark.s3_handler("PutBucketVersioning")
class TestPutBucketVersioningValidStatus:
    """Test PutBucketVersioning with valid Status values."""

    @pytest.mark.parametrize(
        "status",
        [
            pytest.param("Enabled", id="enable"),
            pytest.param("Suspended", id="suspend"),
        ],
    )
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_valid_status_accepted(
        self, status, test_bucket, make_request, json_metadata
    ):
        """Valid Status values should return 200."""
        body = build_versioning_xml(status)
        headers = {"Content-Type": "application/xml"}

        response = make_request(
            "PUT",
            f"/{test_bucket}",
            body=body,
            headers=headers,
            query_params="?versioning",
        )

        json_metadata["versioning_status"] = status

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 200, (
                f"AWS expected 200, got {response.aws.status_code}: {response.aws.text[:200]}"
            )
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 200, (
                f"Expected 200, got {response.status_code}: {response.text[:200]}"
            )
            json_metadata["status"] = response.status_code

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_re_enable_already_enabled(
        self, test_bucket, make_request, json_metadata
    ):
        """Re-enabling versioning on already-Enabled bucket is idempotent (200)."""
        body = build_versioning_xml("Enabled")
        headers = {"Content-Type": "application/xml"}

        # First call: prime state to Enabled
        make_request(
            "PUT",
            f"/{test_bucket}",
            body=body,
            headers=headers,
            query_params="?versioning",
        )

        # Second call: re-enable — should still be 200
        response = make_request(
            "PUT",
            f"/{test_bucket}",
            body=body,
            headers=headers,
            query_params="?versioning",
        )

        json_metadata["test_type"] = "idempotent_re_enable"

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 200, (
                f"AWS expected 200, got {response.aws.status_code}"
            )
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 200, (
                f"Expected 200, got {response.status_code}"
            )

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_re_suspend_already_suspended(
        self, test_bucket, make_request, json_metadata
    ):
        """Re-suspending versioning on already-Suspended bucket is idempotent (200)."""
        body_suspend = build_versioning_xml("Suspended")
        headers = {"Content-Type": "application/xml"}

        # First call: prime state to Suspended
        make_request(
            "PUT",
            f"/{test_bucket}",
            body=body_suspend,
            headers=headers,
            query_params="?versioning",
        )

        # Second call: re-suspend — should still be 200
        response = make_request(
            "PUT",
            f"/{test_bucket}",
            body=body_suspend,
            headers=headers,
            query_params="?versioning",
        )

        json_metadata["test_type"] = "idempotent_re_suspend"

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 200, (
                f"AWS expected 200, got {response.aws.status_code}"
            )
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 200, (
                f"Expected 200, got {response.status_code}"
            )
