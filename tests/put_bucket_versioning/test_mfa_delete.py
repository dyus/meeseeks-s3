"""Tests for PutBucketVersioning MfaDelete element handling.

Verifies S3 behavior with MfaDelete element variations:
- Omitted MfaDelete (optional element)
- Empty MfaDelete element
- Case-sensitive MfaDelete value
- MfaDelete=Disabled with valid Status

Corresponds to putbucketversioning.md tests 7, 8, 11 and
covers MfaDelete presence in tests 1-6.

Supports --endpoint=aws, --endpoint=custom, and --endpoint=both.
"""

import pytest

from s3_compliance.xml_utils import extract_error_info
from tests.put_bucket_versioning.conftest import build_versioning_xml_with_mfa


@pytest.mark.put_bucket_versioning
@pytest.mark.s3_handler("PutBucketVersioning")
class TestPutBucketVersioningMfaDelete:
    """Test PutBucketVersioning MfaDelete element handling."""

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_enabled_with_mfa_delete_disabled(
        self, test_bucket, make_request, json_metadata
    ):
        """Enabled with MfaDelete=Disabled should return 200 (doc test 1)."""
        body = build_versioning_xml_with_mfa("Enabled", mfa_delete="Disabled")
        headers = {"Content-Type": "application/xml"}

        response = make_request(
            "PUT",
            f"/{test_bucket}",
            body=body,
            headers=headers,
            query_params="?versioning",
        )

        json_metadata["versioning_status"] = "Enabled"
        json_metadata["mfa_delete"] = "Disabled"

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 200, (
                f"AWS expected 200, got {response.aws.status_code}: {response.aws.text[:200]}"
            )
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 200, (
                f"Expected 200, got {response.status_code}: {response.text[:200]}"
            )

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_enabled_without_mfa_delete(
        self, test_bucket, make_request, json_metadata
    ):
        """Enabled without MfaDelete element should return 200 (doc test 7).

        MfaDelete is optional — omitting it is valid.
        """
        body = build_versioning_xml_with_mfa("Enabled", mfa_delete=None)
        headers = {"Content-Type": "application/xml"}

        response = make_request(
            "PUT",
            f"/{test_bucket}",
            body=body,
            headers=headers,
            query_params="?versioning",
        )

        json_metadata["versioning_status"] = "Enabled"
        json_metadata["mfa_delete"] = "omitted"

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 200, (
                f"AWS expected 200, got {response.aws.status_code}: {response.aws.text[:200]}"
            )
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 200, (
                f"Expected 200, got {response.status_code}: {response.text[:200]}"
            )

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_enabled_with_empty_mfa_delete(
        self, test_bucket, make_request, json_metadata
    ):
        """Enabled with empty <MfaDelete></MfaDelete> should return 200 (doc test 8).

        Empty MfaDelete is interpreted as absent.
        """
        body = build_versioning_xml_with_mfa("Enabled", mfa_delete="")
        headers = {"Content-Type": "application/xml"}

        response = make_request(
            "PUT",
            f"/{test_bucket}",
            body=body,
            headers=headers,
            query_params="?versioning",
        )

        json_metadata["versioning_status"] = "Enabled"
        json_metadata["mfa_delete"] = "empty"

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 200, (
                f"AWS expected 200, got {response.aws.status_code}: {response.aws.text[:200]}"
            )
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 200, (
                f"Expected 200, got {response.status_code}: {response.text[:200]}"
            )

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_case_sensitive_mfa_delete_lowercase_invalid(
        self, test_bucket, make_request, json_metadata
    ):
        """MfaDelete='disabled' (lowercase) should return 400 MalformedXML (doc test 11).

        MfaDelete value is case-sensitive — only 'Disabled' and 'Enabled' are valid.
        """
        body = build_versioning_xml_with_mfa("Enabled", mfa_delete="disabled")
        headers = {"Content-Type": "application/xml"}

        response = make_request(
            "PUT",
            f"/{test_bucket}",
            body=body,
            headers=headers,
            query_params="?versioning",
        )

        json_metadata["mfa_delete"] = "disabled"

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
    def test_suspended_with_mfa_delete_disabled(
        self, test_bucket, make_request, json_metadata
    ):
        """Suspended with MfaDelete=Disabled should return 200 (doc test 2)."""
        body = build_versioning_xml_with_mfa("Suspended", mfa_delete="Disabled")
        headers = {"Content-Type": "application/xml"}

        response = make_request(
            "PUT",
            f"/{test_bucket}",
            body=body,
            headers=headers,
            query_params="?versioning",
        )

        json_metadata["versioning_status"] = "Suspended"
        json_metadata["mfa_delete"] = "Disabled"

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 200, (
                f"AWS expected 200, got {response.aws.status_code}: {response.aws.text[:200]}"
            )
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 200, (
                f"Expected 200, got {response.status_code}: {response.text[:200]}"
            )
