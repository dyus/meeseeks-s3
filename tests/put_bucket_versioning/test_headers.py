"""Tests for PutBucketVersioning header edge cases.

Verifies S3 behavior with various header manipulations:
- Missing Content-Type
- Invalid x-amz-content-sha256
- Invalid/missing X-Amz-Date
- Wrong Content-Type values
- Malformed XML with trailing characters

Corresponds to putbucketversioning.md tests 15-18, 20-22.

Supports --endpoint=aws, --endpoint=custom, and --endpoint=both.
"""

import pytest

from s3_compliance.xml_utils import extract_error_info
from tests.put_bucket_versioning.conftest import build_versioning_xml_with_mfa


VERSIONING_XML = build_versioning_xml_with_mfa("Enabled", mfa_delete="Disabled")


@pytest.mark.put_bucket_versioning
@pytest.mark.s3_handler("PutBucketVersioning")
class TestPutBucketVersioningHeaders:
    """Test PutBucketVersioning with header edge cases."""

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_missing_content_type_success(
        self, test_bucket, make_request, json_metadata
    ):
        """Missing Content-Type header should still succeed with 200 (doc test 15).

        AWS does not require Content-Type for PutBucketVersioning.
        """
        response = make_request(
            "PUT",
            f"/{test_bucket}",
            body=VERSIONING_XML,
            headers={},  # no Content-Type
            query_params="?versioning",
        )

        json_metadata["content_type"] = "omitted"

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
    def test_content_type_json_properly_signed(
        self, test_bucket, make_request, json_metadata
    ):
        """Content-Type: application/json with correct SigV4 signature → 200 (doc test 21 CORRECTED).

        Original document claims 403 SignatureDoesNotMatch, but that was caused
        by changing Content-Type AFTER signing. When properly signed with
        application/json, AWS accepts the request and processes the XML body.
        AWS does not validate Content-Type for PutBucketVersioning.
        """
        headers = {"Content-Type": "application/json"}

        response = make_request(
            "PUT",
            f"/{test_bucket}",
            body=VERSIONING_XML,
            headers=headers,
            query_params="?versioning",
        )

        json_metadata["content_type"] = "application/json"

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
    def test_content_type_random_properly_signed(
        self, test_bucket, make_request, json_metadata
    ):
        """Content-Type: randomx with correct SigV4 signature → 200 (doc test 22 CORRECTED).

        Original document claims 403 SignatureDoesNotMatch, but that was caused
        by changing Content-Type AFTER signing. When properly signed with
        any Content-Type, AWS accepts the request. Content-Type is not validated.
        """
        headers = {"Content-Type": "randomx"}

        response = make_request(
            "PUT",
            f"/{test_bucket}",
            body=VERSIONING_XML,
            headers=headers,
            query_params="?versioning",
        )

        json_metadata["content_type"] = "randomx"

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
    def test_invalid_content_sha256(
        self, test_bucket, make_request, json_metadata
    ):
        """Invalid x-amz-content-sha256 should return 400 (doc test 16).

        When x-amz-content-sha256 does not match the actual body hash,
        AWS returns InvalidArgument. Note: the signature is computed with
        the wrong sha256, so AWS may also return XAmzContentSHA256Mismatch
        or SignatureDoesNotMatch depending on validation order.
        """
        headers = {
            "Content-Type": "application/xml",
            "x-amz-content-sha256": "wrong_sha256_hash_value_12345",
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}",
            body=VERSIONING_XML,
            headers=headers,
            query_params="?versioning",
        )

        json_metadata["sha256"] = "wrong_sha256_hash_value_12345"

        if hasattr(response, "comparison"):
            assert response.aws.status_code in (400, 403), (
                f"AWS expected 400/403, got {response.aws.status_code}: {response.aws.text[:200]}"
            )
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code in (400, 403), (
                f"Expected 400/403, got {response.status_code}: {response.text[:200]}"
            )
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg


@pytest.mark.put_bucket_versioning
@pytest.mark.s3_handler("PutBucketVersioning")
class TestPutBucketVersioningMalformedXML:
    """Test PutBucketVersioning with malformed XML structures."""

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_xml_with_trailing_characters(
        self, test_bucket, make_request, json_metadata
    ):
        """Valid XML followed by extra characters should return 400 MalformedXML (doc test 20).

        AWS rejects any content after the closing XML tag.
        """
        body = (
            b'<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
            b"<Status>Enabled</Status>"
            b"<MfaDelete>Disabled</MfaDelete>"
            b"</VersioningConfiguration>"
            b"wrongxml"
        )
        headers = {"Content-Type": "application/xml"}

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
    def test_invalid_status_never_enabled(
        self, test_bucket, make_request, json_metadata
    ):
        """Status='NeverEnabled' should return 400 MalformedXML (doc test 9).

        Only 'Enabled' and 'Suspended' are valid Status values.
        """
        body = build_versioning_xml_with_mfa("NeverEnabled", mfa_delete="Disabled")
        headers = {"Content-Type": "application/xml"}

        response = make_request(
            "PUT",
            f"/{test_bucket}",
            body=body,
            headers=headers,
            query_params="?versioning",
        )

        json_metadata["invalid_status"] = "NeverEnabled"

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400, (
                f"AWS expected 400, got {response.aws.status_code}: {response.aws.text[:200]}"
            )
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert error_code == "MalformedXML", (
                f"Expected MalformedXML, got {error_code}"
            )
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400, (
                f"Expected 400, got {response.status_code}: {response.text[:200]}"
            )
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg
            assert error_code == "MalformedXML", (
                f"Expected MalformedXML, got {error_code}"
            )

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_case_sensitive_status_lowercase(
        self, test_bucket, make_request, json_metadata
    ):
        """Status='enabled' (lowercase) should return 400 MalformedXML (doc test 10).

        Status value is case-sensitive.
        """
        body = build_versioning_xml_with_mfa("enabled", mfa_delete="Disabled")
        headers = {"Content-Type": "application/xml"}

        response = make_request(
            "PUT",
            f"/{test_bucket}",
            body=body,
            headers=headers,
            query_params="?versioning",
        )

        json_metadata["invalid_status"] = "enabled"

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400, (
                f"AWS expected 400, got {response.aws.status_code}: {response.aws.text[:200]}"
            )
            error_code, _ = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            assert error_code == "MalformedXML", f"Expected MalformedXML, got {error_code}"
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400, (
                f"Expected 400, got {response.status_code}: {response.text[:200]}"
            )
            error_code, _ = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            assert error_code == "MalformedXML", f"Expected MalformedXML, got {error_code}"
