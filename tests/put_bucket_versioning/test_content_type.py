"""Tests for PutBucketVersioning Content-Type header variations.

Verifies S3 behavior when Content-Type is set to non-standard values.
With correct SigV4 signature (covering Content-Type), AWS should accept
the request regardless of the Content-Type value.

Supports --endpoint=aws, --endpoint=custom, and --endpoint=both.
"""

import pytest

from s3_compliance.xml_utils import extract_error_info
from tests.put_bucket_versioning.conftest import build_versioning_xml


@pytest.mark.put_bucket_versioning
@pytest.mark.s3_handler("PutBucketVersioning")
class TestPutBucketVersioningContentType:
    """Test PutBucketVersioning with various Content-Type values."""

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_random_content_type_accepted(
        self, test_bucket, make_request, json_metadata,
    ):
        """Content-Type: randomx with valid signature should be accepted (200)."""
        body = build_versioning_xml("Enabled")
        headers = {"Content-Type": "randomx"}

        response = make_request(
            "PUT",
            f"/{test_bucket}",
            body=body,
            headers=headers,
            query_params="?versioning",
        )

        json_metadata["content_type"] = "randomx"

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

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_empty_content_type(
        self, test_bucket, make_request, json_metadata,
    ):
        """Content-Type: (empty string) with valid signature."""
        body = build_versioning_xml("Enabled")
        headers = {"Content-Type": ""}

        response = make_request(
            "PUT",
            f"/{test_bucket}",
            body=body,
            headers=headers,
            query_params="?versioning",
        )

        json_metadata["content_type"] = "(empty)"

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

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_text_plain_content_type(
        self, test_bucket, make_request, json_metadata,
    ):
        """Content-Type: text/plain with valid XML body and signature."""
        body = build_versioning_xml("Enabled")
        headers = {"Content-Type": "text/plain"}

        response = make_request(
            "PUT",
            f"/{test_bucket}",
            body=body,
            headers=headers,
            query_params="?versioning",
        )

        json_metadata["content_type"] = "text/plain"

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

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_no_content_type_header(
        self, test_bucket, make_request, json_metadata,
    ):
        """No Content-Type header at all with valid XML body."""
        body = build_versioning_xml("Enabled")

        response = make_request(
            "PUT",
            f"/{test_bucket}",
            body=body,
            headers={},
            query_params="?versioning",
        )

        json_metadata["content_type"] = "(absent)"

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
