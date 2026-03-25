"""Tests for PutBucketVersioning Transfer-Encoding header behavior.

Verifies how AWS S3 handles various Transfer-Encoding values.
All tests send valid versioning XML body to isolate TE behavior from body validation.

Supports --endpoint=aws, --endpoint=custom, and --endpoint=both.
"""

import pytest

from s3_compliance.xml_utils import extract_error_info
from tests.put_bucket_versioning.conftest import build_versioning_xml


VALID_BODY = build_versioning_xml("Enabled")


@pytest.mark.put_bucket_versioning
@pytest.mark.s3_handler("PutBucketVersioning")
class TestPutBucketVersioningTransferEncoding:
    """Test PutBucketVersioning with various Transfer-Encoding values."""

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_transfer_encoding_identity_accepted(
        self, test_bucket, make_request, json_metadata,
    ):
        """Transfer-Encoding: identity with valid body should be accepted (200)."""
        headers = {
            "Content-Type": "application/xml",
            "Transfer-Encoding": "identity",
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}",
            body=VALID_BODY,
            headers=headers,
            query_params="?versioning",
        )

        json_metadata["transfer_encoding"] = "identity"

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
            assert response.comparison.is_compliant, response.diff_summary
        else:
            json_metadata["status"] = response.status_code

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_transfer_encoding_empty_accepted(
        self, test_bucket, make_request, json_metadata,
    ):
        """Transfer-Encoding: (empty string) with valid body should be accepted (200)."""
        headers = {
            "Content-Type": "application/xml",
            "Transfer-Encoding": "",
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}",
            body=VALID_BODY,
            headers=headers,
            query_params="?versioning",
        )

        json_metadata["transfer_encoding"] = "(empty)"

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
            assert response.comparison.is_compliant, response.diff_summary
        else:
            json_metadata["status"] = response.status_code

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_transfer_encoding_gzip_not_implemented(
        self, test_bucket, make_request, json_metadata,
    ):
        """Transfer-Encoding: gzip should return 501 Not Implemented."""
        headers = {
            "Content-Type": "application/xml",
            "Transfer-Encoding": "gzip",
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}",
            body=VALID_BODY,
            headers=headers,
            query_params="?versioning",
        )

        json_metadata["transfer_encoding"] = "gzip"

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
            if response.aws.status_code >= 400:
                error_code, error_msg = extract_error_info(response.aws.text)
                json_metadata["aws_error_code"] = error_code
            assert response.comparison.is_compliant, response.diff_summary
        else:
            json_metadata["status"] = response.status_code
            if response.status_code >= 400:
                error_code, error_msg = extract_error_info(response.text)
                json_metadata["error_code"] = error_code

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_transfer_encoding_deflate_not_implemented(
        self, test_bucket, make_request, json_metadata,
    ):
        """Transfer-Encoding: deflate should return 501 Not Implemented."""
        headers = {
            "Content-Type": "application/xml",
            "Transfer-Encoding": "deflate",
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}",
            body=VALID_BODY,
            headers=headers,
            query_params="?versioning",
        )

        json_metadata["transfer_encoding"] = "deflate"

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
            if response.aws.status_code >= 400:
                error_code, error_msg = extract_error_info(response.aws.text)
                json_metadata["aws_error_code"] = error_code
            assert response.comparison.is_compliant, response.diff_summary
        else:
            json_metadata["status"] = response.status_code
            if response.status_code >= 400:
                error_code, error_msg = extract_error_info(response.text)
                json_metadata["error_code"] = error_code

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_transfer_encoding_br_rejected(
        self, test_bucket, make_request, json_metadata,
    ):
        """Transfer-Encoding: br (brotli) should return 400 — unknown to S3."""
        headers = {
            "Content-Type": "application/xml",
            "Transfer-Encoding": "br",
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}",
            body=VALID_BODY,
            headers=headers,
            query_params="?versioning",
        )

        json_metadata["transfer_encoding"] = "br"

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
            if response.aws.status_code >= 400:
                error_code, error_msg = extract_error_info(response.aws.text)
                json_metadata["aws_error_code"] = error_code
            assert response.comparison.is_compliant, response.diff_summary
        else:
            json_metadata["status"] = response.status_code
            if response.status_code >= 400:
                error_code, error_msg = extract_error_info(response.text)
                json_metadata["error_code"] = error_code

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_transfer_encoding_unknown_rejected(
        self, test_bucket, make_request, json_metadata,
    ):
        """Transfer-Encoding: unknown should return 400."""
        headers = {
            "Content-Type": "application/xml",
            "Transfer-Encoding": "unknown",
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}",
            body=VALID_BODY,
            headers=headers,
            query_params="?versioning",
        )

        json_metadata["transfer_encoding"] = "unknown"

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
            if response.aws.status_code >= 400:
                error_code, error_msg = extract_error_info(response.aws.text)
                json_metadata["aws_error_code"] = error_code
            assert response.comparison.is_compliant, response.diff_summary
        else:
            json_metadata["status"] = response.status_code
            if response.status_code >= 400:
                error_code, error_msg = extract_error_info(response.text)
                json_metadata["error_code"] = error_code

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_transfer_encoding_chunked_gzip_not_implemented(
        self, test_bucket, make_request, json_metadata,
    ):
        """Transfer-Encoding: chunked, gzip — gzip triggers 501."""
        headers = {
            "Content-Type": "application/xml",
            "Transfer-Encoding": "chunked, gzip",
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}",
            body=VALID_BODY,
            headers=headers,
            query_params="?versioning",
        )

        json_metadata["transfer_encoding"] = "chunked, gzip"

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
            if response.aws.status_code >= 400:
                error_code, error_msg = extract_error_info(response.aws.text)
                json_metadata["aws_error_code"] = error_code
            assert response.comparison.is_compliant, response.diff_summary
        else:
            json_metadata["status"] = response.status_code
            if response.status_code >= 400:
                error_code, error_msg = extract_error_info(response.text)
                json_metadata["error_code"] = error_code

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_transfer_encoding_gzip_chunked_not_implemented(
        self, test_bucket, make_request, json_metadata,
    ):
        """Transfer-Encoding: gzip, chunked — gzip triggers 501 regardless of order."""
        headers = {
            "Content-Type": "application/xml",
            "Transfer-Encoding": "gzip, chunked",
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}",
            body=VALID_BODY,
            headers=headers,
            query_params="?versioning",
        )

        json_metadata["transfer_encoding"] = "gzip, chunked"

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
            if response.aws.status_code >= 400:
                error_code, error_msg = extract_error_info(response.aws.text)
                json_metadata["aws_error_code"] = error_code
            assert response.comparison.is_compliant, response.diff_summary
        else:
            json_metadata["status"] = response.status_code
            if response.status_code >= 400:
                error_code, error_msg = extract_error_info(response.text)
                json_metadata["error_code"] = error_code
