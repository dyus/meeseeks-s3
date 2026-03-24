"""Tests for PutBucketVersioning Transfer-Encoding: chunked with empty body.

Verifies how AWS S3 handles Transfer-Encoding: chunked when no body is sent
and Content-Length is not explicitly provided.

Supports --endpoint=aws, --endpoint=custom, and --endpoint=both.
"""

import pytest

from s3_compliance.xml_utils import extract_error_info


@pytest.mark.put_bucket_versioning
@pytest.mark.s3_handler("PutBucketVersioning")
class TestPutBucketVersioningTransferEncodingChunkedEmptyBody:
    """Test PutBucketVersioning with Transfer-Encoding: chunked and empty body."""

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_transfer_encoding_chunked_empty_body(
        self, test_bucket, make_request, json_metadata,
    ):
        """Transfer-Encoding: chunked with empty body, no explicit Content-Length."""
        headers = {
            "Content-Type": "application/xml",
            "Transfer-Encoding": "chunked",
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}",
            body=b"",
            headers=headers,
            query_params="?versioning",
        )

        json_metadata["transfer_encoding"] = "chunked"
        json_metadata["body"] = "(empty)"

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
            if response.aws.status_code >= 400:
                error_code, error_msg = extract_error_info(response.aws.text)
                json_metadata["aws_error_code"] = error_code
                json_metadata["aws_error_msg"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            json_metadata["status"] = response.status_code
            if response.status_code >= 400:
                error_code, error_msg = extract_error_info(response.text)
                json_metadata["error_code"] = error_code
                json_metadata["error_msg"] = error_msg
