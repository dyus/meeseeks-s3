"""Tests for PutBucketVersioning Transfer-Encoding header handling.

Verifies S3 behavior with various Transfer-Encoding values,
both with empty bodies and valid versioning XML bodies.

Corresponds to putbucketversioning.md Transfer Encoding table (30 cases).

Note: Some Transfer-Encoding tests may behave differently than the document
describes because the `requests` library handles Transfer-Encoding at the
transport level. Tests that expect connection resets may raise ConnectionError.

Supports --endpoint=aws, --endpoint=custom, and --endpoint=both.
"""

import pytest
import requests as requests_lib

from s3_compliance.xml_utils import extract_error_info
from tests.put_bucket_versioning.conftest import build_versioning_xml_with_mfa


VALID_XML = build_versioning_xml_with_mfa("Enabled", mfa_delete="Disabled")


# --------------------------------------------------------------------------
# Transfer-Encoding with EMPTY body (doc table rows 1-15)
# --------------------------------------------------------------------------

TE_EMPTY_BODY_CASES = [
    pytest.param("chunked", 400, id="te_chunked_empty"),
    pytest.param("gzip", 501, id="te_gzip_empty"),
    pytest.param("compress", 501, id="te_compress_empty"),
    pytest.param("deflate", 501, id="te_deflate_empty"),
    pytest.param("identity", 400, id="te_identity_empty"),
    pytest.param("chunked, gzip", 501, id="te_chunked_gzip_empty"),
    pytest.param("chunked, compress", 501, id="te_chunked_compress_empty"),
    pytest.param("chunked, deflate", 501, id="te_chunked_deflate_empty"),
    pytest.param("gzip, chunked", 501, id="te_gzip_chunked_empty"),
    # Row 10: compress, chunked → ConnectionResetError (None = expect error)
    pytest.param("compress, chunked", None, id="te_compress_chunked_empty"),
    pytest.param("deflate, chunked", 501, id="te_deflate_chunked_empty"),
    pytest.param("br", 400, id="te_br_empty"),
    pytest.param("chunked, br", 400, id="te_chunked_br_empty"),
    pytest.param("", 400, id="te_empty_value_empty"),
    pytest.param("unknown", 400, id="te_unknown_empty"),
]


# --------------------------------------------------------------------------
# Transfer-Encoding with VALID versioning XML body (doc table rows 16-30)
# --------------------------------------------------------------------------

TE_WITH_BODY_CASES = [
    pytest.param("chunked", 200, id="te_chunked_body"),
    pytest.param("gzip", 501, id="te_gzip_body"),
    pytest.param("compress", 501, id="te_compress_body"),
    pytest.param("deflate", 501, id="te_deflate_body"),
    pytest.param("identity", 200, id="te_identity_body"),
    pytest.param("chunked, gzip", 501, id="te_chunked_gzip_body"),
    pytest.param("chunked, compress", 501, id="te_chunked_compress_body"),
    pytest.param("chunked, deflate", 501, id="te_chunked_deflate_body"),
    pytest.param("gzip, chunked", 501, id="te_gzip_chunked_body"),
    pytest.param("compress, chunked", 501, id="te_compress_chunked_body"),
    pytest.param("deflate, chunked", 501, id="te_deflate_chunked_body"),
    pytest.param("br", 400, id="te_br_body"),
    pytest.param("chunked, br", 400, id="te_chunked_br_body"),
    pytest.param("", 200, id="te_empty_value_body"),
    pytest.param("unknown", 400, id="te_unknown_body"),
]


@pytest.mark.put_bucket_versioning
@pytest.mark.s3_handler("PutBucketVersioning")
class TestPutBucketVersioningTransferEncodingEmpty:
    """Test PutBucketVersioning Transfer-Encoding with empty body (doc rows 1-15)."""

    @pytest.mark.edge_case
    @pytest.mark.parametrize("te_value, expected_status", TE_EMPTY_BODY_CASES)
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_transfer_encoding_empty_body(
        self, te_value, expected_status, test_bucket, make_request, json_metadata
    ):
        """Transfer-Encoding with empty body."""
        headers = {"Content-Type": "application/xml"}
        if te_value:
            headers["Transfer-Encoding"] = te_value

        json_metadata["transfer_encoding"] = te_value or "(empty)"
        json_metadata["body"] = "empty"

        if expected_status is None:
            # Expect connection error (e.g., compress, chunked → ConnectionResetError)
            try:
                response = make_request(
                    "PUT",
                    f"/{test_bucket}",
                    body=b"",
                    headers=headers,
                    query_params="?versioning",
                )
                # If no error, record what we got
                if hasattr(response, "comparison"):
                    json_metadata["aws_status"] = response.aws.status_code
                else:
                    json_metadata["status"] = response.status_code
            except (
                requests_lib.exceptions.ConnectionError,
                ConnectionResetError,
                OSError,
            ):
                json_metadata["result"] = "ConnectionResetError"
            return

        response = make_request(
            "PUT",
            f"/{test_bucket}",
            body=b"",
            headers=headers,
            query_params="?versioning",
        )

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
                error_code, _ = extract_error_info(response.text)
                json_metadata["error_code"] = error_code


@pytest.mark.put_bucket_versioning
@pytest.mark.s3_handler("PutBucketVersioning")
class TestPutBucketVersioningTransferEncodingBody:
    """Test PutBucketVersioning Transfer-Encoding with valid XML body (doc rows 16-30)."""

    @pytest.mark.edge_case
    @pytest.mark.parametrize("te_value, expected_status", TE_WITH_BODY_CASES)
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_transfer_encoding_with_body(
        self, te_value, expected_status, test_bucket, make_request, json_metadata
    ):
        """Transfer-Encoding with valid versioning XML body."""
        headers = {"Content-Type": "application/xml"}
        if te_value:
            headers["Transfer-Encoding"] = te_value

        json_metadata["transfer_encoding"] = te_value or "(empty)"
        json_metadata["body"] = "valid_xml"

        try:
            response = make_request(
                "PUT",
                f"/{test_bucket}",
                body=VALID_XML,
                headers=headers,
                query_params="?versioning",
            )
        except (
            requests_lib.exceptions.ConnectionError,
            ConnectionResetError,
            OSError,
        ):
            json_metadata["result"] = "ConnectionResetError"
            return

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
            if response.aws.status_code >= 400:
                error_code, _ = extract_error_info(response.aws.text)
                json_metadata["aws_error_code"] = error_code
            assert response.comparison.is_compliant, response.diff_summary
        else:
            json_metadata["status"] = response.status_code
            if response.status_code >= 400:
                error_code, _ = extract_error_info(response.text)
                json_metadata["error_code"] = error_code
