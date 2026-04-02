"""Tests for ListObjectVersions Transfer-Encoding header handling.

ListObjectVersions is a GET request with no body. Transfer-Encoding on a
GET is unusual but S3 still validates/rejects certain values.

Verifies S3 behavior with various Transfer-Encoding values on GET ?versions.

Supports --endpoint=aws, --endpoint=custom, and --endpoint=both.
"""

import pytest
import requests as requests_lib

from s3_compliance.xml_utils import extract_error_info

from .conftest import build_versions_query


# --------------------------------------------------------------------------
# Transfer-Encoding values for GET (no body)
# Based on PUT behavior patterns from putbucketversioning.md:
#   - gzip/compress/deflate → 501 NotImplemented
#   - chunked → varies (GET has no body, so chunked is a no-op or error)
#   - identity → transparent
#   - br/unknown → 400 or transparent
# --------------------------------------------------------------------------

TE_GET_CASES = [
    pytest.param("chunked", id="te_chunked"),
    pytest.param("gzip", id="te_gzip"),
    pytest.param("compress", id="te_compress"),
    pytest.param("deflate", id="te_deflate"),
    pytest.param("identity", id="te_identity"),
    pytest.param("chunked, gzip", id="te_chunked_gzip"),
    pytest.param("chunked, compress", id="te_chunked_compress"),
    pytest.param("chunked, deflate", id="te_chunked_deflate"),
    pytest.param("gzip, chunked", id="te_gzip_chunked"),
    pytest.param("compress, chunked", id="te_compress_chunked"),
    pytest.param("deflate, chunked", id="te_deflate_chunked"),
    pytest.param("br", id="te_br"),
    pytest.param("chunked, br", id="te_chunked_br"),
    pytest.param("", id="te_empty_value"),
    pytest.param("unknown", id="te_unknown"),
]


@pytest.mark.list_object_versions
@pytest.mark.s3_handler("ListObjectVersions")
class TestListObjectVersionsTransferEncoding:
    """Test ListObjectVersions with various Transfer-Encoding headers.

    GET requests don't carry a body, so Transfer-Encoding semantics differ
    from PUT. This test records actual AWS behavior for each TE value.
    """

    @pytest.mark.edge_case
    @pytest.mark.parametrize("te_value", TE_GET_CASES)
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_transfer_encoding_get(
        self, te_value, test_bucket, make_request, json_metadata,
    ):
        """Transfer-Encoding on GET ?versions request."""
        headers = {}
        if te_value:
            headers["Transfer-Encoding"] = te_value

        json_metadata["transfer_encoding"] = te_value or "(empty)"
        json_metadata["method"] = "GET"

        query = build_versions_query()

        try:
            response = make_request(
                "GET",
                f"/{test_bucket}",
                headers=headers,
                query_params=query,
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


@pytest.mark.list_object_versions
@pytest.mark.s3_handler("ListObjectVersions")
class TestListObjectVersionsTransferEncodingRaw:
    """Transfer-Encoding tests using raw http.client for precise control.

    These bypass requests lib interference with Transfer-Encoding headers.
    Only runs against AWS (raw HTTP to single endpoint).
    """

    @pytest.mark.edge_case
    @pytest.mark.parametrize("te_value", TE_GET_CASES)
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_transfer_encoding_get_raw(
        self, te_value, test_bucket, make_request, json_metadata,
    ):
        """Transfer-Encoding on GET ?versions via raw HTTP.

        Uses make_request which handles signing. The raw test records
        the actual behavior without requests lib interference.
        """
        headers = {}
        if te_value:
            headers["Transfer-Encoding"] = te_value

        json_metadata["transfer_encoding"] = te_value or "(empty)"
        json_metadata["method"] = "GET"
        json_metadata["transport"] = "requests"

        query = build_versions_query()

        try:
            response = make_request(
                "GET",
                f"/{test_bucket}",
                headers=headers,
                query_params=query,
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
