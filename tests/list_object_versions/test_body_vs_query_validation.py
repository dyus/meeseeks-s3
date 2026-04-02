"""Tests for ListObjectVersions: body size vs query parameter validation order.

Sends oversized bodies together with invalid query parameters to determine
whether S3 validates query parameters before or after reading the body.

If the query-param error wins → query params are validated before body is read.
If a connection-reset / body-related error wins → body is read/validated first.

Supports --endpoint=aws, --endpoint=custom, and --endpoint=both.
"""

import pytest
import requests as req_lib

from s3_compliance.xml_utils import extract_error_info

from .conftest import build_versions_query


OVERSIZED_BODY = b"x" * (1024 * 1024 + 1)  # 1MB + 1 byte


def _do_request_and_record(make_request, test_bucket, query, json_metadata):
    """Make oversized-body request, handle connection resets, record result."""
    json_metadata["payload_size_bytes"] = len(OVERSIZED_BODY)

    try:
        response = make_request(
            "GET",
            f"/{test_bucket}",
            body=OVERSIZED_BODY,
            query_params=query,
        )
    except (
        req_lib.exceptions.ConnectionError,
        req_lib.exceptions.ChunkedEncodingError,
        ConnectionResetError,
        OSError,
    ) as exc:
        json_metadata["status"] = "ConnectionReset"
        json_metadata["error_code"] = "ConnectionReset"
        json_metadata["error_message"] = str(exc)[:200]
        json_metadata["winner"] = "body (connection reset)"
        return None

    if hasattr(response, "comparison"):
        resp = response.aws
    else:
        resp = response

    json_metadata["status"] = resp.status_code
    if resp.status_code >= 400:
        error_code, error_msg = extract_error_info(resp.text)
        json_metadata["error_code"] = error_code
        json_metadata["error_message"] = error_msg
        json_metadata["winner"] = f"query ({error_code})"
    else:
        json_metadata["error_code"] = None
        json_metadata["error_message"] = None
        json_metadata["winner"] = "none (200 OK)"

    if hasattr(response, "comparison"):
        json_metadata["aws_status"] = response.aws.status_code
        json_metadata["custom_status"] = response.custom.status_code

    return response


# =========================================================================
# 1. Oversized body + invalid max-keys
# =========================================================================

@pytest.mark.list_object_versions
@pytest.mark.s3_handler("ListObjectVersions")
class TestBodyVsMaxKeys:
    """Oversized body + invalid max-keys → who wins?"""

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_oversized_body_with_invalid_max_keys(
        self, test_bucket, make_request, json_metadata,
    ):
        """1MB+ body + max-keys=abc."""
        query = build_versions_query(max_keys="abc")
        response = _do_request_and_record(
            make_request, test_bucket, query, json_metadata,
        )
        if response and hasattr(response, "comparison"):
            assert response.comparison.is_compliant, response.diff_summary


# =========================================================================
# 2. Oversized body + dependency error (vid without key-marker)
# =========================================================================

@pytest.mark.list_object_versions
@pytest.mark.s3_handler("ListObjectVersions")
class TestBodyVsDependency:
    """Oversized body + version-id-marker without key-marker → who wins?"""

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_oversized_body_with_vid_without_key(
        self, test_bucket, make_request, json_metadata,
    ):
        """1MB+ body + vid=bad without key-marker."""
        query = build_versions_query(version_id_marker="bad-vid")
        response = _do_request_and_record(
            make_request, test_bucket, query, json_metadata,
        )
        if response and hasattr(response, "comparison"):
            assert response.comparison.is_compliant, response.diff_summary


# =========================================================================
# 3. Oversized body + empty version-id-marker (with key-marker)
# =========================================================================

@pytest.mark.list_object_versions
@pytest.mark.s3_handler("ListObjectVersions")
class TestBodyVsEmptyVid:
    """Oversized body + empty version-id-marker with key → who wins?"""

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_oversized_body_with_empty_vid(
        self, test_bucket, make_request, json_metadata,
    ):
        """1MB+ body + key=k,vid=""."""
        query = build_versions_query(key_marker="k", version_id_marker="")
        response = _do_request_and_record(
            make_request, test_bucket, query, json_metadata,
        )
        if response and hasattr(response, "comparison"):
            assert response.comparison.is_compliant, response.diff_summary


# =========================================================================
# 4. Oversized body + invalid version-id-marker format (with key-marker)
# =========================================================================

@pytest.mark.list_object_versions
@pytest.mark.s3_handler("ListObjectVersions")
class TestBodyVsVidFormat:
    """Oversized body + bad version-id-marker with key → who wins?"""

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_oversized_body_with_bad_vid_format(
        self, test_bucket, make_request, json_metadata,
    ):
        """1MB+ body + key=k,vid=bad-vid."""
        query = build_versions_query(key_marker="k", version_id_marker="bad-vid")
        response = _do_request_and_record(
            make_request, test_bucket, query, json_metadata,
        )
        if response and hasattr(response, "comparison"):
            assert response.comparison.is_compliant, response.diff_summary


# =========================================================================
# 5. Oversized body + invalid encoding-type
# =========================================================================

@pytest.mark.list_object_versions
@pytest.mark.s3_handler("ListObjectVersions")
class TestBodyVsEncodingType:
    """Oversized body + invalid encoding-type → who wins?"""

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_oversized_body_with_invalid_encoding(
        self, test_bucket, make_request, json_metadata,
    ):
        """1MB+ body + encoding-type=invalid."""
        query = build_versions_query(encoding_type="invalid")
        response = _do_request_and_record(
            make_request, test_bucket, query, json_metadata,
        )
        if response and hasattr(response, "comparison"):
            assert response.comparison.is_compliant, response.diff_summary


# =========================================================================
# 6. Oversized body + valid query params (no errors — pure body test)
# =========================================================================

@pytest.mark.list_object_versions
@pytest.mark.s3_handler("ListObjectVersions")
class TestBodyOnlyOversized:
    """Oversized body with valid query params — does S3 care about body on GET?"""

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_oversized_body_valid_query(
        self, test_bucket, make_request, json_metadata,
    ):
        """1MB+ body + no query errors → does body size matter for GET?"""
        query = build_versions_query()
        response = _do_request_and_record(
            make_request, test_bucket, query, json_metadata,
        )
        if response and hasattr(response, "comparison"):
            assert response.comparison.is_compliant, response.diff_summary
