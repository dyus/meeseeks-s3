"""Tests for UploadPartCopy conditional headers.

Verifies S3 behavior with:
- x-amz-copy-source-if-match
- x-amz-copy-source-if-none-match
- x-amz-copy-source-if-modified-since
- x-amz-copy-source-if-unmodified-since

Also tests AWS-documented precedence rules:
- if-match(true) + if-unmodified-since(false) => 200 (if-match wins)
- if-none-match(false) + if-modified-since(true) => 412 (if-none-match wins)

UploadPartCopy: PUT /{Bucket}/{Key}?partNumber={N}&uploadId={Id}
"""

import pytest

from s3_compliance.xml_utils import extract_error_info


@pytest.mark.s3_handler("UploadPartCopy")
class TestUploadPartCopyConditionalHeaders:
    """Test conditional copy headers for UploadPartCopy."""

    def _make_upc_request(
        self, make_request, request, test_bucket, upc_dest_key,
        multipart_upload, headers, part_number=1,
    ):
        """Make an UploadPartCopy request via make_request fixture."""
        endpoint_mode = request.config.getoption("--endpoint")
        if endpoint_mode == "both":
            query_params = f"?uploadId={multipart_upload['aws']}&partNumber={part_number}"
            custom_query_params = f"?uploadId={multipart_upload['custom']}&partNumber={part_number}"
        else:
            query_params = f"?uploadId={multipart_upload}&partNumber={part_number}"
            custom_query_params = None

        return make_request(
            "PUT",
            f"/{test_bucket}/{upc_dest_key}",
            headers=headers,
            query_params=query_params,
            custom_query_params=custom_query_params,
        )

    # =========================================================================
    # x-amz-copy-source-if-match
    # =========================================================================

    def test_if_match_matching_etag(
        self, test_bucket, upc_dest_key, source_object,
        multipart_upload, make_request, request,
    ):
        """if-match with actual ETag should succeed (200)."""
        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{source_object['key']}",
            "x-amz-copy-source-if-match": source_object["etag"],
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, upc_dest_key,
            multipart_upload, headers, part_number=18,
        )

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 200
            assert "CopyPartResult" in response.aws.text
        else:
            assert response.status_code == 200
            assert "CopyPartResult" in response.text

    def test_if_match_wrong_etag(
        self, test_bucket, upc_dest_key, source_object,
        multipart_upload, make_request, request,
    ):
        """if-match with wrong ETag should return 412 PreconditionFailed."""
        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{source_object['key']}",
            "x-amz-copy-source-if-match": '"00000000000000000000000000000000"',
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, upc_dest_key,
            multipart_upload, headers,
        )

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 412
            error_code, _ = extract_error_info(response.aws.text)
            assert error_code == "PreconditionFailed"
        else:
            assert response.status_code == 412
            error_code, _ = extract_error_info(response.text)
            assert error_code == "PreconditionFailed"

    # =========================================================================
    # x-amz-copy-source-if-none-match
    # =========================================================================

    def test_if_none_match_matching_etag(
        self, test_bucket, upc_dest_key, source_object,
        multipart_upload, make_request, request,
    ):
        """if-none-match with actual ETag (match) — should fail."""
        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{source_object['key']}",
            "x-amz-copy-source-if-none-match": source_object["etag"],
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, upc_dest_key,
            multipart_upload, headers,
        )

        # Could be 412 PreconditionFailed or 304 Not Modified
        if hasattr(response, "comparison"):
            assert response.aws.status_code in (304, 412)
        else:
            assert response.status_code in (304, 412)

    def test_if_none_match_different_etag(
        self, test_bucket, upc_dest_key, source_object,
        multipart_upload, make_request, request,
    ):
        """if-none-match with different ETag should succeed (200)."""
        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{source_object['key']}",
            "x-amz-copy-source-if-none-match": '"00000000000000000000000000000000"',
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, upc_dest_key,
            multipart_upload, headers, part_number=19,
        )

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 200
            assert "CopyPartResult" in response.aws.text
        else:
            assert response.status_code == 200
            assert "CopyPartResult" in response.text

    # =========================================================================
    # x-amz-copy-source-if-modified-since
    # =========================================================================

    def test_if_modified_since_old_date(
        self, test_bucket, upc_dest_key, source_object,
        multipart_upload, make_request, request,
    ):
        """if-modified-since with date far in the past — object was modified since, should succeed."""
        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{source_object['key']}",
            "x-amz-copy-source-if-modified-since": "Thu, 01 Jan 2020 00:00:00 GMT",
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, upc_dest_key,
            multipart_upload, headers, part_number=20,
        )

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 200
        else:
            assert response.status_code == 200

    @pytest.mark.edge_case
    def test_if_modified_since_future_date(
        self, test_bucket, upc_dest_key, source_object,
        multipart_upload, make_request, request,
    ):
        """if-modified-since with future date — object was NOT modified since.

        AWS returns 200 anyway — if-modified-since alone does not prevent copy.
        """
        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{source_object['key']}",
            "x-amz-copy-source-if-modified-since": "Thu, 01 Jan 2099 00:00:00 GMT",
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, upc_dest_key,
            multipart_upload, headers, part_number=25,
        )

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 200
        else:
            assert response.status_code == 200

    # =========================================================================
    # x-amz-copy-source-if-unmodified-since
    # =========================================================================

    def test_if_unmodified_since_future_date(
        self, test_bucket, upc_dest_key, source_object,
        multipart_upload, make_request, request,
    ):
        """if-unmodified-since with future date — object was unmodified since, should succeed."""
        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{source_object['key']}",
            "x-amz-copy-source-if-unmodified-since": "Thu, 01 Jan 2099 00:00:00 GMT",
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, upc_dest_key,
            multipart_upload, headers, part_number=21,
        )

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 200
        else:
            assert response.status_code == 200

    def test_if_unmodified_since_old_date(
        self, test_bucket, upc_dest_key, source_object,
        multipart_upload, make_request, request,
    ):
        """if-unmodified-since with past date — object WAS modified since, should return 412."""
        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{source_object['key']}",
            "x-amz-copy-source-if-unmodified-since": "Thu, 01 Jan 2020 00:00:00 GMT",
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, upc_dest_key,
            multipart_upload, headers,
        )

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 412
            error_code, _ = extract_error_info(response.aws.text)
            assert error_code == "PreconditionFailed"
        else:
            assert response.status_code == 412
            error_code, _ = extract_error_info(response.text)
            assert error_code == "PreconditionFailed"

    # =========================================================================
    # Precedence rules (documented by AWS)
    # =========================================================================

    @pytest.mark.edge_case
    def test_precedence_if_match_true_if_unmodified_since_false(
        self, test_bucket, upc_dest_key, source_object,
        multipart_upload, make_request, request,
    ):
        """if-match(true) + if-unmodified-since(false) => 200.

        AWS docs: if-match takes precedence over if-unmodified-since.
        """
        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{source_object['key']}",
            "x-amz-copy-source-if-match": source_object["etag"],
            "x-amz-copy-source-if-unmodified-since": "Thu, 01 Jan 2020 00:00:00 GMT",
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, upc_dest_key,
            multipart_upload, headers, part_number=22,
        )

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 200, (
                f"Expected 200 (if-match wins), got {response.aws.status_code}"
            )
        else:
            assert response.status_code == 200, (
                f"Expected 200 (if-match wins), got {response.status_code}"
            )

    @pytest.mark.edge_case
    def test_precedence_if_none_match_false_if_modified_since_true(
        self, test_bucket, upc_dest_key, source_object,
        multipart_upload, make_request, request,
    ):
        """if-none-match(false) + if-modified-since(true) => 412.

        AWS docs: if-none-match takes precedence over if-modified-since.
        if-none-match is "false" because ETag matches (condition NOT met).
        if-modified-since is "true" because object was modified after 2020.
        """
        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{source_object['key']}",
            "x-amz-copy-source-if-none-match": source_object["etag"],
            "x-amz-copy-source-if-modified-since": "Thu, 01 Jan 2020 00:00:00 GMT",
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, upc_dest_key,
            multipart_upload, headers,
        )

        if hasattr(response, "comparison"):
            assert response.aws.status_code in (304, 412), (
                f"Expected 304/412 (if-none-match wins), got {response.aws.status_code}"
            )
        else:
            assert response.status_code in (304, 412), (
                f"Expected 304/412 (if-none-match wins), got {response.status_code}"
            )

    # =========================================================================
    # Edge cases
    # =========================================================================

    @pytest.mark.edge_case
    def test_if_modified_since_invalid_date(
        self, test_bucket, upc_dest_key, source_object,
        multipart_upload, make_request, request,
    ):
        """if-modified-since with invalid date format."""
        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{source_object['key']}",
            "x-amz-copy-source-if-modified-since": "not-a-date",
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, upc_dest_key,
            multipart_upload, headers, part_number=23,
        )

        # Invalid date might be ignored (200) or cause an error
        if hasattr(response, "comparison"):
            assert response.aws.status_code in (200, 400)
        else:
            assert response.status_code in (200, 400)

    @pytest.mark.edge_case
    def test_if_match_wildcard(
        self, test_bucket, upc_dest_key, source_object,
        multipart_upload, make_request, request,
    ):
        """if-match with wildcard '*' — should match any ETag."""
        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{source_object['key']}",
            "x-amz-copy-source-if-match": "*",
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, upc_dest_key,
            multipart_upload, headers, part_number=24,
        )

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 200
        else:
            assert response.status_code == 200
