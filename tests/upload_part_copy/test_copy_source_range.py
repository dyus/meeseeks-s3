"""Tests for UploadPartCopy x-amz-copy-source-range header.

Verifies how S3 handles byte-range copying for UploadPartCopy.
Per AWS docs, the source object must be >5MB to use byte-range copy.

UploadPartCopy: PUT /{Bucket}/{Key}?partNumber={N}&uploadId={Id}
"""

import pytest

from s3_compliance.xml_utils import extract_error_info


@pytest.mark.s3_handler("UploadPartCopy")
class TestUploadPartCopyCopySourceRange:
    """Test x-amz-copy-source-range header for UploadPartCopy."""

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

    def test_valid_range_on_large_source(
        self, test_bucket, upc_dest_key, large_source_object,
        multipart_upload, make_request, request,
    ):
        """UploadPartCopy with valid byte range on >5MB source should succeed."""
        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{large_source_object['key']}",
            "x-amz-copy-source-range": "bytes=0-1048575",  # first 1 MB
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, upc_dest_key,
            multipart_upload, headers, part_number=11,
        )

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 200
            assert "CopyPartResult" in response.aws.text
        else:
            assert response.status_code == 200
            assert "CopyPartResult" in response.text

    @pytest.mark.edge_case
    def test_range_on_small_source(
        self, test_bucket, upc_dest_key, source_object,
        multipart_upload, make_request, request,
    ):
        """UploadPartCopy with byte range on <5MB source.

        AWS docs say source must be >5MB for byte-range copy,
        but in practice AWS allows it and returns 200.
        """
        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{source_object['key']}",
            "x-amz-copy-source-range": "bytes=0-9",
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, upc_dest_key,
            multipart_upload, headers,
        )

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 200
            assert "CopyPartResult" in response.aws.text
        else:
            assert response.status_code == 200
            assert "CopyPartResult" in response.text

    @pytest.mark.edge_case
    def test_range_exceeding_source_size(
        self, test_bucket, upc_dest_key, large_source_object,
        multipart_upload, make_request, request,
    ):
        """UploadPartCopy with range exceeding source object size."""
        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{large_source_object['key']}",
            "x-amz-copy-source-range": "bytes=0-999999999",  # way beyond 5MB
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, upc_dest_key,
            multipart_upload, headers, part_number=12,
        )

        # AWS may clamp to actual size or return error
        if hasattr(response, "comparison"):
            assert response.aws.status_code in (200, 400, 416)
        else:
            assert response.status_code in (200, 400, 416)

    @pytest.mark.edge_case
    def test_invalid_range_format_no_bytes_prefix(
        self, test_bucket, upc_dest_key, large_source_object,
        multipart_upload, make_request, request,
    ):
        """UploadPartCopy with range missing 'bytes=' prefix."""
        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{large_source_object['key']}",
            "x-amz-copy-source-range": "0-1048575",
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, upc_dest_key,
            multipart_upload, headers,
        )

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
        else:
            assert response.status_code == 400

    @pytest.mark.edge_case
    def test_empty_range(
        self, test_bucket, upc_dest_key, large_source_object,
        multipart_upload, make_request, request,
    ):
        """UploadPartCopy with empty x-amz-copy-source-range value."""
        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{large_source_object['key']}",
            "x-amz-copy-source-range": "",
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, upc_dest_key,
            multipart_upload, headers, part_number=13,
        )

        # Empty range might be ignored (200) or rejected (400)
        if hasattr(response, "comparison"):
            assert response.aws.status_code in (200, 400)
        else:
            assert response.status_code in (200, 400)

    @pytest.mark.edge_case
    def test_reversed_range(
        self, test_bucket, upc_dest_key, large_source_object,
        multipart_upload, make_request, request,
    ):
        """UploadPartCopy with reversed byte range (start > end)."""
        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{large_source_object['key']}",
            "x-amz-copy-source-range": "bytes=1048575-0",
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, upc_dest_key,
            multipart_upload, headers,
        )

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
        else:
            assert response.status_code == 400

    def test_single_byte_range_on_large_source(
        self, test_bucket, upc_dest_key, large_source_object,
        multipart_upload, make_request, request,
    ):
        """UploadPartCopy with bytes=0-0 (single byte) on >5MB source."""
        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{large_source_object['key']}",
            "x-amz-copy-source-range": "bytes=0-0",
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, upc_dest_key,
            multipart_upload, headers, part_number=14,
        )

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 200
            assert "CopyPartResult" in response.aws.text
        else:
            assert response.status_code == 200
            assert "CopyPartResult" in response.text
