"""Tests for UploadPartCopy query parameter edge cases.

Verifies S3 behavior with invalid partNumber and uploadId values,
and other request-level edge cases.

UploadPartCopy: PUT /{Bucket}/{Key}?partNumber={N}&uploadId={Id}
"""

import uuid

import pytest

from s3_compliance.xml_utils import extract_error_info


@pytest.mark.s3_handler("UploadPartCopy")
class TestUploadPartCopyQueryParams:
    """Test partNumber and uploadId edge cases for UploadPartCopy."""

    # =========================================================================
    # partNumber edge cases
    # =========================================================================

    @pytest.mark.edge_case
    def test_part_number_zero(
        self, test_bucket, upc_dest_key, source_object,
        multipart_upload, make_request, request,
    ):
        """partNumber=0 should be rejected (valid range is 1-10000)."""
        endpoint_mode = request.config.getoption("--endpoint")
        if endpoint_mode == "both":
            upload_id = multipart_upload["aws"]
        else:
            upload_id = multipart_upload

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{source_object['key']}",
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}/{upc_dest_key}",
            headers=headers,
            query_params=f"?uploadId={upload_id}&partNumber=0",
        )

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, _ = extract_error_info(response.aws.text)
            assert error_code == "InvalidArgument"
        else:
            assert response.status_code == 400
            error_code, _ = extract_error_info(response.text)
            assert error_code == "InvalidArgument"

    @pytest.mark.edge_case
    def test_part_number_negative(
        self, test_bucket, upc_dest_key, source_object,
        multipart_upload, make_request, request,
    ):
        """partNumber=-1 should be rejected."""
        endpoint_mode = request.config.getoption("--endpoint")
        if endpoint_mode == "both":
            upload_id = multipart_upload["aws"]
        else:
            upload_id = multipart_upload

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{source_object['key']}",
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}/{upc_dest_key}",
            headers=headers,
            query_params=f"?uploadId={upload_id}&partNumber=-1",
        )

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, _ = extract_error_info(response.aws.text)
            assert error_code == "InvalidArgument"
        else:
            assert response.status_code == 400
            error_code, _ = extract_error_info(response.text)
            assert error_code == "InvalidArgument"

    @pytest.mark.edge_case
    def test_part_number_exceeds_max(
        self, test_bucket, upc_dest_key, source_object,
        multipart_upload, make_request, request,
    ):
        """partNumber=10001 should be rejected (max is 10000)."""
        endpoint_mode = request.config.getoption("--endpoint")
        if endpoint_mode == "both":
            upload_id = multipart_upload["aws"]
        else:
            upload_id = multipart_upload

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{source_object['key']}",
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}/{upc_dest_key}",
            headers=headers,
            query_params=f"?uploadId={upload_id}&partNumber=10001",
        )

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, _ = extract_error_info(response.aws.text)
            assert error_code == "InvalidArgument"
        else:
            assert response.status_code == 400
            error_code, _ = extract_error_info(response.text)
            assert error_code == "InvalidArgument"

    def test_part_number_max_valid(
        self, test_bucket, upc_dest_key, source_object,
        multipart_upload, make_request, request,
    ):
        """partNumber=10000 (maximum valid) should succeed."""
        endpoint_mode = request.config.getoption("--endpoint")
        if endpoint_mode == "both":
            upload_id = multipart_upload["aws"]
        else:
            upload_id = multipart_upload

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{source_object['key']}",
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}/{upc_dest_key}",
            headers=headers,
            query_params=f"?uploadId={upload_id}&partNumber=10000",
        )

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 200
            assert "CopyPartResult" in response.aws.text
        else:
            assert response.status_code == 200
            assert "CopyPartResult" in response.text

    @pytest.mark.edge_case
    def test_part_number_non_numeric(
        self, test_bucket, upc_dest_key, source_object,
        multipart_upload, make_request, request,
    ):
        """partNumber=abc (non-numeric) should be rejected."""
        endpoint_mode = request.config.getoption("--endpoint")
        if endpoint_mode == "both":
            upload_id = multipart_upload["aws"]
        else:
            upload_id = multipart_upload

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{source_object['key']}",
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}/{upc_dest_key}",
            headers=headers,
            query_params=f"?uploadId={upload_id}&partNumber=abc",
        )

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
        else:
            assert response.status_code == 400

    @pytest.mark.edge_case
    def test_part_number_missing(
        self, test_bucket, upc_dest_key, source_object,
        multipart_upload, make_request, request,
    ):
        """Missing partNumber — AWS returns 405 Method Not Allowed."""
        endpoint_mode = request.config.getoption("--endpoint")
        if endpoint_mode == "both":
            upload_id = multipart_upload["aws"]
        else:
            upload_id = multipart_upload

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{source_object['key']}",
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}/{upc_dest_key}",
            headers=headers,
            query_params=f"?uploadId={upload_id}",
        )

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 405
            error_code, _ = extract_error_info(response.aws.text)
            assert error_code == "MethodNotAllowed"
        else:
            assert response.status_code == 405
            error_code, _ = extract_error_info(response.text)
            assert error_code == "MethodNotAllowed"

    # =========================================================================
    # uploadId edge cases
    # =========================================================================

    @pytest.mark.edge_case
    def test_upload_id_invalid(
        self, test_bucket, upc_dest_key, source_object,
        make_request, request,
    ):
        """Invalid uploadId should return 404 NoSuchUpload."""
        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{source_object['key']}",
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}/{upc_dest_key}",
            headers=headers,
            query_params=f"?uploadId=invalid-upload-id-{uuid.uuid4().hex[:8]}&partNumber=1",
        )

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 404
            error_code, _ = extract_error_info(response.aws.text)
            assert error_code == "NoSuchUpload"
        else:
            assert response.status_code == 404
            error_code, _ = extract_error_info(response.text)
            assert error_code == "NoSuchUpload"

    @pytest.mark.edge_case
    def test_upload_id_missing(
        self, test_bucket, upc_dest_key, source_object,
        make_request, request,
    ):
        """Missing uploadId — might be treated as CopyObject instead of UploadPartCopy."""
        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{source_object['key']}",
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}/{upc_dest_key}",
            headers=headers,
            query_params="?partNumber=1",
        )

        # partNumber without uploadId → AWS returns 400 InvalidRequest
        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, _ = extract_error_info(response.aws.text)
            assert error_code is not None
        else:
            assert response.status_code == 400
            error_code, _ = extract_error_info(response.text)
            assert error_code is not None

    # =========================================================================
    # Request body edge case
    # =========================================================================

    @pytest.mark.edge_case
    def test_request_with_body(
        self, test_bucket, upc_dest_key, source_object,
        multipart_upload, make_request, request,
    ):
        """UploadPartCopy with unexpected request body.

        UploadPartCopy should not have a body — verify S3 ignores or rejects it.
        """
        endpoint_mode = request.config.getoption("--endpoint")
        if endpoint_mode == "both":
            upload_id = multipart_upload["aws"]
        else:
            upload_id = multipart_upload

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{source_object['key']}",
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}/{upc_dest_key}",
            body=b"unexpected body content",
            headers=headers,
            query_params=f"?uploadId={upload_id}&partNumber=5",
        )

        # S3 might ignore the body and succeed, or reject
        if hasattr(response, "comparison"):
            assert response.aws.status_code in (200, 400)
        else:
            assert response.status_code in (200, 400)
