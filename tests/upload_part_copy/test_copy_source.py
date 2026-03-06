"""Tests for UploadPartCopy x-amz-copy-source header variations.

Verifies how S3 handles the required x-amz-copy-source header
with valid, invalid, missing, and edge-case values.

UploadPartCopy: PUT /{Bucket}/{Key}?partNumber={N}&uploadId={Id}
with x-amz-copy-source header pointing to the source object.
"""

import uuid

import pytest

from s3_compliance.xml_utils import extract_error_info


@pytest.mark.s3_handler("UploadPartCopy")
class TestUploadPartCopyCopySource:
    """Test x-amz-copy-source header variations for UploadPartCopy."""

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

    def test_valid_copy_source(
        self, test_bucket, upc_dest_key, source_object,
        multipart_upload, make_request, request,
    ):
        """UploadPartCopy with valid x-amz-copy-source should return 200 with CopyPartResult XML."""
        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{source_object['key']}",
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, upc_dest_key,
            multipart_upload, headers,
        )

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 200
            assert "CopyPartResult" in response.aws.text
            assert "ETag" in response.aws.text
            assert "LastModified" in response.aws.text
        else:
            assert response.status_code == 200
            assert "CopyPartResult" in response.text
            assert "ETag" in response.text
            assert "LastModified" in response.text

    def test_missing_copy_source(
        self, test_bucket, upc_dest_key,
        multipart_upload, make_request, request,
    ):
        """Without x-amz-copy-source, AWS treats it as regular UploadPart (empty body)."""
        headers = {}

        response = self._make_upc_request(
            make_request, request, test_bucket, upc_dest_key,
            multipart_upload, headers,
        )

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 200
        else:
            assert response.status_code == 200

    def test_empty_copy_source(
        self, test_bucket, upc_dest_key,
        multipart_upload, make_request, request,
    ):
        """UploadPartCopy with empty x-amz-copy-source value."""
        headers = {
            "x-amz-copy-source": "",
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, upc_dest_key,
            multipart_upload, headers,
        )

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, _ = extract_error_info(response.aws.text)
            assert error_code is not None
        else:
            assert response.status_code == 400
            error_code, _ = extract_error_info(response.text)
            assert error_code is not None

    def test_nonexistent_source_key(
        self, test_bucket, upc_dest_key,
        multipart_upload, make_request, request,
    ):
        """UploadPartCopy with non-existent source key should return 404 NoSuchKey."""
        headers = {
            "x-amz-copy-source": f"/{test_bucket}/nonexistent-key-{uuid.uuid4().hex[:8]}",
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, upc_dest_key,
            multipart_upload, headers,
        )

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 404
            error_code, _ = extract_error_info(response.aws.text)
            assert error_code == "NoSuchKey"
        else:
            assert response.status_code == 404
            error_code, _ = extract_error_info(response.text)
            assert error_code == "NoSuchKey"

    def test_nonexistent_source_bucket(
        self, test_bucket, upc_dest_key,
        multipart_upload, make_request, request,
    ):
        """UploadPartCopy with non-existent source bucket should return 404 NoSuchBucket."""
        fake_bucket = f"nonexistent-bucket-{uuid.uuid4().hex[:8]}"
        headers = {
            "x-amz-copy-source": f"/{fake_bucket}/some-key",
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, upc_dest_key,
            multipart_upload, headers,
        )

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 404
            error_code, _ = extract_error_info(response.aws.text)
            assert error_code == "NoSuchBucket"
        else:
            assert response.status_code == 404
            error_code, _ = extract_error_info(response.text)
            assert error_code == "NoSuchBucket"

    def test_copy_source_without_leading_slash(
        self, test_bucket, upc_dest_key, source_object,
        multipart_upload, make_request, request,
    ):
        """UploadPartCopy with copy-source without leading '/' (e.g., 'bucket/key')."""
        headers = {
            "x-amz-copy-source": f"{test_bucket}/{source_object['key']}",
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, upc_dest_key,
            multipart_upload, headers, part_number=2,
        )

        # AWS may accept this — verify actual behavior
        if hasattr(response, "comparison"):
            # Record actual status for future reference
            assert response.aws.status_code in (200, 400)
        else:
            assert response.status_code in (200, 400)

    def test_copy_source_only_bucket(
        self, test_bucket, upc_dest_key,
        multipart_upload, make_request, request,
    ):
        """UploadPartCopy with copy-source = '/bucket' (no key)."""
        headers = {
            "x-amz-copy-source": f"/{test_bucket}",
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, upc_dest_key,
            multipart_upload, headers,
        )

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
        else:
            assert response.status_code == 400

    def test_copy_source_just_slash(
        self, test_bucket, upc_dest_key,
        multipart_upload, make_request, request,
    ):
        """UploadPartCopy with copy-source = '/'."""
        headers = {
            "x-amz-copy-source": "/",
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, upc_dest_key,
            multipart_upload, headers,
        )

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
        else:
            assert response.status_code == 400

    def test_copy_source_with_spaces_in_key(
        self, test_bucket, upc_dest_key, aws_client, setup_test_bucket,
        multipart_upload, make_request, request,
    ):
        """UploadPartCopy with source key containing spaces."""
        key_with_spaces = f"test upc key with spaces {uuid.uuid4().hex[:8]}"

        # Create source object with spaces in key
        aws_client.put_object(
            Bucket=test_bucket, Key=key_with_spaces,
            Body=b"content with spaces in key",
        )

        try:
            headers = {
                "x-amz-copy-source": f"/{test_bucket}/{key_with_spaces}",
            }

            response = self._make_upc_request(
                make_request, request, test_bucket, upc_dest_key,
                multipart_upload, headers, part_number=3,
            )

            # AWS may require URL-encoding or accept as-is
            if hasattr(response, "comparison"):
                assert response.aws.status_code in (200, 400, 404)
            else:
                assert response.status_code in (200, 400, 404)
        finally:
            try:
                aws_client.delete_object(Bucket=test_bucket, Key=key_with_spaces)
            except Exception:
                pass

    @pytest.mark.edge_case
    def test_copy_source_same_as_destination(
        self, test_bucket, upc_dest_key, aws_client, setup_test_bucket,
        multipart_upload, make_request, request,
    ):
        """UploadPartCopy where source key = MPU destination key.

        The destination key doesn't exist as an object yet (only as MPU),
        so this should fail with NoSuchKey.
        """
        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{upc_dest_key}",
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, upc_dest_key,
            multipart_upload, headers,
        )

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 404
            error_code, _ = extract_error_info(response.aws.text)
            assert error_code == "NoSuchKey"
        else:
            assert response.status_code == 404
            error_code, _ = extract_error_info(response.text)
            assert error_code == "NoSuchKey"
