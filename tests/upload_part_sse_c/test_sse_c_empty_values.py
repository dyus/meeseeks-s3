"""UploadPart SSE-C tests with empty string header values.

Tests whether AWS distinguishes between a missing SSE-C header
and a header present with an empty string value ("").

Mirrors tests/put_object_sse_c/test_sse_c_empty_values.py but for UploadPart.
"""

import uuid

import pytest

from s3_compliance.client import S3ClientFactory
from s3_compliance.sse_c import generate_sse_c_key
from s3_compliance.xml_utils import extract_error_info


@pytest.mark.upload_part
@pytest.mark.s3_handler("UploadPart")
@pytest.mark.sse_c
@pytest.mark.edge_case
class TestSSECUploadPartEmptyValues:
    """Test UploadPart with empty string SSE-C header values.

    Compares behavior to missing headers (test_sse_c_headers.py)
    to determine if AWS treats empty vs absent differently.
    """

    @pytest.fixture
    def test_key(self):
        return f"test-ssec-empty-upload-part-{uuid.uuid4().hex[:8]}"

    @pytest.fixture
    def part_body(self):
        return b"test part content for SSE-C empty value test"

    @pytest.fixture
    def ssec_multipart_upload(self, request, s3_client, aws_client, test_bucket, test_key):
        """Create and cleanup SSE-C multipart upload.

        In comparison mode (--endpoint=both), creates uploads on both endpoints.
        Returns upload_id or dict of upload_ids.
        """
        key_b64, key_md5 = generate_sse_c_key()
        endpoint_mode = request.config.getoption("--endpoint")

        ssec_params = {
            "SSECustomerAlgorithm": "AES256",
            "SSECustomerKey": key_b64,
            "SSECustomerKeyMD5": key_md5,
        }

        if endpoint_mode == "both":
            aws_response = aws_client.create_multipart_upload(
                Bucket=test_bucket, Key=test_key, **ssec_params,
            )
            aws_upload_id = aws_response["UploadId"]

            factory = S3ClientFactory()
            custom_client = factory.create_client("custom")

            def _add_forwarded_proto(params, **kwargs):
                params["headers"]["X-Forwarded-Proto"] = "https"

            custom_client.meta.events.register(
                "before-call.s3.CreateMultipartUpload", _add_forwarded_proto,
            )
            custom_response = custom_client.create_multipart_upload(
                Bucket=test_bucket, Key=test_key, **ssec_params,
            )
            custom_client.meta.events.unregister(
                "before-call.s3.CreateMultipartUpload", _add_forwarded_proto,
            )
            custom_upload_id = custom_response["UploadId"]

            yield {"aws": aws_upload_id, "custom": custom_upload_id}

            try:
                aws_client.abort_multipart_upload(
                    Bucket=test_bucket, Key=test_key, UploadId=aws_upload_id,
                )
            except Exception:
                pass
            try:
                custom_client.abort_multipart_upload(
                    Bucket=test_bucket, Key=test_key, UploadId=custom_upload_id,
                )
            except Exception:
                pass
        else:
            endpoint_is_custom = endpoint_mode == "custom"
            if endpoint_is_custom:
                def _add_forwarded_proto(params, **kwargs):
                    params["headers"]["X-Forwarded-Proto"] = "https"

                s3_client.meta.events.register(
                    "before-call.s3.CreateMultipartUpload", _add_forwarded_proto,
                )

            response = s3_client.create_multipart_upload(
                Bucket=test_bucket, Key=test_key, **ssec_params,
            )
            upload_id = response["UploadId"]

            if endpoint_is_custom:
                s3_client.meta.events.unregister(
                    "before-call.s3.CreateMultipartUpload", _add_forwarded_proto,
                )

            yield upload_id

            try:
                s3_client.abort_multipart_upload(
                    Bucket=test_bucket, Key=test_key, UploadId=upload_id,
                )
            except Exception:
                pass

    def _make_upload_part_request(
        self, make_request, request, test_bucket, test_key,
        ssec_multipart_upload, part_body, headers, part_number=1,
    ):
        """Make an UploadPart request via make_request fixture."""
        endpoint_mode = request.config.getoption("--endpoint")
        if endpoint_mode == "both":
            query_params = f"?uploadId={ssec_multipart_upload['aws']}&partNumber={part_number}"
            custom_query_params = f"?uploadId={ssec_multipart_upload['custom']}&partNumber={part_number}"
        else:
            query_params = f"?uploadId={ssec_multipart_upload}&partNumber={part_number}"
            custom_query_params = None

        return make_request(
            "PUT",
            f"/{test_bucket}/{test_key}",
            body=part_body if part_body is not None else b"",
            headers=headers,
            query_params=query_params,
            custom_query_params=custom_query_params,
        )

    # =========================================================================
    # Combo tests: one field empty, others valid
    # =========================================================================

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_empty_algorithm_with_valid_key_and_md5(
        self, test_bucket, test_key, part_body, ssec_multipart_upload,
        make_request, request, json_metadata,
    ):
        """Empty algorithm + valid key + valid MD5.

        AWS treats empty string as an invalid algorithm value, not as absent.
        """
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "Content-Type": "application/octet-stream",
            "x-amz-server-side-encryption-customer-algorithm": "",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_upload_part_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_upload, part_body, headers,
        )

        json_metadata["empty_field"] = "algorithm"

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            json_metadata["custom_status"] = response.custom.status_code
            assert error_code == "InvalidEncryptionAlgorithmError"
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg
            assert error_code == "InvalidEncryptionAlgorithmError"

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_empty_key_with_valid_algorithm_and_md5(
        self, test_bucket, test_key, part_body, ssec_multipart_upload,
        make_request, request, json_metadata,
    ):
        """Valid algorithm + empty key + valid MD5.

        AWS treats empty key as 0-byte key (too short).
        """
        _, key_md5 = generate_sse_c_key()

        headers = {
            "Content-Type": "application/octet-stream",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": "",
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_upload_part_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_upload, part_body, headers,
        )

        json_metadata["empty_field"] = "key"

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            json_metadata["custom_status"] = response.custom.status_code
            assert error_code == "InvalidArgument"
            assert "too short" in error_msg
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg
            assert error_code == "InvalidArgument"
            assert "too short" in error_msg

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_empty_md5_with_valid_algorithm_and_key(
        self, test_bucket, test_key, part_body, ssec_multipart_upload,
        make_request, request, json_metadata,
    ):
        """Valid algorithm + valid key + empty MD5.

        AWS computes MD5 of the key and compares to empty string -- mismatch.
        """
        key_b64, _ = generate_sse_c_key()

        headers = {
            "Content-Type": "application/octet-stream",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": "",
        }

        response = self._make_upload_part_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_upload, part_body, headers,
        )

        json_metadata["empty_field"] = "md5"

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            json_metadata["custom_status"] = response.custom.status_code
            assert error_code == "InvalidArgument"
            assert "MD5 hash" in error_msg
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg
            assert error_code == "InvalidArgument"
            assert "MD5 hash" in error_msg

    # =========================================================================
    # All three empty
    # =========================================================================

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_all_three_headers_empty(
        self, test_bucket, test_key, part_body, ssec_multipart_upload,
        make_request, request, json_metadata,
    ):
        """All three SSE-C headers present but empty.

        AWS validates key length first -- returns "too short".
        """
        headers = {
            "Content-Type": "application/octet-stream",
            "x-amz-server-side-encryption-customer-algorithm": "",
            "x-amz-server-side-encryption-customer-key": "",
            "x-amz-server-side-encryption-customer-key-MD5": "",
        }

        response = self._make_upload_part_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_upload, part_body, headers,
        )

        json_metadata["empty_field"] = "all"

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            json_metadata["custom_status"] = response.custom.status_code
            assert error_code == "InvalidArgument"
            assert "too short" in error_msg
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg
            assert error_code == "InvalidArgument"
            assert "too short" in error_msg

    # =========================================================================
    # Single empty header only (others absent)
    # =========================================================================

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_empty_algorithm_only(
        self, test_bucket, test_key, part_body, ssec_multipart_upload,
        make_request, request, json_metadata,
    ):
        """Only algorithm header present but empty (key and MD5 absent).

        AWS detects SSE-C intent from any SSE-C header presence.
        """
        headers = {
            "Content-Type": "application/octet-stream",
            "x-amz-server-side-encryption-customer-algorithm": "",
        }

        response = self._make_upload_part_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_upload, part_body, headers,
        )

        json_metadata["empty_field"] = "algorithm_only"

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            json_metadata["custom_status"] = response.custom.status_code
            assert error_code == "InvalidArgument"
            assert "appropriate secret key" in error_msg
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg
            assert error_code == "InvalidArgument"
            assert "appropriate secret key" in error_msg

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_empty_key_only(
        self, test_bucket, test_key, part_body, ssec_multipart_upload,
        make_request, request, json_metadata,
    ):
        """Only key header present but empty (algorithm and MD5 absent).

        AWS detects SSE-C from key header, requires algorithm first.
        """
        headers = {
            "Content-Type": "application/octet-stream",
            "x-amz-server-side-encryption-customer-key": "",
        }

        response = self._make_upload_part_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_upload, part_body, headers,
        )

        json_metadata["empty_field"] = "key_only"

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            json_metadata["custom_status"] = response.custom.status_code
            assert error_code == "InvalidArgument"
            assert "valid encryption algorithm" in error_msg
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg
            assert error_code == "InvalidArgument"
            assert "valid encryption algorithm" in error_msg

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_empty_md5_only(
        self, test_bucket, test_key, part_body, ssec_multipart_upload,
        make_request, request, json_metadata,
    ):
        """Only MD5 header present but empty (algorithm and key absent).

        AWS detects SSE-C from MD5 header, requires algorithm first.
        """
        headers = {
            "Content-Type": "application/octet-stream",
            "x-amz-server-side-encryption-customer-key-MD5": "",
        }

        response = self._make_upload_part_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_upload, part_body, headers,
        )

        json_metadata["empty_field"] = "md5_only"

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            json_metadata["custom_status"] = response.custom.status_code
            assert error_code == "InvalidArgument"
            assert "valid encryption algorithm" in error_msg
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg
            assert error_code == "InvalidArgument"
            assert "valid encryption algorithm" in error_msg
