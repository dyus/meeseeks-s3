"""CreateMultipartUpload SSE-C tests with empty string header values.

Tests whether AWS distinguishes between a missing SSE-C header
and a header present with an empty string value ("") when
initiating a multipart upload with SSE-C.

Mirrors tests/put_object_sse_c/test_sse_c_empty_values.py but for CreateMultipartUpload.
"""

import uuid

import pytest

from s3_compliance.sse_c import generate_sse_c_key
from s3_compliance.xml_utils import extract_error_info, extract_upload_id


@pytest.mark.s3_handler("CreateMultipartUpload")
@pytest.mark.sse_c
@pytest.mark.edge_case
class TestSSECCreateMultipartUploadEmptyValues:
    """Test CreateMultipartUpload with empty string SSE-C header values.

    Compares behavior to missing headers (test_sse_c_headers.py)
    to determine if AWS treats empty vs absent differently.
    """

    @pytest.fixture
    def test_key(self):
        return f"test-ssec-empty-mpu-{uuid.uuid4().hex[:8]}"

    def _abort_upload(self, s3_client, bucket, key, response):
        """Abort multipart upload if it was successfully created."""
        if hasattr(response, "comparison"):
            for resp in [response.aws, response.custom]:
                if resp.status_code == 200:
                    upload_id = extract_upload_id(resp.text)
                    if upload_id:
                        try:
                            s3_client.abort_multipart_upload(
                                Bucket=bucket, Key=key, UploadId=upload_id,
                            )
                        except Exception:
                            pass
        else:
            if response.status_code == 200:
                upload_id = extract_upload_id(response.text)
                if upload_id:
                    try:
                        s3_client.abort_multipart_upload(
                            Bucket=bucket, Key=key, UploadId=upload_id,
                        )
                    except Exception:
                        pass

    # =========================================================================
    # Combo tests: one field empty, others valid
    # =========================================================================

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_empty_algorithm_with_valid_key_and_md5(
        self, s3_client, test_bucket, test_key, make_request, json_metadata,
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

        response = make_request(
            "POST", f"/{test_bucket}/{test_key}",
            headers=headers, query_params="?uploads",
        )

        json_metadata["empty_field"] = "algorithm"

        if hasattr(response, "comparison"):
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            json_metadata["custom_status"] = response.custom.status_code
        else:
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._abort_upload(s3_client, test_bucket, test_key, response)

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_empty_key_with_valid_algorithm_and_md5(
        self, s3_client, test_bucket, test_key, make_request, json_metadata,
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

        response = make_request(
            "POST", f"/{test_bucket}/{test_key}",
            headers=headers, query_params="?uploads",
        )

        json_metadata["empty_field"] = "key"

        if hasattr(response, "comparison"):
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            json_metadata["custom_status"] = response.custom.status_code
        else:
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._abort_upload(s3_client, test_bucket, test_key, response)

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_empty_md5_with_valid_algorithm_and_key(
        self, s3_client, test_bucket, test_key, make_request, json_metadata,
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

        response = make_request(
            "POST", f"/{test_bucket}/{test_key}",
            headers=headers, query_params="?uploads",
        )

        json_metadata["empty_field"] = "md5"

        if hasattr(response, "comparison"):
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            json_metadata["custom_status"] = response.custom.status_code
        else:
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._abort_upload(s3_client, test_bucket, test_key, response)

    # =========================================================================
    # All three empty
    # =========================================================================

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_all_three_headers_empty(
        self, s3_client, test_bucket, test_key, make_request, json_metadata,
    ):
        """All three SSE-C headers present but empty.

        AWS validates key length first -- empty key is "too short".
        """
        headers = {
            "Content-Type": "application/octet-stream",
            "x-amz-server-side-encryption-customer-algorithm": "",
            "x-amz-server-side-encryption-customer-key": "",
            "x-amz-server-side-encryption-customer-key-MD5": "",
        }

        response = make_request(
            "POST", f"/{test_bucket}/{test_key}",
            headers=headers, query_params="?uploads",
        )

        json_metadata["empty_field"] = "all"

        if hasattr(response, "comparison"):
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            json_metadata["custom_status"] = response.custom.status_code
        else:
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._abort_upload(s3_client, test_bucket, test_key, response)

    # =========================================================================
    # Single empty header only (others absent)
    # =========================================================================

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_empty_algorithm_only(
        self, s3_client, test_bucket, test_key, make_request, json_metadata,
    ):
        """Only algorithm header present but empty (key and MD5 absent).

        AWS detects SSE-C intent from any SSE-C header presence.
        """
        headers = {
            "Content-Type": "application/octet-stream",
            "x-amz-server-side-encryption-customer-algorithm": "",
        }

        response = make_request(
            "POST", f"/{test_bucket}/{test_key}",
            headers=headers, query_params="?uploads",
        )

        json_metadata["empty_field"] = "algorithm_only"

        if hasattr(response, "comparison"):
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            json_metadata["custom_status"] = response.custom.status_code
        else:
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._abort_upload(s3_client, test_bucket, test_key, response)

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_empty_key_only(
        self, s3_client, test_bucket, test_key, make_request, json_metadata,
    ):
        """Only key header present but empty (algorithm and MD5 absent).

        AWS detects SSE-C from key header, requires algorithm first.
        """
        headers = {
            "Content-Type": "application/octet-stream",
            "x-amz-server-side-encryption-customer-key": "",
        }

        response = make_request(
            "POST", f"/{test_bucket}/{test_key}",
            headers=headers, query_params="?uploads",
        )

        json_metadata["empty_field"] = "key_only"

        if hasattr(response, "comparison"):
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            json_metadata["custom_status"] = response.custom.status_code
        else:
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._abort_upload(s3_client, test_bucket, test_key, response)

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_empty_md5_only(
        self, s3_client, test_bucket, test_key, make_request, json_metadata,
    ):
        """Only MD5 header present but empty (algorithm and key absent).

        AWS detects SSE-C from MD5 header, requires algorithm first.
        """
        headers = {
            "Content-Type": "application/octet-stream",
            "x-amz-server-side-encryption-customer-key-MD5": "",
        }

        response = make_request(
            "POST", f"/{test_bucket}/{test_key}",
            headers=headers, query_params="?uploads",
        )

        json_metadata["empty_field"] = "md5_only"

        if hasattr(response, "comparison"):
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            json_metadata["custom_status"] = response.custom.status_code
        else:
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._abort_upload(s3_client, test_bucket, test_key, response)
