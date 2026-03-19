"""PutObject SSE-C tests with empty string header values.

Tests whether AWS distinguishes between a missing SSE-C header
and a header present with an empty string value ("").

Mirrors tests/post_object_sse_c/test_sse_c_empty_values.py but for PutObject.
"""

import uuid

import pytest

from s3_compliance.sse_c import generate_sse_c_key
from s3_compliance.xml_utils import extract_error_info


@pytest.mark.put_object
@pytest.mark.s3_handler("PutObject")
@pytest.mark.sse_c
@pytest.mark.edge_case
class TestSSECPutObjectEmptyValues:
    """Test PutObject with empty string SSE-C header values.

    Compares behavior to missing headers (test_sse_c_headers.py)
    to determine if AWS treats empty vs absent differently.
    """

    @pytest.fixture
    def test_key(self):
        return f"test-ssec-empty-{uuid.uuid4().hex[:8]}"

    @pytest.fixture
    def test_body(self):
        return b"test content for SSE-C empty value test"

    # =========================================================================
    # Combo tests: one field empty, others valid
    # =========================================================================

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_empty_algorithm_with_valid_key_and_md5(
        self, s3_client, test_bucket, test_key, test_body, make_request, json_metadata,
    ):
        """Empty algorithm + valid key + valid MD5.

        PostObject returns InvalidEncryptionAlgorithmError here.
        AWS treats empty string as an invalid algorithm value, not as absent.
        """
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "Content-Type": "text/plain",
            "x-amz-server-side-encryption-customer-algorithm": "",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "PUT", f"/{test_bucket}/{test_key}",
            body=test_body, headers=headers,
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

        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_empty_key_with_valid_algorithm_and_md5(
        self, s3_client, test_bucket, test_key, test_body, make_request, json_metadata,
    ):
        """Valid algorithm + empty key + valid MD5.

        PostObject returns InvalidArgument with "too short".
        AWS treats empty key as 0-byte key (too short).
        """
        _, key_md5 = generate_sse_c_key()

        headers = {
            "Content-Type": "text/plain",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": "",
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "PUT", f"/{test_bucket}/{test_key}",
            body=test_body, headers=headers,
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

        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_empty_md5_with_valid_algorithm_and_key(
        self, s3_client, test_bucket, test_key, test_body, make_request, json_metadata,
    ):
        """Valid algorithm + valid key + empty MD5.

        PostObject returns InvalidArgument with "MD5 hash".
        AWS computes MD5 of the key and compares to empty string — mismatch.
        """
        key_b64, _ = generate_sse_c_key()

        headers = {
            "Content-Type": "text/plain",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": "",
        }

        response = make_request(
            "PUT", f"/{test_bucket}/{test_key}",
            body=test_body, headers=headers,
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

        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    # =========================================================================
    # All three empty
    # =========================================================================

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_all_three_headers_empty(
        self, s3_client, test_bucket, test_key, test_body, make_request, json_metadata,
    ):
        """All three SSE-C headers present but empty.

        PostObject returns InvalidArgument with "too short" (validates key length first).
        """
        headers = {
            "Content-Type": "text/plain",
            "x-amz-server-side-encryption-customer-algorithm": "",
            "x-amz-server-side-encryption-customer-key": "",
            "x-amz-server-side-encryption-customer-key-MD5": "",
        }

        response = make_request(
            "PUT", f"/{test_bucket}/{test_key}",
            body=test_body, headers=headers,
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

        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    # =========================================================================
    # Single empty header only (others absent)
    # =========================================================================

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_empty_algorithm_only(
        self, s3_client, test_bucket, test_key, test_body, make_request, json_metadata,
    ):
        """Only algorithm header present but empty (key and MD5 absent).

        PostObject returns InvalidArgument with "appropriate secret key".
        AWS detects SSE-C intent from any SSE-C header presence.
        """
        headers = {
            "Content-Type": "text/plain",
            "x-amz-server-side-encryption-customer-algorithm": "",
        }

        response = make_request(
            "PUT", f"/{test_bucket}/{test_key}",
            body=test_body, headers=headers,
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

        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_empty_key_only(
        self, s3_client, test_bucket, test_key, test_body, make_request, json_metadata,
    ):
        """Only key header present but empty (algorithm and MD5 absent).

        PostObject returns InvalidArgument with "valid encryption algorithm".
        AWS detects SSE-C from key header, requires algorithm first.
        """
        headers = {
            "Content-Type": "text/plain",
            "x-amz-server-side-encryption-customer-key": "",
        }

        response = make_request(
            "PUT", f"/{test_bucket}/{test_key}",
            body=test_body, headers=headers,
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

        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_empty_md5_only(
        self, s3_client, test_bucket, test_key, test_body, make_request, json_metadata,
    ):
        """Only MD5 header present but empty (algorithm and key absent).

        PostObject returns InvalidArgument with "valid encryption algorithm".
        AWS detects SSE-C from MD5 header, requires algorithm first.
        """
        headers = {
            "Content-Type": "text/plain",
            "x-amz-server-side-encryption-customer-key-MD5": "",
        }

        response = make_request(
            "PUT", f"/{test_bucket}/{test_key}",
            body=test_body, headers=headers,
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

        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass
