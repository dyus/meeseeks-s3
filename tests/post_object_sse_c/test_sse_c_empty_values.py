"""PostObject SSE-C tests with empty string field values.

Tests whether AWS distinguishes between a missing SSE-C field
and a field present with an empty string value ("").

Key finding: AWS treats empty fields as PRESENT with invalid value,
not as absent. Empty algorithm="" gives InvalidEncryptionAlgorithmError,
while missing algorithm gives InvalidArgument.
"""

import pytest

from s3_compliance.sse_c import generate_sse_c_key
from s3_compliance.xml_utils import extract_error_info
from tests.post_object_sse_c.conftest import ALL_SSEC_CONDITIONS, make_presigned_post


@pytest.mark.post_object
@pytest.mark.s3_handler("PostObject")
@pytest.mark.sse_c
@pytest.mark.edge_case
class TestSSECPostObjectEmptyValues:
    """Test PostObject with empty string SSE-C field values.

    Compares behavior to missing fields (test_sse_c_fields.py)
    to determine if AWS treats empty vs absent differently.
    """

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_empty_algorithm_with_valid_key_and_md5(
        self, s3_client, test_bucket, test_key, file_content, post_with_ssec, json_metadata,
    ):
        """Empty algorithm + valid key + valid MD5.

        Returns InvalidEncryptionAlgorithmError (not InvalidArgument as with missing algorithm).
        AWS treats empty string as an invalid algorithm value, not as absent.
        """
        key_b64, key_md5 = generate_sse_c_key()

        presigned = make_presigned_post(
            s3_client, test_bucket, test_key,
            ssec_conditions=ALL_SSEC_CONDITIONS,
        )

        response = post_with_ssec(presigned["url"], presigned["fields"], file_content, {
            "x-amz-server-side-encryption-customer-algorithm": "",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        })

        json_metadata["status"] = response.status_code
        assert response.status_code == 400
        error_code, error_msg = extract_error_info(response.text)
        json_metadata["error_code"] = error_code
        json_metadata["error_message"] = error_msg
        assert error_code == "InvalidEncryptionAlgorithmError"

        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_empty_key_with_valid_algorithm_and_md5(
        self, s3_client, test_bucket, test_key, file_content, post_with_ssec, json_metadata,
    ):
        """Valid algorithm + empty key + valid MD5.

        AWS treats empty key as too short (0 bytes instead of 32).
        """
        _, key_md5 = generate_sse_c_key()

        presigned = make_presigned_post(
            s3_client, test_bucket, test_key,
            ssec_conditions=ALL_SSEC_CONDITIONS,
        )

        response = post_with_ssec(presigned["url"], presigned["fields"], file_content, {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": "",
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        })

        json_metadata["status"] = response.status_code
        assert response.status_code == 400
        error_code, error_msg = extract_error_info(response.text)
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
        self, s3_client, test_bucket, test_key, file_content, post_with_ssec, json_metadata,
    ):
        """Valid algorithm + valid key + empty MD5.

        AWS computes MD5 of the key and compares to empty string — mismatch.
        """
        key_b64, _ = generate_sse_c_key()

        presigned = make_presigned_post(
            s3_client, test_bucket, test_key,
            ssec_conditions=ALL_SSEC_CONDITIONS,
        )

        response = post_with_ssec(presigned["url"], presigned["fields"], file_content, {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": "",
        })

        json_metadata["status"] = response.status_code
        assert response.status_code == 400
        error_code, error_msg = extract_error_info(response.text)
        json_metadata["error_code"] = error_code
        json_metadata["error_message"] = error_msg
        assert error_code == "InvalidArgument"
        assert "MD5 hash" in error_msg

        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_all_three_fields_empty(
        self, s3_client, test_bucket, test_key, file_content, post_with_ssec, json_metadata,
    ):
        """All three SSE-C fields present but empty.

        AWS validates key first (too short), not algorithm.
        Validation order: key length > algorithm > MD5.
        """
        presigned = make_presigned_post(
            s3_client, test_bucket, test_key,
            ssec_conditions=ALL_SSEC_CONDITIONS,
        )

        response = post_with_ssec(presigned["url"], presigned["fields"], file_content, {
            "x-amz-server-side-encryption-customer-algorithm": "",
            "x-amz-server-side-encryption-customer-key": "",
            "x-amz-server-side-encryption-customer-key-MD5": "",
        })

        json_metadata["status"] = response.status_code
        assert response.status_code == 400
        error_code, error_msg = extract_error_info(response.text)
        json_metadata["error_code"] = error_code
        json_metadata["error_message"] = error_msg
        assert error_code == "InvalidArgument"
        assert "too short" in error_msg

        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_empty_algorithm_only(
        self, s3_client, test_bucket, test_key, file_content, post_with_ssec, json_metadata,
    ):
        """Only algorithm field present but empty (key and MD5 absent).

        AWS detects SSE-C intent from any SSE-C field presence,
        then requires the key — "must provide an appropriate secret key".
        """
        presigned = make_presigned_post(
            s3_client, test_bucket, test_key,
            ssec_conditions=[
                ["starts-with", "$x-amz-server-side-encryption-customer-algorithm", ""],
            ],
        )

        response = post_with_ssec(presigned["url"], presigned["fields"], file_content, {
            "x-amz-server-side-encryption-customer-algorithm": "",
        })

        json_metadata["status"] = response.status_code
        assert response.status_code == 400
        error_code, error_msg = extract_error_info(response.text)
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
        self, s3_client, test_bucket, test_key, file_content, post_with_ssec, json_metadata,
    ):
        """Only key field present but empty (algorithm and MD5 absent).

        AWS detects SSE-C from key field, requires algorithm first —
        "must provide a valid encryption algorithm".
        """
        presigned = make_presigned_post(
            s3_client, test_bucket, test_key,
            ssec_conditions=[
                ["starts-with", "$x-amz-server-side-encryption-customer-key", ""],
            ],
        )

        response = post_with_ssec(presigned["url"], presigned["fields"], file_content, {
            "x-amz-server-side-encryption-customer-key": "",
        })

        json_metadata["status"] = response.status_code
        assert response.status_code == 400
        error_code, error_msg = extract_error_info(response.text)
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
        self, s3_client, test_bucket, test_key, file_content, post_with_ssec, json_metadata,
    ):
        """Only MD5 field present but empty (algorithm and key absent).

        AWS detects SSE-C from MD5 field, requires algorithm first —
        "must provide a valid encryption algorithm".
        """
        presigned = make_presigned_post(
            s3_client, test_bucket, test_key,
            ssec_conditions=[
                ["starts-with", "$x-amz-server-side-encryption-customer-key-MD5", ""],
            ],
        )

        response = post_with_ssec(presigned["url"], presigned["fields"], file_content, {
            "x-amz-server-side-encryption-customer-key-MD5": "",
        })

        json_metadata["status"] = response.status_code
        assert response.status_code == 400
        error_code, error_msg = extract_error_info(response.text)
        json_metadata["error_code"] = error_code
        json_metadata["error_message"] = error_msg
        assert error_code == "InvalidArgument"
        assert "valid encryption algorithm" in error_msg

        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass
