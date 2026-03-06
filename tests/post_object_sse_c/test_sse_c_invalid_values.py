"""PostObject SSE-C tests with invalid field values.

All tests send all 3 SSE-C fields (algorithm, key, MD5) but with one or more
invalid values to verify S3 rejects them properly.
"""

import base64
import hashlib

import pytest

from s3_compliance.sse_c import generate_sse_c_key
from s3_compliance.xml_utils import extract_error_info
from tests.post_object_sse_c.conftest import ALL_SSEC_CONDITIONS, make_presigned_post


@pytest.mark.post_object
@pytest.mark.s3_handler("PostObject")
@pytest.mark.sse_c
class TestSSECPostObjectInvalidValues:

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_invalid_algorithm(
        self, s3_client, test_bucket, test_key, file_content, post_with_ssec, json_metadata,
    ):
        """Invalid algorithm value — should be rejected."""
        key_b64, key_md5 = generate_sse_c_key()

        presigned = make_presigned_post(
            s3_client, test_bucket, test_key,
            ssec_conditions=ALL_SSEC_CONDITIONS,
        )

        response = post_with_ssec(presigned["url"], presigned["fields"], file_content, {
            "x-amz-server-side-encryption-customer-algorithm": "AES128-INVALID",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        })

        json_metadata["status"] = response.status_code
        assert response.status_code == 400, (
            f"Expected 400, got {response.status_code}: {response.text[:300]}"
        )
        error_code, error_msg = extract_error_info(response.text)
        json_metadata["error_code"] = error_code
        json_metadata["error_message"] = error_msg

        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_short_key(
        self, s3_client, test_bucket, test_key, file_content, post_with_ssec, json_metadata,
    ):
        """Key too short (10 bytes instead of 32) — should be rejected."""
        key_b64, key_md5 = generate_sse_c_key(b"1234567890")

        presigned = make_presigned_post(
            s3_client, test_bucket, test_key,
            ssec_conditions=ALL_SSEC_CONDITIONS,
        )

        response = post_with_ssec(presigned["url"], presigned["fields"], file_content, {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        })

        json_metadata["status"] = response.status_code
        assert response.status_code == 400, (
            f"Expected 400, got {response.status_code}: {response.text[:300]}"
        )
        error_code, error_msg = extract_error_info(response.text)
        json_metadata["error_code"] = error_code
        json_metadata["error_message"] = error_msg

        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_key_md5_mismatch(
        self, s3_client, test_bucket, test_key, file_content, post_with_ssec, json_metadata,
    ):
        """Valid key but MD5 of a different key — should be rejected."""
        key_b64, _key_md5 = generate_sse_c_key()
        wrong_md5 = base64.b64encode(hashlib.md5(b"wrong-key").digest()).decode("utf-8")

        presigned = make_presigned_post(
            s3_client, test_bucket, test_key,
            ssec_conditions=ALL_SSEC_CONDITIONS,
        )

        response = post_with_ssec(presigned["url"], presigned["fields"], file_content, {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": wrong_md5,
        })

        json_metadata["status"] = response.status_code
        assert response.status_code == 400, (
            f"Expected 400, got {response.status_code}: {response.text[:300]}"
        )
        error_code, error_msg = extract_error_info(response.text)
        json_metadata["error_code"] = error_code
        json_metadata["error_message"] = error_msg

        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_key_md5_invalid_base64(
        self, s3_client, test_bucket, test_key, file_content, post_with_ssec, json_metadata,
    ):
        """Valid key but MD5 is not valid base64 — should be rejected."""
        key_b64, _key_md5 = generate_sse_c_key()

        presigned = make_presigned_post(
            s3_client, test_bucket, test_key,
            ssec_conditions=ALL_SSEC_CONDITIONS,
        )

        response = post_with_ssec(presigned["url"], presigned["fields"], file_content, {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": "not-valid-base64!!!",
        })

        json_metadata["status"] = response.status_code
        assert response.status_code == 400, (
            f"Expected 400, got {response.status_code}: {response.text[:300]}"
        )
        error_code, error_msg = extract_error_info(response.text)
        json_metadata["error_code"] = error_code
        json_metadata["error_message"] = error_msg

        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_customer_key_invalid_base64(
        self, s3_client, test_bucket, test_key, file_content, post_with_ssec, json_metadata,
    ):
        """Key is not valid base64 — should be rejected."""
        fake_md5 = base64.b64encode(hashlib.md5(b"anything").digest()).decode("utf-8")

        presigned = make_presigned_post(
            s3_client, test_bucket, test_key,
            ssec_conditions=ALL_SSEC_CONDITIONS,
        )

        response = post_with_ssec(presigned["url"], presigned["fields"], file_content, {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": "not-valid-base64!!!",
            "x-amz-server-side-encryption-customer-key-MD5": fake_md5,
        })

        json_metadata["status"] = response.status_code
        assert response.status_code == 400, (
            f"Expected 400, got {response.status_code}: {response.text[:300]}"
        )
        error_code, error_msg = extract_error_info(response.text)
        json_metadata["error_code"] = error_code
        json_metadata["error_message"] = error_msg

        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass
