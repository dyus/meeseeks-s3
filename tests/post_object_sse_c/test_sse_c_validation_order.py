"""Tests for PostObject SSE-C validation priority.

Determines which error is returned first when multiple SSE-C fields are invalid.
"""

import base64
import hashlib

import pytest

from s3_compliance.sse_c import generate_sse_c_key
from s3_compliance.xml_utils import extract_error_info
from tests.post_object_sse_c.conftest import (
    ALL_SSEC_CONDITIONS,
    make_presigned_post,
)


@pytest.mark.post_object
@pytest.mark.s3_handler("PostObject")
@pytest.mark.sse_c
@pytest.mark.edge_case
class TestSSECPostObjectValidationOrder:
    """Determine PostObject SSE-C validation priority when multiple fields are invalid."""

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_all_invalid_b64_key(
        self, s3_client, test_bucket, test_key, file_content, post_with_ssec, json_metadata,
    ):
        """All three SSE-C fields invalid: bad algo, bad b64 key, wrong MD5."""
        wrong_md5 = base64.b64encode(hashlib.md5(b"wrong").digest()).decode("utf-8")

        presigned = make_presigned_post(
            s3_client, test_bucket, test_key,
            ssec_conditions=ALL_SSEC_CONDITIONS,
        )

        response = post_with_ssec(presigned["url"], presigned["fields"], file_content, {
            "x-amz-server-side-encryption-customer-algorithm": "AES256-INVALID",
            "x-amz-server-side-encryption-customer-key": "not-valid-base64!!!",
            "x-amz-server-side-encryption-customer-key-MD5": wrong_md5,
        })

        json_metadata["status"] = response.status_code
        assert response.status_code == 400, (
            f"Expected 400, got {response.status_code}: {response.text[:300]}"
        )
        error_code, error_msg = extract_error_info(response.text)
        json_metadata["error_code"] = error_code
        json_metadata["error_message"] = error_msg
        json_metadata["first_validation_error"] = error_code

        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_invalid_b64_key_with_invalid_algorithm(
        self, s3_client, test_bucket, test_key, file_content, post_with_ssec, json_metadata,
    ):
        """Invalid algo + invalid b64 key + valid-format MD5."""
        fake_md5 = base64.b64encode(hashlib.md5(b"anything").digest()).decode("utf-8")

        presigned = make_presigned_post(
            s3_client, test_bucket, test_key,
            ssec_conditions=ALL_SSEC_CONDITIONS,
        )

        response = post_with_ssec(presigned["url"], presigned["fields"], file_content, {
            "x-amz-server-side-encryption-customer-algorithm": "INVALID-ALGO",
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
        json_metadata["first_validation_error"] = error_code

        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_invalid_algorithm_with_short_key(
        self, s3_client, test_bucket, test_key, file_content, post_with_ssec, json_metadata,
    ):
        """Invalid algo + short key (10 bytes) with matching MD5."""
        key_b64, key_md5 = generate_sse_c_key(b"1234567890")

        presigned = make_presigned_post(
            s3_client, test_bucket, test_key,
            ssec_conditions=ALL_SSEC_CONDITIONS,
        )

        response = post_with_ssec(presigned["url"], presigned["fields"], file_content, {
            "x-amz-server-side-encryption-customer-algorithm": "INVALID-ALGO",
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
        json_metadata["first_validation_error"] = error_code

        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_short_key_with_mismatched_md5(
        self, s3_client, test_bucket, test_key, file_content, post_with_ssec, json_metadata,
    ):
        """Valid algo + short key (10 bytes) + wrong MD5."""
        short_key_b64 = base64.b64encode(b"1234567890").decode()
        wrong_md5 = base64.b64encode(hashlib.md5(b"wrong").digest()).decode("utf-8")

        presigned = make_presigned_post(
            s3_client, test_bucket, test_key,
            ssec_conditions=ALL_SSEC_CONDITIONS,
        )

        response = post_with_ssec(presigned["url"], presigned["fields"], file_content, {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": short_key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": wrong_md5,
        })

        json_metadata["status"] = response.status_code
        assert response.status_code == 400, (
            f"Expected 400, got {response.status_code}: {response.text[:300]}"
        )
        error_code, error_msg = extract_error_info(response.text)
        json_metadata["error_code"] = error_code
        json_metadata["error_message"] = error_msg
        json_metadata["first_validation_error"] = error_code

        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass
