"""Tests for PostObject with SSE-C field combinations.

Verifies S3 behavior when SSE-C form fields are provided in various
combinations via POST (form-based upload).

Supports single endpoint mode (--endpoint=aws or --endpoint=custom).
"""

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
class TestSSECPostObjectFields:
    """Test PostObject API with SSE-C field combinations."""

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_all_valid_fields_accepted(
        self, s3_client, test_bucket, test_key, file_content, post_with_ssec, json_metadata,
    ):
        """All three SSE-C fields valid — object uploaded successfully."""
        key_b64, key_md5 = generate_sse_c_key()

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
        assert response.status_code in [200, 201, 204], (
            f"Expected success, got {response.status_code}: {response.text[:300]}"
        )

        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    # Test 2: Only algorithm field
    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_only_algorithm_rejected(
        self, s3_client, test_bucket, test_key, file_content, post_with_ssec, json_metadata,
    ):
        """Only algorithm field — should be rejected (missing key + MD5)."""
        presigned = make_presigned_post(
            s3_client, test_bucket, test_key,
            ssec_conditions=[
                ["starts-with", "$x-amz-server-side-encryption-customer-algorithm", ""],
            ],
        )

        response = post_with_ssec(presigned["url"], presigned["fields"], file_content, {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
        })

        json_metadata["status"] = response.status_code
        assert response.status_code == 400, (
            f"Expected 400, got {response.status_code}: {response.text[:300]}"
        )
        if response.status_code >= 400:
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    # Test 3: Only key field
    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_only_key_rejected(
        self, s3_client, test_bucket, test_key, file_content, post_with_ssec, json_metadata,
    ):
        """Only key field — should be rejected (missing algorithm + MD5)."""
        key_b64, _ = generate_sse_c_key()

        presigned = make_presigned_post(
            s3_client, test_bucket, test_key,
            ssec_conditions=[
                ["starts-with", "$x-amz-server-side-encryption-customer-key", ""],
            ],
        )

        response = post_with_ssec(presigned["url"], presigned["fields"], file_content, {
            "x-amz-server-side-encryption-customer-key": key_b64,
        })

        json_metadata["status"] = response.status_code
        assert response.status_code == 400, (
            f"Expected 400, got {response.status_code}: {response.text[:300]}"
        )
        if response.status_code >= 400:
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    # Test 4: Only key-MD5 field
    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_only_key_md5_rejected(
        self, s3_client, test_bucket, test_key, file_content, post_with_ssec, json_metadata,
    ):
        """Only key-MD5 field — should be rejected (missing algorithm + key)."""
        _, key_md5 = generate_sse_c_key()

        presigned = make_presigned_post(
            s3_client, test_bucket, test_key,
            ssec_conditions=[
                ["starts-with", "$x-amz-server-side-encryption-customer-key-MD5", ""],
            ],
        )

        response = post_with_ssec(presigned["url"], presigned["fields"], file_content, {
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        })

        json_metadata["status"] = response.status_code
        assert response.status_code == 400, (
            f"Expected 400, got {response.status_code}: {response.text[:300]}"
        )
        if response.status_code >= 400:
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    # Test 5: Algorithm + key, missing MD5
    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_algorithm_and_key_missing_md5_rejected(
        self, s3_client, test_bucket, test_key, file_content, post_with_ssec, json_metadata,
    ):
        """Algorithm + key, no MD5 — should be rejected."""
        key_b64, _ = generate_sse_c_key()

        presigned = make_presigned_post(
            s3_client, test_bucket, test_key,
            ssec_conditions=[
                ["starts-with", "$x-amz-server-side-encryption-customer-algorithm", ""],
                ["starts-with", "$x-amz-server-side-encryption-customer-key", ""],
            ],
        )

        response = post_with_ssec(presigned["url"], presigned["fields"], file_content, {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
        })

        json_metadata["status"] = response.status_code
        assert response.status_code == 400, (
            f"Expected 400, got {response.status_code}: {response.text[:300]}"
        )
        if response.status_code >= 400:
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    # Test 6: Algorithm + MD5, missing key
    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_algorithm_and_md5_missing_key_rejected(
        self, s3_client, test_bucket, test_key, file_content, post_with_ssec, json_metadata,
    ):
        """Algorithm + MD5, no key — should be rejected."""
        _, key_md5 = generate_sse_c_key()

        presigned = make_presigned_post(
            s3_client, test_bucket, test_key,
            ssec_conditions=[
                ["starts-with", "$x-amz-server-side-encryption-customer-algorithm", ""],
                ["starts-with", "$x-amz-server-side-encryption-customer-key-MD5", ""],
            ],
        )

        response = post_with_ssec(presigned["url"], presigned["fields"], file_content, {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        })

        json_metadata["status"] = response.status_code
        assert response.status_code == 400, (
            f"Expected 400, got {response.status_code}: {response.text[:300]}"
        )
        if response.status_code >= 400:
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    # Test 7: Key + MD5, missing algorithm
    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_key_and_md5_missing_algorithm_rejected(
        self, s3_client, test_bucket, test_key, file_content, post_with_ssec, json_metadata,
    ):
        """Key + MD5, no algorithm — should be rejected."""
        key_b64, key_md5 = generate_sse_c_key()

        presigned = make_presigned_post(
            s3_client, test_bucket, test_key,
            ssec_conditions=[
                ["starts-with", "$x-amz-server-side-encryption-customer-key", ""],
                ["starts-with", "$x-amz-server-side-encryption-customer-key-MD5", ""],
            ],
        )

        response = post_with_ssec(presigned["url"], presigned["fields"], file_content, {
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        })

        json_metadata["status"] = response.status_code
        assert response.status_code == 400, (
            f"Expected 400, got {response.status_code}: {response.text[:300]}"
        )
        if response.status_code >= 400:
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass
