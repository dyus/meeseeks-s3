"""Tests for PutObject cross-header validation order.

Determine which validation runs first when multiple headers are invalid:
- SSE-C algorithm (x-amz-server-side-encryption-customer-algorithm)
- Storage class (x-amz-storage-class)
- Content-MD5

Each test sends a combination of invalid headers and records which error
S3 returns first. By comparing single-invalid baselines with pair/triple
combinations, we can determine the validation priority order.
"""

import uuid

import pytest

from s3_compliance.sse_c import generate_sse_c_key
from s3_compliance.utils import calculate_content_md5
from s3_compliance.xml_utils import extract_error_info


@pytest.mark.put_object
@pytest.mark.s3_handler("PutObject")
@pytest.mark.sse_c
@pytest.mark.edge_case
class TestPutObjectCrossValidationOrder:
    """Determine PutObject validation order across SSE-C, storage class, and Content-MD5."""

    @pytest.fixture
    def test_key(self):
        return f"test-validation-order-{uuid.uuid4().hex[:8]}"

    @pytest.fixture
    def test_body(self):
        return b"validation order test content"

    def _valid_sse_c_headers(self) -> dict:
        """Return valid SSE-C headers."""
        key_b64, key_md5 = generate_sse_c_key()
        return {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

    # =========================================================================
    # Baselines: single invalid header
    # =========================================================================

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_baseline_invalid_algorithm_only(
        self, s3_client, test_bucket, test_key, test_body, make_request, json_metadata,
    ):
        """Baseline: only SSE-C algorithm is invalid."""
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "Content-Type": "text/plain",
            "Content-MD5": calculate_content_md5(test_body),
            "x-amz-storage-class": "STANDARD",
            "x-amz-server-side-encryption-customer-algorithm": "AES128-INVALID",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request("PUT", f"/{test_bucket}/{test_key}", body=test_body, headers=headers)

        if hasattr(response, "comparison"):
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_status"] = response.aws.status_code
        else:
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["status"] = response.status_code
        json_metadata["error_code"] = error_code
        json_metadata["error_message"] = error_msg
        json_metadata["invalid_headers"] = ["algorithm"]

        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_baseline_invalid_storage_class_only(
        self, s3_client, test_bucket, test_key, test_body, make_request, json_metadata,
    ):
        """Baseline: only storage class is invalid."""
        headers = {
            "Content-Type": "text/plain",
            "Content-MD5": calculate_content_md5(test_body),
            "x-amz-storage-class": "INVALID_STORAGE_CLASS",
            **self._valid_sse_c_headers(),
        }

        response = make_request("PUT", f"/{test_bucket}/{test_key}", body=test_body, headers=headers)

        if hasattr(response, "comparison"):
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_status"] = response.aws.status_code
        else:
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["status"] = response.status_code
        json_metadata["error_code"] = error_code
        json_metadata["error_message"] = error_msg
        json_metadata["invalid_headers"] = ["storage_class"]

        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_baseline_invalid_content_md5_only(
        self, s3_client, test_bucket, test_key, test_body, make_request, json_metadata,
    ):
        """Baseline: only Content-MD5 is invalid."""
        headers = {
            "Content-Type": "text/plain",
            "Content-MD5": "dGhpcyBpcyB3cm9uZw==",  # valid base64, wrong digest
            "x-amz-storage-class": "STANDARD",
            **self._valid_sse_c_headers(),
        }

        response = make_request("PUT", f"/{test_bucket}/{test_key}", body=test_body, headers=headers)

        if hasattr(response, "comparison"):
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_status"] = response.aws.status_code
        else:
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["status"] = response.status_code
        json_metadata["error_code"] = error_code
        json_metadata["error_message"] = error_msg
        json_metadata["invalid_headers"] = ["content_md5"]

        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    # =========================================================================
    # Pairs: two invalid headers
    # =========================================================================

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_pair_invalid_algorithm_and_storage_class(
        self, s3_client, test_bucket, test_key, test_body, make_request, json_metadata,
    ):
        """Pair: invalid SSE-C algorithm + invalid storage class."""
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "Content-Type": "text/plain",
            "Content-MD5": calculate_content_md5(test_body),
            "x-amz-storage-class": "INVALID_STORAGE_CLASS",
            "x-amz-server-side-encryption-customer-algorithm": "AES128-INVALID",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request("PUT", f"/{test_bucket}/{test_key}", body=test_body, headers=headers)

        if hasattr(response, "comparison"):
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_status"] = response.aws.status_code
        else:
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["status"] = response.status_code
        json_metadata["error_code"] = error_code
        json_metadata["error_message"] = error_msg
        json_metadata["invalid_headers"] = ["algorithm", "storage_class"]

        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_pair_invalid_algorithm_and_content_md5(
        self, s3_client, test_bucket, test_key, test_body, make_request, json_metadata,
    ):
        """Pair: invalid SSE-C algorithm + invalid Content-MD5."""
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "Content-Type": "text/plain",
            "Content-MD5": "dGhpcyBpcyB3cm9uZw==",
            "x-amz-storage-class": "STANDARD",
            "x-amz-server-side-encryption-customer-algorithm": "AES128-INVALID",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request("PUT", f"/{test_bucket}/{test_key}", body=test_body, headers=headers)

        if hasattr(response, "comparison"):
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_status"] = response.aws.status_code
        else:
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["status"] = response.status_code
        json_metadata["error_code"] = error_code
        json_metadata["error_message"] = error_msg
        json_metadata["invalid_headers"] = ["algorithm", "content_md5"]

        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_pair_invalid_storage_class_and_content_md5(
        self, s3_client, test_bucket, test_key, test_body, make_request, json_metadata,
    ):
        """Pair: invalid storage class + invalid Content-MD5."""
        headers = {
            "Content-Type": "text/plain",
            "Content-MD5": "dGhpcyBpcyB3cm9uZw==",
            "x-amz-storage-class": "INVALID_STORAGE_CLASS",
            **self._valid_sse_c_headers(),
        }

        response = make_request("PUT", f"/{test_bucket}/{test_key}", body=test_body, headers=headers)

        if hasattr(response, "comparison"):
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_status"] = response.aws.status_code
        else:
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["status"] = response.status_code
        json_metadata["error_code"] = error_code
        json_metadata["error_message"] = error_msg
        json_metadata["invalid_headers"] = ["storage_class", "content_md5"]

        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    # =========================================================================
    # Triple: all three invalid
    # =========================================================================

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_triple_all_invalid(
        self, s3_client, test_bucket, test_key, test_body, make_request, json_metadata,
    ):
        """Triple: invalid SSE-C algorithm + invalid storage class + invalid Content-MD5."""
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "Content-Type": "text/plain",
            "Content-MD5": "dGhpcyBpcyB3cm9uZw==",
            "x-amz-storage-class": "INVALID_STORAGE_CLASS",
            "x-amz-server-side-encryption-customer-algorithm": "AES128-INVALID",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request("PUT", f"/{test_bucket}/{test_key}", body=test_body, headers=headers)

        if hasattr(response, "comparison"):
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_status"] = response.aws.status_code
        else:
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["status"] = response.status_code
        json_metadata["error_code"] = error_code
        json_metadata["error_message"] = error_msg
        json_metadata["invalid_headers"] = ["algorithm", "storage_class", "content_md5"]

        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass
