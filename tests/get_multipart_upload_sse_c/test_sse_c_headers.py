"""Tests for GetObject with SSE-C on objects created via multipart upload.

These tests verify S3 behavior when retrieving an SSE-C encrypted object
(created through CreateMultipartUpload + UploadPart + CompleteMultipartUpload)
with various header combinations and validation errors.

A single SSE-C encrypted multipart object is created once per module and reused.

GetObject for SSE-C requires three headers:
- x-amz-server-side-encryption-customer-algorithm: Must be "AES256"
- x-amz-server-side-encryption-customer-key: Base64-encoded 32-byte key
- x-amz-server-side-encryption-customer-key-MD5: Base64-encoded MD5 of the key
"""

import base64
import hashlib
import os
import uuid

import pytest

from s3_compliance.client import S3ClientFactory
from s3_compliance.sse_c import DEFAULT_SSE_C_KEY_BYTES, generate_sse_c_key
from s3_compliance.xml_utils import extract_error_info

PART_BODY = b"A" * (5 * 1024 * 1024)  # 5 MB — minimum for non-last part


@pytest.fixture(scope="module")
def ssec_mpu_key():
    """Unique key for the SSE-C multipart object shared across the module."""
    return f"test-ssec-get-mpu-{uuid.uuid4().hex[:8]}"


@pytest.fixture(scope="module")
def ssec_mpu_object(request, aws_client, test_bucket, setup_test_bucket, ssec_mpu_key):
    """Create a single SSE-C encrypted object via multipart upload for the entire module.

    Creates the object on the endpoint(s) being tested:
    - aws: AWS only
    - custom: Custom only
    - both: AWS and Custom
    """
    key_b64 = base64.b64encode(DEFAULT_SSE_C_KEY_BYTES).decode("utf-8")
    key_md5 = base64.b64encode(
        hashlib.md5(DEFAULT_SSE_C_KEY_BYTES).digest()
    ).decode("utf-8")

    ssec_params = {
        "SSECustomerAlgorithm": "AES256",
        "SSECustomerKey": key_b64,
        "SSECustomerKeyMD5": key_md5,
    }

    endpoint_mode = request.config.getoption("--endpoint")

    def _add_forwarded_proto(params, **kwargs):
        params["headers"]["X-Forwarded-Proto"] = "https"

    def _create_mpu_object(client, use_forwarded_proto=False):
        """Create multipart upload, upload one part, complete."""
        if use_forwarded_proto:
            client.meta.events.register("before-call.s3.CreateMultipartUpload", _add_forwarded_proto)
        mpu = client.create_multipart_upload(
            Bucket=test_bucket, Key=ssec_mpu_key, **ssec_params,
        )
        upload_id = mpu["UploadId"]
        if use_forwarded_proto:
            client.meta.events.unregister("before-call.s3.CreateMultipartUpload", _add_forwarded_proto)
            client.meta.events.register("before-call.s3.UploadPart", _add_forwarded_proto)
        client.upload_part(
            Bucket=test_bucket, Key=ssec_mpu_key,
            UploadId=upload_id, PartNumber=1,
            Body=PART_BODY, **ssec_params,
        )
        if use_forwarded_proto:
            client.meta.events.unregister("before-call.s3.UploadPart", _add_forwarded_proto)
            client.meta.events.register("before-call.s3.CompleteMultipartUpload", _add_forwarded_proto)
        client.complete_multipart_upload(
            Bucket=test_bucket, Key=ssec_mpu_key,
            UploadId=upload_id,
            MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": mpu.get("ETag", "")}]},
        )
        if use_forwarded_proto:
            client.meta.events.unregister("before-call.s3.CompleteMultipartUpload", _add_forwarded_proto)

    def _create_mpu_object_v2(client, use_forwarded_proto=False):
        """Create multipart upload, upload one part, complete — with proper ETag."""
        if use_forwarded_proto:
            client.meta.events.register("before-call.s3.CreateMultipartUpload", _add_forwarded_proto)
        mpu = client.create_multipart_upload(
            Bucket=test_bucket, Key=ssec_mpu_key, **ssec_params,
        )
        upload_id = mpu["UploadId"]
        if use_forwarded_proto:
            client.meta.events.unregister("before-call.s3.CreateMultipartUpload", _add_forwarded_proto)
            client.meta.events.register("before-call.s3.UploadPart", _add_forwarded_proto)
        part = client.upload_part(
            Bucket=test_bucket, Key=ssec_mpu_key,
            UploadId=upload_id, PartNumber=1,
            Body=PART_BODY, **ssec_params,
        )
        if use_forwarded_proto:
            client.meta.events.unregister("before-call.s3.UploadPart", _add_forwarded_proto)
            client.meta.events.register("before-call.s3.CompleteMultipartUpload", _add_forwarded_proto)
        client.complete_multipart_upload(
            Bucket=test_bucket, Key=ssec_mpu_key,
            UploadId=upload_id,
            MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": part["ETag"]}]},
        )
        if use_forwarded_proto:
            client.meta.events.unregister("before-call.s3.CompleteMultipartUpload", _add_forwarded_proto)

    custom_cl = None
    if os.getenv("S3_ENDPOINT") and endpoint_mode in ("custom", "both"):
        custom_cl = S3ClientFactory().create_client("custom")

    if endpoint_mode in ("aws", "both"):
        _create_mpu_object_v2(aws_client, use_forwarded_proto=False)
    if custom_cl:
        _create_mpu_object_v2(custom_cl, use_forwarded_proto=True)

    yield ssec_mpu_key

    # Cleanup
    if endpoint_mode in ("aws", "both"):
        try:
            aws_client.delete_object(Bucket=test_bucket, Key=ssec_mpu_key)
        except Exception:
            pass
    if custom_cl:
        try:
            custom_cl.delete_object(Bucket=test_bucket, Key=ssec_mpu_key)
        except Exception:
            pass


@pytest.mark.s3_handler("GetObject")
@pytest.mark.sse_c
class TestSSECGetMultipartObjectHeaders:
    """Test GetObject API with SSE-C header combinations on multipart-uploaded object."""

    # =========================================================================
    # Successful Request
    # =========================================================================

    def test_get_ssec_mpu_with_valid_headers(
        self,
        test_bucket,
        ssec_mpu_object,
        make_request,
        json_metadata,
    ):
        """Server should return decrypted multipart object with all valid SSE-C headers."""
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "GET",
            f"/{test_bucket}/{ssec_mpu_object}",
            headers=headers,
        )

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 200, (
                f"AWS expected 200, got {response.aws.status_code}"
            )
            assert response.aws.content == PART_BODY
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            assert response.status_code == 200, (
                f"Expected 200, got {response.status_code}: {response.text[:200]}"
            )
            assert response.content == PART_BODY
            json_metadata["status"] = response.status_code

    # =========================================================================
    # No SSE-C Headers (plain GET on encrypted multipart object)
    # =========================================================================

    def test_get_ssec_mpu_without_headers_rejected(
        self,
        test_bucket,
        ssec_mpu_object,
        make_request,
        json_metadata,
    ):
        """Server should reject GET without any SSE-C headers on encrypted multipart object."""
        response = make_request(
            "GET",
            f"/{test_bucket}/{ssec_mpu_object}",
        )

        json_metadata["provided_headers"] = []

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400, (
                f"AWS expected 400, got {response.aws.status_code}"
            )
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
        else:
            assert response.status_code == 400, (
                f"Expected 400, got {response.status_code}"
            )
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

    # =========================================================================
    # Missing Header Tests (partial SSE-C headers)
    # =========================================================================

    @pytest.mark.edge_case
    def test_get_ssec_mpu_only_algorithm_rejected(
        self, test_bucket, ssec_mpu_object, make_request, json_metadata,
    ):
        """Server should reject GET with only SSE-C algorithm header."""
        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
        }

        response = make_request(
            "GET", f"/{test_bucket}/{ssec_mpu_object}",
            headers=headers,
        )

        json_metadata["provided_headers"] = ["algorithm"]

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code

    @pytest.mark.edge_case
    def test_get_ssec_mpu_only_key_rejected(
        self, test_bucket, ssec_mpu_object, make_request, json_metadata,
    ):
        """Server should reject GET with only SSE-C key header."""
        key_b64, _ = generate_sse_c_key()

        headers = {
            "x-amz-server-side-encryption-customer-key": key_b64,
        }

        response = make_request(
            "GET", f"/{test_bucket}/{ssec_mpu_object}",
            headers=headers,
        )

        json_metadata["provided_headers"] = ["key"]

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code

    @pytest.mark.edge_case
    def test_get_ssec_mpu_only_key_md5_rejected(
        self, test_bucket, ssec_mpu_object, make_request, json_metadata,
    ):
        """Server should reject GET with only SSE-C key MD5 header."""
        _, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "GET", f"/{test_bucket}/{ssec_mpu_object}",
            headers=headers,
        )

        json_metadata["provided_headers"] = ["key_md5"]

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code

    @pytest.mark.edge_case
    def test_get_ssec_mpu_algorithm_and_key_without_md5_accepted(
        self, test_bucket, ssec_mpu_object, make_request, json_metadata,
    ):
        """Server accepts GET with algorithm and key but missing MD5.

        Unlike PutObject, GetObject does NOT require the key MD5 header.
        """
        key_b64, _ = generate_sse_c_key()

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
        }

        response = make_request(
            "GET", f"/{test_bucket}/{ssec_mpu_object}",
            headers=headers,
        )

        json_metadata["provided_headers"] = ["algorithm", "key"]

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 200
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            assert response.status_code == 200
            json_metadata["status"] = response.status_code

    @pytest.mark.edge_case
    def test_get_ssec_mpu_algorithm_and_md5_missing_key_rejected(
        self, test_bucket, ssec_mpu_object, make_request, json_metadata,
    ):
        """Server should reject GET with algorithm and MD5 but missing key."""
        _, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "GET", f"/{test_bucket}/{ssec_mpu_object}",
            headers=headers,
        )

        json_metadata["provided_headers"] = ["algorithm", "key_md5"]

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code

    @pytest.mark.edge_case
    def test_get_ssec_mpu_key_and_md5_missing_algorithm_rejected(
        self, test_bucket, ssec_mpu_object, make_request, json_metadata,
    ):
        """Server should reject GET with key and MD5 but missing algorithm."""
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "GET", f"/{test_bucket}/{ssec_mpu_object}",
            headers=headers,
        )

        json_metadata["provided_headers"] = ["key", "key_md5"]

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code

    # =========================================================================
    # Invalid Value Tests
    # =========================================================================

    @pytest.mark.edge_case
    def test_get_ssec_mpu_invalid_algorithm_rejected(
        self, test_bucket, ssec_mpu_object, make_request, json_metadata,
    ):
        """Server should reject GET with invalid SSE-C algorithm."""
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES128-INVALID",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "GET", f"/{test_bucket}/{ssec_mpu_object}",
            headers=headers,
        )

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, _ = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
        else:
            assert response.status_code == 400
            error_code, _ = extract_error_info(response.text)
            json_metadata["error_code"] = error_code

    @pytest.mark.edge_case
    def test_get_ssec_mpu_wrong_key_rejected(
        self, test_bucket, ssec_mpu_object, make_request, json_metadata,
    ):
        """Server should reject GET with a different (wrong) SSE-C key."""
        wrong_key_bytes = hashlib.sha256(b"this_is_a_totally_wrong_key").digest()
        key_b64, key_md5 = generate_sse_c_key(wrong_key_bytes)

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "GET", f"/{test_bucket}/{ssec_mpu_object}",
            headers=headers,
        )

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 403
            error_code, _ = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
        else:
            assert response.status_code == 403
            error_code, _ = extract_error_info(response.text)
            json_metadata["error_code"] = error_code

    @pytest.mark.edge_case
    def test_get_ssec_mpu_invalid_key_length_10_rejected(
        self, test_bucket, ssec_mpu_object, make_request, json_metadata,
    ):
        """Server should reject GET with invalid key length (10 bytes)."""
        short_key = b"1234567890"
        key_b64, key_md5 = generate_sse_c_key(short_key)

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "GET", f"/{test_bucket}/{ssec_mpu_object}",
            headers=headers,
        )

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 403
            error_code, _ = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
        else:
            assert response.status_code == 403
            error_code, _ = extract_error_info(response.text)
            json_metadata["error_code"] = error_code

    @pytest.mark.edge_case
    def test_get_ssec_mpu_mismatched_key_md5_rejected(
        self, test_bucket, ssec_mpu_object, make_request, json_metadata,
    ):
        """Server should reject GET with mismatched key MD5."""
        key_b64, _ = generate_sse_c_key()
        wrong_md5 = base64.b64encode(hashlib.md5(b"wrong_key_data").digest()).decode("utf-8")

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": wrong_md5,
        }

        response = make_request(
            "GET", f"/{test_bucket}/{ssec_mpu_object}",
            headers=headers,
        )

        if hasattr(response, "comparison"):
            error_code, _ = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
        else:
            error_code, _ = extract_error_info(response.text)
            json_metadata["error_code"] = error_code

    @pytest.mark.edge_case
    def test_get_ssec_mpu_invalid_key_md5_not_base64_rejected(
        self, test_bucket, ssec_mpu_object, make_request, json_metadata,
    ):
        """Server should reject GET with non-base64 key MD5."""
        key_b64, _ = generate_sse_c_key()

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": "not-valid-base64!!!",
        }

        response = make_request(
            "GET", f"/{test_bucket}/{ssec_mpu_object}",
            headers=headers,
        )

        if hasattr(response, "comparison"):
            error_code, _ = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
        else:
            error_code, _ = extract_error_info(response.text)
            json_metadata["error_code"] = error_code

    # =========================================================================
    # Key encoding edge cases
    # =========================================================================

    @pytest.mark.edge_case
    def test_get_ssec_mpu_key_latin1_chars(
        self, test_bucket, ssec_mpu_object, make_request, json_metadata,
    ):
        """Latin-1 characters in key cause SignatureDoesNotMatch."""
        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": "\u00e9\u00f1\u00fc\u00df",
            "x-amz-server-side-encryption-customer-key-MD5": "I0aPuXuw4REDJuP1fw07QQ==",
        }

        response = make_request(
            "GET", f"/{test_bucket}/{ssec_mpu_object}",
            headers=headers,
        )

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 403
            error_code, _ = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
        else:
            assert response.status_code == 403
            error_code, _ = extract_error_info(response.text)
            json_metadata["error_code"] = error_code

    @pytest.mark.edge_case
    def test_get_ssec_mpu_key_base64_with_tabs_and_newlines(
        self, test_bucket, ssec_mpu_object, make_request, json_metadata,
    ):
        """Tabs in base64 key — AWS ignores them, decodes correctly."""
        key_b64, key_md5 = generate_sse_c_key()
        # Insert tabs into valid base64
        tabbed_key = key_b64[:8] + "\t" + key_b64[8:16] + "\t" + key_b64[16:]

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": tabbed_key,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "GET", f"/{test_bucket}/{ssec_mpu_object}",
            headers=headers,
        )

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code

    @pytest.mark.edge_case
    def test_get_ssec_mpu_all_invalid_headers_over_http(
        self, test_bucket, ssec_mpu_object, make_request, json_metadata,
    ):
        """SSE-C GET over HTTP should be rejected."""
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES128-INVALID",
            "x-amz-server-side-encryption-customer-key": "not-valid-base64!!!",
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "GET", f"/{test_bucket}/{ssec_mpu_object}",
            headers=headers,
            scheme="http",
        )

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, _ = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
        else:
            assert response.status_code == 400
            error_code, _ = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
