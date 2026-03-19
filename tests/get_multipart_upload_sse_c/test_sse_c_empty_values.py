"""GetObject SSE-C tests with empty string header values on multipart-uploaded objects.

Tests whether AWS distinguishes between a missing SSE-C header
and a header present with an empty string value ("") when
retrieving an SSE-C encrypted multipart object.
"""

import base64
import hashlib
import os
import uuid

import pytest

from s3_compliance.client import S3ClientFactory
from s3_compliance.sse_c import DEFAULT_SSE_C_KEY_BYTES, generate_sse_c_key
from s3_compliance.xml_utils import extract_error_info

PART_BODY = b"A" * (5 * 1024 * 1024)  # 5 MB


@pytest.fixture(scope="module")
def ssec_mpu_key():
    """Unique key for the SSE-C multipart object shared across the module."""
    return f"test-ssec-get-mpu-empty-{uuid.uuid4().hex[:8]}"


@pytest.fixture(scope="module")
def ssec_mpu_object(request, aws_client, test_bucket, setup_test_bucket, ssec_mpu_key):
    """Create a single SSE-C encrypted object via multipart upload for the entire module."""
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
        _create_mpu_object(aws_client, use_forwarded_proto=False)
    if custom_cl:
        _create_mpu_object(custom_cl, use_forwarded_proto=True)

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
@pytest.mark.edge_case
class TestSSECGetMultipartObjectEmptyValues:
    """Test GetObject with empty string SSE-C header values on multipart object."""

    # =========================================================================
    # Combo tests: one field empty, others valid
    # =========================================================================

    def test_get_ssec_mpu_empty_algorithm_with_valid_key_and_md5(
        self, test_bucket, ssec_mpu_object, make_request, json_metadata,
    ):
        """Empty algorithm + valid key + valid MD5."""
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "GET", f"/{test_bucket}/{ssec_mpu_object}",
            headers=headers,
        )

        json_metadata["empty_field"] = "algorithm"

        if hasattr(response, "comparison"):
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["aws_error_code"] = error_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code

    def test_get_ssec_mpu_empty_key_with_valid_algorithm_and_md5(
        self, test_bucket, ssec_mpu_object, make_request, json_metadata,
    ):
        """Valid algorithm + empty key + valid MD5."""
        _, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": "",
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "GET", f"/{test_bucket}/{ssec_mpu_object}",
            headers=headers,
        )

        json_metadata["empty_field"] = "key"

        if hasattr(response, "comparison"):
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["aws_error_code"] = error_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code

    def test_get_ssec_mpu_empty_md5_with_valid_algorithm_and_key(
        self, test_bucket, ssec_mpu_object, make_request, json_metadata,
    ):
        """Valid algorithm + valid key + empty MD5."""
        key_b64, _ = generate_sse_c_key()

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": "",
        }

        response = make_request(
            "GET", f"/{test_bucket}/{ssec_mpu_object}",
            headers=headers,
        )

        json_metadata["empty_field"] = "md5"

        if hasattr(response, "comparison"):
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["aws_error_code"] = error_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code

    # =========================================================================
    # All three empty
    # =========================================================================

    def test_get_ssec_mpu_all_three_headers_empty(
        self, test_bucket, ssec_mpu_object, make_request, json_metadata,
    ):
        """All three SSE-C headers present but empty."""
        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "",
            "x-amz-server-side-encryption-customer-key": "",
            "x-amz-server-side-encryption-customer-key-MD5": "",
        }

        response = make_request(
            "GET", f"/{test_bucket}/{ssec_mpu_object}",
            headers=headers,
        )

        json_metadata["empty_field"] = "all"

        if hasattr(response, "comparison"):
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["aws_error_code"] = error_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code

    # =========================================================================
    # Single empty header only (others absent)
    # =========================================================================

    def test_get_ssec_mpu_empty_algorithm_only(
        self, test_bucket, ssec_mpu_object, make_request, json_metadata,
    ):
        """Only algorithm header present but empty."""
        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "",
        }

        response = make_request(
            "GET", f"/{test_bucket}/{ssec_mpu_object}",
            headers=headers,
        )

        json_metadata["empty_field"] = "algorithm_only"

        if hasattr(response, "comparison"):
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["aws_error_code"] = error_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code

    def test_get_ssec_mpu_empty_key_only(
        self, test_bucket, ssec_mpu_object, make_request, json_metadata,
    ):
        """Only key header present but empty."""
        headers = {
            "x-amz-server-side-encryption-customer-key": "",
        }

        response = make_request(
            "GET", f"/{test_bucket}/{ssec_mpu_object}",
            headers=headers,
        )

        json_metadata["empty_field"] = "key_only"

        if hasattr(response, "comparison"):
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["aws_error_code"] = error_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code

    def test_get_ssec_mpu_empty_md5_only(
        self, test_bucket, ssec_mpu_object, make_request, json_metadata,
    ):
        """Only MD5 header present but empty."""
        headers = {
            "x-amz-server-side-encryption-customer-key-MD5": "",
        }

        response = make_request(
            "GET", f"/{test_bucket}/{ssec_mpu_object}",
            headers=headers,
        )

        json_metadata["empty_field"] = "md5_only"

        if hasattr(response, "comparison"):
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["aws_error_code"] = error_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code
