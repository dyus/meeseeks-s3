"""HeadObject SSE-C tests with empty string header values.

Tests whether AWS distinguishes between a missing SSE-C header
and a header present with an empty string value ("") when
calling HeadObject on an SSE-C encrypted object.

Mirrors tests/get_object_sse_c/test_sse_c_empty_values.py but for HeadObject.

Note: HEAD responses have no body per HTTP spec, so error details
are only available via status code.
"""

import base64
import hashlib
import uuid

import pytest

from s3_compliance.sse_c import DEFAULT_SSE_C_KEY_BYTES, generate_sse_c_key


@pytest.fixture(scope="module")
def ssec_object_key():
    """Unique key for the SSE-C encrypted object shared across the module."""
    return f"test-ssec-head-empty-{uuid.uuid4().hex[:8]}"


@pytest.fixture(scope="module")
def ssec_object(request, aws_client, test_bucket, setup_test_bucket, ssec_object_key):
    """Create a single SSE-C encrypted object for the entire module."""
    import os
    from s3_compliance.client import S3ClientFactory

    sse_kwargs = dict(
        Bucket=test_bucket,
        Key=ssec_object_key,
        Body=b"head-object sse-c empty values test content",
        SSECustomerAlgorithm="AES256",
        SSECustomerKey=base64.b64encode(DEFAULT_SSE_C_KEY_BYTES).decode("utf-8"),
        SSECustomerKeyMD5=base64.b64encode(
            hashlib.md5(DEFAULT_SSE_C_KEY_BYTES).digest()
        ).decode("utf-8"),
    )

    endpoint_mode = request.config.getoption("--endpoint")

    if endpoint_mode in ("aws", "both"):
        aws_client.put_object(**sse_kwargs)

    custom_cl = None
    if os.getenv("S3_ENDPOINT") and endpoint_mode in ("custom", "both"):
        custom_cl = S3ClientFactory().create_client("custom")
        custom_cl.put_object(**sse_kwargs)

    yield ssec_object_key

    # Cleanup
    del_kwargs = dict(
        Bucket=test_bucket,
        Key=ssec_object_key,
    )
    if endpoint_mode in ("aws", "both"):
        try:
            aws_client.delete_object(**del_kwargs)
        except Exception:
            pass
    if custom_cl:
        try:
            custom_cl.delete_object(**del_kwargs)
        except Exception:
            pass


@pytest.mark.s3_handler("HeadObject")
@pytest.mark.sse_c
@pytest.mark.edge_case
class TestSSECHeadObjectEmptyValues:
    """Test HeadObject with empty string SSE-C header values.

    Compares behavior to missing headers (test_sse_c_headers.py)
    to determine if AWS treats empty vs absent differently.

    Note: HEAD responses have no body, so only status codes are checked.
    """

    # =========================================================================
    # Combo tests: one field empty, others valid
    # =========================================================================

    def test_head_ssec_empty_algorithm_with_valid_key_and_md5(
        self, test_bucket, ssec_object, make_request, json_metadata,
    ):
        """Empty algorithm + valid key + valid MD5.

        AWS treats empty string as an invalid algorithm value, not as absent.
        """
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "HEAD", f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["empty_field"] = "algorithm"

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code

    def test_head_ssec_empty_key_with_valid_algorithm_and_md5(
        self, test_bucket, ssec_object, make_request, json_metadata,
    ):
        """Valid algorithm + empty key + valid MD5.

        AWS treats empty key as 0-byte key (too short).
        """
        _, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": "",
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request(
            "HEAD", f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["empty_field"] = "key"

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code

    def test_head_ssec_empty_md5_with_valid_algorithm_and_key(
        self, test_bucket, ssec_object, make_request, json_metadata,
    ):
        """Valid algorithm + valid key + empty MD5.

        AWS computes MD5 of the key and compares to empty string -- mismatch.
        """
        key_b64, _ = generate_sse_c_key()

        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": "",
        }

        response = make_request(
            "HEAD", f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["empty_field"] = "md5"

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code

    # =========================================================================
    # All three empty
    # =========================================================================

    def test_head_ssec_all_three_headers_empty(
        self, test_bucket, ssec_object, make_request, json_metadata,
    ):
        """All three SSE-C headers present but empty.

        AWS validates key length first -- empty key is "too short".
        """
        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "",
            "x-amz-server-side-encryption-customer-key": "",
            "x-amz-server-side-encryption-customer-key-MD5": "",
        }

        response = make_request(
            "HEAD", f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["empty_field"] = "all"

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code

    # =========================================================================
    # Single empty header only (others absent)
    # =========================================================================

    def test_head_ssec_empty_algorithm_only(
        self, test_bucket, ssec_object, make_request, json_metadata,
    ):
        """Only algorithm header present but empty (key and MD5 absent).

        AWS detects SSE-C intent from any SSE-C header presence.
        """
        headers = {
            "x-amz-server-side-encryption-customer-algorithm": "",
        }

        response = make_request(
            "HEAD", f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["empty_field"] = "algorithm_only"

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code

    def test_head_ssec_empty_key_only(
        self, test_bucket, ssec_object, make_request, json_metadata,
    ):
        """Only key header present but empty (algorithm and MD5 absent).

        AWS detects SSE-C from key header, requires algorithm first.
        """
        headers = {
            "x-amz-server-side-encryption-customer-key": "",
        }

        response = make_request(
            "HEAD", f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["empty_field"] = "key_only"

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code

    def test_head_ssec_empty_md5_only(
        self, test_bucket, ssec_object, make_request, json_metadata,
    ):
        """Only MD5 header present but empty (algorithm and key absent).

        AWS detects SSE-C from MD5 header, requires algorithm first.
        """
        headers = {
            "x-amz-server-side-encryption-customer-key-MD5": "",
        }

        response = make_request(
            "HEAD", f"/{test_bucket}/{ssec_object}",
            headers=headers,
        )

        json_metadata["empty_field"] = "md5_only"

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code
